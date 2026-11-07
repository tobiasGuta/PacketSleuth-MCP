"""Real TShark DNS answers and query/response evidence from synthetic PCAPs."""

from __future__ import annotations

import hashlib
import ipaddress
import shutil
import struct

import pytest

from packetsleuth.core import CaptureStore, InvestigationEngine
from packetsleuth.dns import query_dns

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="TShark unavailable")


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def name_bytes(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii")
                    for label in name.split(".")) + b"\x00"


def frame(dns: bytes, response: bool) -> bytes:
    src = ipaddress.IPv4Address("192.0.2.53" if response else "198.51.100.2").packed
    dst = ipaddress.IPv4Address("198.51.100.2" if response else "192.0.2.53").packed
    sport, dport = (53, 39876) if response else (39876, 53)
    udp = struct.pack("!HHHH", sport, dport, 8 + len(dns), 0) + dns
    header = (b"\x45\x00" + struct.pack("!H", 20 + len(udp))
              + b"\x00\x01\x00\x00\x40\x11\x00\x00" + src + dst)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return b"\x00" * 12 + b"\x08\x00" + header + udp


def dns_message(response: bool) -> bytes:
    label = name_bytes("multi.example.test")
    question = label + struct.pack("!HH", 1, 1)
    flags = 0x8180 if response else 0x0100
    ancount = 3 if response else 0
    header = struct.pack("!HHHHHH", 0x1234, flags, 1, ancount, 0, 0)
    answers = b""
    if response:
        for ttl, address in ((60, "192.0.2.10"), (120, "192.0.2.11")):
            raw = ipaddress.IPv4Address(address).packed
            answers += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, len(raw)) + raw
        raw = ipaddress.IPv6Address("2001:db8::10").packed
        answers += b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 30, len(raw)) + raw
    return header + question + answers


def test_real_dns_multianswer_ttl_and_cursor(tmp_path):
    path = tmp_path / "dns-evidence.pcap"
    packets = [frame(dns_message(False), False), frame(dns_message(True), True)]
    with path.open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, packet in enumerate(packets):
            out.write(struct.pack("<IIII", 1_700_000_000 + i, 0,
                                  len(packet), len(packet)))
            out.write(packet)
    engine = InvestigationEngine(CaptureStore(tmp_path))
    capture = engine.store.list()[0]["capture_id"]
    pin = hashlib.sha256(path.read_bytes()).hexdigest()

    first = query_dns(engine, capture, pin, start_frame=1, scan_frames=2, limit=1)
    assert first["has_more"] and first["next_cursor"], first
    assert first["events"][0]["message_kind"] == "query"
    assert first["events"][0]["transaction_id"] == 0x1234

    second = query_dns(
        engine, capture, pin, start_frame=1, scan_frames=2, limit=1,
        cursor=first["next_cursor"],
    )
    assert not second["has_more"], second
    reply = second["events"][0]
    assert reply["message_kind"] == "response"
    assert reply["query_name"] == "multi.example.test"
    assert reply["query_type"] == 1
    assert reply["response_code"] == 0
    assert reply["query_frame"] == 1
    assert reply["frame"] == 2
    assert reply["record_parse_complete"], reply
    assert [(rec["record_type"], rec["ttl"]) for rec in reply["answer_records"]] == [
        ("A", 60), ("A", 120), ("AAAA", 30),
    ]
    assert reply["answer_ips"] == [
        "192.0.2.10", "192.0.2.11", "2001:db8::10",
    ]
    assert second["sha256"] == pin
