"""Actual TShark JSON-raw offset verification on generated ICMP PCAPs."""

from __future__ import annotations

import hashlib
import ipaddress
import shutil
import struct
from pathlib import Path

import pytest

from packetsleuth.core import CaptureStore, InvestigationEngine
from packetsleuth.icmp import inspect_icmp_payload

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark unavailable")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_echo(payload: bytes, echo_type: int = 8) -> bytes:
    src = ipaddress.IPv4Address("192.0.2.11").packed
    dst = ipaddress.IPv4Address("198.51.100.12").packed
    echo = bytes([echo_type, 0, 0, 0]) + struct.pack("!HH", 0x200, 9) + payload
    echo = echo[:2] + struct.pack("!H", checksum(echo)) + echo[4:]
    ip = (b"\x45\x00" + struct.pack("!H", 20 + len(echo))
          + b"\x00\x01\x00\x00\x40\x01\x00\x00" + src + dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return b"\x00" * 12 + b"\x08\x00" + ip + echo + b"\x00" * 6


def ipv6_echo(payload: bytes) -> bytes:
    src = ipaddress.IPv6Address("2001:db8::11").packed
    dst = ipaddress.IPv6Address("2001:db8::12").packed
    # Hop-by-Hop extension: next header=ICMPv6, length=8 bytes.
    ext = bytes([58, 0]) + bytes(6)
    echo = b"\x80\x00\x00\x00" + struct.pack("!HH", 0x321, 10) + payload
    pseudo = src + dst + struct.pack("!I", len(echo)) + b"\x00\x00\x00\x3a"
    echo = echo[:2] + struct.pack("!H", checksum(pseudo + echo)) + echo[4:]
    ip = b"\x60\x00\x00\x00" + struct.pack("!H", len(ext) + len(echo))
    ip += bytes([0, 64]) + src + dst
    return b"\x00" * 12 + b"\x86\xdd" + ip + ext + echo


def write_pcap(path: Path, packets: list[bytes]) -> None:
    with path.open("wb") as file:
        file.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, wire in enumerate(packets):
            file.write(struct.pack("<IIII", 1_700_000_000 + index, 0,
                                   len(wire), len(wire)))
            file.write(wire)


def test_real_tshark_icmp_echo_ipv4_ipv6_and_empty(tmp_path):
    path = tmp_path / "icmp.pcap"
    write_pcap(path, [
        ipv4_echo(b"EXFIL? no, synthetic"),
        ipv4_echo(b"", echo_type=0),
        ipv6_echo(b"V6\x00ECHO"),
    ])
    engine = InvestigationEngine(CaptureStore(tmp_path))
    capture_id = engine.store.list()[0]["capture_id"]
    pin = hashlib.sha256(path.read_bytes()).hexdigest()

    v4 = inspect_icmp_payload(engine, capture_id, 1, pin)
    assert v4["status"] == "ok", v4
    assert bytes.fromhex(v4["payload_hex"]) == b"EXFIL? no, synthetic"
    assert v4["payload_offset_in_frame"] == 42
    assert v4["frame_sha256"] == hashlib.sha256(ipv4_echo(b"EXFIL? no, synthetic")).hexdigest()

    empty = inspect_icmp_payload(engine, capture_id, 2, pin)
    assert empty["status"] == "ok", empty
    assert empty["payload_bytes"] == 0
    assert empty["payload_hex"] == ""

    v6 = inspect_icmp_payload(engine, capture_id, 3, pin)
    assert v6["status"] == "ok", v6
    assert bytes.fromhex(v6["payload_hex"]) == b"V6\x00ECHO"
    assert v6["payload_offset_in_frame"] == 70
    assert v6["sequence"] == 10
