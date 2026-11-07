"""Deterministic ICMP Echo extraction, offset, and safety regression tests."""

from __future__ import annotations

import hashlib
import ipaddress
import struct
from pathlib import Path

import pytest

from packetsleuth.core import CaptureStore, InvestigationEngine, PacketSleuthError
from packetsleuth.icmp import inspect_icmp_payload


def packet_v4(payload=b"ABC\\x00XYZ", *, fragment=0, icmp_type=8):
    # Ethernet frame has padding deliberately excluded from Echo data.
    icmp = bytes([icmp_type, 0, 0, 0]) + struct.pack("!HH", 7, 11) + payload
    ip = (bytes([0x45, 0]) + struct.pack("!H", 20 + len(icmp))
          + struct.pack("!HH", 0, fragment) + bytes([64, 1, 0, 0])
          + ipaddress.IPv4Address("192.0.2.10").packed
          + ipaddress.IPv4Address("198.51.100.20").packed)
    return bytes(12) + b"\\x08\\x00" + ip + icmp + b"\\x00" * 6


def packet_v6(payload=b"V6", *, extension=False):
    ext = bytes([58, 0]) + bytes(6) if extension else b""
    icmp = bytes([128, 0, 0, 0]) + struct.pack("!HH", 23, 42) + payload
    header = (bytes([0x60, 0, 0, 0]) + struct.pack("!H", len(ext) + len(icmp))
              + bytes([0 if extension else 58, 64])
              + ipaddress.IPv6Address("2001:db8::1").packed
              + ipaddress.IPv6Address("2001:db8::2").packed)
    return bytes(12) + b"\\x86\\xdd" + header + ext + icmp


def raw_packet(frame, protocol="icmpv4", extension=False):
    net_off = 14
    icmp_off = net_off + (20 if protocol == "icmpv4" else 40 + (8 if extension else 0))
    key = "ip_raw" if protocol == "icmpv4" else "ipv6_raw"
    icmp_key = "icmp_raw" if protocol == "icmpv4" else "icmpv6_raw"
    ip_len = 20 if protocol == "icmpv4" else 40
    # Mimic jsonraw dissectors which expose only the ICMP header, not data.
    layers = {
        "frame_raw": [frame.hex(), 0, len(frame), 0, 1],
        key: [frame[net_off:net_off + ip_len].hex(), net_off, ip_len, 0, 1],
        icmp_key: [frame[icmp_off:icmp_off + 8].hex(), icmp_off, 8, 0, 1],
    }
    return {"_source": {"layers": layers}}


class Runner:
    def __init__(self, packet, *, present=True):
        self.raw = packet
        self.present = present

    def raw_frame(self, path, frame):
        return self.raw if self.present else None

    def query(self, path, fields=None, display_filter=None, scan_limit=None):
        if not self.present:
            return []
        size = len(bytes.fromhex(self.raw["_source"]["layers"]["frame_raw"][0]))
        row = {"frame.number": "1", "frame.time_epoch": "1700000001.0",
               "frame.cap_len": str(size), "frame.len": str(size), "frame.file_off": "24"}
        return [row]


def case(tmp_path: Path, raw):
    (tmp_path / "case.pcap").write_bytes(bytes.fromhex("d4c3b2a1") + bytes(24))
    engine = InvestigationEngine(CaptureStore(tmp_path), Runner(raw))
    capture_id = engine.store.list()[0]["capture_id"]
    digest = engine.inspect_capture(capture_id)["sha256"] if False else hashlib.sha256(
        (tmp_path / "case.pcap").read_bytes()).hexdigest()
    return engine, capture_id, digest


def test_v4_padding_excluded_and_bounded(tmp_path):
    wire = packet_v4(b"AB\\x00\\xffZ")
    engine, capture_id, digest = case(tmp_path, raw_packet(wire))
    result = inspect_icmp_payload(engine, capture_id, 1, digest, 3)
    assert result["status"] == "ok"
    assert result["payload_hex"] == b"AB\\x00".hex()
    assert result["payload_ascii"] == "AB."
    assert result["payload_bytes"] == 5
    assert result["payload_truncated"] is True
    assert result["payload_offset_in_frame"] == 42
    assert result["payload_sha256"] == hashlib.sha256(b"AB\\x00\\xffZ").hexdigest()
    assert result["frame_sha256"] == hashlib.sha256(wire).hexdigest()
    assert result["identifier"] == 7 and result["sequence"] == 11
    assert result["untrusted_data"] is True


def test_v6_extension_offset(tmp_path):
    wire = packet_v6(b"HELLO", extension=True)
    engine, capture_id, digest = case(tmp_path, raw_packet(wire, "icmpv6", extension=True))
    result = inspect_icmp_payload(engine, capture_id, 1, digest)
    assert result["status"] == "ok"
    assert result["payload_hex"] == b"HELLO".hex()
    assert result["payload_offset_in_frame"] == 70
    assert result["identifier"] == 23 and result["sequence"] == 42


def test_reject_fragment_and_inconsistent_raw(tmp_path):
    wire = packet_v4(fragment=0x2000)
    engine, capture_id, digest = case(tmp_path, raw_packet(wire))
    assert inspect_icmp_payload(engine, capture_id, 1, digest)["status"] == "unsupported_layout"
    original = packet_v4()
    bad = raw_packet(original)
    bad["_source"]["layers"]["icmp_raw"][0] = "00" * 8
    engine.runner.raw = bad
    assert inspect_icmp_payload(engine, capture_id, 1, digest)["status"] == "unsupported_layout"


def test_not_echo_and_hash_pin(tmp_path):
    wire = packet_v4(icmp_type=3)
    engine, capture_id, digest = case(tmp_path, raw_packet(wire))
    assert inspect_icmp_payload(engine, capture_id, 1, digest)["status"] == "not_icmp_echo"
    with pytest.raises(PacketSleuthError, match="mismatch"):
        inspect_icmp_payload(engine, capture_id, 1, "0" * 64)
    with pytest.raises(PacketSleuthError, match="required"):
        inspect_icmp_payload(engine, capture_id, 1, None)
    with pytest.raises(PacketSleuthError, match="max_bytes"):
        inspect_icmp_payload(engine, capture_id, 1, digest, 10_000)
