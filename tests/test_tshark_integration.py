"""Small, synthetic PCAP integration test; requires TShark in CI / local PATH."""

from __future__ import annotations

import shutil
import socket
import struct
from pathlib import Path

import pytest

from packetsleuth.core import CaptureStore, InvestigationEngine

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    values = struct.unpack(f"!{len(data) // 2}H", data)
    value = sum(values)
    while value > 0xFFFF:
        value = (value & 0xFFFF) + (value >> 16)
    return (~value) & 0xFFFF


def tcp_frame(seq: int, flags: int, payload: bytes) -> bytes:
    src, dst = socket.inet_aton("192.0.2.15"), socket.inet_aton("198.51.100.25")
    eth = bytes.fromhex("aabbccddeeff0011223344550800")
    tcp_base = struct.pack("!HHLLBBHHH", 47123, 9001, seq, 0, 0x50, flags, 4096, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp_base) + len(payload))
    tcp_check = checksum(pseudo + tcp_base + payload)
    tcp = struct.pack("!HHLLBBHHH", 47123, 9001, seq, 0, 0x50, flags, 4096, tcp_check, 0)
    ip_base = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload),
        1337, 0x4000, 64, 6, 0, src, dst,
    )
    ip_check = checksum(ip_base)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload),
        1337, 0x4000, 64, 6, ip_check, src, dst,
    )
    return eth + ip + tcp + payload


def make_pcap(path: Path) -> Path:
    frames = [tcp_frame(100, 0x02, b""), tcp_frame(101, 0x18, b"CTF_TEST_MARKER")]
    with path.open("wb") as fh:
        fh.write(bytes.fromhex("d4c3b2a1") + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate(frames):
            fh.write(struct.pack("<IIII", 1700000000 + i, 0, len(frame), len(frame)))
            fh.write(frame)
    return path


def test_pcap_tcp_payload_and_stream_parsing(tmp_path):
    make_pcap(tmp_path / "synthetic.pcap")
    engine = InvestigationEngine(CaptureStore(tmp_path))
    capture = engine.store.list()[0]["capture_id"]

    overview = engine.inspect_capture(capture)
    assert overview["observed_packets"] == 2

    flow_result = engine.query_flows(capture)
    assert len(flow_result["flows"]) == 1
    stream_id = int(flow_result["flows"][0]["stream_id"])

    payload = engine.inspect_tcp_payload(capture, frame=2)
    assert payload["found"] is True
    assert bytes.fromhex(payload["payload_hex"]) == b"CTF_TEST_MARKER"

    segments = engine.query_tcp_segments(capture, stream_id, scan_frames=3)
    assert len(segments["segments"]) == 1
    assert segments["segments"][0]["frame"] == 2

    preview = engine.follow_stream(capture, stream_id)
    assert "CTF_TEST_MARKER" in preview["data"]
    assert preview["output_truncated"] is False

    assert engine.verify_evidence(capture, [1, 2])["references_verified"]


def test_generic_query_and_out_of_order_reconstruction(tmp_path):
    """No CTF fixture: recover deliberately out-of-order generic TCP bytes."""
    from packetsleuth.forensics import query_packets, reconstruct_tcp, identify_stream_content

    path = tmp_path / "reorder.pcap"
    frames = [
        tcp_frame(100, 0x02, b""),
        tcp_frame(106, 0x18, b"1.7\n"),
        tcp_frame(101, 0x18, b"%PDF-"),
    ]
    with path.open("wb") as fh:
        fh.write(bytes.fromhex("d4c3b2a1") + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            fh.write(struct.pack("<IIII", 1700001000 + index, 0, len(frame), len(frame)))
            fh.write(frame)

    engine = InvestigationEngine(CaptureStore(tmp_path))
    capture = engine.store.list()[0]["capture_id"]
    generic = query_packets(engine, capture, ["frame.number", "tcp.len"],
                            match_field="tcp.stream", match_value="0",
                            match_mode="exact")
    assert len(generic["records"]) == 3
    stream = reconstruct_tcp(engine, capture, 0, source_ip="192.0.2.15",
                             start_frame=1, scan_frames=10)
    assert bytes.fromhex(stream["data_hex"]) == b"%PDF-1.7\n"
    assert stream["complete_sequence_span"]
    signature = identify_stream_content(engine, capture, 0, source_ip="192.0.2.15")
    assert signature["content_hint"]["format"] == "PDF document"
