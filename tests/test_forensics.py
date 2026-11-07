"""Protocol-neutral v0.3 behavior on synthetic traffic unrelated to any CTF."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from packetsleuth.core import CaptureStore, InvestigationEngine, PacketSleuthError
from packetsleuth.forensics import (
    _magic_kind,
    identify_stream_content,
    query_packets,
    reconstruct_tcp,
    verify_stream_range,
)


class FakeTShark:
    """Honor only the fixed frame/stream expressions used by the forensic layer."""

    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def query(self, path, fields=None, display_filter=None, scan_limit=10_000):
        self.calls.append((fields, display_filter, scan_limit))
        rows = list(self.rows)
        if scan_limit is not None:
            rows = [r for r in rows if int(r["frame.number"]) <= scan_limit]
        if display_filter:
            lower = re.search(r"frame.number >= (\d+)", display_filter)
            upper = re.search(r"frame.number <= (\d+)", display_filter)
            stream = re.search(r"tcp.stream == (\d+)", display_filter)
            if lower:
                rows = [r for r in rows if int(r["frame.number"]) >= int(lower.group(1))]
            if upper:
                rows = [r for r in rows if int(r["frame.number"]) <= int(upper.group(1))]
            if stream:
                rows = [r for r in rows if r.get("tcp.stream") == stream.group(1)]
            if "tcp.len > 0" in display_filter:
                rows = [r for r in rows if int(r.get("tcp.len") or 0) > 0]
        return rows


def tcp_row(frame, seq, data, source="192.0.2.10", source_port=5000):
    target = "198.51.100.8" if source == "192.0.2.10" else "192.0.2.10"
    return {
        "frame.number": str(frame), "frame.time_epoch": str(1700000000 + frame),
        "frame.len": str(60 + len(data)), "frame.protocols": "eth:ip:tcp",
        "ip.src": source, "ip.dst": target,
        "tcp.srcport": str(source_port), "tcp.dstport": "443" if source_port == 5000 else "5000",
        "tcp.stream": "0", "tcp.seq_raw": str(seq), "tcp.seq": str(seq),
        "tcp.len": str(len(data)), "tcp.payload": data.hex(),
    }


@pytest.fixture
def demo(tmp_path: Path):
    (tmp_path / "sample.pcap").write_bytes(bytes.fromhex("d4c3b2a1") + b"\0" * 24)
    rows = [
        tcp_row(801, 106, b"world"),  # out-of-order observed BEFORE earlier bytes
        tcp_row(802, 101, b"hello"),
        tcp_row(803, 101, b"hello"),  # identical retransmission
        tcp_row(804, 900, b"HTTP/1.1 200 OK", "198.51.100.8", 443),
    ]
    fake = FakeTShark(rows)
    engine = InvestigationEngine(CaptureStore(tmp_path), fake)
    return engine, engine.store.list()[0]["capture_id"], fake


def test_frame_cursor_does_not_skip_matches(demo):
    engine, capture, runner = demo
    page1 = query_packets(engine, capture, ["frame.number", "ip.src", "tcp.stream"],
                          match_field="ip.src", match_value="192.0.2.10", limit=2,
                          start_frame=800, scan_frames=5)
    assert [entry["frame"] for entry in page1["records"]] == [801, 802]
    assert page1["next_start_frame"] == 803
    assert page1["results_truncated"] is True
    page2 = query_packets(engine, capture, ["frame.number", "ip.src"],
                          match_field="ip.src", match_value="192.0.2.10",
                          start_frame=page1["next_start_frame"], scan_frames=5)
    assert [entry["frame"] for entry in page2["records"]] == [803]
    assert runner.calls[-1][2] == 807
    assert page2["coverage"]["complete_capture_scan"] is False


def test_query_is_not_an_arbitrary_tshark_filter(demo):
    engine, capture, runner = demo
    with pytest.raises(PacketSleuthError, match="Unsupported"):
        query_packets(engine, capture, fields=["tcp.payload"])
    with pytest.raises(PacketSleuthError, match="Unsupported"):
        query_packets(engine, capture, match_field="frame.number || true", match_value="x")
    with pytest.raises(PacketSleuthError, match="must be supplied together"):
        query_packets(engine, capture, match_field="http.host")
    with pytest.raises(PacketSleuthError, match="scan_frames"):
        query_packets(engine, capture, scan_frames=10_000)
    with pytest.raises(PacketSleuthError, match="printable"):
        query_packets(engine, capture, match_field="http.host", match_value="abc\nBAD")
    assert not runner.calls


def test_direction_selection_and_reassembly(demo):
    engine, capture, _ = demo
    first = reconstruct_tcp(engine, capture, 0, start_frame=800, scan_frames=10)
    assert first["status"] == "direction_required"
    assert len(first["directions"]) == 2
    output = reconstruct_tcp(engine, capture, 0, source_ip="192.0.2.10",
                             start_frame=800, scan_frames=10)
    assert bytes.fromhex(output["data_hex"]) == b"helloworld"
    assert output["complete_sequence_span"] is True
    assert output["overlap_bytes"] == 5
    assert output["contributing_frames"] == [801, 802, 803]
    assert not output["missing_ranges"]
    assert output["returned_range_sha256"] == hashlib.sha256(b"helloworld").hexdigest()
    second = reconstruct_tcp(engine, capture, 0, source_ip="192.0.2.10",
                             start_frame=800, scan_frames=10, byte_offset=5,
                             max_bytes=5)
    assert bytes.fromhex(second["data_hex"]) == b"world"
    verified = verify_stream_range(
        engine, capture, 0, hashlib.sha256(b"world").hexdigest(),
        source_ip="192.0.2.10", start_frame=800, scan_frames=10,
        byte_offset=5, max_bytes=5,
    )
    assert verified["range_sha256_matches"]


def test_missing_bytes_not_filled_and_conflicts_reported(demo):
    engine, capture, fake = demo
    fake.rows = [tcp_row(101, 1000, b"ABCD"), tcp_row(102, 1007, b"ZZ")]
    result = reconstruct_tcp(engine, capture, 0)
    assert result["missing_ranges"] == [{"start": 4, "end_exclusive": 7}]
    assert not result["complete_sequence_span"]
    assert bytes.fromhex(result["data_hex"]) == b"ABCD"
    assert result["next_byte_offset"] is None  # gap: do not silently join
    latter = reconstruct_tcp(engine, capture, 0, byte_offset=7)
    assert bytes.fromhex(latter["data_hex"]) == b"ZZ"
    fake.rows = [tcp_row(101, 1000, b"abc"), tcp_row(102, 1000, b"axc")]
    conflict = reconstruct_tcp(engine, capture, 0)
    assert conflict["conflicting_overlap_frames"] == [102]
    assert not conflict["complete_sequence_span"]
    assert bytes.fromhex(conflict["data_hex"]) == b"abc"  # first captured wins


def test_format_identification_and_hash_pin(demo):
    engine, capture, fake = demo
    fake.rows = [tcp_row(11, 200, b"%PDF-1.7\n%binary...")]
    result = identify_stream_content(engine, capture, 0)
    assert result["content_hint"]["format"] == "PDF document"
    assert "data_hex" not in result
    assert _magic_kind(b"\x16\x03\x03\x00\x05hello")["format"] == "TLS record candidate"
    assert _magic_kind(b"PK\x03\x04rest")["format"] == "ZIP archive"
    with pytest.raises(PacketSleuthError, match="SHA-256 mismatch"):
        reconstruct_tcp(engine, capture, 0, expected_sha256="0" * 64)
    assert not verify_stream_range(engine, capture, 0, "0" * 64)["range_sha256_matches"]


def test_source_ports_and_size_bounds(demo):
    engine, capture, fake = demo
    with pytest.raises(PacketSleuthError):
        reconstruct_tcp(engine, capture, 0, source_port=80)
    with pytest.raises(PacketSleuthError):
        reconstruct_tcp(engine, capture, 0, source_ip="foo")
    with pytest.raises(PacketSleuthError):
        reconstruct_tcp(engine, capture, 0, max_bytes=10_000)
    with pytest.raises(PacketSleuthError):
        reconstruct_tcp(engine, capture, 0, start_frame=True)
    fake.rows = [tcp_row(1, 1000, b"a"), tcp_row(2, 1_500_000, b"b")]
    with pytest.raises(PacketSleuthError, match="sequence span"):
        reconstruct_tcp(engine, capture, 0)


def test_length_mismatch_does_not_claim_complete(demo):
    engine, capture, fake = demo
    row = tcp_row(101, 1234, b"xyz")
    row["tcp.len"] = "10"
    fake.rows = [row]
    result = reconstruct_tcp(engine, capture, 0)
    assert result["reported_length_mismatch_frames"] == [101]
    assert result["missing_ranges"] == [{"start": 3, "end_exclusive": 10}]
    assert not result["complete_sequence_span"]
