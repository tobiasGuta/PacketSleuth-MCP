"""Unit tests for bounded ICMP Echo grouping and candidate-only reconstruction."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from packetsleuth.core import CaptureStore, InvestigationEngine, PacketSleuthError
from packetsleuth.icmp_flow import reconstruct_icmp_flow


def row(frame, kind="request", seq=1, ident=10, src=None, dst=None, proto="icmpv4"):
    if src is None:
        src = "192.0.2.10" if kind == "request" else "198.51.100.22"
    if dst is None:
        dst = "198.51.100.22" if kind == "request" else "192.0.2.10"
    value = {"frame.number": str(frame), "frame.time_epoch": str(1_700_000_000 + frame)}
    if proto == "icmpv4":
        value.update({"ip.src": src, "ip.dst": dst,
                      "icmp.type": "8" if kind == "request" else "0",
                      "icmp.ident": str(ident), "icmp.seq": str(seq)})
    else:
        value.update({"ipv6.src": src, "ipv6.dst": dst,
                      "icmpv6.type": "128" if kind == "request" else "129",
                      "icmpv6.echo.identifier": str(ident),
                      "icmpv6.echo.sequence_number": str(seq)})
    return value


class FakeRunner:
    def __init__(self, records):
        self.rows = records
        self.calls = []

    def query(self, path, fields, display_filter, scan_limit):
        self.calls.append((fields, display_filter, scan_limit))
        window = re.search(r"frame.number >= (\d+) && frame.number <= (\d+)", display_filter)
        start, end = map(int, window.groups())
        return [r for r in self.rows if start <= int(r["frame.number"]) <= end]


def case(tmp_path: Path, monkeypatch, rows, payloads=None, reject=None):
    path = tmp_path / "fake.pcap"
    path.write_bytes(bytes.fromhex("d4c3b2a1") + bytes(24))
    engine = InvestigationEngine(CaptureStore(tmp_path), FakeRunner(rows))
    capture_id = engine.store.list()[0]["capture_id"]
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    payloads = payloads or {int(r["frame.number"]): b"ABC" for r in rows}
    lookup = {int(r["frame.number"]): r for r in rows}

    def inspect(_engine, _capture, frame, expected_sha256, max_bytes):
        assert expected_sha256 == digest
        original = lookup[frame]
        from packetsleuth.icmp_flow import _echo_row
        metadata = _echo_row(original)
        if frame == reject:
            return {"status": "unsupported_layout"}
        data = payloads[frame]
        return {
            "status": "ok", "protocol": metadata["protocol"],
            "identifier": metadata["identifier"], "sequence": metadata["sequence"],
            "src_ip": metadata["src_ip"], "dst_ip": metadata["dst_ip"],
            "message_kind": "echo_" + metadata["kind"],
            "frame_sha256": hashlib.sha256(str(frame).encode()).hexdigest(),
            "payload_sha256": hashlib.sha256(data).hexdigest(),
            "payload_bytes": len(data), "payload_offset_in_frame": 42,
            "payload_truncated": len(data) > max_bytes,
            "payload_hex": data[:max_bytes].hex(),
        }

    monkeypatch.setattr("packetsleuth.icmp_flow.icmp.inspect_icmp_payload", inspect)
    return engine, capture_id, digest


def test_pairing_and_evidence(tmp_path, monkeypatch):
    rows = [row(1, seq=10), row(2, "reply", seq=10), row(3, seq=11)]
    engine, capture, pin = case(tmp_path, monkeypatch, rows)
    result = reconstruct_icmp_flow(engine, capture, pin, scan_frames=3)
    assert result["status"] == "correlated_window"
    pairs = result["correlation"]["pairs"]
    assert pairs == [{"sequence": 10, "request_frame": 1,
                      "reply_frame": 2, "payload_equal": True}]
    assert result["correlation"]["unmatched_request_frames"] == [3]
    assert result["candidate"]["status"] == "not_requested"
    assert result["untrusted_data"] is True
    assert len(result["packets"]) == 3
    assert all("payload_preview_hex" in p for p in result["packets"])


def test_selection_does_not_mix_sessions(tmp_path, monkeypatch):
    rows = [row(1, ident=7), row(2, ident=8), row(3, ident=8)]
    engine, capture, pin = case(tmp_path, monkeypatch, rows)
    broad = reconstruct_icmp_flow(engine, capture, pin, scan_frames=3)
    assert broad["status"] == "group_selection_required"
    assert len(broad["groups"]) == 2
    narrow = reconstruct_icmp_flow(engine, capture, pin, scan_frames=3, identifier=7)
    assert narrow["status"] == "correlated_window"
    assert [p["frame"] for p in narrow["packets"]] == [1]


def test_candidate_concatenation_and_duplicate_reporting(tmp_path, monkeypatch):
    rows = [row(1, seq=101), row(2, seq=100), row(3, seq=100)]
    payloads = {1: b"B", 2: b"A", 3: b"A"}
    engine, capture, pin = case(tmp_path, monkeypatch, rows, payloads)
    result = reconstruct_icmp_flow(engine, capture, pin, scan_frames=3,
                                   reconstruction_mode="request")
    candidate = result["candidate"]
    assert candidate["status"] == "candidate_only"
    assert bytes.fromhex(candidate["data_hex"]) == b"AB"
    assert candidate["candidate_sha256"] == hashlib.sha256(b"AB").hexdigest()
    assert candidate["dropped_identical_sequence_frames"] == [3]
    assert candidate["provenance"] == [
        {"frame": 2, "sequence": 100, "start": 0, "end_exclusive": 1,
         "payload_sha256": hashlib.sha256(b"A").hexdigest()},
        {"frame": 1, "sequence": 101, "start": 1, "end_exclusive": 2,
         "payload_sha256": hashlib.sha256(b"B").hexdigest()},
    ]
    assert result["correlation"]["ambiguous_sequences"]


def test_sequence_gap_and_conflicts_do_not_forge_bytes(tmp_path, monkeypatch):
    rows = [row(1, seq=10), row(2, seq=12)]
    engine, capture, pin = case(tmp_path, monkeypatch, rows)
    gap = reconstruct_icmp_flow(engine, capture, pin, scan_frames=2,
                                reconstruction_mode="request")
    assert gap["candidate"]["status"] == "sequence_gaps"
    assert gap["candidate"]["gaps"] == [{"start": 11, "end_inclusive": 11}]
    engine, capture, pin = case(tmp_path, monkeypatch, [row(1), row(2)],
                                {1: b"A", 2: b"B"})
    conflict = reconstruct_icmp_flow(engine, capture, pin, scan_frames=2,
                                     reconstruction_mode="request")
    assert conflict["candidate"]["status"] == "conflicting_sequence"
    assert conflict["correlation"]["duplicate_sequences"][0]["same_payload"] is False


def test_wrap_limit_and_rejected_frames(tmp_path, monkeypatch):
    engine, capture, pin = case(tmp_path, monkeypatch, [row(1, seq=65535), row(2, seq=0)])
    result = reconstruct_icmp_flow(engine, capture, pin, scan_frames=2,
                                   reconstruction_mode="request")
    assert result["candidate"]["status"] == "ambiguous_wrap"
    engine, capture, pin = case(tmp_path, monkeypatch, [row(1), row(2)], reject=2)
    result = reconstruct_icmp_flow(engine, capture, pin, scan_frames=2)
    assert result["status"] == "incomplete_evidence"
    assert result["rejected_frames"] == [{"frame": 2, "status": "unsupported_layout"}]


def test_too_many_and_no_echo(tmp_path, monkeypatch):
    rows = [row(n, seq=n) for n in range(1, 6)]
    engine, capture, pin = case(tmp_path, monkeypatch, rows)
    output = reconstruct_icmp_flow(engine, capture, pin, scan_frames=5, max_packets=4)
    assert output["status"] == "too_many_echo_packets"
    assert output["matched_packets"] == 5
    empty = reconstruct_icmp_flow(engine, capture, pin, start_frame=20, scan_frames=5)
    assert empty["status"] == "no_echo_group"


def test_validation(tmp_path, monkeypatch):
    engine, capture, pin = case(tmp_path, monkeypatch, [row(1)])
    with pytest.raises(PacketSleuthError, match="required"):
        reconstruct_icmp_flow(engine, capture, None)
    with pytest.raises(PacketSleuthError, match="mismatch"):
        reconstruct_icmp_flow(engine, capture, "0" * 64)
    with pytest.raises(PacketSleuthError, match="max_packets"):
        reconstruct_icmp_flow(engine, capture, pin, max_packets=25)
    with pytest.raises(PacketSleuthError, match="scan_frames"):
        reconstruct_icmp_flow(engine, capture, pin, scan_frames=300)
    with pytest.raises(PacketSleuthError, match="protocol"):
        reconstruct_icmp_flow(engine, capture, pin, protocol="tcp")
    with pytest.raises(PacketSleuthError, match="host_ip"):
        reconstruct_icmp_flow(engine, capture, pin, peer_ip="192.0.2.1")


def test_two_request_origins_require_explicit_direction(tmp_path, monkeypatch):
    # Same Echo identifier in both directions must never become a combined blob.
    a, b = "192.0.2.10", "198.51.100.22"
    rows = [
        row(1, seq=5, src=a, dst=b),
        row(2, seq=6, src=b, dst=a),
    ]
    engine, capture, pin = case(tmp_path, monkeypatch, rows, {1: b"A", 2: b"B"})
    unspecified = reconstruct_icmp_flow(
        engine, capture, pin, scan_frames=2, reconstruction_mode="request",
    )
    assert unspecified["status"] == "correlated_window"
    candidate = unspecified["candidate"]
    assert candidate["status"] == "source_direction_required"
    assert len(candidate["source_directions"]) == 2
    assert "data_hex" not in candidate

    left = reconstruct_icmp_flow(
        engine, capture, pin, scan_frames=2, reconstruction_mode="request",
        candidate_source_ip=a,
    )
    assert left["candidate"]["status"] == "candidate_only"
    assert bytes.fromhex(left["candidate"]["data_hex"]) == b"A"
    assert left["candidate"]["source_ip"] == a

    right = reconstruct_icmp_flow(
        engine, capture, pin, scan_frames=2, reconstruction_mode="request",
        candidate_source_ip=b,
    )
    assert bytes.fromhex(right["candidate"]["data_hex"]) == b"B"

    absent = reconstruct_icmp_flow(
        engine, capture, pin, scan_frames=2, reconstruction_mode="request",
        candidate_source_ip="203.0.113.99",
    )
    assert absent["candidate"]["status"] == "no_packets_in_direction"


def test_identical_payloads_are_not_called_independent_chunks(tmp_path, monkeypatch):
    rows = [row(1, seq=100), row(2, seq=101)]
    engine, capture, pin = case(tmp_path, monkeypatch, rows)
    result = reconstruct_icmp_flow(
        engine, capture, pin, scan_frames=2, reconstruction_mode="request",
    )
    candidate = result["candidate"]
    assert candidate["status"] == "candidate_only"
    assert candidate["candidate_bytes"] == 6
    assert candidate["all_payloads_equal"] is True
    assert candidate["unique_payload_hashes"] == 1
    assert "Repeated identical payloads" in candidate["note"]
