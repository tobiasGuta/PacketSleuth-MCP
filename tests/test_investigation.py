"""Regression tests for bounded investigation and previously failing stream previews."""

from __future__ import annotations

from pathlib import Path

import pytest

from packetsleuth.core import CaptureStore, InvestigationEngine, PacketSleuthError, TSharkRunner


class WindowRunner:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def query(self, path, fields=None, display_filter=None, scan_limit=10_000):
        self.calls.append((fields, display_filter, scan_limit))
        output = [r for r in self.rows if scan_limit is None or int(r["frame.number"]) <= scan_limit]
        if display_filter:
            import re

            bounds = re.search(r"frame.number >= (\d+) && frame.number <= (\d+)", display_filter)
            if bounds:
                start, end = map(int, bounds.groups())
                output = [r for r in output if start <= int(r["frame.number"]) <= end]
            exact = re.search(r"frame.number == (\d+)", display_filter)
            if exact:
                output = [r for r in output if int(r["frame.number"]) == int(exact.group(1))]
            stream = re.search(r"tcp.stream == (\d+)", display_filter)
            if stream:
                output = [r for r in output if r.get("tcp.stream") == stream.group(1)]
            if "tcp.len > 0" in display_filter:
                output = [r for r in output if int(r.get("tcp.len") or 0) > 0]
        return output

    def follow_tcp(self, path, stream_id, limit_bytes):
        return {"text": "Follow: tcp,ascii\\n...", "truncated": True}


@pytest.fixture
def demo(tmp_path):
    (tmp_path / "example.pcap").write_bytes(bytes.fromhex("d4c3b2a1") + b"\0" * 24)
    rows = [
        {
            "frame.number": "10101", "frame.time_epoch": "1700000000.0", "frame.len": "70",
            "frame.protocols": "eth:ip:tcp", "ip.src": "192.0.2.12",
            "ip.dst": "198.51.100.5", "tcp.stream": "0", "tcp.seq": "100",
            "tcp.len": "5", "tcp.srcport": "4444", "tcp.dstport": "80",
            "tcp.payload": "48454c4c4f",
        },
        {
            "frame.number": "10102", "frame.time_epoch": "1700000000.5", "frame.len": "72",
            "frame.protocols": "eth:ip:tcp", "ip.src": "192.0.2.12",
            "ip.dst": "198.51.100.5", "tcp.stream": "0", "tcp.seq": "105",
            "tcp.len": "7", "tcp.srcport": "4444", "tcp.dstport": "80",
            "tcp.payload": "53454352455421",
        },
        {
            "frame.number": "10103", "frame.time_epoch": "1700000001.0", "frame.len": "52",
            "frame.protocols": "eth:ip:tcp", "ip.src": "198.51.100.5",
            "ip.dst": "192.0.2.12", "tcp.stream": "0", "tcp.seq": "40",
            "tcp.len": "0", "tcp.srcport": "80", "tcp.dstport": "4444",
            "tcp.payload": "",
        },
    ]
    runner = WindowRunner(rows)
    engine = InvestigationEngine(CaptureStore(tmp_path), runner)
    return engine, engine.store.list()[0]["capture_id"], runner


def test_page_flows_after_initial_scan_limit(demo):
    engine, capture, runner = demo
    result = engine.query_flows(capture, scan_frames=500, start_frame=10_000)
    assert len(result["flows"]) == 1
    assert result["flows"][0]["stream_id"] == "0"
    assert result["coverage"]["next_start_frame"] == 10_500
    assert runner.calls[-1][2] == 10_499
    assert "frame.number >= 10000" in runner.calls[-1][1]


def test_exact_payload_is_hex_and_untrusted(demo):
    engine, capture, runner = demo
    result = engine.inspect_tcp_payload(capture, 10102)
    assert result["found"] and result["untrusted_data"]
    assert result["payload_hex"] == "53454352455421"
    assert result["payload_text_preview"] == "SECRET!"
    assert runner.calls[-1][2] == 10102
    assert engine.inspect_tcp_payload(capture, 20000)["found"] is False
    with pytest.raises(PacketSleuthError):
        engine.inspect_tcp_payload(capture, 1, max_bytes=100_000)


def test_stream_segments_can_page_and_clip(demo):
    engine, capture, runner = demo
    first = engine.query_tcp_segments(
        capture, 0, start_frame=10101, scan_frames=3, limit=1,
        max_bytes_per_segment=3,
    )
    assert first["segments"][0]["payload_hex"] == "48454c"
    assert first["segments"][0]["payload_truncated"] is True
    assert first["results_truncated"] is True
    assert first["next_offset"] == 1
    second = engine.query_tcp_segments(
        capture, 0, start_frame=10101, scan_frames=3, limit=1, offset=1
    )
    assert second["segments"][0]["payload_text_preview"] == "SECRET!"
    assert second["next_offset"] is None
    assert second["coverage"]["next_start_frame"] == 10104
    assert runner.calls[-1][2] == 10103


def test_window_and_offset_validation(demo):
    engine, capture, _ = demo
    for invalid in (0, -1, True, 2_147_483_648):
        with pytest.raises(PacketSleuthError):
            engine.query_flows(capture, start_frame=invalid)
    with pytest.raises(PacketSleuthError):
        engine.query_flows(capture, start_frame=2_147_483_647, scan_frames=2)
    with pytest.raises(PacketSleuthError):
        engine.query_flows(capture, scan_frames=20_000)
    with pytest.raises(PacketSleuthError):
        engine.query_events(capture, "dns", offset=-1)
    with pytest.raises(PacketSleuthError):
        engine.query_flows(capture, host_ip="1.2.3.4 || frame.number")
    with pytest.raises(PacketSleuthError):
        engine.query_tcp_segments(capture, 0, limit=50)


def test_follow_stream_reports_truncation(demo):
    engine, capture, _ = demo
    result = engine.follow_stream(capture, stream_id=0)
    assert result["output_truncated"] is True
    assert "query_tcp_segments" in result["note"]


def test_oversized_follow_is_preview_not_failure(tmp_path):
    stub = tmp_path / "tshark-stub"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.write('A' * 30000)\n"
        "sys.stdout.flush()\n"
    )
    stub.chmod(0o755)
    runner = TSharkRunner(str(stub), timeout=5.0)
    preview = runner.follow_tcp(Path("fake.pcap"), 0, 2048)
    assert preview["truncated"] is True
    assert len(preview["text"]) <= 2048
    with pytest.raises(PacketSleuthError, match="output limit"):
        runner._run(["-r", "fake.pcap"], max_bytes=2048)


def test_payload_hex_validation(demo):
    engine, capture, runner = demo
    runner.rows[0]["tcp.payload"] = "this is not hex"
    with pytest.raises(PacketSleuthError, match="invalid TCP payload"):
        engine.inspect_tcp_payload(capture, 10101)


def test_healthcheck_reports_readiness(demo):
    engine, _, _ = demo
    status = engine.healthcheck()
    assert status["capture_directory_exists"]
    assert status["capture_count"] == 1
    assert isinstance(status["tshark_found"], bool)
    assert "does not verify" in status["note"]
