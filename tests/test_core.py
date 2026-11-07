from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from packetsleuth.core import (
    CaptureStore,
    InvestigationEngine,
    PacketSleuthError,
    TSharkRunner,
)


def make_capture(root: Path, name: str = "case.pcap") -> Path:
    path = root / name
    path.write_bytes(bytes.fromhex("d4c3b2a1") + b"\x00" * 24)
    return path


class FakeRunner:
    def __init__(self, rows=None):
        self.rows = rows if rows is not None else []
        self.calls = []

    def query(self, path, fields=None, display_filter=None, scan_limit=10_000):
        self.calls.append({"path": path, "filter": display_filter, "scan_limit": scan_limit})
        if display_filter and "frame.number" in display_filter:
            return [
                r for r in self.rows
                if f"frame.number == {r['frame.number']}" in display_filter
            ]
        return self.rows

    def follow_tcp(self, path, stream_id, limit_bytes):
        return "UNTRUSTED mock payload"[:limit_bytes]


@pytest.fixture
def case(tmp_path):
    path = make_capture(tmp_path)
    store = CaptureStore(tmp_path)
    runner = FakeRunner([
        {
            "frame.number": "1", "frame.time_epoch": "1700000000.000",
            "frame.len": "74", "frame.protocols": "eth:ip:tcp",
            "ip.src": "192.0.2.10", "ip.dst": "198.51.100.2",
            "tcp.srcport": "43210", "tcp.dstport": "443", "tcp.stream": "0",
            "tcp.flags.syn": "1", "tcp.flags.ack": "0",
        },
        {
            "frame.number": "2", "frame.time_epoch": "1700000001.000",
            "frame.len": "100", "frame.protocols": "eth:ip:tcp:tls",
            "ip.src": "198.51.100.2", "ip.dst": "192.0.2.10",
            "tcp.srcport": "443", "tcp.dstport": "43210", "tcp.stream": "0",
        },
    ])
    return InvestigationEngine(store, runner), store.list()[0]["capture_id"], path, runner


def test_capture_directory_allowlist_and_magic(tmp_path):
    good = make_capture(tmp_path)
    (tmp_path / "bad.pcap").write_bytes(b"NOT_A_CAPTURE")
    (tmp_path / "secret.txt").write_bytes(b"hi")
    (tmp_path / "link.pcap").symlink_to(good)
    store = CaptureStore(tmp_path)
    assert [item["filename"] for item in store.list()] == ["case.pcap"]
    with pytest.raises(PacketSleuthError):
        store.get("../../etc/passwd")
    assert store.get(store.list()[0]["capture_id"]) == good


def test_invalid_directory_returns_empty(tmp_path):
    assert CaptureStore(tmp_path / "missing").list() == []


def test_inspect_has_hash_and_coverage(case):
    engine, capture_id, path, _ = case
    result = engine.inspect_capture(capture_id)
    assert result["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["observed_packets"] == 2
    assert result["coverage"]["complete_capture_scan"] is True


def test_query_flows_aggregates_bidirectional_tcp_stream(case):
    engine, capture_id, _, _ = case
    result = engine.query_flows(capture_id)
    assert len(result["flows"]) == 1
    assert result["flows"][0]["packets"] == 2
    assert result["flows"][0]["bytes"] == 174
    assert result["flows"][0]["sample_frames"] == [1, 2]


def test_events_filter_is_constructed_and_ip_validated(case):
    engine, capture_id, _, runner = case
    result = engine.query_events(capture_id, "dns", "192.0.2.10", limit=1)
    assert result["coverage"]["complete_capture_scan"] is False
    assert runner.calls[-1]["filter"] == "dns && ip.addr == 192.0.2.10"
    engine.query_events(capture_id, "tls", "2001:db8::1")
    assert runner.calls[-1]["filter"] == "tls && ipv6.addr == 2001:db8::1"
    with pytest.raises(PacketSleuthError):
        engine.query_events(capture_id, "dns", "127.0.0.1 || tcp")
    with pytest.raises(PacketSleuthError):
        engine.query_events(capture_id, "dns", limit=1000)


def test_inspect_and_verify_only_existing_frames(case):
    engine, capture_id, path, runner = case
    result = engine.inspect_frames(capture_id, [3, 1])
    assert result["missing_frames"] == [3]
    assert runner.calls[-1]["scan_limit"] is None
    verified = engine.verify_evidence(capture_id, [1, 2], hashlib.sha256(path.read_bytes()).hexdigest())
    assert verified["references_verified"]
    assert not engine.verify_evidence(capture_id, [1], "0" * 64)["references_verified"]
    with pytest.raises(PacketSleuthError):
        engine.verify_evidence(capture_id, [1], "not a sha256")
    with pytest.raises(PacketSleuthError):
        engine.inspect_frames(capture_id, [0])


def test_follow_stream_bounded(case):
    engine, capture_id, _, _ = case
    assert engine.follow_stream(capture_id, 0)["untrusted_data"] is True
    with pytest.raises(PacketSleuthError):
        engine.follow_stream(capture_id, 0, 100_000)


def test_syn_fanout_is_lead_not_verdict(tmp_path):
    make_capture(tmp_path)
    rows = [
        {
            "frame.number": str(n + 1), "frame.len": "60", "frame.protocols": "eth:ip:tcp",
            "ip.src": "192.0.2.4", "ip.dst": "198.51.100.1",
            "tcp.dstport": str(2000 + n), "tcp.flags.syn": "1", "tcp.flags.ack": "0",
        }
        for n in range(25)
    ]
    engine = InvestigationEngine(CaptureStore(tmp_path), FakeRunner(rows))
    result = engine.get_detections(engine.store.list()[0]["capture_id"])
    assert len(result["findings"]) == 1
    assert result["findings"][0]["rule_id"] == "heuristic.tcp_syn_fanout"
    assert len(result["findings"][0]["evidence_frames"]) <= 20


def test_nxdomain_attribution_uses_requester_address(tmp_path):
    make_capture(tmp_path)
    rows = [
        {
            "frame.number": str(n + 1), "frame.len": "60", "frame.protocols": "eth:ip:udp:dns",
            "ip.src": "198.51.100.53", "ip.dst": "192.0.2.10",
            "dns.qry.name": f"bad{n}.example", "dns.flags.rcode": "3",
        }
        for n in range(10)
    ]
    engine = InvestigationEngine(CaptureStore(tmp_path), FakeRunner(rows))
    result = engine.get_detections(engine.store.list()[0]["capture_id"])
    assert result["findings"][0]["host_ip"] == "192.0.2.10"


def test_runner_does_not_use_shell_and_parses_tsv(tmp_path):
    # Fake executable prints well-formed TShark -T fields records.
    script = tmp_path / "tshark-stub"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "assert '-r' in sys.argv and '-T' in sys.argv\n"
        "print(chr(34) + '1' + chr(34) + '\\t' + chr(34) + '3.5' + chr(34))\n"
    )
    script.chmod(0o755)
    runner = TSharkRunner(str(script))
    rows = runner.query(tmp_path / "fake.pcap", fields=("frame.number", "frame.time_epoch"))
    assert rows == [{"frame.number": "1", "frame.time_epoch": "3.5"}]
