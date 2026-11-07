"""Regression coverage for stable cursors, DNS evidence, and subprocess safety."""

from __future__ import annotations

import asyncio
import hashlib
import re
import subprocess
import sys
from xml.etree import ElementTree as ET

import pytest

from packetsleuth import core
from packetsleuth.core import CaptureStore, InvestigationEngine, PacketSleuthError, TSharkRunner
from packetsleuth.dns import _read_pdml_packet
from packetsleuth.forensics import query_packets


def make_capture(tmp_path):
    path = tmp_path / "evidence.pcap"
    path.write_bytes(bytes.fromhex("d4c3b2a1") + bytes(24))
    return CaptureStore(tmp_path), hashlib.sha256(path.read_bytes()).hexdigest()


class FrameRunner:
    def __init__(self):
        self.calls = []
        self.rows = [{
            "frame.number": str(i),
            "frame.time_epoch": str(i),
            "ip.src": "192.0.2.1",
            "ip.dst": "192.0.2.2",
            "frame.len": "80",
            "frame.protocols": "eth:ip:dns",
            "dns.qry.name": f"query{i}.example",
            "dns.flags.rcode": "0",
            "tcp.stream": "",
        } for i in range(1, 9)]

    def query(self, path, fields=(), display_filter=None, scan_limit=10000):
        self.calls.append({"scan_limit": scan_limit, "display_filter": display_filter})
        selected = []
        for row in self.rows:
            frame = int(row["frame.number"])
            if scan_limit is not None and frame > scan_limit:
                continue
            if display_filter:
                if (m := re.search(r"frame.number >= (\d+)", display_filter)):
                    if frame < int(m.group(1)):
                        continue
                if (m := re.search(r"frame.number <= (\d+)", display_filter)):
                    if frame > int(m.group(1)):
                        continue
            selected.append({key: row.get(key, "") for key in fields} if fields else row)
        return selected


def test_packet_cursor_is_stable_and_pinned(tmp_path):
    store, pin = make_capture(tmp_path)
    engine = InvestigationEngine(store, FrameRunner())
    capture = store.list()[0]["capture_id"]
    params = dict(fields=["frame.number", "dns.qry.name"], start_frame=1,
                  scan_frames=8, limit=3, expected_sha256=pin)
    first = query_packets(engine, capture, **params)
    assert first["has_more"] and first["next_cursor"]
    assert first["scan_range"] == {"start_frame": 1, "end_frame": 8}
    second = query_packets(engine, capture, cursor=first["next_cursor"], **params)
    third = query_packets(engine, capture, cursor=second["next_cursor"], **params)
    assert [r["frame"] for part in (first, second, third) for r in part["records"]] == (
        list(range(1, 9))
    )
    assert not third["has_more"] and third["next_cursor"] is None
    with pytest.raises(PacketSleuthError, match="Cursor"):
        query_packets(engine, capture, cursor=first["next_cursor"],
                      **(params | {"match_field": "dns.qry.name", "match_value": "query"}))
    with pytest.raises(PacketSleuthError, match="cursor"):
        query_packets(engine, capture, cursor="nonsense", **params)


def test_legacy_flow_and_event_offset_remain_supported(tmp_path):
    store, _ = make_capture(tmp_path)
    engine = InvestigationEngine(store, FrameRunner())
    capture = store.list()[0]["capture_id"]
    first = engine.query_events(capture, "dns", limit=3, scan_frames=8)
    assert first["next_offset"] == 3
    assert first["has_more"]
    second = engine.query_events(capture, "dns", limit=3, scan_frames=8,
                                 cursor=first["next_cursor"])
    assert [e["frame"] for e in second["events"]] == [4, 5, 6]
    legacy = engine.query_events(capture, "dns", limit=3, scan_frames=8, offset=3)
    assert legacy["events"] == second["events"]
    flows = engine.query_flows(capture, limit=1, scan_frames=8)
    assert flows["returned_flows"] == 1
    assert flows["has_more"] is False
    assert flows["next_cursor"] is None


def test_dns_multiple_records_and_ttls_without_value_misalignment():
    xml = """<packet><proto name="dns">
      <field name="dns.count.answers" show="3"/>
      <field name="Answers">
        <field name="" showname="RR 1">
          <field name="dns.resp.name" show="example.test"/>
          <field name="dns.resp.type" show="1"/>
          <field name="dns.resp.ttl" show="60"/>
          <field name="dns.a" show="192.0.2.10"/>
        </field>
        <field name="" showname="RR 2">
          <field name="dns.resp.name" show="example.test"/>
          <field name="dns.resp.type" show="1"/>
          <field name="dns.resp.ttl" show="120"/>
          <field name="dns.a" show="192.0.2.11"/>
        </field>
        <field name="" showname="RR 3">
          <field name="dns.resp.name" show="example.test"/>
          <field name="dns.resp.type" show="28"/>
          <field name="dns.resp.ttl" show="30"/>
          <field name="dns.aaaa" show="2001:db8::10"/>
        </field>
      </field>
    </proto></packet>"""
    result = _read_pdml_packet(ET.fromstring(xml), 7, 8)
    records = result["answer_records"]
    assert [(r["record_type"], r["ttl"]) for r in records] == [
        ("A", 60), ("A", 120), ("AAAA", 30),
    ]
    assert result["answer_ips"] == ["192.0.2.10", "192.0.2.11", "2001:db8::10"]
    assert result["record_parse_complete"]
    partial = _read_pdml_packet(ET.fromstring(xml), 7, 2)
    assert partial["answers_truncated"] and not partial["record_parse_complete"]


def test_dns_pdml_failure_is_parser_error(tmp_path, monkeypatch):
    stub = tmp_path / "tshark-stub"
    stub.write_text("#!/bin/sh\nprintf '<broken>'\n")
    stub.chmod(0o755)
    runner = TSharkRunner(str(stub))
    with pytest.raises(PacketSleuthError) as exc:
        runner.dns_details(tmp_path / "fake.pcap", [1], 1)
    assert exc.value.code == "PARSER_FAILURE"


def test_malformed_tsv_is_error_not_silent_data_loss(tmp_path):
    stub = tmp_path / "tshark-stub"
    stub.write_text("#!/bin/sh\nprintf '1\\t2\\nBAD\\n'\n")
    stub.chmod(0o755)
    runner = TSharkRunner(str(stub))
    with pytest.raises(PacketSleuthError) as exc:
        runner.query(tmp_path / "fake.pcap", fields=("a", "b"))
    assert exc.value.code == "PARSER_FAILURE"


def test_tshark_timeout_and_cancellation_reap_child(tmp_path, monkeypatch):
    stub = tmp_path / "tshark-stub"
    stub.write_text(
        f"#!{sys.executable}\nimport time\ntime.sleep(30)\n"
    )
    stub.chmod(0o755)
    runner = TSharkRunner(str(stub), timeout=0.1)
    with pytest.raises(PacketSleuthError) as exc:
        runner._run(["-r", str(tmp_path / "fake.pcap")])
    assert exc.value.code == "TIMEOUT"

    runner = TSharkRunner(str(stub), timeout=3)
    original = subprocess.Popen
    processes = []

    def record_popen(*args, **kwargs):
        proc = original(*args, **kwargs)
        processes.append(proc)
        return proc

    def cancelled(_seconds):
        raise asyncio.CancelledError()

    monkeypatch.setattr(core.subprocess, "Popen", record_popen)
    monkeypatch.setattr(core.time, "sleep", cancelled)
    with pytest.raises(asyncio.CancelledError):
        runner._run(["-r", str(tmp_path / "fake.pcap")])
    assert processes and processes[0].poll() is not None


def test_output_limit_and_adaptive_query_split(tmp_path, monkeypatch):
    stub = tmp_path / "tshark-stub"
    stub.write_text("#!/bin/sh\npython -c 'print(\"x\"*100000)'\n")
    stub.chmod(0o755)
    runner = TSharkRunner(str(stub))
    runner.max_output_bytes = 1024
    with pytest.raises(PacketSleuthError) as exc:
        runner._run(["-r", str(tmp_path / "fake.pcap")])
    assert exc.value.code == "OUTPUT_LIMIT"

    def bounded_run(args, **kwargs):
        count = int(args[args.index("-c") + 1])
        if count > 4 and "frame.number >" not in " ".join(args):
            raise PacketSleuthError("mock large result", code="OUTPUT_LIMIT")
        filt = args[args.index("-Y") + 1] if "-Y" in args else ""
        lines = []
        for frame in range(1, count + 1):
            if (m := re.search(r"frame.number <= (\d+)", filt)):
                if frame > int(m.group(1)):
                    continue
            if (m := re.search(r"frame.number > (\d+)", filt)):
                if frame <= int(m.group(1)):
                    continue
            lines.append(f'"{frame}"')
        return "\n".join(lines)

    monkeypatch.setattr(runner, "_run", bounded_run)
    result = runner.query(tmp_path / "fake.pcap", fields=("frame.number",), scan_limit=8)
    assert [x["frame.number"] for x in result] == [str(i) for i in range(1, 9)]


def test_error_envelope_and_config_limits(tmp_path, monkeypatch):
    from packetsleuth.server import query_dns as mcp_query_dns

    result = mcp_query_dns("invalid", "0" * 64)
    assert result["ok"] is False
    assert result["error"]["code"] == "INVALID_INPUT"

    store = CaptureStore(tmp_path)
    with pytest.raises(PacketSleuthError) as exc:
        store.get("0" * 24)
    assert exc.value.code == "CAPTURE_NOT_FOUND"

    monkeypatch.setenv("PACKETSLEUTH_MAX_SCAN_FRAMES", "5")
    with pytest.raises(PacketSleuthError):
        core._frame_window(1, 6)
    monkeypatch.setenv("PACKETSLEUTH_MAX_CAPTURE_BYTES", "64")
    assert CaptureStore(tmp_path).max_bytes == 64
    monkeypatch.setenv("PACKETSLEUTH_MAX_OUTPUT_BYTES", "2048")
    assert TSharkRunner(sys.executable).max_output_bytes == 2048
    monkeypatch.setenv("PACKETSLEUTH_TSHARK_TIMEOUT_SECONDS", "invalid")
    with pytest.raises(PacketSleuthError):
        TSharkRunner(sys.executable)


def test_summary_and_detection_respect_configured_scan_ceiling(tmp_path, monkeypatch):
    store, _ = make_capture(tmp_path)
    runner = FrameRunner()
    engine = InvestigationEngine(store, runner)
    capture = store.list()[0]["capture_id"]
    monkeypatch.setenv("PACKETSLEUTH_MAX_SCAN_FRAMES", "4")
    summary = engine.inspect_capture(capture)
    assert summary["observed_packets"] == 4
    assert summary["coverage"]["scan_limit_frames"] == 4
    assert summary["coverage"]["complete_capture_scan"] is False
    assert runner.calls[-1]["scan_limit"] == 4
    engine.get_detections(capture)
    assert runner.calls[-1]["scan_limit"] == 4


def test_clipped_dns_and_packet_values_are_explicit(tmp_path):
    store, pin = make_capture(tmp_path)
    runner = FrameRunner()
    runner.rows[0]["dns.qry.name"] = "q" * 500
    engine = InvestigationEngine(store, runner)
    capture = store.list()[0]["capture_id"]
    packets = query_packets(
        engine, capture, fields=["frame.number", "dns.qry.name"],
        limit=2, scan_frames=8, expected_sha256=pin,
    )
    assert packets["truncation"]["field_values_truncated"] is True
    assert packets["records"][0]["truncated_fields"] == ["dns.qry.name"]
    events = engine.query_events(capture, "dns", limit=2, scan_frames=8)
    assert events["truncation"]["field_values_truncated"] is True
    assert events["events"][0]["truncated_fields"] == ["dns.qry.name"]


def test_long_dns_rdata_has_explicit_truncation_flag():
    xml = ('<packet><proto name="dns"><field name="dns.count.answers" show="1"/>'
           '<field name="Answers"><field name="" showname="RR">'
           '<field name="dns.resp.name" show="long.example"/>'
           '<field name="dns.resp.type" show="16"/>'
           '<field name="dns.resp.ttl" show="300"/>'
           '<field name="dns.txt" show="' + "T" * 400 + '"/>'
           '</field></field></proto></packet>')
    record = _read_pdml_packet(ET.fromstring(xml), 1, 5)["answer_records"][0]
    assert record["record_type"] == "TXT"
    assert record["rdata_truncated"] is True
    assert len(record["rdata"]["dns.txt"][0]) == 256
