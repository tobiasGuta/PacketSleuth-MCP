"""Read-only, local PCAP operations; no dependency on the LLM or MCP transport.

Every packet-derived value is untrusted. The caller must not interpret payload
strings as instructions. For hostile captures, run the entire service and TShark
inside a separate sandbox with no network access and low privileges.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import ipaddress
import os
import re
import shutil
import signal
import stat
import subprocess
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Literal

ALLOWED_SUFFIXES = {".pcap", ".pcapng"}
PCAP_MAGICS = {
    bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("4d3cb2a1"),
    bytes.fromhex("a1b23c4d"),
    bytes.fromhex("0a0d0d0a"),
}
BASE_FIELDS = (
    "frame.number", "frame.time_epoch", "frame.len", "frame.protocols",
    "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "tcp.stream", "udp.stream", "tcp.flags.syn", "tcp.flags.ack",
    "dns.qry.name", "dns.flags.rcode", "http.host", "http.request.method",
    "http.request.uri", "tls.handshake.extensions_server_name",
)
MAX_SCAN_FRAMES = 10_000
MAX_CAPTURE_BYTES = 128 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_STDERR_BYTES = 16 * 1024
MAX_TOOL_RECORDS = 100
MAX_FRAME_NUMBER = 2_147_483_647
MAX_SEGMENT_BYTES = 2048
MAX_TCP_SEGMENT_RECORDS = 25


class PacketSleuthError(ValueError):
    """Expected, safe-to-surface operation error."""


def _clip(value: str, limit: int = 300) -> str:
    # Strip ANSI and terminal control characters (including malicious line breaks).
    value = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", str(value))
    value = "".join(c if c.isprintable() else " " for c in value)
    return value[:limit]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _validate_ip(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise PacketSleuthError("host_ip must be a valid IPv4 or IPv6 address") from exc


def _validate_limit(limit: int) -> int:
    if type(limit) is not int or not 1 <= limit <= MAX_TOOL_RECORDS:
        raise PacketSleuthError(f"limit must be an integer from 1 to {MAX_TOOL_RECORDS}")
    return limit


def _validate_offset(offset: int) -> int:
    if type(offset) is not int or not 0 <= offset <= MAX_SCAN_FRAMES:
        raise PacketSleuthError(f"offset must be from 0 to {MAX_SCAN_FRAMES}")
    return offset


def _validate_frames(frames: list[int]) -> list[int]:
    if not isinstance(frames, list) or not 1 <= len(frames) <= 25:
        raise PacketSleuthError("Supply 1 to 25 frame numbers")
    if any(type(n) is not int or not 1 <= n <= MAX_FRAME_NUMBER for n in frames):
        raise PacketSleuthError("Frame numbers must be positive integers")
    return sorted(set(frames))


def _frame_window(start_frame: int, scan_frames: int) -> tuple[str, int, dict]:
    """Allow bounded pages beyond the first 10,000 frames without free-form filters.

    `-c` applies to input frames, not display-filter matches; the end frame
    must be used as the TShark read limit, and the starting frame in -Y.
    """
    if type(start_frame) is not int or not 1 <= start_frame <= MAX_FRAME_NUMBER:
        raise PacketSleuthError("start_frame must be a positive frame number")
    if type(scan_frames) is not int or not 1 <= scan_frames <= MAX_SCAN_FRAMES:
        raise PacketSleuthError(f"scan_frames must be between 1 and {MAX_SCAN_FRAMES}")
    last_frame = start_frame + scan_frames - 1
    if last_frame > MAX_FRAME_NUMBER:
        raise PacketSleuthError("requested frame window exceeds the supported frame range")
    coverage = {
        "requested_start_frame": start_frame,
        "requested_end_frame": last_frame,
        "next_start_frame": last_frame + 1 if last_frame < MAX_FRAME_NUMBER else None,
        "complete_capture_scan": False,
        "note": (
            "Only the requested frame window was scanned. The next frame cursor is "
            "a candidate position, not proof that additional packets exist."
        ),
    }
    return f"frame.number >= {start_frame} && frame.number <= {last_frame}", last_frame, coverage


def _decode_payload(hex_value: str, max_bytes: int) -> dict:
    """Return raw hex and a printable display preview; do not interpret as commands."""
    cleaned = hex_value.replace(":", "").strip()
    if not cleaned or len(cleaned) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        raise PacketSleuthError("TShark returned invalid TCP payload encoding")
    raw = bytes.fromhex(cleaned)
    prefix = raw[:max_bytes]
    return {
        "captured_payload_bytes": len(raw),
        "payload_hex": prefix.hex(),
        "payload_text_preview": _clip(prefix.decode("utf-8", errors="replace"), max_bytes),
        "payload_truncated": len(raw) > max_bytes,
    }


class CaptureStore:
    """Allowlisted, non-recursive capture directory; identifiers are not paths."""

    def __init__(self, root: Path, max_bytes: int = MAX_CAPTURE_BYTES):
        self.root = Path(root).expanduser().resolve()
        self.max_bytes = max_bytes

    @staticmethod
    def _id(name: str) -> str:
        return hashlib.sha256(name.encode("utf-8")).hexdigest()[:24]

    def _valid_file(self, path: Path) -> bool:
        try:
            # Exclude terminal-control characters and prompt-like filenames from tool output.
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,120}\.(?:pcap|pcapng)", path.name, re.I):
                return False
            if path.is_symlink() or path.suffix.lower() not in ALLOWED_SUFFIXES:
                return False
            if path.parent != self.root or not path.is_file():
                return False
            st = path.stat()
            if not stat.S_ISREG(st.st_mode) or not 4 <= st.st_size <= self.max_bytes:
                return False
            with path.open("rb") as stream:
                return stream.read(4) in PCAP_MAGICS
        except (OSError, ValueError):
            return False

    def list(self) -> list[dict]:
        if not self.root.is_dir():
            return []
        output = []
        for path in sorted(self.root.iterdir(), key=lambda p: p.name):
            if self._valid_file(path):
                output.append({
                    "capture_id": self._id(path.name),
                    "filename": path.name,
                    "size_bytes": path.stat().st_size,
                })
            if len(output) >= 200:
                break
        return output

    def get(self, capture_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{24}", capture_id):
            raise PacketSleuthError("Unknown capture ID")
        for item in self.list():
            if item["capture_id"] == capture_id:
                path = self.root / item["filename"]
                if self._valid_file(path) and path.resolve().parent == self.root:
                    return path
        raise PacketSleuthError("Unknown capture ID")


class TSharkRunner:
    """Fixed-argument TShark subprocess; never invokes a shell.

    Pipe readers cap the output, terminate overproducing processes, and enforce
    a timeout. This is resource hygiene, not a substitute for OS sandboxing.
    """

    def __init__(self, executable: str = "tshark", timeout: float = 20.0):
        resolved = shutil.which(executable)
        if resolved is None:
            raise PacketSleuthError("tshark not found on PATH; install Wireshark CLI tools")
        self.executable = resolved
        self.timeout = timeout

    def _run(
        self, args: list[str], max_bytes: int = MAX_OUTPUT_BYTES, *,
        allow_truncation: bool = False,
    ) -> str | tuple[str, bool]:
        proc = subprocess.Popen(
            [self.executable, *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=(os.name == "posix"),
        )
        stdout = bytearray()
        stderr = bytearray()
        exceeded = threading.Event()

        def drain(stream, target: bytearray, byte_cap: int) -> None:
            try:
                while True:
                    chunk = stream.read(8192)
                    if not chunk:
                        break
                    room = byte_cap - len(target)
                    target.extend(chunk[: max(room, 0)])
                    if len(chunk) > room:
                        exceeded.set()
                        break
            finally:
                stream.close()

        threads = [
            threading.Thread(target=drain, args=(proc.stdout, stdout, max_bytes), daemon=True),
            threading.Thread(target=drain, args=(proc.stderr, stderr, MAX_STDERR_BYTES), daemon=True),
        ]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + self.timeout
        timed_out = False
        try:
            while proc.poll() is None:
                if exceeded.is_set():
                    break
                if time.monotonic() > deadline:
                    timed_out = True
                    break
                time.sleep(0.02)
            if proc.poll() is None:
                if os.name == "posix":
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
            proc.wait(timeout=3)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            for thread in threads:
                thread.join(timeout=2)
        if timed_out:
            raise PacketSleuthError("TShark exceeded the analysis timeout")
        truncated = exceeded.is_set()
        if truncated and not allow_truncation:
            raise PacketSleuthError("TShark exceeded the output limit")
        if proc.returncode != 0 and not (truncated and allow_truncation):
            raise PacketSleuthError(f"TShark failed: {_clip(stderr.decode(errors='replace'), 400)}")
        decoded = stdout.decode("utf-8", errors="replace")
        return (decoded, truncated) if allow_truncation else decoded

    def query(
        self,
        path: Path,
        fields: tuple[str, ...] = BASE_FIELDS,
        display_filter: str | None = None,
        scan_limit: int | None = MAX_SCAN_FRAMES,
    ) -> list[dict[str, str]]:
        args = ["-n", "-r", str(path), "-T", "fields", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
        if scan_limit is not None:
            args.extend(["-c", str(scan_limit)])
        if display_filter:
            args.extend(["-Y", display_filter])
        for field in fields:
            args.extend(["-e", field])
        raw = self._run(args)
        reader = csv.reader(io.StringIO(raw), delimiter="\t", quotechar='"')
        return [dict(zip(fields, row)) for row in reader if len(row) == len(fields)]

    def raw_frame(self, path: Path, frame: int) -> dict | None:
        """Read one bounded TShark jsonraw packet, including raw-layer byte offsets."""
        raw = self._run([
            "-n", "-r", str(path), "-c", str(frame),
            "-Y", f"frame.number == {frame}", "-T", "jsonraw",
        ])
        try:
            packets = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PacketSleuthError("TShark returned malformed raw-frame JSON") from exc
        if not isinstance(packets, list) or len(packets) > 1:
            raise PacketSleuthError("TShark returned an unexpected raw-frame result")
        return packets[0] if packets else None

    def follow_tcp(self, path: Path, stream_id: int, limit_bytes: int) -> dict:
        # Limit the *returned preview*, not the success of a large stream.
        # For later bytes, use query_tcp_segments with a frame window.
        raw, truncated = self._run(
            ["-n", "-r", str(path), "-q", "-z", f"follow,tcp,ascii,{stream_id}"],
            max_bytes=limit_bytes,
            allow_truncation=True,
        )
        return {"text": _clip(raw, limit_bytes), "truncated": truncated}


def _summarize_row(row: dict[str, str]) -> dict:
    src = row.get("ip.src") or row.get("ipv6.src") or ""
    dst = row.get("ip.dst") or row.get("ipv6.dst") or ""
    result = {
        "frame": int(row.get("frame.number") or 0),
        "timestamp_epoch": row.get("frame.time_epoch") or "",
        "size_bytes": int(row.get("frame.len") or 0),
        "src_ip": src,
        "dst_ip": dst,
        "src_port": row.get("tcp.srcport") or row.get("udp.srcport") or "",
        "dst_port": row.get("tcp.dstport") or row.get("udp.dstport") or "",
        "protocols": row.get("frame.protocols") or "",
    }
    for name in ("dns.qry.name", "dns.flags.rcode", "http.host", "http.request.method",
                 "http.request.uri", "tls.handshake.extensions_server_name", "tcp.stream"):
        if row.get(name):
            result[name] = _clip(row[name])
    return result


class InvestigationEngine:
    def __init__(self, store: CaptureStore, runner: TSharkRunner | None = None):
        self.store = store
        self._runner = runner

    @property
    def runner(self) -> TSharkRunner:
        if self._runner is None:
            self._runner = TSharkRunner()
        return self._runner

    def healthcheck(self) -> dict:
        """Report local readiness without opening captures or executing TShark."""
        tshark = shutil.which("tshark")
        return {
            "capture_directory": str(self.store.root),
            "capture_directory_exists": self.store.root.is_dir(),
            "capture_count": len(self.store.list()),
            "tshark_found": tshark is not None,
            "tshark_executable": tshark,
            "tool_output_limit_bytes": MAX_OUTPUT_BYTES,
            "maximum_capture_size_bytes": self.store.max_bytes,
            "note": (
                "This only checks configuration. It does not verify TShark can parse "
                "the selected PCAP or that your MCP client accepts the tool call."
            ),
        }

    def list_captures(self) -> dict:
        return {"captures": self.store.list(), "directory": str(self.store.root)}

    def _capture(self, capture_id: str) -> tuple[Path, str]:
        path = self.store.get(capture_id)
        return path, _sha256(path)

    def inspect_capture(self, capture_id: str) -> dict:
        path, digest = self._capture(capture_id)
        rows = self.runner.query(path)
        sources = Counter((r.get("ip.src") or r.get("ipv6.src")) for r in rows)
        protocols = Counter((r.get("frame.protocols") or "unknown").split(":")[-1] for r in rows)
        count = len(rows)
        return {
            "capture_id": capture_id,
            "sha256": digest,
            "size_bytes": path.stat().st_size,
            "observed_packets": count,
            "observed_bytes": sum(int(r.get("frame.len") or 0) for r in rows),
            "first_timestamp_epoch": rows[0].get("frame.time_epoch") if rows else None,
            "last_timestamp_epoch": rows[-1].get("frame.time_epoch") if rows else None,
            "top_source_ips": sources.most_common(10),
            "top_protocols": protocols.most_common(10),
            "coverage": self._coverage(count, filtered=False),
        }

    @staticmethod
    def _coverage(count: int, filtered: bool) -> dict:
        return {
            "scan_limit_frames": MAX_SCAN_FRAMES,
            "complete_capture_scan": not filtered and count < MAX_SCAN_FRAMES,
            "note": (
                "Filtered results may exclude later capture frames; results are not exhaustive."
                if filtered else
                "At the configured frame limit, completeness is unknown."
                if count >= MAX_SCAN_FRAMES else "All frames were scanned."
            ),
        }

    def query_flows(
        self, capture_id: str, limit: int = 50,
        start_frame: int = 1, scan_frames: int = MAX_SCAN_FRAMES,
        offset: int = 0, host_ip: str | None = None,
    ) -> dict:
        limit = _validate_limit(limit)
        offset = _validate_offset(offset)
        ip = _validate_ip(host_ip)
        frame_filter, end_frame, coverage = _frame_window(start_frame, scan_frames)
        path, digest = self._capture(capture_id)
        if ip:
            ip_filter = f"{'ipv6.addr' if ':' in ip else 'ip.addr'} == {ip}"
            display_filter = f"({ip_filter}) && ({frame_filter})"
        elif start_frame == 1 and scan_frames == MAX_SCAN_FRAMES:
            display_filter = None
        else:
            display_filter = frame_filter
        rows = self.runner.query(
            path, display_filter=display_filter,
            scan_limit=MAX_SCAN_FRAMES if display_filter is None else end_frame,
        )
        flows: dict[tuple, dict] = {}
        for r in rows:
            src = r.get("ip.src") or r.get("ipv6.src") or ""
            dst = r.get("ip.dst") or r.get("ipv6.dst") or ""
            if not src or not dst:
                continue
            proto = "tcp" if r.get("tcp.stream") else "udp" if r.get("udp.stream") else "other"
            stream = r.get(f"{proto}.stream") if proto != "other" else None
            sport = r.get("tcp.srcport") or r.get("udp.srcport") or ""
            dport = r.get("tcp.dstport") or r.get("udp.dstport") or ""
            key = (proto, stream) if stream else (proto, tuple(sorted(((src, sport), (dst, dport)))))
            if key not in flows:
                flows[key] = {
                    "protocol": proto,
                    "stream_id": stream,
                    "src_ip": src, "src_port": sport,
                    "dst_ip": dst, "dst_port": dport,
                    "packets": 0, "bytes": 0, "sample_frames": [],
                }
            flow = flows[key]
            flow["packets"] += 1
            flow["bytes"] += int(r.get("frame.len") or 0)
            if len(flow["sample_frames"]) < 8:
                flow["sample_frames"].append(int(r.get("frame.number") or 0))
        output = sorted(flows.values(), key=lambda item: item["bytes"], reverse=True)
        return {
            "capture_id": capture_id, "sha256": digest,
            "flows": output[offset:offset + limit], "observed_flows": len(output),
            "returned_flows": len(output[offset:offset + limit]),
            "results_truncated": len(output) > offset + limit,
            "next_offset": offset + limit if len(output) > offset + limit else None,
            "host_ip": ip,
            "coverage": coverage,
            "aggregation_scope": "Requested frame window only; a stream can span pages.",
        }

    def query_events(
        self,
        capture_id: str,
        protocol: Literal["dns", "http", "tls"],
        host_ip: str | None = None,
        limit: int = 50,
        start_frame: int = 1,
        scan_frames: int = MAX_SCAN_FRAMES,
        offset: int = 0,
    ) -> dict:
        limit = _validate_limit(limit)
        offset = _validate_offset(offset)
        frame_filter, end_frame, coverage = _frame_window(start_frame, scan_frames)
        if protocol not in ("dns", "http", "tls"):
            raise PacketSleuthError("protocol must be dns, http, or tls")
        ip = _validate_ip(host_ip)
        path, digest = self._capture(capture_id)
        display_filter = protocol
        if ip:
            display_filter += f" && {'ipv6.addr' if ':' in ip else 'ip.addr'} == {ip}"
        if start_frame == 1 and scan_frames == MAX_SCAN_FRAMES:
            rows = self.runner.query(path, display_filter=display_filter)
        else:
            rows = self.runner.query(
                path, display_filter=f"({display_filter}) && ({frame_filter})",
                scan_limit=end_frame,
            )
        return {
            "capture_id": capture_id, "sha256": digest,
            "protocol": protocol, "host_ip": ip,
            "events": [_summarize_row(r) for r in rows[offset:offset + limit]],
            "observed_matches_in_scan": len(rows),
            "results_truncated": len(rows) > offset + limit,
            "next_offset": offset + limit if len(rows) > offset + limit else None,
            "coverage": coverage,
            "untrusted_data": True,
        }

    def inspect_tcp_payload(
        self, capture_id: str, frame: int, max_bytes: int = 2048,
    ) -> dict:
        """Retrieve original, uninterpreted TCP payload bytes from one frame."""
        if type(frame) is not int or not 1 <= frame <= MAX_FRAME_NUMBER:
            raise PacketSleuthError("frame must be a positive integer")
        if type(max_bytes) is not int or not 1 <= max_bytes <= 8192:
            raise PacketSleuthError("max_bytes must be between 1 and 8192")
        path, digest = self._capture(capture_id)
        fields = ("frame.number", "frame.time_epoch", "tcp.stream", "tcp.len", "tcp.payload")
        rows = self.runner.query(
            path, fields=fields, display_filter=f"frame.number == {frame}",
            scan_limit=frame,
        )
        if not rows:
            return {"capture_id": capture_id, "sha256": digest, "frame": frame,
                    "found": False, "note": "Frame missing or not decoded as TCP."}
        row = rows[0]
        payload = row.get("tcp.payload", "")
        result = {
            "capture_id": capture_id, "sha256": digest, "frame": frame,
            "found": True, "tcp_stream_id": row.get("tcp.stream") or None,
            "tcp_len_reported": row.get("tcp.len") or "0",
            "timestamp_epoch": row.get("frame.time_epoch"),
            "untrusted_data": True,
            "note": "Per-frame TCP payload only, not reassembled or decrypted stream data.",
        }
        if payload:
            result.update(_decode_payload(payload, max_bytes))
        else:
            result.update({"captured_payload_bytes": 0, "payload_hex": "",
                           "payload_text_preview": "", "payload_truncated": False})
        return result

    def query_tcp_segments(
        self, capture_id: str, stream_id: int, start_frame: int = 1,
        scan_frames: int = 500, limit: int = 20,
        max_bytes_per_segment: int = 512, offset: int = 0,
    ) -> dict:
        """Page raw TCP segments by frame window without claiming reassembly."""
        if type(stream_id) is not int or not 0 <= stream_id <= 1_000_000:
            raise PacketSleuthError("stream_id must be from 0 to 1000000")
        limit = _validate_limit(limit)
        offset = _validate_offset(offset)
        if limit > MAX_TCP_SEGMENT_RECORDS:
            raise PacketSleuthError(f"segment limit cannot exceed {MAX_TCP_SEGMENT_RECORDS}")
        if type(max_bytes_per_segment) is not int or not 1 <= max_bytes_per_segment <= MAX_SEGMENT_BYTES:
            raise PacketSleuthError(f"max_bytes_per_segment must be 1 to {MAX_SEGMENT_BYTES}")
        frame_filter, end_frame, coverage = _frame_window(start_frame, scan_frames)
        fields = (
            "frame.number", "frame.time_epoch", "ip.src", "ipv6.src",
            "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport", "tcp.stream",
            "tcp.seq", "tcp.len", "tcp.payload",
        )
        path, digest = self._capture(capture_id)
        rows = self.runner.query(
            path, fields=fields,
            display_filter=(f"tcp.stream == {stream_id} && tcp.len > 0 "
                            f"&& ({frame_filter})"),
            scan_limit=end_frame,
        )
        segments = []
        for row in rows[offset:offset + limit]:
            payload = row.get("tcp.payload") or ""
            if not payload:
                continue
            segments.append({
                "frame": int(row["frame.number"]),
                "timestamp_epoch": row.get("frame.time_epoch"),
                "src_ip": row.get("ip.src") or row.get("ipv6.src") or "",
                "dst_ip": row.get("ip.dst") or row.get("ipv6.dst") or "",
                "src_port": row.get("tcp.srcport") or "",
                "dst_port": row.get("tcp.dstport") or "",
                "tcp_seq": row.get("tcp.seq") or "",
                "tcp_len_reported": row.get("tcp.len") or "",
                **_decode_payload(payload, max_bytes_per_segment),
            })
        return {
            "capture_id": capture_id, "sha256": digest, "tcp_stream_id": stream_id,
            "segments": segments, "matched_segments_in_window": len(rows),
            "results_truncated": len(rows) > offset + limit,
            "next_offset": offset + limit if len(rows) > offset + limit else None,
            "coverage": coverage, "untrusted_data": True,
            "note": (
                "These are captured per-frame TCP bytes, not a reassembled stream. "
                "Retransmissions, gaps, out-of-order frames, and TLS encryption may occur. "
                "If results_truncated is true, narrow scan_frames to inspect all matches."
            ),
        }

    def inspect_frames(self, capture_id: str, frames: list[int]) -> dict:
        frames = _validate_frames(frames)
        path, digest = self._capture(capture_id)
        filt = " || ".join(f"frame.number == {n}" for n in frames)
        rows = self.runner.query(path, display_filter=filt, scan_limit=None)
        found = {int(r.get("frame.number") or 0) for r in rows}
        return {
            "capture_id": capture_id, "sha256": digest,
            "frames": [_summarize_row(r) for r in rows],
            "missing_frames": [n for n in frames if n not in found],
            "untrusted_data": True,
        }

    def follow_stream(self, capture_id: str, stream_id: int, max_bytes: int = 8192) -> dict:
        if type(stream_id) is not int or not 0 <= stream_id <= 1_000_000:
            raise PacketSleuthError("stream_id must be from 0 to 1000000")
        if type(max_bytes) is not int or not 256 <= max_bytes <= 16384:
            raise PacketSleuthError("max_bytes must be from 256 to 16384")
        path, digest = self._capture(capture_id)
        preview = self.runner.follow_tcp(path, stream_id, max_bytes)
        data = preview["text"] if isinstance(preview, dict) else preview
        truncated = preview.get("truncated", False) if isinstance(preview, dict) else False
        return {
            "capture_id": capture_id, "sha256": digest,
            "tcp_stream_id": stream_id, "data": data,
            "output_truncated": truncated,
            "untrusted_data": True,
            "note": (
                "Only a bounded TShark follow preview. Use query_tcp_segments to page "
                "through frame-number ranges and inspect_tcp_payload for exact bytes; "
                "per-frame bytes are not reassembled or decrypted."
            ),
        }

    def get_detections(self, capture_id: str) -> dict:
        """Conservative heuristics; findings are leads, never compromise verdicts."""
        path, digest = self._capture(capture_id)
        rows = self.runner.query(path)
        scan_ports: dict[str, set[tuple[str, str]]] = defaultdict(set)
        scan_frames: dict[str, list[int]] = defaultdict(list)
        nxdomain_frames: dict[str, list[int]] = defaultdict(list)
        for r in rows:
            src = r.get("ip.src") or r.get("ipv6.src") or ""
            dst = r.get("ip.dst") or r.get("ipv6.dst") or ""
            frame = int(r.get("frame.number") or 0)
            if not src or not frame:
                continue
            if r.get("tcp.flags.syn") == "1" and r.get("tcp.flags.ack") == "0" and dst:
                port = r.get("tcp.dstport") or ""
                if port:
                    scan_ports[src].add((dst, port))
                    scan_frames[src].append(frame)
            if r.get("dns.flags.rcode") == "3" and r.get("dns.qry.name"):
                nxdomain_frames[dst or src].append(frame)
        findings = []
        for src, ports in scan_ports.items():
            if len(ports) >= 20:
                findings.append({
                    "rule_id": "heuristic.tcp_syn_fanout", "host_ip": src,
                    "description": "TCP SYN probes to 20+ distinct destination/port pairs",
                    "observed_unique_targets": len(ports),
                    "evidence_frames": scan_frames[src][:20],
                    "assessment": "Investigate; legitimate scanning is possible.",
                })
        for src, frames in nxdomain_frames.items():
            if len(frames) >= 10:
                findings.append({
                    "rule_id": "heuristic.dns_nxdomain_burst", "host_ip": src,
                    "description": "10+ DNS NXDOMAIN responses observed",
                    "observed_responses": len(frames),
                    "evidence_frames": frames[:20],
                    "assessment": "Investigate; negative responses alone do not prove DGA or malware.",
                })
        return {
            "capture_id": capture_id, "sha256": digest,
            "findings": findings,
            "coverage": self._coverage(len(rows), filtered=False),
            "note": "No finding is not proof of benign traffic. Heuristics are not malware verdicts.",
        }

    def verify_evidence(
        self, capture_id: str, frames: list[int], expected_sha256: str | None = None
    ) -> dict:
        """Verify reference integrity only, not the truth of an analyst interpretation."""
        frames = _validate_frames(frames)
        if expected_sha256 is not None and not re.fullmatch(r"[a-fA-F0-9]{64}", expected_sha256):
            raise PacketSleuthError("expected_sha256 must be 64 hexadecimal characters")
        result = self.inspect_frames(capture_id, frames)
        digest_matches = expected_sha256 is None or result["sha256"] == expected_sha256.lower()
        return {
            "capture_id": capture_id, "sha256": result["sha256"],
            "hash_matches": digest_matches,
            "found_frames": [frame["frame"] for frame in result["frames"]],
            "missing_frames": result["missing_frames"],
            "references_verified": digest_matches and not result["missing_frames"],
            "scope": "Checks capture hash and frame existence; does not verify a threat hypothesis.",
        }
