"""Protocol-neutral investigative queries and bounded TCP byte reconstruction.

No arbitrary packet filter, shell command, filesystem path, or generated code is
accepted from an MCP caller. Decoded packet content is always untrusted data.

TCP reconstruction is scoped to a requested frame window and one direction. It
reports missing bytes, overlap conflicts, and coverage rather than synthesizing
unobserved bytes or claiming the full session was recovered.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from typing import TYPE_CHECKING, Literal

from packetsleuth.core import (
    PacketSleuthError,
    _clip,
    _frame_window,
    _sha256,
    _validate_ip,
)

if TYPE_CHECKING:
    from packetsleuth.core import InvestigationEngine

# Explicit field catalog: protocol-agnostic querying without arbitrary TShark
# expressions. Keep output fields small; raw bytes are retrieved separately.
QUERY_FIELDS = frozenset({
    "frame.number", "frame.time_epoch", "frame.len", "frame.protocols",
    "eth.src", "eth.dst", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "ip.ttl", "ipv6.hlim", "ip.proto", "tcp.stream", "tcp.srcport",
    "tcp.dstport", "tcp.len", "tcp.flags", "tcp.flags.syn", "tcp.flags.ack",
    "tcp.analysis.retransmission", "udp.stream", "udp.srcport", "udp.dstport",
    "dns.qry.name", "dns.flags.rcode", "dns.qry.type", "http.host",
    "http.request.method", "http.request.uri", "http.response.code",
    "tls.handshake.extensions_server_name", "tls.record.content_type",
    "icmp.type", "icmp.code", "icmp.ident", "icmp.seq",
    "icmpv6.type", "icmpv6.code", "icmpv6.echo.identifier",
    "icmpv6.echo.sequence_number", "arp.opcode", "ftp.request.command", "smtp.req.command",
})
DEFAULT_FIELDS = (
    "frame.number", "frame.time_epoch", "frame.len", "frame.protocols",
    "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.stream",
)
TCP_FIELDS = (
    "frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst",
    "ipv6.dst", "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.seq_raw",
    "tcp.seq", "tcp.len", "tcp.payload",
)
MAX_QUERY_SCAN = 1_000
MAX_TCP_SCAN = 500
MAX_TCP_SEGMENTS = 256
MAX_TCP_BYTES = 512 * 1024
MAX_RETURN_BYTES = 8_192
MAX_REPORTED_SPANS = 32
MAX_QUERY_FIELDS = 12
MAX_QUERY_MATCHES = 50


def _validate_hash(expected: str | None) -> str | None:
    if expected is None:
        return None
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
        raise PacketSleuthError("expected_sha256 must be 64 hex characters")
    return expected.lower()


def _capture_pinned(engine: InvestigationEngine, capture_id: str, expected: str | None):
    path, digest = engine._capture(capture_id)
    if (wanted := _validate_hash(expected)) is not None and wanted != digest:
        raise PacketSleuthError("Capture SHA-256 mismatch; refresh capture ID and hash")
    return path, digest


def _assert_unchanged(path, digest: str) -> None:
    if _sha256(path) != digest:
        raise PacketSleuthError("Capture changed during analysis; discard these results")


def _check_stream_id(stream_id: int) -> None:
    if type(stream_id) is not int or not 0 <= stream_id <= 1_000_000:
        raise PacketSleuthError("stream_id must be an integer from 0 to 1000000")


def _check_window(start_frame: int, scan_frames: int, maximum: int):
    if type(scan_frames) is not int or not 1 <= scan_frames <= maximum:
        raise PacketSleuthError(f"scan_frames must be an integer from 1 to {maximum}")
    return _frame_window(start_frame, scan_frames)


def query_packets(
    engine: InvestigationEngine, capture_id: str,
    fields: list[str] | None = None,
    match_field: str | None = None,
    match_value: str | None = None,
    match_mode: Literal["exact", "contains"] = "contains",
    host_ip: str | None = None,
    start_frame: int = 1, scan_frames: int = 250, limit: int = 25,
    expected_sha256: str | None = None,
) -> dict:
    """Search a bounded frame window and page by *frame number*, not result offset.

    The matching operation happens in Python on a fixed set of decoded fields,
    avoiding user-supplied display-filter expressions and injection issues.
    """
    if fields is None:
        fields = list(DEFAULT_FIELDS)
    if not isinstance(fields, list) or not 1 <= len(fields) <= MAX_QUERY_FIELDS:
        raise PacketSleuthError(f"Provide 1 to {MAX_QUERY_FIELDS} fields")
    if any(not isinstance(field, str) or field not in QUERY_FIELDS for field in fields):
        raise PacketSleuthError("Unsupported query field; see list_query_fields")
    if match_field is not None and match_field not in QUERY_FIELDS:
        raise PacketSleuthError("Unsupported match_field; see list_query_fields")
    if (match_field is None) != (match_value is None):
        raise PacketSleuthError("match_field and match_value must be supplied together")
    if match_value is not None and (not isinstance(match_value, str) or len(match_value) > 128
                                    or any(ord(c) < 32 for c in match_value)):
        raise PacketSleuthError("match_value must be printable and at most 128 characters")
    if match_mode not in ("exact", "contains"):
        raise PacketSleuthError("match_mode must be exact or contains")
    if type(limit) is not int or not 1 <= limit <= MAX_QUERY_MATCHES:
        raise PacketSleuthError(f"limit must be an integer from 1 to {MAX_QUERY_MATCHES}")
    ip = _validate_ip(host_ip)
    frame_filter, end_frame, coverage = _check_window(start_frame, scan_frames, MAX_QUERY_SCAN)
    requested = tuple(dict.fromkeys(("frame.number", *fields,
                                     *((match_field,) if match_field else ()),
                                     *(("ip.src", "ip.dst", "ipv6.src", "ipv6.dst") if ip else ()))))
    path, digest = _capture_pinned(engine, capture_id, expected_sha256)
    rows = engine.runner.query(path, fields=requested, display_filter=frame_filter,
                               scan_limit=end_frame)
    matches = []
    for row in rows:
        if ip and ip not in (row.get("ip.src"), row.get("ip.dst"), row.get("ipv6.src"),
                            row.get("ipv6.dst")):
            continue
        if match_field is not None:
            value = row.get(match_field, "")
            if match_mode == "exact" and value != match_value:
                continue
            if match_mode == "contains" and match_value.casefold() not in value.casefold():
                continue
        matches.append({field: _clip(row.get(field, ""), 256) for field in fields}
                       | {"frame": int(row["frame.number"])})
    _assert_unchanged(path, digest)
    if len(matches) > limit:
        next_frame = matches[limit - 1]["frame"] + 1
    else:
        next_frame = coverage["next_start_frame"]
    return {
        "capture_id": capture_id, "sha256": digest, "records": matches[:limit],
        "matched_in_window": len(matches), "returned": min(len(matches), limit),
        "results_truncated": len(matches) > limit,
        "next_start_frame": next_frame,
        "coverage": coverage,
        "search": {"fields": fields, "match_field": match_field, "match_mode": match_mode,
                   "host_ip": ip},
        "untrusted_data": True,
        "note": (
            "next_start_frame is a candidate cursor; do not infer end-of-capture. "
            "For additional matches, repeat the same query using that frame, "
            "with expected_sha256 pinned to this response."
        ),
    }


def _direction_key(row: dict) -> tuple[str, int, str, int]:
    src = row.get("ip.src") or row.get("ipv6.src") or ""
    dst = row.get("ip.dst") or row.get("ipv6.dst") or ""
    return (src, int(row.get("tcp.srcport") or 0), dst,
            int(row.get("tcp.dstport") or 0))


def _decode_tcp_row(row: dict) -> dict | None:
    frame = int(row.get("frame.number") or 0)
    seq = row.get("tcp.seq_raw") or row.get("tcp.seq")
    if not frame or not seq or not seq.isdecimal():
        return None
    field = row.get("tcp.payload") or ""
    if not field:
        data = b""
    else:
        field = field.replace(":", "")
        if len(field) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", field):
            raise PacketSleuthError("Malformed TShark TCP payload encoding")
        data = bytes.fromhex(field)
    return {
        "frame": frame, "seq": int(seq), "data": data,
        "reported_length": int(row.get("tcp.len") or 0),
        "key": _direction_key(row),
        "seq_source": "tcp.seq_raw" if row.get("tcp.seq_raw") else "tcp.seq",
    }


def _magic_kind(data: bytes) -> dict:
    """Small, format-neutral header classifier; no parsing/execution of artifacts."""
    signatures = (
        (b"%PDF-", "application/pdf", "PDF document"),
        (b"PK\x03\x04", "application/zip", "ZIP archive"),
        (b"\x1f\x8b", "application/gzip", "gzip stream"),
        (b"\x89PNG\r\n\x1a\n", "image/png", "PNG image"),
        (b"GIF87a", "image/gif", "GIF image"),
        (b"GIF89a", "image/gif", "GIF image"),
        (b"\xff\xd8\xff", "image/jpeg", "JPEG image"),
        (b"\x7fELF", "application/x-elf", "ELF executable"),
        (b"MZ", "application/x-dosexec", "PE/DOS executable candidate"),
        (b"SQLite format 3\0", "application/vnd.sqlite3", "SQLite database"),
        (b"PACK", "application/x-git-pack", "Git packfile"),
        (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "7-Zip archive"),
        (b"Rar!\x1a\x07", "application/vnd.rar", "RAR archive"),
        (b"HTTP/1.", "message/http", "HTTP response"),
    )
    for magic, mime, label in signatures:
        if data.startswith(magic):
            return {"format": label, "mime_hint": mime, "confidence": "signature"}
    if len(data) >= 5 and data[0] in (20, 21, 22, 23) and data[1] == 3 and data[2] <= 4:
        return {"format": "TLS record candidate", "mime_hint": None,
                "confidence": "heuristic"}
    if any(data.startswith(x) for x in (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ")):
        return {"format": "HTTP request candidate", "mime_hint": "message/http",
                "confidence": "heuristic"}
    if not data:
        return {"format": "no bytes at offset", "mime_hint": None,
                "confidence": "none"}
    if len(data) >= 16 and sum(c in b"\t\r\n" or 32 <= c <= 126 for c in data) / len(data) > 0.95:
        return {"format": "printable text candidate", "mime_hint": "text/plain",
                "confidence": "heuristic"}
    return {"format": "unknown binary", "mime_hint": None, "confidence": "unknown"}


def _ranges(bitmap: bytearray, kind: int) -> list[dict]:
    found = []
    run_start = None
    for i, value in enumerate(bitmap):
        if value == kind and run_start is None:
            run_start = i
        if value != kind and run_start is not None:
            found.append({"start": run_start, "end_exclusive": i})
            run_start = None
    if run_start is not None:
        found.append({"start": run_start, "end_exclusive": len(bitmap)})
    return found


def reconstruct_tcp(
    engine: InvestigationEngine, capture_id: str, stream_id: int,
    source_ip: str | None = None, source_port: int | None = None,
    start_frame: int = 1, scan_frames: int = 250,
    byte_offset: int = 0, max_bytes: int = 2048,
    expected_sha256: str | None = None,
    include_hex: bool = True,
) -> dict:
    """Bounded single-direction reassembly with explicit uncertainty.

    Relative output offset 0 is the smallest TCP sequence observed in the
    requested frame window, *not* necessarily the beginning of the connection.
    """
    _check_stream_id(stream_id)
    ip = _validate_ip(source_ip)
    if source_port is not None and (type(source_port) is not int or not 1 <= source_port <= 65535):
        raise PacketSleuthError("source_port must be 1 to 65535")
    if source_port is not None and ip is None:
        raise PacketSleuthError("source_ip required when source_port is specified")
    if type(byte_offset) is not int or not 0 <= byte_offset <= MAX_TCP_BYTES:
        raise PacketSleuthError(f"byte_offset must be 0 to {MAX_TCP_BYTES}")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_RETURN_BYTES:
        raise PacketSleuthError(f"max_bytes must be 1 to {MAX_RETURN_BYTES}")
    frame_filter, end_frame, coverage = _check_window(start_frame, scan_frames, MAX_TCP_SCAN)
    path, digest = _capture_pinned(engine, capture_id, expected_sha256)
    filt = f"tcp.stream == {stream_id} && tcp.len > 0 && ({frame_filter})"
    rows = engine.runner.query(path, fields=TCP_FIELDS, display_filter=filt,
                               scan_limit=end_frame)
    segments = [item for row in rows if (item := _decode_tcp_row(row)) is not None]
    if len(segments) > MAX_TCP_SEGMENTS:
        raise PacketSleuthError("Too many TCP segments in window; narrow scan_frames")
    directions = Counter(item["key"] for item in segments)
    candidates = [
        {"src_ip": key[0], "src_port": key[1], "dst_ip": key[2],
         "dst_port": key[3], "segments": count}
        for key, count in directions.most_common()
    ]
    selected = [item for item in segments if (ip is None or item["key"][0] == ip)
                and (source_port is None or item["key"][1] == source_port)]
    selected_keys = {item["key"] for item in selected}
    base = {
        "capture_id": capture_id, "sha256": digest, "tcp_stream_id": stream_id,
        "coverage": coverage, "directions": candidates, "untrusted_data": True,
    }
    if len(selected_keys) > 1:
        _assert_unchanged(path, digest)
        return base | {
            "status": "direction_required", "note": (
                "Multiple source endpoints found. Select a direction using source_ip "
                "and source_port; opposite TCP directions cannot be concatenated."
            ),
        }
    if not selected:
        _assert_unchanged(path, digest)
        return base | {"status": "no_payload_in_window", "available_bytes": 0,
                       "note": "No TCP payload in this frame window/direction."}
    if len({item["seq_source"] for item in selected}) > 1:
        raise PacketSleuthError("Inconsistent TCP sequence fields; cannot reconstruct safely")
    # Direction-specific raw TCP sequence numbers, unwrapped around the first
    # captured segment. Works across 32-bit rollover for windows shorter than 2 GiB.
    anchor = selected[0]["seq"]
    seq_values = [((item["seq"] - anchor + (1 << 31)) % (1 << 32)) - (1 << 31)
                  for item in selected]
    minimum = min(seq_values)
    positions = [seq - minimum for seq in seq_values]
    span = max(pos + max(len(item["data"]), item["reported_length"])
               for pos, item in zip(positions, selected))
    if span > MAX_TCP_BYTES:
        raise PacketSleuthError("TCP sequence span exceeds 512 KiB; narrow the frame window")
    payload = bytearray(span)
    observed = bytearray(span)
    conflict_frames = []
    retransmitted = 0
    overlap_conflict_count = 0
    length_mismatches = []
    contributions = []
    for position, item in zip(positions, selected):
        data = item["data"]
        if len(data) != item["reported_length"]:
            length_mismatches.append(item["frame"])
        contributions.append({"frame": item["frame"], "start": position,
                              "end_exclusive": position + len(data)})
        for index, byte in enumerate(data, start=position):
            if observed[index]:
                retransmitted += 1
                if payload[index] != byte:
                    overlap_conflict_count += 1
                    if len(conflict_frames) < 16:
                        conflict_frames.append(item["frame"])
            else:
                payload[index] = byte
                observed[index] = 1
    gaps = _ranges(observed, 0)
    spans = _ranges(observed, 1)
    end_offset = byte_offset
    if byte_offset < span and observed[byte_offset]:
        end_offset = min(span, byte_offset + max_bytes)
        for gap in gaps:
            if gap["start"] >= byte_offset:
                end_offset = min(end_offset, gap["start"])
                break
    excerpt = bytes(payload[byte_offset:end_offset])
    frames = sorted({entry["frame"] for entry in contributions
                     if entry["start"] < end_offset and entry["end_exclusive"] > byte_offset})
    returned_provenance = [
        {"frame": entry["frame"],
         "relative_seq_start": max(entry["start"], byte_offset),
         "relative_seq_end_exclusive": min(entry["end_exclusive"], end_offset)}
        for entry in contributions
        if entry["start"] < end_offset and entry["end_exclusive"] > byte_offset
    ]
    _assert_unchanged(path, digest)
    result = base | {
        "status": "reconstructed_window", "direction": candidates[0] if len(candidates) == 1
        else next(candidate for candidate in candidates if candidate["src_ip"] == selected[0]["key"][0]
                  and candidate["src_port"] == selected[0]["key"][1]),
        "sequence_basis": "smallest observed sequence in frame window, not session origin",
        "sequence_field": selected[0]["seq_source"],
        "sequence_span_bytes": span,
        "unique_observed_bytes": sum(observed),
        "complete_sequence_span": not gaps and not conflict_frames and not length_mismatches,
        "missing_ranges": gaps[:MAX_REPORTED_SPANS],
        "missing_ranges_truncated": len(gaps) > MAX_REPORTED_SPANS,
        "observed_ranges": spans[:MAX_REPORTED_SPANS],
        "observed_ranges_truncated": len(spans) > MAX_REPORTED_SPANS,
        "overlap_bytes": retransmitted,
        "overlap_conflicting_bytes": overlap_conflict_count,
        "conflicting_frames_truncated": overlap_conflict_count > len(conflict_frames),
        "conflicting_overlap_frames": conflict_frames,
        "reported_length_mismatch_frames": length_mismatches[:16],
        "returned_offset": byte_offset, "returned_length": len(excerpt),
        "returned_range_sha256": hashlib.sha256(excerpt).hexdigest(),
        "contributing_frames": frames[:64],
        "contributing_frames_truncated": len(frames) > 64,
        "returned_range_provenance": returned_provenance[:64],
        "returned_range_provenance_truncated": len(returned_provenance) > 64,
        "next_byte_offset": end_offset if end_offset < span and observed[end_offset] else None,
        "content_hint": _magic_kind(excerpt[:128]),
        "note": (
            "Reassembled from captured TCP sequence data within this frame window/direction; "
            "no decryption or protocol decoding. Missing bytes are never fabricated. "
            "Complete_sequence_span does NOT prove the full TCP session was captured. "
            "The requested byte offset is relative to the minimum observed sequence."
        ),
    }
    if include_hex:
        result["data_hex"] = excerpt.hex()
    return result


def identify_stream_content(
    engine: InvestigationEngine, capture_id: str, stream_id: int,
    source_ip: str | None = None, source_port: int | None = None,
    start_frame: int = 1, scan_frames: int = 250, byte_offset: int = 0,
    expected_sha256: str | None = None,
) -> dict:
    """Identify a format at an arbitrary TCP byte offset without revealing raw bytes."""
    result = reconstruct_tcp(
        engine, capture_id, stream_id, source_ip, source_port, start_frame,
        scan_frames, byte_offset, 128, expected_sha256, include_hex=True,
    )
    if result["status"] != "reconstructed_window":
        return result
    return {
        "capture_id": capture_id, "sha256": result["sha256"],
        "tcp_stream_id": stream_id, "direction": result["direction"],
        "status": result["status"], "byte_offset": byte_offset,
        "content_hint": result["content_hint"],
        "available_header_bytes": result["returned_length"],
        "evidence_frames": result["contributing_frames"],
        "has_gaps": bool(result["missing_ranges"]),
        "has_conflicts": bool(result["conflicting_overlap_frames"]),
        "coverage": result["coverage"],
        "note": "Signature/heuristic only, not proof of file validity or full transfer.",
        "untrusted_data": True,
    }


def verify_stream_range(
    engine: InvestigationEngine, capture_id: str, stream_id: int,
    expected_range_sha256: str, source_ip: str | None = None,
    source_port: int | None = None, start_frame: int = 1,
    scan_frames: int = 250, byte_offset: int = 0, max_bytes: int = 2048,
    expected_sha256: str | None = None,
) -> dict:
    """Recompute SHA256 from original packet bytes, without returning data."""
    wanted = _validate_hash(expected_range_sha256)
    if wanted is None:
        raise PacketSleuthError("expected_range_sha256 required")
    result = reconstruct_tcp(
        engine, capture_id, stream_id, source_ip, source_port, start_frame,
        scan_frames, byte_offset, max_bytes, expected_sha256, include_hex=False,
    )
    if result["status"] != "reconstructed_window":
        return result
    return {
        "capture_id": capture_id, "sha256": result["sha256"],
        "status": "verified_range", "tcp_stream_id": stream_id,
        "byte_offset": byte_offset, "actual_bytes": result["returned_length"],
        "range_sha256_matches": (result["returned_length"] > 0
                                  and result["returned_range_sha256"] == wanted),
        "contributing_frames": result["contributing_frames"],
        "has_gaps": bool(result["missing_ranges"]),
        "has_conflicts": bool(result["conflicting_overlap_frames"]),
        "coverage": result["coverage"],
        "scope": "Checks captured bytes in this bounded window; not the full application transfer.",
    }
