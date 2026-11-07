"""Conservative, bounded ICMP Echo correlation and optional candidate concatenation.

ICMP Echo identifier/sequence are message metadata, not TCP byte offsets.
This module never silently merges opposite directions, fills sequence gaps,
or treats a candidate sequence-ordered blob as proven exfiltration.
"""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from typing import TYPE_CHECKING, Literal

from packetsleuth import icmp
from packetsleuth.core import PacketSleuthError, _validate_ip
from packetsleuth.forensics import _assert_unchanged, _capture_pinned, _check_window

if TYPE_CHECKING:
    from packetsleuth.core import InvestigationEngine

MAX_ICMP_SCAN = 250
MAX_ICMP_INSPECT = 24
MAX_GROUPS_RETURNED = 16
MAX_CANDIDATE_BYTES = 8192
PREVIEW_BYTES = 32

ICMP_FIELDS = (
    "frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst",
    "ipv6.dst", "icmp.type", "icmp.ident", "icmp.seq", "icmpv6.type",
    "icmpv6.echo.identifier", "icmpv6.echo.sequence_number",
)


def _number(value: str | None) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        # TShark may emit either decimal or 0x-prefixed numeric fields.
        return int(value, 16) if value.lower().startswith("0x") else int(value, 10)
    except ValueError:
        return None


def _echo_row(row: dict) -> dict | None:
    frame = _number(row.get("frame.number"))
    v4type = _number(row.get("icmp.type"))
    v6type = _number(row.get("icmpv6.type"))
    if v4type in (0, 8) and v6type is None:
        proto, kind, identity, sequence = (
            "icmpv4", "request" if v4type == 8 else "reply",
            _number(row.get("icmp.ident")), _number(row.get("icmp.seq")),
        )
        src, dst = row.get("ip.src") or "", row.get("ip.dst") or ""
    elif v6type in (128, 129) and v4type is None:
        proto, kind, identity, sequence = (
            "icmpv6", "request" if v6type == 128 else "reply",
            _number(row.get("icmpv6.echo.identifier")),
            _number(row.get("icmpv6.echo.sequence_number")),
        )
        src, dst = row.get("ipv6.src") or "", row.get("ipv6.dst") or ""
    else:
        return None
    if (frame is None or frame < 1 or identity is None or not 0 <= identity <= 65535
            or sequence is None or not 0 <= sequence <= 65535 or not src or not dst):
        return None
    endpoints = tuple(sorted((src, dst)))
    return {
        "frame": frame, "protocol": proto, "kind": kind, "src_ip": src,
        "dst_ip": dst, "identifier": identity, "sequence": sequence,
        "timestamp_epoch": row.get("frame.time_epoch") or None,
        "group_key": (proto, *endpoints, identity),
    }


def _summarize_group(key: tuple, records: list[dict]) -> dict:
    return {
        "protocol": key[0], "endpoint_a": key[1], "endpoint_b": key[2],
        "identifier": key[3], "observed_echo_packets": len(records),
        "first_frame": records[0]["frame"], "last_frame": records[-1]["frame"],
        "requests": sum(record["kind"] == "request" for record in records),
        "replies": sum(record["kind"] == "reply" for record in records),
    }


def _correlate(packets: list[dict]) -> dict:
    indexed = defaultdict(lambda: {"request": [], "reply": []})
    for packet in packets:
        indexed[packet["sequence"]][packet["kind"]].append(packet)
    pairs, ambiguous, unmatched_req, unmatched_reply = [], [], [], []
    for sequence, kinds in sorted(indexed.items()):
        requests, replies = kinds["request"], kinds["reply"]
        if len(requests) > 1 or len(replies) > 1:
            ambiguous.append({
                "sequence": sequence, "request_frames": [p["frame"] for p in requests],
                "reply_frames": [p["frame"] for p in replies],
                "reason": "Repeated sequence prevents unambiguous one-to-one pairing",
            })
        elif requests and replies and (
            requests[0]["src_ip"] == replies[0]["dst_ip"]
            and requests[0]["dst_ip"] == replies[0]["src_ip"]
        ):
            pairs.append({
                "sequence": sequence, "request_frame": requests[0]["frame"],
                "reply_frame": replies[0]["frame"],
                "payload_equal": requests[0]["payload_sha256"] == replies[0]["payload_sha256"],
            })
        else:
            unmatched_req.extend(p["frame"] for p in requests)
            unmatched_reply.extend(p["frame"] for p in replies)
    duplicates = []
    for kind in ("request", "reply"):
        grouped = defaultdict(list)
        for packet in packets:
            if packet["kind"] == kind:
                grouped[packet["sequence"]].append(packet)
        for sequence, entries in sorted(grouped.items()):
            if len(entries) > 1:
                duplicates.append({
                    "kind": kind, "sequence": sequence,
                    "frames": [p["frame"] for p in entries],
                    "same_payload": len({p["payload_sha256"] for p in entries}) == 1,
                    "note": "Repeated ICMP sequence; not proof of retransmission",
                })
    return {
        "pairs": pairs, "ambiguous_sequences": ambiguous,
        "unmatched_request_frames": unmatched_req,
        "unmatched_reply_frames": unmatched_reply,
        "duplicate_sequences": duplicates,
        "payload_hashes": dict(Counter(p["payload_sha256"] for p in packets)),
    }


def _candidate(packets: list[dict], kind: str) -> dict:
    selected = [p for p in packets if p["kind"] == kind]
    if not selected:
        return {"status": "no_packets", "kind": kind}
    sequence_map = defaultdict(list)
    for packet in selected:
        sequence_map[packet["sequence"]].append(packet)
    ordered = sorted(sequence_map)
    if ordered[-1] - ordered[0] > 32768:
        return {"status": "ambiguous_wrap", "kind": kind,
                "note": "16-bit sequence wrap/ordering is ambiguous"}
    gaps = [
        {"start": a + 1, "end_inclusive": b - 1}
        for a, b in zip(ordered, ordered[1:]) if b - a > 1
    ]
    if gaps:
        return {"status": "sequence_gaps", "kind": kind, "gaps": gaps,
                "note": "Refusing to concatenate across missing sequence numbers"}
    if any(len({p["payload_sha256"] for p in sequence_map[seq]}) > 1 for seq in ordered):
        return {"status": "conflicting_sequence", "kind": kind,
                "note": "Different payloads share a sequence number"}
    unique = [sequence_map[seq][0] for seq in ordered]
    if any(p["payload_truncated"] for p in unique):
        return {"status": "payload_truncated", "kind": kind}
    length = sum(p["payload_bytes"] for p in unique)
    if length > MAX_CANDIDATE_BYTES:
        return {"status": "output_limit", "kind": kind, "candidate_bytes": length,
                "max_bytes": MAX_CANDIDATE_BYTES}
    data = b"".join(bytes.fromhex(p["data_hex"]) for p in unique)
    if len(data) != length:
        raise PacketSleuthError("Candidate length differs from captured bytes")
    offset = 0
    contributions = []
    for p in unique:
        contributions.append({
            "frame": p["frame"], "sequence": p["sequence"],
            "start": offset, "end_exclusive": offset + p["payload_bytes"],
            "payload_sha256": p["payload_sha256"],
        })
        offset += p["payload_bytes"]
    return {
        "status": "candidate_only", "kind": kind,
        "ordering_rule": "ascending 16-bit sequence without wrap",
        "sequence_start": ordered[0], "sequence_end": ordered[-1],
        "dropped_identical_sequence_frames": [
            p["frame"] for seq in ordered for p in sequence_map[seq][1:]
        ],
        "candidate_bytes": len(data), "candidate_sha256": hashlib.sha256(data).hexdigest(),
        "data_hex": data.hex(), "provenance": contributions,
        "note": (
            "Hypothetical sequence-ordered concatenation. ICMP sequence numbers are "
            "not byte offsets; sequence continuity does not establish chunking, "
            "file transfer, completeness, or exfiltration."
        ),
    }


def reconstruct_icmp_flow(
    engine: InvestigationEngine,
    capture_id: str,
    expected_sha256: str,
    start_frame: int = 1,
    scan_frames: int = 100,
    host_ip: str | None = None,
    peer_ip: str | None = None,
    identifier: int | None = None,
    protocol: Literal["icmpv4", "icmpv6"] | None = None,
    max_packets: int = 16,
    reconstruction_mode: Literal["none", "request", "reply"] = "none",
) -> dict:
    """Correlate one bounded Echo group; optional, explicitly hypothetical bytes."""
    if expected_sha256 is None:
        raise PacketSleuthError("expected_sha256 is required")
    ip = _validate_ip(host_ip)
    peer = _validate_ip(peer_ip)
    if peer and not ip:
        raise PacketSleuthError("host_ip is required when peer_ip is provided")
    if identifier is not None and (type(identifier) is not int or not 0 <= identifier <= 65535):
        raise PacketSleuthError("identifier must be an integer from 0 to 65535")
    if protocol not in (None, "icmpv4", "icmpv6"):
        raise PacketSleuthError("protocol must be icmpv4 or icmpv6")
    if type(max_packets) is not int or not 1 <= max_packets <= MAX_ICMP_INSPECT:
        raise PacketSleuthError(f"max_packets must be 1 to {MAX_ICMP_INSPECT}")
    if reconstruction_mode not in ("none", "request", "reply"):
        raise PacketSleuthError("reconstruction_mode must be none, request, or reply")

    frame_filter, end_frame, coverage = _check_window(
        start_frame, scan_frames, MAX_ICMP_SCAN
    )
    path, digest = _capture_pinned(engine, capture_id, expected_sha256)
    # Fields are static; no caller-defined display filter or arbitrary path.
    rows = engine.runner.query(
        path, fields=ICMP_FIELDS, display_filter=frame_filter, scan_limit=end_frame
    )
    groups = defaultdict(list)
    undecoded = 0
    for row in rows:
        packet = _echo_row(row)
        if packet is None:
            if row.get("icmp.type") or row.get("icmpv6.type"):
                undecoded += 1
            continue
        if protocol and packet["protocol"] != protocol:
            continue
        if ip and ip not in (packet["src_ip"], packet["dst_ip"]):
            continue
        if peer and peer not in (packet["src_ip"], packet["dst_ip"]):
            continue
        if identifier is not None and packet["identifier"] != identifier:
            continue
        groups[packet["group_key"]].append(packet)

    candidates = [_summarize_group(key, entries) for key, entries in groups.items()]
    candidates.sort(key=lambda group: group["first_frame"])
    base = {
        "capture_id": capture_id, "sha256": digest, "coverage": coverage,
        "untrusted_data": True, "content_interpreted": False,
        "matching_groups_in_window": len(groups),
        "undecoded_icmp_rows": undecoded,
    }

    def finish(value: dict) -> dict:
        _assert_unchanged(path, digest)
        return base | value

    if not groups:
        return finish({"status": "no_echo_group", "groups": []})
    if len(groups) != 1:
        return finish({
            "status": "group_selection_required", "groups": candidates[:MAX_GROUPS_RETURNED],
            "groups_truncated": len(candidates) > MAX_GROUPS_RETURNED,
            "note": "Narrow by host_ip, peer_ip, identifier, protocol, or frame window.",
        })

    key, selected = next(iter(groups.items()))
    if len(selected) > max_packets:
        return finish({
            "status": "too_many_echo_packets", "group": candidates[0],
            "matched_packets": len(selected), "max_packets": max_packets,
            "note": "Narrow the frame window; packets are not silently omitted.",
        })

    verified = []
    rejected = []
    for metadata in selected:
        evidence = icmp.inspect_icmp_payload(
            engine, capture_id, metadata["frame"], digest,
            max_bytes=icmp.MAX_ICMP_RETURN_BYTES,
        )
        if evidence["status"] != "ok":
            rejected.append({"frame": metadata["frame"], "status": evidence["status"]})
            continue
        if (
            evidence["protocol"] != metadata["protocol"]
            or evidence["identifier"] != metadata["identifier"]
            or evidence["sequence"] != metadata["sequence"]
            or evidence["src_ip"] != metadata["src_ip"]
            or evidence["dst_ip"] != metadata["dst_ip"]
            or evidence["message_kind"] != f"echo_{metadata['kind']}"
        ):
            rejected.append({"frame": metadata["frame"], "status": "metadata_disagreement"})
            continue
        verified.append({
            **metadata, "frame_sha256": evidence["frame_sha256"],
            "payload_sha256": evidence["payload_sha256"],
            "payload_bytes": evidence["payload_bytes"],
            "payload_offset_in_frame": evidence["payload_offset_in_frame"],
            "payload_truncated": evidence["payload_truncated"],
            "data_hex": evidence["payload_hex"],
        })

    # Never correlate partial evidence as though all selected Echo frames were verified.
    if rejected:
        return finish({
            "status": "incomplete_evidence", "group": candidates[0],
            "verified_frames": [p["frame"] for p in verified],
            "rejected_frames": rejected,
            "note": "Correlation/reconstruction withheld because frame verification was incomplete.",
        })

    correlation = _correlate(verified)
    preview = [{
        "frame": p["frame"], "timestamp_epoch": p["timestamp_epoch"],
        "kind": p["kind"], "sequence": p["sequence"],
        "src_ip": p["src_ip"], "dst_ip": p["dst_ip"],
        "payload_bytes": p["payload_bytes"], "payload_sha256": p["payload_sha256"],
        "frame_sha256": p["frame_sha256"],
        "payload_offset_in_frame": p["payload_offset_in_frame"],
        "payload_preview_hex": p["data_hex"][:2 * PREVIEW_BYTES],
        "payload_preview_truncated": p["payload_bytes"] > PREVIEW_BYTES,
    } for p in verified]
    candidate = (
        {"status": "not_requested"} if reconstruction_mode == "none"
        else _candidate(verified, reconstruction_mode)
    )
    return finish({
        "status": "correlated_window", "group": _summarize_group(key, selected),
        "packets": preview, "correlation": correlation, "candidate": candidate,
        "notes": [
            "Grouping uses endpoint pair, ICMP family, and Echo identifier inside one frame window.",
            "Repeated identifiers or sequences can belong to different sessions; no session boundary is inferred.",
            "ICMP duplicates are not necessarily retransmissions. A matched Echo reply is not proof of delivery to an application.",
            "No automatic Base64, decompression, or payload execution occurs.",
        ],
    })
