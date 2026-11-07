"""Evidence-scoped DNS packet and resource-record inspection via TShark PDML.

Packet details are parsed from the dissector's field hierarchy, preserving
multiple records instead of conflating occurrence-first DNS A/AAAA and TTL fields.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING
from xml.etree import ElementTree as ET

from packetsleuth.core import PacketSleuthError, _clip, _validate_ip
from packetsleuth.forensics import _assert_unchanged, _capture_pinned, _check_window
from packetsleuth.pagination import decode_cursor, page

if TYPE_CHECKING:
    from packetsleuth.core import InvestigationEngine

DNS_FIELDS = (
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "udp.srcport", "udp.dstport", "tcp.srcport", "tcp.dstport",
    "dns.id", "dns.flags.response", "dns.flags.rcode",
    "dns.qry.name", "dns.qry.type", "dns.response_to", "dns.response_in",
    "dns.count.answers", "dns.count.auth_rr", "dns.count.add_rr",
)
TYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
    41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC",
    48: "DNSKEY", 52: "TLSA", 64: "SVCB", 65: "HTTPS",
    257: "CAA",
}
RDATA_FIELDS = (
    "dns.a", "dns.aaaa", "dns.cname", "dns.ns",
    "dns.ptr.domain_name", "dns.txt", "dns.mx.mail_exchange",
    "dns.srv.target", "dns.soa.mname", "dns.soa.rname",
    "dns.caa.issue", "dns.caa.issuewild", "dns.caa.iodef",
)
MAX_DNS_PAGE = 10
MAX_DNS_WINDOW = 250
MAX_RECORDS = 64


def _integer(value: str | None) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value, 10)
    except ValueError:
        return None


def _field_values(root: ET.Element, name: str) -> list[str]:
    return [
        f.attrib.get("show", f.attrib.get("value", ""))
        for f in root.iter("field") if f.attrib.get("name") == name
    ]


def _first(root: ET.Element, name: str) -> str | None:
    items = _field_values(root, name)
    return items[0] if items else None


def _record_nodes(dns: ET.Element) -> list[ET.Element]:
    """Find one tree per RR, retaining repeated owner names and different TTLs."""
    parents = {child: parent for parent in dns.iter() for child in parent}
    candidates = []
    for field in dns.iter("field"):
        if field.attrib.get("name") != "dns.resp.name":
            continue
        node = parents.get(field)
        if node is None:
            continue
        # Ascend while the parent contains exactly this one owner-name field.
        # Avoid taking the entire Answers section when it contains many RRs.
        while node is not dns:
            parent = parents.get(node)
            if parent is None or parent is dns:
                break
            if len(_field_values(parent, "dns.resp.name")) != 1:
                break
            node = parent
        if len(_field_values(node, "dns.resp.name")) == 1:
            candidates.append(node)
    return candidates


def _parse_records(dns: ET.Element, max_records: int) -> tuple[list[dict], dict]:
    expected_answers = _integer(_first(dns, "dns.count.answers"))
    records = []
    nodes = _record_nodes(dns)
    for node in nodes[:max_records]:
        name = _first(node, "dns.resp.name")
        number = _integer(_first(node, "dns.resp.type"))
        ttl = _integer(_first(node, "dns.resp.ttl"))
        if name is None or number is None:
            continue
        data = {}
        for key in RDATA_FIELDS:
            values = _field_values(node, key)
            if values:
                data[key] = [_clip(v, 256) for v in values[:8]]
        ips = []
        for field in ("dns.a", "dns.aaaa"):
            for value in data.get(field, ()):
                try:
                    ips.append(str(ipaddress.ip_address(value)))
                except ValueError:
                    continue
        records.append({
            "name": _clip(name, 255), "type_code": number,
            "record_type": TYPE_NAMES.get(number, f"TYPE{number}"),
            "ttl": ttl, "rdata": data, "answer_ips": ips,
            "rdata_decoded": bool(data),
        })
    # DNS header separates answer, authority, and additional sections by count.
    # If record owners could not be located, do not manufacture missing RRs.
    answer_count = expected_answers if expected_answers is not None else len(records)
    answer_records = records[:answer_count]
    return answer_records, {
        "expected_answer_count": expected_answers,
        "parsed_answer_count": len(answer_records),
        "answers_truncated": len(nodes) > max_records
        or (expected_answers is not None and expected_answers > len(answer_records)),
        "record_parse_complete": (
            expected_answers is not None and len(answer_records) == expected_answers
            and len(nodes) <= max_records
        ),
        "records_in_packet_with_owner_name": len(nodes),
    }


def _read_pdml_packet(root: ET.Element, frame: int, max_records: int) -> dict:
    dns_layers = [
        p for p in root.iter("proto") if p.attrib.get("name") == "dns"
    ]
    if len(dns_layers) != 1:
        raise PacketSleuthError(
            f"Expected one DNS layer in frame {frame}; got {len(dns_layers)}",
            code="PARSER_FAILURE",
        )
    dns = dns_layers[0]
    answer_records, metadata = _parse_records(dns, max_records)
    questions = []
    names = _field_values(dns, "dns.qry.name")
    types = _field_values(dns, "dns.qry.type")
    for idx, name in enumerate(names):
        number = _integer(types[idx]) if idx < len(types) else None
        questions.append({
            "name": _clip(name, 255), "type_code": number,
            "record_type": TYPE_NAMES.get(number, f"TYPE{number}") if number else None,
        })
    return {
        "questions": questions[:32],
        "questions_truncated": len(questions) > 32,
        "answer_records": answer_records,
        "answer_ips": sorted({
            address for record in answer_records for address in record["answer_ips"]
        }),
        **metadata,
    }


def query_dns(
    engine: InvestigationEngine, capture_id: str, expected_sha256: str,
    start_frame: int = 1, scan_frames: int = 100, limit: int = 5,
    host_ip: str | None = None, cursor: str | None = None,
    max_records_per_message: int = 32,
) -> dict:
    """Bounded DNS evidence pages with capture-pinned, query-bound stable cursors."""
    if expected_sha256 is None:
        raise PacketSleuthError("expected_sha256 is required")
    if type(limit) is not int or not 1 <= limit <= MAX_DNS_PAGE:
        raise PacketSleuthError(f"limit must be between 1 and {MAX_DNS_PAGE}")
    if (type(max_records_per_message) is not int
            or not 1 <= max_records_per_message <= MAX_RECORDS):
        raise PacketSleuthError(
            f"max_records_per_message must be 1 to {MAX_RECORDS}"
        )
    ip = _validate_ip(host_ip)
    filter_window, end_frame, coverage = _check_window(
        start_frame, scan_frames, MAX_DNS_WINDOW
    )
    path, digest = _capture_pinned(engine, capture_id, expected_sha256)
    scope = {
        "tool": "query_dns", "capture_id": capture_id, "start_frame": start_frame,
        "scan_frames": scan_frames, "host_ip": ip,
        "max_records_per_message": max_records_per_message,
    }
    display_filter = f"dns && ({filter_window})"
    rows = engine.runner.query(
        path, fields=DNS_FIELDS, display_filter=display_filter, scan_limit=end_frame,
    )
    if ip:
        rows = [
            row for row in rows if ip in (
                row.get("ip.src"), row.get("ip.dst"),
                row.get("ipv6.src"), row.get("ipv6.dst"),
            )
        ]
    offset = decode_cursor(cursor, digest, scope, 0, len(rows))
    selected, meta = page(rows, limit, offset, digest, scope, start_frame, end_frame)
    frame_numbers = [_integer(r.get("frame.number")) for r in selected]
    if any(frame is None or frame < 1 for frame in frame_numbers):
        raise PacketSleuthError("TShark returned malformed DNS frame numbers",
                               code="PARSER_FAILURE")
    details = engine.runner.dns_details(path, frame_numbers, end_frame) if selected else {}
    events = []
    for row, frame in zip(selected, frame_numbers):
        detail = details.get(frame)
        if detail is None:
            raise PacketSleuthError(
                f"TShark omitted DNS packet details for frame {frame}",
                code="PARSER_FAILURE",
            )
        parsed = _read_pdml_packet(detail, frame, max_records_per_message)
        flag = (row.get("dns.flags.response") or "").strip().casefold()
        is_response = flag in ("1", "0x1", "true", "yes", "set")
        query_ref = _integer(row.get("dns.response_to"))
        response_ref = _integer(row.get("dns.response_in"))
        events.append({
            "frame": frame, "timestamp_epoch": row.get("frame.time_epoch") or None,
            "src_ip": row.get("ip.src") or row.get("ipv6.src") or None,
            "dst_ip": row.get("ip.dst") or row.get("ipv6.dst") or None,
            "src_port": row.get("udp.srcport") or row.get("tcp.srcport") or None,
            "dst_port": row.get("udp.dstport") or row.get("tcp.dstport") or None,
            "transaction_id": _integer(row.get("dns.id")),
            "message_kind": "response" if is_response else "query",
            "query_name": _clip(row.get("dns.qry.name") or "", 255),
            "query_type": _integer(row.get("dns.qry.type")),
            "response_code": _integer(row.get("dns.flags.rcode")) if is_response else None,
            "query_frame": query_ref if is_response else frame,
            "response_frame": frame if is_response else response_ref,
            "correlation": (
                "tshark_response_to" if is_response and query_ref
                else "tshark_response_in" if not is_response and response_ref
                else "unmatched_or_outside_window"
            ),
            **parsed,
        })
    _assert_unchanged(path, digest)
    return {
        "capture_id": capture_id, "sha256": digest, "events": events,
        "returned": len(events), "matched_in_window": len(rows),
        "coverage": coverage, "untrusted_data": True,
        "has_more": meta["has_more"], "results_truncated": meta["results_truncated"],
        "next_cursor": meta["next_cursor"], "scan_range": meta["scan_range"],
        "truncation": {
            **meta["truncation"],
            "any_answer_records_truncated": any(e["answers_truncated"] for e in events),
        },
        "note": (
            "DNS response references are TShark's dissection links, not proof "
            "of network delivery. Record parsing may be incomplete; inspect "
            "record_parse_complete and answers_truncated per frame."
        ),
    }
