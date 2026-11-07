"""Bounded, evidence-pinned extraction of ICMPv4/v6 Echo message data.

TShark jsonraw supplies captured frame bytes and protocol-layer positions.
We validate IP lengths and layer boundaries against the original frame before
slicing Echo data; generic data.data/icmp.data fields are never trusted as the
definition of an Echo payload. No decryption, decoding, or execution occurs.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import TYPE_CHECKING

from packetsleuth.core import MAX_FRAME_NUMBER, PacketSleuthError
from packetsleuth.forensics import _assert_unchanged, _capture_pinned

if TYPE_CHECKING:
    from packetsleuth.core import InvestigationEngine

MAX_ICMP_RETURN_BYTES = 4096


class _UnsupportedLayout(ValueError):
    """Packet structure cannot be mapped to exact, complete Echo bytes."""


def _raw_field(layers: dict, key: str, frame: bytes | None = None) -> tuple[bytes, int] | None:
    value = layers.get(key)
    if value is None:
        return None
    # A repeated raw layer is ambiguous: never silently select one.
    if (not isinstance(value, list) or len(value) < 3
            or not isinstance(value[0], str)
            or type(value[1]) is not int or type(value[2]) is not int):
        raise _UnsupportedLayout(f"Invalid or ambiguous {key} raw-layer location")
    encoded, offset, length = value[:3]
    if (offset < 0 or length < 0 or len(encoded) != length * 2
            or re.fullmatch(r"[0-9a-fA-F]*", encoded) is None):
        raise _UnsupportedLayout(f"Malformed {key} raw-layer bytes or length")
    data = bytes.fromhex(encoded)
    if frame is not None and (offset + length > len(frame)
                              or frame[offset:offset + length] != data):
        raise _UnsupportedLayout(f"{key} does not match the original captured frame")
    return data, offset


def _icmpv4_bounds(frame: bytes, layers: dict, icmp_offset: int) -> tuple[int, str, str]:
    raw = _raw_field(layers, "ip_raw", frame)
    if raw is None:
        raise _UnsupportedLayout("No unambiguous IPv4 layer for ICMP")
    ip, offset = raw
    if len(ip) < 20 or ip[0] >> 4 != 4:
        raise _UnsupportedLayout("Invalid IPv4 header")
    ihl = (ip[0] & 15) * 4
    if ihl < 20 or offset + ihl > len(frame):
        raise _UnsupportedLayout("Invalid IPv4 header length")
    total = int.from_bytes(frame[offset + 2:offset + 4], "big")
    flags_fragment = int.from_bytes(frame[offset + 6:offset + 8], "big")
    if flags_fragment & 0x3FFF:
        raise _UnsupportedLayout("Fragmented IPv4 Echo cannot be extracted as a complete message")
    if frame[offset + 9] != 1 or icmp_offset != offset + ihl:
        raise _UnsupportedLayout("IPv4 protocol or ICMP layer offset mismatch")
    end = offset + total
    if total < ihl + 8 or end > len(frame):
        raise _UnsupportedLayout("IPv4 datagram is truncated or has an invalid total length")
    src = str(ipaddress.ip_address(frame[offset + 12:offset + 16]))
    dst = str(ipaddress.ip_address(frame[offset + 16:offset + 20]))
    return end, src, dst


def _icmpv6_bounds(frame: bytes, layers: dict, icmp_offset: int) -> tuple[int, str, str]:
    raw = _raw_field(layers, "ipv6_raw", frame)
    if raw is None:
        raise _UnsupportedLayout("No unambiguous IPv6 layer for ICMPv6")
    ip, offset = raw
    if len(ip) < 40 or ip[0] >> 4 != 6:
        raise _UnsupportedLayout("Invalid IPv6 header")
    payload_length = int.from_bytes(frame[offset + 4:offset + 6], "big")
    if payload_length == 0:
        raise _UnsupportedLayout("IPv6 jumbograms are not supported")
    end = offset + 40 + payload_length
    if end > len(frame):
        raise _UnsupportedLayout("IPv6 datagram is truncated")
    position = offset + 40
    next_header = frame[offset + 6]
    for _ in range(16):
        if next_header == 58:
            break
        if next_header == 44:
            raise _UnsupportedLayout("IPv6 Fragment header is not supported")
        if next_header not in (0, 43, 60, 51, 135):
            raise _UnsupportedLayout("Unknown or unsupported IPv6 extension header")
        if position + 2 > end:
            raise _UnsupportedLayout("Truncated IPv6 extension header")
        new_next = frame[position]
        size = ((frame[position + 1] + 2) * 4 if next_header == 51
                else (frame[position + 1] + 1) * 8)
        if position + size > end:
            raise _UnsupportedLayout("Invalid IPv6 extension length")
        position += size
        next_header = new_next
    if next_header != 58 or position != icmp_offset or end - position < 8:
        raise _UnsupportedLayout("IPv6 ICMP header does not match extension chain")
    src = str(ipaddress.ip_address(frame[offset + 8:offset + 24]))
    dst = str(ipaddress.ip_address(frame[offset + 24:offset + 40]))
    return end, src, dst


def _optional_decimal(value: str | None) -> int | None:
    return int(value) if isinstance(value, str) and value.isdecimal() else None


def inspect_icmp_payload(
    engine: InvestigationEngine,
    capture_id: str,
    frame: int,
    expected_sha256: str,
    max_bytes: int = 1024,
) -> dict:
    """Inspect exactly one Echo frame; reject ambiguous/truncated byte provenance."""
    if type(frame) is not int or not 1 <= frame <= MAX_FRAME_NUMBER:
        raise PacketSleuthError("frame must be a positive integer")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_ICMP_RETURN_BYTES:
        raise PacketSleuthError(f"max_bytes must be between 1 and {MAX_ICMP_RETURN_BYTES}")
    if expected_sha256 is None:
        raise PacketSleuthError("expected_sha256 is required for ICMP extraction")

    path, digest = _capture_pinned(engine, capture_id, expected_sha256)
    raw_packet = engine.runner.raw_frame(path, frame)
    fields = ("frame.number", "frame.time_epoch", "frame.len", "frame.cap_len", "frame.file_off")
    rows = engine.runner.query(path, fields=fields,
                               display_filter=f"frame.number == {frame}", scan_limit=frame)
    base = {
        "capture_id": capture_id, "sha256": digest, "frame": frame,
        "untrusted_data": True, "content_interpreted": False,
    }

    def finish(result: dict) -> dict:
        _assert_unchanged(path, digest)
        return base | result

    if raw_packet is None and not rows:
        return finish({"status": "frame_not_found", "found": False})
    if raw_packet is None or len(rows) != 1 or rows[0].get("frame.number") != str(frame):
        return finish({"status": "unsupported_layout", "found": bool(rows),
                       "reason": "Raw frame and metadata disagree"})

    row = rows[0]
    try:
        layers = raw_packet["_source"]["layers"]
        if not isinstance(layers, dict):
            raise _UnsupportedLayout("Invalid raw packet layers")
        framed = _raw_field(layers, "frame_raw")
        if framed is None or framed[1] != 0:
            raise _UnsupportedLayout("TShark did not supply complete raw frame bytes")
        frame_bytes = framed[0]
        if _optional_decimal(row.get("frame.cap_len")) != len(frame_bytes):
            raise _UnsupportedLayout("Captured frame length differs from raw bytes")

        icmp4 = _raw_field(layers, "icmp_raw", frame_bytes)
        icmp6 = _raw_field(layers, "icmpv6_raw", frame_bytes)
        if icmp4 is None and icmp6 is None:
            return finish({"status": "not_icmp_echo", "found": True,
                           "frame_sha256": hashlib.sha256(frame_bytes).hexdigest()})
        if icmp4 is not None and icmp6 is not None:
            raise _UnsupportedLayout("Multiple ICMP protocol layers")
        protocol = "icmpv4" if icmp4 is not None else "icmpv6"
        icmp_raw, icmp_offset = icmp4 if icmp4 is not None else icmp6
        if len(icmp_raw) < 8 or icmp_offset + 8 > len(frame_bytes):
            raise _UnsupportedLayout("Incomplete ICMP Echo header")
        icmp_type, code = frame_bytes[icmp_offset:icmp_offset + 2]
        allowed = (0, 8) if icmp4 is not None else (128, 129)
        if icmp_type not in allowed or code != 0:
            return finish({
                "status": "not_icmp_echo", "found": True, "protocol": protocol,
                "icmp_type": icmp_type, "icmp_code": code,
                "frame_sha256": hashlib.sha256(frame_bytes).hexdigest(),
            })
        if icmp4 is not None:
            end, src, dst = _icmpv4_bounds(frame_bytes, layers, icmp_offset)
        else:
            end, src, dst = _icmpv6_bounds(frame_bytes, layers, icmp_offset)
        payload_offset = icmp_offset + 8
        payload = frame_bytes[payload_offset:end]
        excerpt = payload[:max_bytes]
        identifier = int.from_bytes(frame_bytes[icmp_offset + 4:icmp_offset + 6], "big")
        sequence = int.from_bytes(frame_bytes[icmp_offset + 6:icmp_offset + 8], "big")
        return finish({
            "status": "ok", "found": True, "protocol": protocol,
            "icmp_type": icmp_type, "icmp_code": code,
            "message_kind": "echo_request" if icmp_type in (8, 128) else "echo_reply",
            "identifier": identifier, "sequence": sequence,
            "src_ip": src, "dst_ip": dst,
            "timestamp_epoch": row.get("frame.time_epoch") or None,
            "frame_file_offset": _optional_decimal(row.get("frame.file_off")),
            "frame_file_offset_note": "Capture record location, not a frame-relative byte offset",
            "captured_frame_bytes": len(frame_bytes),
            "frame_sha256": hashlib.sha256(frame_bytes).hexdigest(),
            "payload_offset_in_frame": payload_offset,
            "payload_end_offset_exclusive": end,
            "payload_bytes": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "returned_bytes": len(excerpt),
            "returned_prefix_sha256": hashlib.sha256(excerpt).hexdigest(),
            "payload_hex": excerpt.hex(),
            "payload_ascii": "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in excerpt),
            "payload_truncated": len(payload) > max_bytes,
            "note": (
                "Verified captured Echo data only, excluding IP/ICMP headers and frame "
                "padding. Hashes cover captured frame, full Echo data, and returned prefix "
                "separately. No fragmentation reassembly or content decoding."
            ),
        })
    except (KeyError, TypeError, _UnsupportedLayout) as exc:
        return finish({"status": "unsupported_layout", "found": True,
                       "reason": str(exc) if isinstance(exc, _UnsupportedLayout)
                       else "Malformed raw-frame structure"})
