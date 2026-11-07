"""Capture-pinned, deterministic page cursors and explicit result coverage."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from packetsleuth.core import PacketSleuthError


def _fingerprint(capture_sha256: str, scope: Mapping[str, Any]) -> str:
    data = json.dumps(
        {"capture_sha256": capture_sha256, "scope": scope},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def encode_cursor(position: int, capture_sha256: str, scope: Mapping[str, Any]) -> str:
    """Stateless continuation bound to a capture digest and exact query parameters."""
    payload = json.dumps(
        {"v": 1, "p": position, "f": _fingerprint(capture_sha256, scope)},
        sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def decode_cursor(
    cursor: str | None, capture_sha256: str, scope: Mapping[str, Any],
    default: int, maximum: int,
) -> int:
    if cursor is None:
        return default
    if not isinstance(cursor, str) or not 1 <= len(cursor) <= 512:
        raise PacketSleuthError("cursor must be a bounded continuation token")
    try:
        token = base64.b64decode(
            cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True,
        )
        decoded = json.loads(token)
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise PacketSleuthError("Malformed page cursor") from exc
    if (not isinstance(decoded, dict) or decoded.get("v") != 1
            or decoded.get("f") != _fingerprint(capture_sha256, scope)
            or type(decoded.get("p")) is not int
            or not default <= decoded["p"] <= maximum):
        raise PacketSleuthError(
            "Cursor does not match this capture, query, or scan window"
        )
    return decoded["p"]


def page(
    items: Sequence[dict], limit: int, offset: int, capture_sha256: str,
    scope: Mapping[str, Any], scan_start: int, scan_end: int,
) -> tuple[list[dict], dict]:
    """Page finite window results; has_more means MORE WITHIN the scanned window."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise PacketSleuthError("limit must be from 1 to 100")
    if type(offset) is not int or not 0 <= offset <= 10_000:
        raise PacketSleuthError("Page offset must be from 0 to 10000")
    result = list(items[offset:offset + limit])
    next_offset = offset + len(result)
    has_more = next_offset < len(items)
    return result, {
        "has_more": has_more, "results_truncated": has_more,
        "next_offset": next_offset if has_more else None,
        "next_cursor": encode_cursor(next_offset, capture_sha256, scope) if has_more else None,
        "scan_range": {"start_frame": scan_start, "end_frame": scan_end},
        "truncation": {
            "page_truncated": has_more, "output_truncated": False,
            "window_may_have_more_frames": True,
        },
    }
