"""Capture-pinned, deterministic page cursors and explicit result coverage."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
from collections.abc import Mapping, Sequence
from typing import Any

from packetsleuth.core import PacketSleuthError

# Short-lived cursors are authenticated within one MCP server process.
# On restart, clients should begin a new scan with the same capture SHA-256.
_CURSOR_KEY = secrets.token_bytes(32)


def _fingerprint(capture_sha256: str, scope: Mapping[str, Any]) -> str:
    data = json.dumps(
        {"capture_sha256": capture_sha256, "scope": scope},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _serialize(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")


def encode_cursor(position: int, capture_sha256: str, scope: Mapping[str, Any]) -> str:
    """Authenticated, short-lived continuation bound to exact capture/query scope."""
    body = {"v": 2, "p": position, "f": _fingerprint(capture_sha256, scope)}
    signature = hmac.new(_CURSOR_KEY, _serialize(body), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(
        _serialize({**body, "s": signature})
    ).decode("ascii").rstrip("=")


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
    if not isinstance(decoded, dict) or decoded.get("v") != 2:
        raise PacketSleuthError("Unsupported cursor version; restart the page traversal")
    position = decoded.get("p")
    signature = decoded.get("s")
    fingerprint = decoded.get("f")
    if (type(position) is not int or not isinstance(fingerprint, str)
            or not isinstance(signature, str) or len(signature) != 64):
        raise PacketSleuthError("Malformed page cursor")
    body = {"v": 2, "p": position, "f": fingerprint}
    expected_sig = hmac.new(_CURSOR_KEY, _serialize(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_sig):
        raise PacketSleuthError("Cursor authentication failed; restart the traversal")
    if fingerprint != _fingerprint(capture_sha256, scope) or not default <= position <= maximum:
        raise PacketSleuthError(
            "Cursor does not match this capture, query, or scan window"
        )
    return position


def stable_frame_rows(rows: Sequence[dict[str, str]]) -> list[dict[str, str]]:
    """Canonical packet-frame ordering; never silently collapse duplicate/malformed rows."""
    ordered = []
    seen = set()
    for row in rows:
        raw = row.get("frame.number")
        if not isinstance(raw, str) or not raw.isdecimal():
            raise PacketSleuthError(
                "TShark returned a result without a valid frame number",
                code="PARSER_FAILURE",
            )
        frame = int(raw)
        if frame < 1 or frame in seen:
            raise PacketSleuthError(
                "TShark returned duplicate or invalid frame numbers",
                code="PARSER_FAILURE",
            )
        seen.add(frame)
        ordered.append((frame, row))
    ordered.sort(key=lambda item: item[0])
    return [row for _, row in ordered]


def page(
    items: Sequence[dict], limit: int, offset: int, capture_sha256: str,
    scope: Mapping[str, Any], scan_start: int, scan_end: int,
) -> tuple[list[dict], dict]:
    """Page finite window results; has_more means MORE WITHIN the scanned window."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise PacketSleuthError("limit must be from 1 to 100")
    if type(offset) is not int or not 0 <= offset <= len(items):
        raise PacketSleuthError("Page offset is outside the scanned result window")
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
