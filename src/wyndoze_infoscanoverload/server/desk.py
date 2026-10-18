"""Desk query and return-path rules.

One parse at the HTTP boundary. ``active`` is a query word, not a stored status.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TypeGuard
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

_DEFAULT_NEXT = "/triage"
_HOST_MAX = 255
_RULE_MAX = 512
_PAGE_MAX = 1000000
_ASCII_DELETE = 127
_CONTROL_BELOW = 32
_STATUSES = frozenset({"triage", "flagged", "archived", "suppressed", "active"})
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_NEXT_PATHS = frozenset(
    {
        "/",
        "/triage",
        "/timeline",
        "/endpoints",
        "/reports/summary",
    }
)
_NEXT_KEYS = frozenset({"status", "severity", "host"})
_SCAN_NEXT = re.compile(r"/scans/[0-9]{1,18}")


def legal_host(value: object) -> TypeGuard[str]:
    """Return True when a host may be placed in an href or a Location."""
    if not isinstance(value, str) or not value or len(value) > _HOST_MAX:
        return False
    return all(ord(char) >= _CONTROL_BELOW and ord(char) != _ASCII_DELETE for char in value)


@dataclass(frozen=True, slots=True)
class DeskQuery:
    """Filters for the triage desk. ``status`` may be the virtual word active."""

    status: str
    severity: str | None
    host: str | None
    rule_id: str | None = None


def parse_desk_query(source: Mapping[str, str]) -> DeskQuery:
    """Parse a desk query. Omitted or illegal status becomes triage."""
    raw_status = source.get("status")
    status = raw_status if raw_status in _STATUSES else "triage"
    raw_severity = source.get("severity")
    severity = raw_severity if raw_severity in _SEVERITIES else None
    raw_host = source.get("host")
    host = raw_host if legal_host(raw_host) else None
    return DeskQuery(status=status, severity=severity, host=host)


def encode_desk_query(
    status: str | None,
    severity: str | None,
    host: str | None,
    *,
    rule_id: str | None = None,
) -> str:
    """Rebuild a desk query. Empty means the path has no query string."""
    pairs: list[tuple[str, str]] = []
    if status in _STATUSES:
        pairs.append(("status", status))
    if severity in _SEVERITIES:
        pairs.append(("severity", severity))
    if legal_host(host):
        pairs.append(("host", host))
    if rule_id:
        pairs.append(("rule_id", rule_id))
    if not pairs:
        return ""
    return urlencode(pairs, quote_via=quote)


def desk_path(query: DeskQuery) -> str:
    """Return the current desk URL, including a default status."""
    encoded = encode_desk_query(query.status, query.severity, query.host, rule_id=query.rule_id)
    if not encoded:
        return _DEFAULT_NEXT
    return f"{_DEFAULT_NEXT}?{encoded}"


def suppress_confirm_href(finding_id: int, next_path: str) -> str:
    """Return the confirm URL. ``next`` is encoded once more as a query value."""
    query = urlencode([("next", next_path)], quote_via=quote)
    return f"/findings/{finding_id}/suppress/confirm?{query}"


def host_href(query: DeskQuery, hostname: str) -> str | None:
    """Return a desk link for one host, or None when the name is not legal."""
    if not legal_host(hostname):
        return None
    encoded = encode_desk_query(query.status, query.severity, hostname, rule_id=query.rule_id)
    return f"{_DEFAULT_NEXT}?{encoded}"


def safe_next(value: object) -> str:
    """Return an allowlisted relative URL, or /triage."""
    rebuilt = _rebuild_next(value)
    if rebuilt is None:
        return _DEFAULT_NEXT
    return rebuilt


def _rebuild_next(value: object) -> str | None:
    """Return a rebuilt next URL, or None when the value is rejected."""
    accepted = _accepted_target(value)
    if accepted is None:
        return None
    path, query = accepted
    if not query and path.startswith("/scans/"):
        return path
    pairs = parse_qsl(query, keep_blank_values=True)
    if _has_repeat(pairs):
        return None
    status, severity, host = _take_desk_values(pairs)
    present = dict(pairs)
    extras = []
    hostname = present.get("hostname")
    if legal_host(hostname):
        extras.append(("hostname", hostname))
    rule_id = present.get("rule_id", "")
    if (
        rule_id
        and len(rule_id) <= _RULE_MAX
        and not any(ord(char) < _CONTROL_BELOW or ord(char) == _ASCII_DELETE for char in rule_id)
    ):
        extras.append(("rule_id", rule_id))
    page_number = present.get("page", "")
    if (
        page_number.isascii()
        and page_number.isdecimal()
        and len(page_number) <= len(str(_PAGE_MAX))
        and 1 <= int(page_number) <= _PAGE_MAX
    ):
        extras.append(("page", str(int(page_number))))
    encoded = "&".join(
        part
        for part in (encode_desk_query(status, severity, host), urlencode(extras, quote_via=quote))
        if part
    )
    if not encoded:
        return path
    return f"{path}?{encoded}"


def _accepted_target(value: object) -> tuple[str, str] | None:
    """Return the raw path and query, or None when the URL is not allowlisted."""
    if not isinstance(value, str) or value == "":
        return None
    parts = urlsplit(value)
    if parts.scheme or parts.netloc or parts.fragment:
        return None
    if parts.path.startswith("/scans/"):
        if parts.query or _SCAN_NEXT.fullmatch(parts.path) is None:
            return None
        return parts.path, ""
    if parts.path not in _NEXT_PATHS:
        return None
    return parts.path, parts.query


def _has_repeat(pairs: list[tuple[str, str]]) -> bool:
    """Return True when any query key appears more than once."""
    seen: set[str] = set()
    for key, _raw in pairs:
        if key in seen:
            return True
        seen.add(key)
    return False


def _take_desk_values(
    pairs: list[tuple[str, str]],
) -> tuple[str | None, str | None, str | None]:
    """Keep allowlisted values. A present illegal status becomes triage."""
    present = {key: raw for key, raw in pairs if key in _NEXT_KEYS}
    if "status" not in present:
        status = None
    elif present["status"] in _STATUSES:
        status = present["status"]
    else:
        status = "triage"
    raw_severity = present.get("severity")
    severity = raw_severity if raw_severity in _SEVERITIES else None
    raw_host = present.get("host")
    host = raw_host if legal_host(raw_host) else None
    return status, severity, host


__all__ = [
    "DeskQuery",
    "desk_path",
    "encode_desk_query",
    "host_href",
    "legal_host",
    "parse_desk_query",
    "safe_next",
    "suppress_confirm_href",
]
