"""Reduce a stored scan to facts the dashboard may render.

Command lines and pattern names outside the loaded pack stop here.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from wyndoze_infoscanoverload.core.models import ScanReport


class UnreadableScan(Exception):  # noqa: N818 - the scan reducer contract uses this name
    """The stored scan JSON cannot be shown."""

    def __init__(self) -> None:
        super().__init__("unreadable scan")


def public_scan_facts(
    raw_json: str,
    received_at_utc: str,
    allowed_flags: frozenset[str],
) -> dict[str, Any]:
    """Return counts and pack-allowed pattern names. Never a command line."""
    try:
        report = ScanReport.model_validate_json(raw_json)
    except (ValidationError, json.JSONDecodeError):
        raise UnreadableScan from None
    sealed = sum(1 for proc in report.processes if proc.cmdline is not None)
    patterns = [
        flag.strip().lower()
        for flag in report.cmdline_flags
        if flag.strip().lower() in allowed_flags
    ]
    return {
        "hostname": report.hostname,
        "fqdn": report.fqdn or "",
        "role": report.role.value,
        "scan_time_utc": report.scan_time_utc,
        "received_at_utc": received_at_utc,
        "platform_system": report.platform.system,
        "platform_release": report.platform.release,
        "ip_addresses": list(report.ip_addresses),
        "process_count": len(report.processes),
        "listening_count": len(report.listening_connections),
        "service_count": len(report.services),
        "software_count": len(report.installed_software),
        "local_admin_count": len(report.local_admins),
        "patterns": patterns,
        "sealed_command_line_count": sealed,
    }


__all__ = ["UnreadableScan", "public_scan_facts"]
