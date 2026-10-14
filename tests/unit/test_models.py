"""Tests for the Pydantic models and helpers."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from wyndoze_infoscanoverload.core.models import (
    EndpointRole,
    Finding,
    ScanReport,
    ServiceInfo,
    dedupe_key,
    utc_now_iso,
)
from wyndoze_infoscanoverload.core.severity import Severity
from wyndoze_infoscanoverload.server.config import default_db_path


def test_utc_now_iso_is_tz_aware() -> None:
    value = utc_now_iso()
    assert value.endswith("+00:00") or value.endswith("Z")


def test_scan_report_round_trip(backup_server_report: ScanReport) -> None:
    raw = backup_server_report.model_dump_json()
    restored = ScanReport.model_validate_json(raw)
    assert restored.hostname == backup_server_report.hostname
    assert restored.role is EndpointRole.BACKUP_SERVER
    assert restored.processes[0].name == "mimikatz.exe"


def test_dedupe_key_stable_and_distinct() -> None:
    f1 = Finding(rule_id="r1", title="t", severity=Severity.HIGH, evidence=["a"])
    f2 = Finding(rule_id="r1", title="t", severity=Severity.HIGH, evidence=["a"])
    f3 = Finding(rule_id="r1", title="t", severity=Severity.HIGH, evidence=["b"])
    assert dedupe_key(f1, "host") == dedupe_key(f2, "host")
    assert dedupe_key(f1, "host") != dedupe_key(f3, "host")
    assert dedupe_key(f1, "host") != dedupe_key(f1, "other")


def test_role_defaults_to_unknown() -> None:
    report = ScanReport(scan_time_utc=utc_now_iso(), hostname="H")
    assert report.role is EndpointRole.UNKNOWN


def test_service_extra_field_is_dropped() -> None:
    info = ServiceInfo.model_validate({"name": "Spooler", "binpath": r"C:\x"})
    assert "binpath" not in info.model_dump()


def test_default_db_path_uses_programdata() -> None:
    path = default_db_path()
    assert path.name == "WynDoze-InfoScanOverload.sqlite3"
    if os.name == "nt":
        root = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        assert path == Path(root) / "WynDoze-InfoScanOverload" / "WynDoze-InfoScanOverload.sqlite3"


def test_scan_time_utc_is_capped() -> None:
    ScanReport(scan_time_utc="2026-01-01T00:00:00Z", hostname="H")
    too_long = "2026-01-01T00:00:00." + ("1" * 60) + "Z"
    assert len(too_long) > 64
    with pytest.raises(ValidationError):
        ScanReport(scan_time_utc=too_long, hostname="H")
