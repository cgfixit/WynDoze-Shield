"""SQLite layer behavior that the HTTP tests do not reach directly."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from wyndoze_infoscanoverload.core.models import CollectionHealth, ScanReport
from wyndoze_infoscanoverload.core.rulepacks import default_rule_pack
from wyndoze_infoscanoverload.core.rules import evaluate
from wyndoze_infoscanoverload.server import storage as storage_module
from wyndoze_infoscanoverload.server.storage import Storage


@pytest.fixture
def storage(tmp_db: Path) -> Storage:
    store = Storage(tmp_db)
    store.init_db()
    return store


def test_invalid_status_is_rejected_before_any_write(storage: Storage) -> None:
    with pytest.raises(ValueError, match="invalid status"):
        storage.set_finding_status(1, "deleted")
    assert storage.set_finding_status(999, "archived") is False


def test_list_scans_decodes_ip_addresses(
    storage: Storage, backup_server_report: ScanReport
) -> None:
    findings = evaluate(backup_server_report, default_rule_pack())
    scan_id = storage.record_scan(backup_server_report, findings)
    (row,) = storage.list_scans()
    assert row["id"] == scan_id
    assert row["ip_addresses"] == ["192.0.2.10"]
    assert row["finding_count"] == len(findings)


def test_corrupt_json_columns_degrade_to_empty_lists(
    storage: Storage, tmp_db: Path, backup_server_report: ScanReport
) -> None:
    findings = evaluate(backup_server_report, default_rule_pack())
    scan_id = storage.record_scan(backup_server_report, findings)
    with sqlite3.connect(tmp_db) as conn:
        conn.execute("UPDATE scans SET ip_addresses_json = '{broken' WHERE id = ?", (scan_id,))
        conn.execute("UPDATE findings SET evidence_json = 'nope'")
    assert storage.list_scans()[0]["ip_addresses"] == []
    listed = storage.list_findings()
    assert listed
    assert all(item["evidence"] == [] for item in listed)
    fetched = storage.get_finding(listed[0]["id"])
    assert fetched is not None
    assert fetched["evidence"] == []


def test_wal_journal_mode(storage: Storage, tmp_db: Path) -> None:
    assert storage.list_scans() == []
    with sqlite3.connect(tmp_db) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_endpoint_names_are_newest_first_without_scan_payloads(
    storage: Storage,
    backup_server_report: ScanReport,
    clean_report: ScanReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Windows clocks can stamp two back-to-back scans identically; drive the clock.
    clock = iter(
        (
            "2026-10-19T10:00:00+00:00",
            "2026-10-19T10:00:01+00:00",
            "2026-10-19T10:00:02+00:00",
        )
    )
    monkeypatch.setattr(storage_module, "utc_now_iso", lambda: next(clock))
    storage.record_scan(backup_server_report, [])
    storage.record_scan(clean_report, [])
    assert storage.list_endpoint_names() == ["WS-001", "BACKUPSRV01"]
    storage.record_scan(backup_server_report, [])
    assert storage.list_endpoint_names() == ["BACKUPSRV01", "WS-001"]


def test_endpoint_names_break_timestamp_ties_by_hostname(
    storage: Storage,
    backup_server_report: ScanReport,
    clean_report: ScanReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(storage_module, "utc_now_iso", lambda: "2026-10-19T10:00:00+00:00")
    storage.record_scan(clean_report, [])
    storage.record_scan(backup_server_report, [])
    assert storage.list_endpoint_names() == ["BACKUPSRV01", "WS-001"]


def test_endpoint_health_matches_with_and_without_json_functions(
    storage: Storage, backup_server_report: ScanReport, clean_report: ScanReport
) -> None:
    partial = backup_server_report.model_copy(
        update={
            "collection_health": {
                "services": CollectionHealth(status="partial", issues=["limit_reached"])
            }
        }
    )
    storage.record_scan(partial, [])
    storage.record_scan(clean_report, [])
    extracted = sorted(storage.list_endpoints(), key=lambda row: row["hostname"])
    assert storage._json_functions is True
    storage._json_functions = False
    fallback = sorted(storage.list_endpoints(), key=lambda row: row["hostname"])
    assert extracted == fallback
    by_host = {row["hostname"]: row["collection_health"] for row in extracted}
    assert by_host["WS-001"] == {}
    assert by_host["BACKUPSRV01"]["services"]["status"] == "partial"
    assert by_host["BACKUPSRV01"]["services"]["issues"] == ["limit_reached"]
    assert all("raw_json" not in row and "health_json" not in row for row in extracted)
