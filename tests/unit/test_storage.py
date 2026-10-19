"""SQLite layer behavior that the HTTP tests do not reach directly."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from wyndoze_infoscanoverload.core.models import CollectionHealth, ScanReport
from wyndoze_infoscanoverload.core.rulepacks import default_rule_pack
from wyndoze_infoscanoverload.core.rules import evaluate
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
    assert row["ip_addresses"] == ["10.0.0.10"]
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
    storage: Storage, backup_server_report: ScanReport, clean_report: ScanReport
) -> None:
    storage.record_scan(backup_server_report, [])
    storage.record_scan(clean_report, [])
    assert storage.list_endpoint_names() == ["WS-001", "VBRSRV01"]
    storage.record_scan(backup_server_report, [])
    assert storage.list_endpoint_names() == ["VBRSRV01", "WS-001"]


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
    extracted = storage.list_endpoints()
    assert storage._json_functions is True
    storage._json_functions = False
    fallback = storage.list_endpoints()
    assert extracted == fallback
    by_host = {row["hostname"]: row["collection_health"] for row in extracted}
    assert by_host["WS-001"] == {}
    assert by_host["VBRSRV01"]["services"]["status"] == "partial"
    assert by_host["VBRSRV01"]["services"]["issues"] == ["limit_reached"]
    assert "raw_json" not in extracted[0]
    assert "health_json" not in extracted[0]
