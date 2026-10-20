"""Exports include rows beyond the bounded dashboard query."""

import csv
import io
import json

import pytest
from fastapi.testclient import TestClient

from wyndoze_infoscanoverload.core.models import Finding, ScanReport, SoftwareInfo
from wyndoze_infoscanoverload.core.severity import Severity
from wyndoze_infoscanoverload.server.app import create_app
from wyndoze_infoscanoverload.server.config import ServerConfig

PASSWORD = "synthetic"  # noqa: S105 - disposable fixture


@pytest.mark.parametrize("fmt", ["json", "csv", "md", "sentinel"])
def test_exports_include_all_rows_beyond_dashboard_cap(tmp_path, fmt):
    app = create_app(ServerConfig(db_path=tmp_path / "state.sqlite3", dashboard_password=PASSWORD))
    storage = app.state.storage
    report = ScanReport(hostname="=synthetic", scan_time_utc="2026-10-18T12:00:00Z")
    storage.record_scan(
        report,
        [Finding(rule_id=f"r{n}", title=f"Finding {n}", severity=Severity.LOW) for n in range(501)],
    )
    assert len(storage.list_findings()) == 500
    with TestClient(app) as client:
        assert client.get(f"/export/findings.{fmt}").status_code == 401
        response = client.get(f"/export/findings.{fmt}", auth=("admin", "synthetic"))
    assert response.status_code == 200
    if fmt == "json":
        rows = response.json()
    elif fmt == "csv":
        rows = list(csv.DictReader(io.StringIO(response.text)))
        assert all(row["hostname"].startswith("'") for row in rows)
    elif fmt == "sentinel":
        rows = [json.loads(line) for line in response.text.splitlines()]
    else:
        rows = [line for line in response.text.splitlines() if line.startswith("| low |")]
        assert "Total: **501**" in response.text
    assert len(rows) == 501


def test_markdown_export_keeps_inventory_as_table_text(tmp_path):
    app = create_app(
        ServerConfig(
            db_path=tmp_path / "state.sqlite3",
            dashboard_password=PASSWORD,
            ingest_token=PASSWORD,
        )
    )
    report = ScanReport(
        hostname="synthetic|column\r\n## heading",
        scan_time_utc="2026-10-19T12:00:00Z",
        installed_software=[
            SoftwareInfo(name=r"AnyDesk ![image](https://example.invalid/a) <b>&#124;</b> C:\tools")
        ],
    )
    with TestClient(app) as client:
        accepted = client.post(
            "/api/scans",
            content=report.model_dump_json(),
            headers={"Authorization": f"Bearer {PASSWORD}"},
        )
        assert accepted.status_code == 201
        assert accepted.json()["findings"] == 1
        exported = client.get("/export/findings.md", auth=("admin", PASSWORD))
        original = client.get("/export/findings.json", auth=("admin", PASSWORD)).json()
    assert exported.status_code == 200
    rows = exported.text.splitlines()
    assert len(rows) == 7
    assert rows[-1] == (
        "| medium | synthetic&#124;column ## heading | Remote-access software is installed | "
        "T1219 Remote Access Software | triage | "
        "AnyDesk !&#91;image&#93;(https://example.invalid/a) "
        "&#60;b&#62;&#38;#124;&#60;/b&#62; C:&#92;tools |"
    )
    assert original[0]["hostname"] == report.hostname
    assert original[0]["evidence"] == [report.installed_software[0].name]
