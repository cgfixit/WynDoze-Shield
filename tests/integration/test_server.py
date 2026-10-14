"""Integration tests for the FastAPI server via TestClient."""

from __future__ import annotations

import csv
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPBasicCredentials
from fastapi.testclient import TestClient

from wyndoze_infoscanoverload.server.__main__ import main
from wyndoze_infoscanoverload.server.app import _require_dashboard, create_app
from wyndoze_infoscanoverload.server.config import ServerConfig

if TYPE_CHECKING:
    from collections.abc import Iterator

    from wyndoze_infoscanoverload.core.models import ScanReport

INGEST_TOKEN = "test-ingest-token"  # noqa: S105 - test fixture, not a real secret
DASH_USER = "admin"
DASH_PASSWORD = "test-dashboard-password"  # noqa: S105 - test fixture, not a real secret
DASH_AUTH = (DASH_USER, DASH_PASSWORD)


@pytest.fixture
def client(tmp_db: Path) -> Iterator[TestClient]:
    config = ServerConfig(
        db_path=tmp_db,
        ingest_token=INGEST_TOKEN,
        dashboard_password=DASH_PASSWORD,
    )
    app = create_app(config)
    with TestClient(app) as test_client:
        yield test_client


def _ingest(client: TestClient, report: ScanReport) -> dict[str, object]:
    response = client.post(
        "/api/scans",
        json=report.model_dump(mode="json"),
        headers={"Authorization": f"Bearer {INGEST_TOKEN}"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_health(client: TestClient) -> None:
    assert client.get("/api/health").json() == {"status": "ok"}


def test_ingest_requires_token(client: TestClient, clean_report: ScanReport) -> None:
    response = client.post("/api/scans", json=clean_report.model_dump(mode="json"))
    assert response.status_code == 401


def test_ingest_closed_when_token_unset(tmp_db: Path, clean_report: ScanReport) -> None:
    config = ServerConfig(db_path=tmp_db, ingest_token=None, dashboard_password=DASH_PASSWORD)
    with TestClient(create_app(config)) as bare:
        response = bare.post(
            "/api/scans",
            json=clean_report.model_dump(mode="json"),
            headers={"Authorization": "Bearer anything"},
        )
    assert response.status_code == 401


def test_dashboard_closed_when_password_unset(tmp_db: Path) -> None:
    config = ServerConfig(db_path=tmp_db, ingest_token=INGEST_TOKEN, dashboard_password=None)
    with TestClient(create_app(config)) as bare:
        assert bare.get("/").status_code == 401
        assert bare.get("/", auth=(DASH_USER, "")).status_code == 401


def test_dashboard_wrong_password(client: TestClient) -> None:
    assert client.get("/", auth=(DASH_USER, "nope")).status_code == 401


def test_dashboard_non_ascii_password(tmp_db: Path) -> None:
    password = "päss"  # noqa: S105 - fixture, not a real secret
    config = ServerConfig(db_path=tmp_db, ingest_token=INGEST_TOKEN, dashboard_password=password)
    app = create_app(config)
    # Byte compare accepts the password. HTTP Basic on this FastAPI rejects
    # a non-ASCII payload as 401 before that compare runs.
    _require_dashboard(app, HTTPBasicCredentials(username=DASH_USER, password=password))
    wrong = "x"
    with pytest.raises(HTTPException) as exc:
        _require_dashboard(app, HTTPBasicCredentials(username=DASH_USER, password=wrong))
    assert exc.value.status_code == 401
    with TestClient(app) as bare:
        assert bare.get("/", auth=(DASH_USER, password)).status_code == 401


def test_docs_disabled(client: TestClient) -> None:
    assert client.get("/api/docs").status_code == 404
    assert client.get("/api/openapi.json").status_code == 404
    assert client.get("/redoc").status_code == 404


def test_ingest_and_findings(client: TestClient, backup_server_report: ScanReport) -> None:
    result = _ingest(client, backup_server_report)
    assert result["findings"] >= 3
    assert result["hostname"] == "VBRSRV01"

    for path in ("/", "/triage", "/timeline", "/endpoints", "/reports/summary"):
        assert client.get(path, auth=DASH_AUTH).status_code == 200

    assert "VBRSRV01" in client.get("/endpoints", auth=DASH_AUTH).text


def test_finding_lifecycle(client: TestClient, backup_server_report: ScanReport) -> None:
    _ingest(client, backup_server_report)
    response = client.post("/findings/1/flag", follow_redirects=False, auth=DASH_AUTH)
    assert response.status_code == 303
    assert response.headers["location"] == "/triage"
    missing = client.post("/findings/1/frobnicate", follow_redirects=False, auth=DASH_AUTH)
    assert missing.status_code == 404


@pytest.mark.parametrize("fmt", ["csv", "md", "json", "sentinel"])
def test_exports(client: TestClient, backup_server_report: ScanReport, fmt: str) -> None:
    _ingest(client, backup_server_report)
    response = client.get(f"/export/findings.{fmt}", auth=DASH_AUTH)
    assert response.status_code == 200
    assert response.text.strip()


def test_dedupe_across_two_scans(client: TestClient, backup_server_report: ScanReport) -> None:
    _ingest(client, backup_server_report)
    first = len(client.get("/timeline", auth=DASH_AUTH).text)
    _ingest(client, backup_server_report)
    second = client.get("/timeline", auth=DASH_AUTH).text
    assert second.count("<tr>") <= first


def test_main_rejects_non_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECON_HOST", "0.0.0.0")  # noqa: S104 - launcher must refuse this host

    def boom(*_args: object, **_kwargs: object) -> None:
        msg = "uvicorn should not start"
        raise AssertionError(msg)

    monkeypatch.setattr("wyndoze_infoscanoverload.server.__main__.uvicorn.run", boom)

    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2


def test_main_binds_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECON_HOST", "127.0.0.1")
    seen: dict[str, object] = {}

    def fake_run(*_args: object, **kwargs: object) -> None:
        seen.update(kwargs)

    monkeypatch.setattr("wyndoze_infoscanoverload.server.__main__.uvicorn.run", fake_run)

    main()
    assert seen["host"] == "127.0.0.1"


def test_ingest_rejects_oversize_body(client: TestClient, tmp_db: Path) -> None:
    before = tmp_db.stat().st_size
    response = client.post(
        "/api/scans",
        content=b"{" + (b" " * (8 * 1024 * 1024)),
        headers={"Authorization": f"Bearer {INGEST_TOKEN}", "Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert tmp_db.stat().st_size == before


def test_lifecycle_rejects_foreign_origin(
    client: TestClient, backup_server_report: ScanReport
) -> None:
    _ingest(client, backup_server_report)
    for origin in ("https://evil.example", "null"):
        response = client.post(
            "/findings/1/flag",
            headers={"Origin": origin},
            auth=DASH_AUTH,
            follow_redirects=False,
        )
        assert response.status_code == 403
    page = client.get("/triage", auth=DASH_AUTH)
    assert "VBRSRV01" in page.text


def test_csv_prefixes_formula(client: TestClient, backup_server_report: ScanReport) -> None:
    report = backup_server_report.model_copy(update={"hostname": "=cmd"})
    _ingest(client, report)
    text = client.get("/export/findings.csv", auth=DASH_AUTH).text
    rows = list(csv.reader(text.splitlines()))
    host_index = rows[0].index("hostname")
    hosts = [row[host_index] for row in rows[1:] if row]
    assert hosts
    assert all(host.startswith("'") for host in hosts)


def test_journal_mode_is_wal(client: TestClient, tmp_db: Path) -> None:
    assert client.get("/api/health").status_code == 200
    with sqlite3.connect(tmp_db) as conn:
        mode = conn.execute("PRAGMA journal_mode").fetchone()
    assert mode is not None
    assert mode[0] == "wal"
