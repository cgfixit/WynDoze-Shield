"""Coverage and collection freshness across authenticated ingest and rendering."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from wyndoze_infoscanoverload.core.models import CollectionHealth, ScanReport
from wyndoze_infoscanoverload.server.app import create_app
from wyndoze_infoscanoverload.server.config import ServerConfig

PASSWORD = "synthetic"  # noqa: S105 - disposable fixture
TOKEN = "synthetic"  # noqa: S105 - disposable fixture


@pytest.mark.parametrize(
    ("offset", "expected"),
    [(-48, "overdue"), (-1, "current"), (24, "unknown")],
)
def test_inventory_age_is_not_upload_age(tmp_path, offset, expected):
    app = create_app(
        ServerConfig(
            db_path=tmp_path / "test.db",
            ingest_token=TOKEN,
            dashboard_password=PASSWORD,
            stale_after_hours=36,
        )
    )
    report = ScanReport(
        hostname="synthetic<script>",
        scan_time_utc=(datetime.now(UTC) + timedelta(hours=offset)).isoformat(),
        collection_health={"services": CollectionHealth(status="failed", issues=["access_denied"])},
    )
    with TestClient(app) as client:
        assert (
            client.post(
                "/api/scans",
                json=report.model_dump(mode="json"),
                headers={"Authorization": "Bearer synthetic"},
            ).status_code
            == 201
        )
        assert client.get("/endpoints").status_code == 401
        response = client.get("/endpoints", auth=("admin", "synthetic"))
        assert response.status_code == 200
        assert "services: failed" in response.text
        assert "access_denied" in response.text
        assert expected in response.text
        assert "synthetic&lt;script&gt;" in response.text
        assert "synthetic<script>" not in response.text
        endpoint = app.state.storage.list_endpoints()[0]
        assert endpoint["freshness"] == expected
        assert endpoint["last_seen_utc"] != endpoint["scan_time_utc"]


def test_legacy_timezone_less_scan_has_unknown_coverage(tmp_path):
    app = create_app(ServerConfig(db_path=tmp_path / "test.db", dashboard_password=PASSWORD))
    app.state.storage.record_scan(
        ScanReport(hostname="legacy", scan_time_utc="2026-10-18T12:00:00"), []
    )
    with TestClient(app) as client:
        response = client.get("/endpoints", auth=("admin", "synthetic"))
        assert "Unknown (older agent)" in response.text
        assert app.state.storage.list_endpoints()[0]["freshness"] == "unknown"
