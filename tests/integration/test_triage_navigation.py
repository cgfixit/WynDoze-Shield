"""Authenticated triage navigation with synthetic evidence and review decisions."""

import re
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from wyndoze_infoscanoverload.core.models import Finding, ScanReport
from wyndoze_infoscanoverload.core.severity import Severity
from wyndoze_infoscanoverload.server.app import create_app
from wyndoze_infoscanoverload.server.config import ServerConfig

PASSWORD = "synthetic"  # noqa: S105 - disposable fixture
AUTH = ("admin", PASSWORD)


@pytest.fixture
def client(tmp_path):
    app = create_app(ServerConfig(db_path=tmp_path / "test.db", dashboard_password=PASSWORD))
    storage = app.state.storage
    for host, amount in (("synthetic-a", 55), ("synthetic-b", 3)):
        report = ScanReport(hostname=host, scan_time_utc="2026-10-18T12:00:00Z")
        storage.record_scan(
            report,
            [
                Finding(
                    rule_id=f"rule-{index}",
                    title=f"Finding {host} {index}",
                    severity=Severity.HIGH,
                    evidence=["X" * 400 + "<script>tail</script>"],
                )
                for index in range(amount)
            ],
        )
    with TestClient(app) as api:
        yield api


def _ids(html):
    return re.findall(r"href='/findings/(\d+)'", html)


def test_pages_are_disjoint_and_keep_filters(client):
    first = client.get(
        "/timeline", params={"hostname": "synthetic-a", "severity": "high"}, auth=AUTH
    )
    assert first.status_code == 200
    assert len(_ids(first.text)) == 50
    href = re.search(r"href='([^']+)'>Next</a>", first.text)[1].replace("&amp;", "&")
    query = parse_qs(urlparse(href).query)
    assert query == {"hostname": ["synthetic-a"], "severity": ["high"], "page": ["2"]}
    second = client.get(href, auth=AUTH)
    assert len(_ids(second.text)) == 5
    assert set(_ids(first.text)).isdisjoint(_ids(second.text))
    assert "Previous" in second.text
    assert ">Next</a>" not in second.text
    assert len(client.get("/export/findings.json", auth=AUTH).json()) == 58


def test_all_form_inputs_accept_empty_values(client):
    response = client.get("/timeline?hostname=&rule_id=&status=&severity=", auth=AUTH)
    assert response.status_code == 200
    assert len(_ids(response.text)) == 50


def test_exact_filters_and_empty_results_remain_usable(client):
    response = client.get(
        "/timeline", params={"hostname": "synthetic-b", "rule_id": "rule-1"}, auth=AUTH
    )
    assert len(_ids(response.text)) == 1
    response = client.get("/timeline", params={"hostname": "' OR 1=1 --"}, auth=AUTH)
    assert response.status_code == 200
    assert "No findings match" in response.text
    assert "Filter</button>" in response.text
    assert len(_ids(response.text)) == 0


@pytest.mark.parametrize(
    "query",
    ["page=0", "page=-1", "page=1.2", "status=unknown", "severity=urgent", "hostname=" + "x" * 256],
)
def test_invalid_parameters_are_rejected(client, query):
    assert client.get("/timeline?" + query, auth=AUTH).status_code == 422


def test_details_show_complete_escaped_evidence_and_scan_times(client):
    finding_id = client.app.state.storage.list_findings()[0]["id"]
    assert client.get(f"/findings/{finding_id}").status_code == 401
    response = client.get(f"/findings/{finding_id}", auth=AUTH)
    assert response.status_code == 200
    assert "X" * 400 + "&lt;script&gt;tail&lt;/script&gt;" in response.text
    assert "<script>tail</script>" not in response.text
    assert "Collected" in response.text
    assert "Received" in response.text
    assert "First seen" in response.text
    assert client.get("/findings/99999", auth=AUTH).status_code == 404


@pytest.mark.parametrize("action", ["flag", "archive", "suppress"])
def test_repeated_evidence_preserves_review_decisions(client, action):
    storage = client.app.state.storage
    original = storage.list_findings()[0]
    assert (
        client.post(
            f"/findings/{original['id']}/{action}", auth=AUTH, follow_redirects=False
        ).status_code
        == 303
    )
    chosen = storage.get_finding(original["id"])["status"]
    report = ScanReport(hostname=original["hostname"], scan_time_utc="2026-10-18T13:00:00Z")
    finding = Finding(
        rule_id=original["rule_id"],
        title=original["title"],
        severity=Severity.HIGH,
        evidence=original["evidence"],
    )
    storage.record_scan(report, [finding])
    updated = storage.get_finding(original["id"])
    assert updated["status"] == chosen
    assert updated["seen_count"] == 2
    finding.evidence = ["changed evidence"]
    storage.record_scan(report, [finding])
    matching = storage.list_findings(hostname=original["hostname"], rule_id=original["rule_id"])
    assert {row["status"] for row in matching} == {chosen, "triage"}
    response = client.get("/timeline", params={"status": chosen}, auth=AUTH)
    assert str(original["id"]) in _ids(response.text)


def test_triage_defaults_to_unreviewed_and_actions_keep_origin_guard(client):
    finding_id = client.app.state.storage.list_findings()[0]["id"]
    assert (
        client.post(
            f"/findings/{finding_id}/flag", auth=AUTH, headers={"Origin": "https://foreign.invalid"}
        ).status_code
        == 403
    )
    assert (
        client.post(f"/findings/{finding_id}/flag", auth=AUTH, follow_redirects=False).status_code
        == 303
    )
    response = client.get("/triage", auth=AUTH)
    assert str(finding_id) not in _ids(response.text)
