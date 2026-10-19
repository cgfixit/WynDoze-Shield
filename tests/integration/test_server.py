"""Integration tests for the FastAPI server via TestClient."""

from __future__ import annotations

import csv
import logging
import re
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, parse_qsl, urlsplit

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPBasicCredentials
from fastapi.testclient import TestClient

from wyndoze_infoscanoverload.core.models import EndpointRole, ProcessInfo, SoftwareInfo
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


def test_html_shell_headers(client: TestClient) -> None:
    pages = ("/", "/triage", "/timeline", "/endpoints", "/reports/summary")
    for path in pages:
        page = client.get(path, auth=DASH_AUTH)
        assert page.status_code == 200
        assert "script-src 'none'" in page.headers["content-security-policy"]
        assert page.headers["referrer-policy"] == "same-origin"
        assert page.headers["x-content-type-options"] == "nosniff"
        assert "Skip to content" in page.text
        assert "Local triage" in page.text
        assert "aria-current='page'" in page.text
        assert "<script" not in page.text
    home = client.get("/", auth=DASH_AUTH)
    assert "href='/' aria-current='page'" in home.text
    reports = client.get("/reports/summary", auth=DASH_AUTH)
    assert "href='/reports/summary' aria-current='page'" in reports.text
    health = client.get("/api/health")
    assert "content-security-policy" not in health.headers
    export = client.get("/export/findings.csv", auth=DASH_AUTH)
    assert export.status_code == 200
    assert "content-security-policy" not in export.headers


def test_endpoints_open_count_links_active(
    client: TestClient, backup_server_report: ScanReport
) -> None:
    result = _ingest(client, backup_server_report)
    page = client.get("/endpoints", auth=DASH_AUTH).text
    match = re.search(
        r'<tr><td><a href="(?P<href>[^"]+)">VBRSRV01</a></td>'
        r"<td>[^<]*</td><td><code>backup_server</code></td>"
        r"<td>[^<]*</td><td>[^<]*</td><td>[^<]*</td>"
        r"<td>[^<]*</td><td>Unknown \(older agent\)</td><td>(?P<open>\d+)</td></tr>",
        page,
    )
    assert match is not None
    href = match.group("href").replace("&amp;", "&")
    query = parse_qs(urlsplit(href).query)
    assert query["status"] == ["active"]
    assert query["host"] == ["VBRSRV01"]
    assert int(match.group("open")) == result["findings"]
    assert "<table>" in page


def test_endpoint_host_ampersand_stays_active(
    client: TestClient, backup_server_report: ScanReport
) -> None:
    report = backup_server_report.model_copy(update={"hostname": "a&status=archived"})
    _ingest(client, report)
    page = client.get("/endpoints", auth=DASH_AUTH).text
    links = [href for href in _hrefs(page) if "host=" in href]
    assert links
    for href in links:
        pairs = parse_qsl(urlsplit(href).query, keep_blank_values=True)
        statuses = [value for key, value in pairs if key == "status"]
        hosts = [value for key, value in pairs if key == "host"]
        assert statuses == ["active"]
        assert hosts == ["a&status=archived"]


def test_endpoint_control_host_has_no_href(
    client: TestClient, backup_server_report: ScanReport
) -> None:
    report = backup_server_report.model_copy(update={"hostname": "bad\r\nhost"})
    _ingest(client, report)
    page = client.get("/endpoints", auth=DASH_AUTH).text
    assert "bad\r\nhost" in page
    assert ">bad\r\nhost</a>" not in page
    assert all("\r" not in href and "\n" not in href for href in _hrefs(page))


def test_ingest_and_findings(client: TestClient, backup_server_report: ScanReport) -> None:
    result = _ingest(client, backup_server_report)
    assert result["findings"] >= 3
    assert result["hostname"] == "VBRSRV01"

    for path in ("/", "/triage", "/timeline", "/endpoints", "/reports/summary"):
        assert client.get(path, auth=DASH_AUTH).status_code == 200

    assert "VBRSRV01" in client.get("/endpoints", auth=DASH_AUTH).text


def test_hostile_title_is_escaped(client: TestClient, backup_server_report: ScanReport) -> None:
    _ingest(client, backup_server_report)
    db_path = client.app.state.storage._db_path
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE findings SET title = ? WHERE id = 1",
            ("<script>alert(1)</script>",),
        )
    page = client.get("/triage", auth=DASH_AUTH)
    assert page.status_code == 200
    assert "<script" not in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
    assert 'rel="noopener noreferrer"' in page.text


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
    first = client.get("/triage", auth=DASH_AUTH).text
    _ingest(client, backup_server_report)
    second = client.get("/triage", auth=DASH_AUTH).text
    assert second.count('class="finding"') == first.count('class="finding"')
    assert second.count('class="finding"') > 0
    assert "Seen 2" in second


def _hrefs(page: str) -> list[str]:
    raw = re.findall(r"""href=["']([^"']*)["']""", page)
    return [href.replace("&amp;", "&") for href in raw]


def test_host_ampersand_is_one_parameter(
    client: TestClient, backup_server_report: ScanReport
) -> None:
    report = backup_server_report.model_copy(update={"hostname": "a&status=archived"})
    _ingest(client, report)
    page = client.get("/triage", auth=DASH_AUTH).text
    host_links = [href for href in _hrefs(page) if "host=" in href]
    assert host_links
    for href in host_links:
        query = parse_qs(urlsplit(href).query)
        assert query["host"] == ["a&status=archived"]
        assert query["status"] == ["triage"]
    response = client.post(
        "/findings/1/archive",
        data={"next": host_links[0]},
        follow_redirects=False,
        auth=DASH_AUTH,
    )
    assert response.status_code == 303
    location = response.headers["location"]
    query = parse_qs(urlsplit(location).query)
    assert query["host"] == ["a&status=archived"]
    assert query["status"] == ["triage"]


def test_control_host_is_absent_from_location(
    client: TestClient, backup_server_report: ScanReport
) -> None:
    report = backup_server_report.model_copy(update={"hostname": "bad\r\nhost"})
    _ingest(client, report)
    page = client.get("/triage", auth=DASH_AUTH).text
    assert all("\r" not in href and "\n" not in href for href in _hrefs(page))
    response = client.post(
        "/findings/1/flag",
        data={"next": "/triage?host=bad%0d%0aX-Injected"},
        follow_redirects=False,
        auth=DASH_AUTH,
    )
    location = response.headers["location"]
    assert response.status_code == 303
    assert location == "/triage"
    assert "\r" not in location
    assert "\n" not in location
    assert "X-Injected" not in location


@pytest.mark.parametrize(
    ("nxt", "location"),
    [
        ("/triage/../scans/4", "/triage"),
        ("/scans/%34", "/triage"),
        ("https://evil.example", "/triage"),
        ("/triage?severity=high", "/triage?severity=high"),
    ],
)
def test_next_allowlist(
    client: TestClient, backup_server_report: ScanReport, nxt: str, location: str
) -> None:
    _ingest(client, backup_server_report)
    response = client.post(
        "/findings/1/flag",
        data={"next": nxt},
        follow_redirects=False,
        auth=DASH_AUTH,
    )
    assert response.status_code == 303
    assert response.headers["location"] == location


def test_triage_card_actions(client: TestClient, backup_server_report: ScanReport) -> None:
    _ingest(client, backup_server_report)
    page = client.get("/triage", auth=DASH_AUTH).text
    assert "VBRSRV01" in page
    assert 'class="finding"' in page
    assert 'class="actions-main"' in page
    assert 'class="actions-sticky"' in page
    assert ">Flag</button>" in page
    assert ">Archive</button>" in page
    assert ">Suppress</a>" in page
    assert ">Suppress</button>" not in page
    assert "Re-triage" not in page
    assert 'href="/triage?status=triage&amp;severity=critical"' in page


def test_low_findings_stay_in_details(client: TestClient, backup_server_report: ScanReport) -> None:
    report = backup_server_report.model_copy(
        update={"installed_software": [SoftwareInfo(name="PuTTY")]}
    )
    _ingest(client, report)
    page = client.get("/triage", auth=DASH_AUTH).text
    assert "<details>" in page
    assert "Low and info (" in page
    assert page.index('data-severity="critical"') < page.index("<details>")
    details = page.split("<details>", 1)[1]
    assert "Administration or dual-use software is installed" in details
    filtered = client.get("/triage?severity=low", auth=DASH_AUTH).text
    assert "<details>" not in filtered
    assert 'data-severity="low"' in filtered


def test_empty_filter_copy(client: TestClient) -> None:
    page = client.get("/triage?host=missing-host", auth=DASH_AUTH)
    assert page.status_code == 200
    assert "No findings for this filter." in page.text


def test_missing_finding_is_404(client: TestClient, backup_server_report: ScanReport) -> None:
    _ingest(client, backup_server_report)
    response = client.post("/findings/99999/flag", follow_redirects=False, auth=DASH_AUTH)
    assert response.status_code == 404


def test_action_body_over_2048_does_not_write(
    client: TestClient, backup_server_report: ScanReport
) -> None:
    _ingest(client, backup_server_report)
    response = client.post(
        "/findings/1/archive",
        content=b"next=" + (b"a" * 2048),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
        auth=DASH_AUTH,
    )
    assert response.status_code == 400
    assert client.app.state.storage.get_finding(1)["status"] == "triage"


def test_active_includes_flagged(client: TestClient, backup_server_report: ScanReport) -> None:
    _ingest(client, backup_server_report)
    flagged = client.post("/findings/1/flag", follow_redirects=False, auth=DASH_AUTH)
    assert flagged.status_code == 303
    inbox = client.get("/triage", auth=DASH_AUTH).text
    active = client.get("/triage?status=active", auth=DASH_AUTH).text
    assert active.count('class="finding"') == inbox.count('class="finding"') + 1


def _cancel_href(page: str) -> str:
    match = re.search(r'href="([^"]*)">Cancel</a>', page)
    assert match is not None
    return match.group(1).replace("&amp;", "&")


def test_suppress_confirm_cancel_does_not_write(
    client: TestClient, backup_server_report: ScanReport
) -> None:
    _ingest(client, backup_server_report)
    assert client.get("/findings/1/suppress/confirm").status_code == 401
    with sqlite3.connect(client.app.state.storage._db_path) as conn:
        conn.execute("UPDATE findings SET title = ? WHERE id = 1", ("<b>Secret</b>",))
    page = client.get(
        "/findings/1/suppress/confirm",
        params={"next": "/triage?severity=high"},
        auth=DASH_AUTH,
    )
    assert page.status_code == 200
    assert "script-src 'none'" in page.headers["content-security-policy"]
    assert "<script" not in page.text
    assert "&lt;b&gt;Secret&lt;/b&gt;" in page.text
    severity = client.app.state.storage.get_finding(1)["severity"]
    assert severity.upper() in page.text
    stick = (
        "Suppress sticks across later scans. The rule still runs. "
        "The same evidence stays suppressed instead of returning to triage."
    )
    assert stick in page.text
    assert client.app.state.storage.get_finding(1)["status"] == "triage"
    followed = client.get(_cancel_href(page.text), auth=DASH_AUTH)
    assert followed.status_code == 200
    assert client.app.state.storage.get_finding(1)["status"] == "triage"
    rejected = client.get(
        "/findings/1/suppress/confirm",
        params={"next": "https://evil.example"},
        auth=DASH_AUTH,
    )
    assert _cancel_href(rejected.text) == "/triage"
    assert "evil.example" not in rejected.text
    assert client.app.state.storage.get_finding(1)["status"] == "triage"
    missing = client.get("/findings/99999/suppress/confirm", auth=DASH_AUTH)
    assert missing.status_code == 404
    assert client.app.state.storage.get_finding(1)["status"] == "triage"


def test_suppress_confirm_post_writes(client: TestClient, backup_server_report: ScanReport) -> None:
    report = backup_server_report.model_copy(update={"hostname": "a&b"})
    _ingest(client, report)
    desk = client.get(
        "/triage",
        params={"severity": "high", "host": "a&b"},
        auth=DASH_AUTH,
    ).text
    assert "a%2526b" in desk
    assert ">Flag</button>" in desk
    assert ">Archive</button>" in desk
    assert not re.search(r'action="/findings/\d+/suppress"', desk)
    response = client.post(
        "/findings/1/suppress",
        data={"next": "/triage?severity=high"},
        follow_redirects=False,
        auth=DASH_AUTH,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/triage?severity=high"
    assert client.app.state.storage.get_finding(1)["status"] == "suppressed"
    title = client.app.state.storage.get_finding(1)["title"]
    _ingest(client, report)
    inbox = client.get("/triage", auth=DASH_AUTH).text
    assert title not in inbox
    assert client.app.state.storage.get_finding(1)["status"] == "suppressed"
    blocked = client.post(
        "/findings/2/suppress",
        data={"next": "/triage"},
        headers={"Origin": "https://evil.example"},
        follow_redirects=False,
        auth=DASH_AUTH,
    )
    assert blocked.status_code == 403
    assert client.app.state.storage.get_finding(2)["status"] == "triage"


def _critical_only(report: ScanReport, hostname: str) -> ScanReport:
    return report.model_copy(
        update={
            "hostname": hostname,
            "role": EndpointRole.WORKSTATION,
            "listening_connections": [],
            "services": [],
            "installed_software": [],
            "local_admins": ["Administrator"],
            "processes": [ProcessInfo(pid=1, name="mimikatz.exe")],
        }
    )


def test_timeline_lists_scans_not_raw_json(
    client: TestClient, backup_server_report: ScanReport
) -> None:
    token = "gAAAAA" + ("T" * 40)
    report = backup_server_report.model_copy(
        update={
            "processes": [ProcessInfo(pid=10, name="mimikatz.exe", cmdline=token)],
            "installed_software": [SoftwareInfo(name="ONLYINRAW-WIDGET")],
        }
    )
    _ingest(client, report)
    _ingest(client, report)
    page = client.get("/timeline", auth=DASH_AUTH).text
    assert page.count('class="scan"') == 2
    assert 'href="/scans/1"' in page
    assert 'href="/scans/2"' in page
    assert token not in page
    assert "ONLYINRAW-WIDGET" not in page
    assert "raw_json" not in page
    assert "ip_addresses_json" not in page
    assert "listening_connections" not in page
    assert "VBRSRV01" in page


def _article(page: str, title: str) -> str:
    for part in page.split('<article class="finding"'):
        if title in part:
            return part
    msg = f"missing card {title}"
    raise AssertionError(msg)


def test_scan_page_hides_command_lines(
    client: TestClient, backup_server_report: ScanReport, caplog: pytest.LogCaptureFixture
) -> None:
    token = "gAAAAA" + ("Z" * 40)
    report = backup_server_report.model_copy(
        update={
            "role": EndpointRole.WORKSTATION,
            "listening_connections": [],
            "services": [],
            "installed_software": [],
            "local_admins": ["Administrator"],
            "processes": [ProcessInfo(pid=10, name="mimikatz.exe", cmdline=token)],
            "cmdline_flags": ["encoded-powershell", "not-in-the-pack-zz"],
        }
    )
    _ingest(client, report)
    with sqlite3.connect(client.app.state.storage._db_path) as conn:
        conn.execute(
            """
            INSERT INTO findings (
                dedupe_key, hostname, scan_id, rule_id, title, severity,
                category, message, evidence_json, status, first_seen_utc,
                last_seen_utc, seen_count
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)
            """,
            (
                "collision",
                report.hostname,
                1,
                "proc-credential-dumping",
                "Colliding process name",
                "medium",
                "dual_use_tool",
                "A process name collided with a pattern.",
                '["encoded-powershell"]',
                "triage",
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00",
            ),
        )
    assert client.get("/scans/99999", auth=DASH_AUTH).status_code == 404
    with caplog.at_level(logging.INFO, logger="wyndoze_infoscanoverload.server"):
        page = client.get("/scans/1", auth=DASH_AUTH)
    assert page.status_code == 200
    assert "script-src 'none'" in page.headers["content-security-policy"]
    assert token not in page.text
    assert token not in caplog.text
    assert "1 command lines are stored as sealed tokens." in page.text
    assert "This page does not show them and cannot decrypt them." in page.text
    assert "encoded-powershell" in page.text
    assert "not-in-the-pack-zz" not in page.text
    assert "Findings were last updated by this scan." in page.text
    collision = _article(page.text, "Colliding process name")
    assert "<h4>Evidence</h4>" in collision
    assert "Matched pattern" not in collision
    matched = _article(page.text, "Command-line supporting signal observed")
    assert "<h4>Matched pattern</h4>" in matched
    assert 'value="/scans/1"' in page.text
    moved = client.post(
        "/findings/1/archive",
        data={"next": "/scans/1"},
        follow_redirects=False,
        auth=DASH_AUTH,
    )
    assert moved.status_code == 303
    assert moved.headers["location"] == "/scans/1"


def test_unreadable_scan_is_404_without_the_token(
    client: TestClient, backup_server_report: ScanReport, caplog: pytest.LogCaptureFixture
) -> None:
    token = "gAAAAA" + ("Q" * 40)
    report = backup_server_report.model_copy(
        update={"processes": [ProcessInfo(pid=1, name="mimikatz.exe", cmdline=token)]}
    )
    _ingest(client, report)
    with sqlite3.connect(client.app.state.storage._db_path) as conn:
        conn.execute("UPDATE scans SET raw_json = ? WHERE id = 1", ("{not-json " + token,))
    with caplog.at_level(logging.INFO, logger="wyndoze_infoscanoverload.server"):
        response = client.get("/scans/1", auth=DASH_AUTH)
    assert response.status_code == 404
    assert response.json()["detail"] == "not found"
    assert "scan id=1 unreadable" in caplog.text
    assert token not in caplog.text
    assert token not in response.text


def test_reports_page_describes_exports(client: TestClient) -> None:
    reports = client.get("/reports/summary", auth=DASH_AUTH)
    home = client.get("/", auth=DASH_AUTH)
    assert reports.status_code == 200
    assert home.status_code == 200
    text = reports.text
    assert text != home.text
    for href in (
        "/export/findings.csv",
        "/export/findings.md",
        "/export/findings.json",
        "/export/findings.sentinel",
    ):
        assert f'href="{href}"' in text
        assert href not in home.text
    assert (
        "Columns are id, hostname, severity, rule_id, title, technique_id, "
        "technique_name, tactic, status, seen_count, first_seen_utc, and last_seen_utc. "
        "Formula-looking cells are prefixed."
    ) in text
    assert "Evidence is clipped at 160 characters." in text
    assert "Finding objects without *_json columns." in text
    assert "NDJSON, one object per finding." in text
    assert "Exports include every status" in text
    assert "Active means triage or flagged." in text


def test_summary_zero_is_not_colored(client: TestClient) -> None:
    home = client.get("/", auth=DASH_AUTH).text
    match = re.search(
        r'<a class="([^"]*)" href="/triage\?status=active&amp;severity=critical">',
        home,
    )
    assert match is not None
    assert "critical" not in match.group(1).split()
    assert "severity=info" not in home
    assert "Review decisions persist across later scans." in home
    assert 'href="/triage?status=flagged"' in home


def test_summary_critical_counts_triage_and_flagged(
    client: TestClient, backup_server_report: ScanReport
) -> None:
    _ingest(client, _critical_only(backup_server_report, "crit-a"))
    _ingest(client, _critical_only(backup_server_report, "crit-b"))
    flagged = client.post("/findings/1/flag", follow_redirects=False, auth=DASH_AUTH)
    assert flagged.status_code == 303
    home = client.get("/", auth=DASH_AUTH).text
    block = re.search(
        r'<a class="([^"]*)" href="/triage\?status=active&amp;severity=critical">(.*?)</a>',
        home,
        re.DOTALL,
    )
    assert block is not None
    assert "critical" in block.group(1).split()
    assert ">2<" in block.group(2)
    desk = client.get("/triage?status=active&severity=critical", auth=DASH_AUTH).text
    assert desk.count('class="finding"') == 2


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
