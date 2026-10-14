"""Command lines are opt-in and are not stored in clear text."""

from __future__ import annotations

from wyndoze_infoscanoverload.agent.cmdline import seal_command_lines
from wyndoze_infoscanoverload.agent.collectors import collect_processes
from wyndoze_infoscanoverload.agent.crypto import generate_key
from wyndoze_infoscanoverload.core.models import ProcessInfo, ScanReport
from wyndoze_infoscanoverload.core.rulepacks import default_rule_pack
from wyndoze_infoscanoverload.core.rules import evaluate


def _report(cmdline: str | None) -> ScanReport:
    return ScanReport(
        scan_time_utc="2026-01-01T00:00:00Z",
        hostname="WS-001",
        processes=[ProcessInfo(name="powershell.exe", cmdline=cmdline)],
    )


def test_default_collection_omits_cmdline() -> None:
    rows = collect_processes(30)
    assert all(row.cmdline is None for row in rows)


def test_seal_drops_plaintext() -> None:
    line = "powershell -enc SECRETTOKEN"
    report = _report(line)
    seal_command_lines(report, generate_key())
    dumped = report.model_dump_json()
    assert "SECRETTOKEN" not in dumped
    assert report.processes[0].cmdline not in {None, line}
    assert report.cmdline_flags == ["encoded-powershell"]


def test_malware_name_and_bypass_flag() -> None:
    report = ScanReport(
        scan_time_utc="2026-01-01T00:00:00Z",
        hostname="WS-001",
        processes=[
            ProcessInfo(name="xmrig.exe", cmdline="powershell -executionpolicy bypass -file a.ps1")
        ],
        installed_software=[],
    )
    seal_command_lines(report, generate_key())
    dumped = report.model_dump_json()
    assert "executionpolicy" not in dumped.lower()
    assert "execution-policy-bypass" in report.cmdline_flags
    findings = evaluate(report, default_rule_pack())
    ids = {item.rule_id for item in findings}
    assert "proc-malware-adware" in ids
    assert "cmd-suspicious-line" in ids


def test_cmdline_flag_rule_uses_label_only() -> None:
    report = _report(None)
    report.cmdline_flags = ["encoded-powershell"]
    findings = evaluate(report, default_rule_pack())
    hit = next(item for item in findings if item.rule_id == "cmd-suspicious-line")
    assert "SECRETTOKEN" not in hit.message
    assert all("SECRETTOKEN" not in piece for piece in hit.evidence)
