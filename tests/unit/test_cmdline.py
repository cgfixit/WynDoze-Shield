"""Command lines are opt-in and are not stored in clear text."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from wyndoze_infoscanoverload.agent.cache import BundleCache
from wyndoze_infoscanoverload.agent.cmdline import seal_command_lines
from wyndoze_infoscanoverload.agent.collectors import collect_processes
from wyndoze_infoscanoverload.agent.crypto import decrypt_bytes, generate_key
from wyndoze_infoscanoverload.core.models import ProcessInfo, ScanReport
from wyndoze_infoscanoverload.core.rulepacks import default_rule_pack
from wyndoze_infoscanoverload.core.rules import evaluate


def _report(cmdline: str | None) -> ScanReport:
    return ScanReport(
        scan_time_utc="2026-01-01T00:00:00Z",
        hostname="WS-001",
        processes=[ProcessInfo(name="powershell.exe", cmdline=cmdline)],
    )


def test_default_collection_omits_cmdline(monkeypatch) -> None:
    def processes(attrs):
        assert "cmdline" not in attrs
        return [SimpleNamespace(info={"pid": 1, "name": "synthetic.exe", "cmdline": ["private"]})]

    monkeypatch.setattr("wyndoze_infoscanoverload.agent.collectors.psutil.process_iter", processes)
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
            ProcessInfo(name="xmrig.exe"),
            ProcessInfo(
                name="powershell.exe", cmdline="powershell -executionpolicy bypass -file a.ps1"
            ),
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


@pytest.mark.parametrize(
    "line",
    ["🙂" * 800, "é" * 800, "🙂" * 770 + " powershell -enc x"],
    ids=["four-byte", "two-byte", "late-pattern"],
)
def test_unicode_command_line_wire_and_cache_roundtrip(tmp_path, line):
    key = generate_key()
    report = _report(line)
    seal_command_lines(report, key)
    token = report.processes[0].cmdline
    assert token is not None
    assert len(token) <= 4096
    plain = decrypt_bytes(token.encode("ascii"), key).decode("utf-8")
    assert line.startswith(plain)
    assert plain
    if "-enc" in line:
        assert "encoded-powershell" in report.cmdline_flags
    ScanReport.model_validate_json(report.model_dump_json())
    cache = BundleCache(tmp_path, key)
    assert cache.load(cache.save(report)).processes[0].cmdline == token
