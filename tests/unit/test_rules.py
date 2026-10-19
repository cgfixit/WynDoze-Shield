"""Tests for the YAML rules engine and the bundled pack."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from wyndoze_infoscanoverload.core.models import ProcessInfo, ScanReport, SoftwareInfo
from wyndoze_infoscanoverload.core.rulepacks import default_rule_pack
from wyndoze_infoscanoverload.core.rules import RuleError, evaluate, load_rule_pack


def test_default_pack_loads() -> None:
    pack = default_rule_pack()
    assert pack.rules
    assert pack.name
    # Every rule with a technique should reference a plausible ATT&CK id.
    for rule in pack.rules:
        if rule.technique:
            assert rule.technique.startswith("T")


def test_backup_server_findings(backup_server_report: ScanReport) -> None:
    findings = evaluate(backup_server_report, default_rule_pack())
    rule_ids = {f.rule_id for f in findings}
    # Credential dumping must be flagged critical.
    cred = next(f for f in findings if f.rule_id == "proc-credential-dumping")
    assert cred.severity.value == "critical"
    assert cred.technique_id == "T1003"
    # RDP and an unexpected admin should both appear.
    assert "admin-unexpected-local-admin" in rule_ids
    assert any(r.startswith("net-rdp") for r in rule_ids)


@pytest.mark.parametrize(
    "software_name",
    ["qBittorrent", "PuTTY", "FileZilla", "WinSCP", "KiTTY", "KiTTY 0.76.1.1"],
)
def test_admin_tools_are_low(clean_report: ScanReport, software_name: str) -> None:
    report = clean_report.model_copy(
        update={"installed_software": [SoftwareInfo(name=software_name)]}
    )
    findings = evaluate(report, default_rule_pack())
    hit = next(item for item in findings if item.rule_id == "sw-potentially-suspicious")
    assert hit.severity.value == "low"
    assert hit.title == "Administration or dual-use software is installed"
    assert hit.category == "administration"
    assert "sw-pup-adware" not in {item.rule_id for item in findings}


def test_hello_kitty_is_not_the_ssh_client(clean_report: ScanReport) -> None:
    report = clean_report.model_copy(
        update={"installed_software": [SoftwareInfo(name="Hello Kitty Wallpaper")]}
    )
    findings = evaluate(report, default_rule_pack())
    assert "sw-potentially-suspicious" not in {item.rule_id for item in findings}


def test_clean_report_has_no_findings(clean_report: ScanReport) -> None:
    findings = evaluate(clean_report, default_rule_pack())
    # A plain workstation with root as the only admin trips nothing critical/high.
    assert all(f.severity.value not in {"critical", "high"} for f in findings)


def test_findings_sorted_desc(backup_server_report: ScanReport) -> None:
    findings = evaluate(backup_server_report, default_rule_pack())
    ranks = [f.severity.rank for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_load_rule_pack_rejects_bad_yaml(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("this: [unclosed", encoding="utf-8")
    with pytest.raises(RuleError):
        load_rule_pack(bad)


def test_load_rule_pack_minimal(tmp_path: Path) -> None:
    pack_file = tmp_path / "p.yaml"
    pack_file.write_text(
        textwrap.dedent(
            """
            name: test-pack
            version: "0.1"
            rules:
              - id: telnet-listener
                kind: listening_port
                title: Telnet is listening
                severity: high
                ports: [23]
            """
        ).strip(),
        encoding="utf-8",
    )
    pack = load_rule_pack(pack_file)
    assert pack.name == "test-pack"
    assert len(pack.rules) == 1
    assert pack.rules[0].kind == "listening_port"


def test_unknown_severity_is_rejected(tmp_path: Path) -> None:
    pack_file = tmp_path / "bad-severity.yaml"
    pack_file.write_text(
        textwrap.dedent(
            """
            name: bad
            version: "0.1"
            rules:
              - id: banana-rule
                kind: listening_port
                title: Banana
                severity: banana
                ports: [1]
            """
        ).strip(),
        encoding="utf-8",
    )
    with pytest.raises(RuleError):
        load_rule_pack(pack_file)


@pytest.mark.parametrize(
    "name", ["procdump.exe", "procdump64.exe", "procdump64a.exe", "ntdsutil.exe"]
)
def test_diagnostic_process_presence_is_advisory(clean_report: ScanReport, name: str) -> None:
    clean_report.processes = [ProcessInfo(name=name)]
    findings = evaluate(clean_report, default_rule_pack())
    assert [(f.rule_id, f.severity.value) for f in findings] == [("proc-diagnostic-admin", "low")]
