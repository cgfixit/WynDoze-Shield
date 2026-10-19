"""Rule kinds and pack validation beyond the bundled pack."""

from __future__ import annotations

import textwrap

import pytest

from wyndoze_infoscanoverload.core.models import (
    EndpointRole,
    ListeningConnection,
    ProcessInfo,
    ScanReport,
    ServiceInfo,
)
from wyndoze_infoscanoverload.core.rulepacks import default_rule_pack
from wyndoze_infoscanoverload.core.rules import (
    RuleError,
    evaluate,
    evaluate_many,
    load_rule_pack,
)


def _pack(body: str) -> str:
    rules = textwrap.indent(textwrap.dedent(body).strip("\n"), "  ")
    return f'name: t\nversion: "1"\nrules:\n{rules}\n'


def test_yaml_string_source_is_accepted() -> None:
    pack = load_rule_pack(
        _pack(
            """
            - id: a
              kind: listening_port
              title: A
              ports: [1]
            """
        )
    )
    assert pack.name == "t"
    assert pack.rules[0].severity.value == "medium"


def test_missing_expected_service_fires_per_absent_name(clean_report: ScanReport) -> None:
    pack = load_rule_pack(
        _pack(
            """
            - id: posture
              kind: missing_expected_service
              title: Posture
              severity: low
              substrings: [defender, backup]
            """
        )
    )
    report = clean_report.model_copy(
        update={"services": [ServiceInfo(name="WinDefend", display_name="Microsoft Defender")]}
    )
    (finding,) = evaluate(report, pack)
    assert finding.evidence == ["expected service matching 'backup' not found"]
    both = report.model_copy(
        update={
            "services": [
                *report.services,
                ServiceInfo(name="BackupSvc", display_name="Backup Service"),
            ]
        }
    )
    assert evaluate(both, pack) == []


def test_service_present_respects_states(clean_report: ScanReport) -> None:
    pack = load_rule_pack(
        _pack(
            """
            - id: spooler
              kind: service_present
              title: Spooler
              substrings: [spooler]
              states: [running]
            """
        )
    )
    stopped = clean_report.model_copy(
        update={"services": [ServiceInfo(name="Spooler", display_name="Print", state="stopped")]}
    )
    running = clean_report.model_copy(
        update={"services": [ServiceInfo(name="Spooler", display_name="Print", state="RUNNING")]}
    )
    assert evaluate(stopped, pack) == []
    assert evaluate(running, pack)[0].evidence == ["Spooler"]


def test_role_scope_skips_other_roles(clean_report: ScanReport) -> None:
    pack = load_rule_pack(
        _pack(
            """
            - id: dc-only
              kind: process_name
              title: DC only
              roles: [domain_controller]
              names: [Explorer.EXE]
            """
        )
    )
    report = clean_report.model_copy(update={"processes": [ProcessInfo(name="explorer.exe")]})
    assert evaluate(report, pack) == []
    as_dc = report.model_copy(update={"role": EndpointRole.DOMAIN_CONTROLLER})
    assert evaluate(as_dc, pack)[0].evidence == ["explorer.exe"]


def test_unknown_technique_keeps_id_without_catalog_fields(clean_report: ScanReport) -> None:
    pack = load_rule_pack(
        _pack(
            """
            - id: p
              kind: listening_port
              title: P
              technique: T9999
              ports: [23]
            """
        )
    )
    report = clean_report.model_copy(
        update={"listening_connections": [ListeningConnection(local_port=23)]}
    )
    (finding,) = evaluate(report, pack)
    assert finding.technique_id == "T9999"
    assert finding.technique_name is None
    assert finding.technique_url is None


def test_evaluate_many_keys_by_hostname(
    clean_report: ScanReport, backup_server_report: ScanReport
) -> None:
    pack = load_rule_pack(
        _pack(
            """
            - id: rdp
              kind: listening_port
              title: RDP
              ports: [3389]
            """
        )
    )
    result = evaluate_many([clean_report, backup_server_report], pack)
    assert set(result) == {clean_report.hostname, backup_server_report.hostname}
    assert result[clean_report.hostname] == []
    assert len(result[backup_server_report.hostname]) == 1


@pytest.mark.parametrize(
    ("body", "match"),
    [
        ("- id: x\n  kind: file_hash\n  title: X", "unknown kind"),
        ("- id: x\n  title: X", "missing required field"),
        ("- id: ''\n  kind: process_name\n  title: X", "non-empty"),
        ("- id: x\n  kind: listening_port\n  title: X\n  ports: [a]", "integers"),
        ("- id: x\n  kind: listening_port\n  title: X\n  ports: 23", "ports must be a list"),
        ("- id: x\n  kind: process_name\n  title: X\n  roles: [mainframe]", "unknown role"),
        ("- id: x\n  kind: process_name\n  title: X\n  roles: workstation", "roles must be a list"),
        ("- id: x\n  kind: process_name\n  title: X\n  names: nope", "list of strings"),
        ("- id: x\n  kind: process_name\n  title: X\n  severity: 3", "severity must be a string"),
        (
            (
                "- id: dup\n  kind: process_name\n  title: X\n"
                "- id: dup\n  kind: process_name\n  title: Y"
            ),
            "duplicate rule id",
        ),
    ],
)
def test_malformed_rules_fail_load(body: str, match: str) -> None:
    with pytest.raises(RuleError, match=match):
        load_rule_pack(_pack(body))


@pytest.mark.parametrize(
    "text",
    ["- just\n- a list", "name: t\nrules: []", "name: t\nrules: nope"],
)
def test_malformed_pack_root_fails_load(text: str) -> None:
    with pytest.raises(RuleError):
        load_rule_pack(text)


@pytest.mark.parametrize("address", ["127.0.0.1", "::1", "::ffff:127.0.0.1"])
def test_listener_context_and_role_severity(clean_report: ScanReport, address: str) -> None:
    clean_report.role = EndpointRole.BACKUP_SERVER
    clean_report.processes = [ProcessInfo(pid=42, name="remote.exe")]
    clean_report.listening_connections = [
        ListeningConnection(local_port=3389, local_ip=address, pid=42)
    ]
    findings = [
        f for f in evaluate(clean_report, default_rule_pack()) if f.rule_id.startswith("net-rdp")
    ]
    assert len(findings) == 1
    assert findings[0].severity.value == "info"
    assert f"on {address} (loopback); pid=42; process=remote.exe" in findings[0].evidence[0]
    clean_report.listening_connections.append(
        ListeningConnection(local_port=3389, local_ip="0.0.0.0")  # noqa: S104 - synthetic inventory
    )
    finding = next(
        f for f in evaluate(clean_report, default_rule_pack()) if f.rule_id == "net-rdp-listener"
    )
    assert finding.severity.value == "high"
    assert any("(wildcard)" in e for e in finding.evidence)


def test_listener_evidence_is_bounded(clean_report: ScanReport) -> None:
    clean_report.processes = [ProcessInfo(pid=42, name="p" * 512)]
    clean_report.listening_connections = [
        ListeningConnection(pid=42, local_port=4444, local_ip="x" * 512)
    ]
    finding = next(
        f
        for f in evaluate(clean_report, default_rule_pack())
        if f.rule_id == "net-unusual-listener"
    )
    assert "(unknown); pid=42; process=" in finding.evidence[0]
    assert len(finding.evidence[0]) == 512


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("loopback_severity", "bad"),
        ("role_severities", "[]"),
        ("role_severities", "{mainframe: high}"),
        ("role_severities", "{workstation: bad}"),
    ],
)
def test_listener_overrides_validate(field: str, value: str) -> None:
    with pytest.raises(RuleError):
        load_rule_pack(_pack(f"- id: x\n  kind: listening_port\n  title: X\n  {field}: {value}"))
