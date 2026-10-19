"""Pack parity, platform scope, and canonical Windows admin identities."""

import json
from pathlib import Path

import pytest

from wyndoze_infoscanoverload.agent import collectors
from wyndoze_infoscanoverload.core.models import (
    ListeningConnection,
    PlatformInfo,
    ScanReport,
    ServiceInfo,
    SoftwareInfo,
)
from wyndoze_infoscanoverload.core.rulepacks import default_rule_pack
from wyndoze_infoscanoverload.core.rules import evaluate, load_rule_pack


def test_source_and_installed_rules_match():
    root = Path(__file__).resolve().parents[2]
    assert (root / "rules/windows_default.yaml").read_bytes() == (
        root / "src/wyndoze_infoscanoverload/core/rulepacks/windows_default.yaml"
    ).read_bytes()
    report = ScanReport(
        hostname="H",
        scan_time_utc="2026-10-18T12:00:00Z",
        listening_connections=[ListeningConnection(local_port=445)],
    )
    assert "net-smb-listener" in {f.rule_id for f in evaluate(report, default_rule_pack())}


def test_canonical_admin_policy():
    names = [r"HOST\RenamedAdmin", r"EXAMPLE\Administrateurs", r"EVIL\Administrator"]
    data = {
        "hostname": "H",
        "scan_time_utc": "2026-10-18T12:00:00Z",
        "local_admins": names,
        "local_admin_sids": {
            names[0]: "S-1-5-21-11-22-33-500",
            names[1]: "S-1-5-21-44-55-66-512",
            names[2]: "S-1-5-21-77-88-99-1100",
        },
    }
    report = ScanReport.model_validate(data)
    findings = evaluate(report, default_rule_pack())
    assert next(f for f in findings if f.rule_id == "admin-unexpected-local-admin").evidence == [
        names[2]
    ]
    restored = ScanReport.model_validate_json(report.model_dump_json())
    assert restored.local_admin_sids == data["local_admin_sids"]


def test_unknown_qualified_admin_is_not_trusted():
    report = ScanReport(
        hostname="H", scan_time_utc="2026-10-18T12:00:00Z", local_admins=[r"EVIL\Administrator"]
    )
    assert any(
        f.rule_id == "admin-unexpected-local-admin" for f in evaluate(report, default_rule_pack())
    )


def test_windows_admin_json_collection(monkeypatch):
    monkeypatch.setattr(collectors, "_IS_WINDOWS", True)
    output = json.dumps([{"Name": "HOST\\Administrateur", "Sid": "S-1-5-21-1-2-3-500"}])
    monkeypatch.setattr(collectors, "_run_command", lambda *_args, **_kwargs: output)
    names, sids = collectors._collect_local_admin_identities(5)
    assert names == ["HOST\\Administrateur"]
    assert sids[names[0]] == "S-1-5-21-1-2-3-500"


@pytest.mark.parametrize(
    ("system", "services"), [("Linux", [ServiceInfo(name="sshd")]), ("Windows", [])]
)
def test_missing_windows_services_require_applicable_inventory(system, services):
    report = ScanReport(
        hostname="H",
        scan_time_utc="2026-10-18T12:00:00Z",
        platform=PlatformInfo(system=system),
        services=services,
    )
    ids = {f.rule_id for f in evaluate(report, default_rule_pack())}
    assert "svc-eventlog-missing" not in ids


def test_tunnel_substring_near_miss():
    report = ScanReport(
        hostname="H",
        scan_time_utc="2026-10-18T12:00:00Z",
        installed_software=[SoftwareInfo(name="surfprint")],
    )
    assert "sw-tunnel-software" not in {f.rule_id for f in evaluate(report, default_rule_pack())}


def test_legacy_unscoped_missing_service_keeps_empty_inventory_semantics():
    pack = load_rule_pack("""name: legacy
rules:
  - id: expected
    title: Expected service
    kind: missing_expected_service
    substrings: [custom-service]
""")
    report = ScanReport(hostname="H", scan_time_utc="2026-10-18T12:00:00Z")
    assert [f.rule_id for f in evaluate(report, pack)] == ["expected"]


def test_windows_service_names_are_exact():
    report = ScanReport(
        hostname="H",
        scan_time_utc="2026-10-18T12:00:00Z",
        platform=PlatformInfo(system="Windows"),
        services=[
            ServiceInfo(name="LicenseSenseService", state="stopped"),
            ServiceInfo(name="VendorEventLogHelper", display_name="EventLog"),
        ],
    )
    findings = evaluate(report, default_rule_pack())
    assert "svc-defender-or-mde-stopped" not in {f.rule_id for f in findings}
    assert "svc-eventlog-missing" in {f.rule_id for f in findings}
    report.services = [ServiceInfo(name="EVENTLOG"), ServiceInfo(name="Sense", state="stopped")]
    findings = evaluate(report, default_rule_pack())
    assert "svc-eventlog-missing" not in {f.rule_id for f in findings}
    assert (
        next(f for f in findings if f.rule_id == "svc-defender-or-mde-stopped").severity.value
        == "low"
    )
