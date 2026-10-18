"""Collection coverage with synthetic inputs; no endpoint inventory is read."""

import subprocess
from types import SimpleNamespace

import psutil
import pytest
from pydantic import ValidationError

from wyndoze_infoscanoverload.agent import collectors
from wyndoze_infoscanoverload.agent.cache import BundleCache
from wyndoze_infoscanoverload.agent.config import AgentConfig
from wyndoze_infoscanoverload.agent.crypto import generate_key
from wyndoze_infoscanoverload.core.models import CollectionHealth, ScanReport, ServiceInfo
from wyndoze_infoscanoverload.core.rules import evaluate, load_rule_pack


@pytest.mark.parametrize(
    ("failure", "state", "issue"),
    [
        (FileNotFoundError(), "unavailable", "not_supported"),
        (PermissionError(), "failed", "access_denied"),
        (subprocess.TimeoutExpired("synthetic", 1), "failed", "timeout"),
    ],
)
def test_command_failure_categories(monkeypatch, failure, state, issue):
    def fail(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(collectors.subprocess, "run", fail)
    health = CollectionHealth()
    assert collectors._run_command(["synthetic"], 1, health=health) == ""
    assert health.status == state
    assert health.issues == [issue]


def test_command_nonzero_and_output_cap(monkeypatch):
    monkeypatch.setattr(
        collectors.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=5, stdout="x" * 200001),
    )
    health = CollectionHealth()
    rows = collectors._collect_with_health(
        lambda: [collectors._run_command(["synthetic"], 1, health=health)],
        health,
    )
    assert len(rows[0]) == 200000
    assert health.status == "partial"
    assert health.truncated
    assert health.issues == ["command_failed", "output_truncated"]


def test_denied_sockets_and_successful_empty_results(monkeypatch):
    def denied(**_kwargs):
        raise psutil.AccessDenied

    monkeypatch.setattr(collectors.psutil, "net_connections", denied)
    health = CollectionHealth()
    assert (
        collectors._collect_with_health(
            lambda: collectors.collect_listening_connections(2, health=health),
            health,
        )
        == []
    )
    assert health.status == "failed"
    assert health.issues == ["access_denied"]
    empty = CollectionHealth()
    assert collectors._collect_with_health(list, empty) == []
    assert empty.status == "ok"
    assert empty.item_count == 0


def test_item_limit_is_reported_conservatively():
    health = CollectionHealth()
    assert collectors._collect_with_health(lambda: ["one"], health, 1) == ["one"]
    assert health.status == "partial"
    assert health.truncated
    assert health.item_count == 1
    assert health.duration_ms >= 0


def test_inaccessible_process_is_partial(monkeypatch):
    class Denied:
        @property
        def info(self):
            raise psutil.AccessDenied

    monkeypatch.setattr(
        collectors.psutil,
        "process_iter",
        lambda **_kwargs: [Denied(), SimpleNamespace(info={"pid": 1, "name": "synthetic"})],
    )
    health = CollectionHealth()
    rows = collectors._collect_with_health(
        lambda: collectors.collect_processes(5, health=health),
        health,
        5,
    )
    assert len(rows) == 1
    assert health.status == "partial"
    assert health.issues == ["item_skipped"]


def test_unsupported_collectors_and_full_report_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setattr(collectors, "_IS_WINDOWS", False)
    monkeypatch.setattr(collectors, "_IS_LINUX", False)
    monkeypatch.setattr(collectors, "collect_ip_addresses", list)
    monkeypatch.setattr(collectors.psutil, "process_iter", lambda **_kwargs: [])
    monkeypatch.setattr(collectors.psutil, "net_connections", lambda **_kwargs: [])
    monkeypatch.setattr(collectors.socket, "gethostname", lambda: "synthetic")
    monkeypatch.setattr(collectors.socket, "getfqdn", lambda: "synthetic.invalid")
    report = collectors.collect_report(AgentConfig())
    assert len(report.collection_health) == 6
    assert report.collection_health["services"].status == "unavailable"
    assert report.collection_health["local_admins"].issues == ["not_supported"]
    assert report.collection_health["processes"].status == "ok"
    assert not report.processes
    cache = BundleCache(tmp_path, generate_key())
    assert cache.load(cache.save(report)).collection_health == report.collection_health
    assert (
        ScanReport.model_validate_json(report.model_dump_json()).collection_health
        == report.collection_health
    )


@pytest.mark.parametrize("state", ["partial", "failed", "unavailable"])
def test_incomplete_inventory_does_not_prove_service_absence(state):
    pack = load_rule_pack("""name: test
rules:
- id: missing
  kind: missing_expected_service
  title: missing
  substrings: [wanted]
""")
    report = ScanReport(
        hostname="synthetic",
        scan_time_utc="2026-10-18T12:00:00Z",
        services=[ServiceInfo(name="other")],
        collection_health={"services": CollectionHealth(status=state)},
    )
    assert evaluate(report, pack) == []
    report.collection_health = {}
    assert [finding.rule_id for finding in evaluate(report, pack)] == ["missing"]


def test_health_schema_is_optional_and_bounded():
    report = ScanReport(hostname="synthetic", scan_time_utc="2026-10-18T12:00:00Z")
    assert report.collection_health == {}
    with pytest.raises(ValidationError):
        CollectionHealth(issues=["stderr containing secrets"])
    with pytest.raises(ValidationError):
        CollectionHealth(item_count=-1)


def test_windows_service_skip_and_missing_api(monkeypatch):
    class Denied:
        def name(self):
            raise psutil.AccessDenied

    good = SimpleNamespace(
        name=lambda: "synthetic", display_name=lambda: "Synthetic", status=lambda: "running"
    )
    monkeypatch.setattr(
        collectors.psutil, "win_service_iter", lambda: [Denied(), good], raising=False
    )
    health = CollectionHealth()
    assert (
        len(
            collectors._collect_with_health(
                lambda: collectors._collect_windows_services(10, health=health), health
            )
        )
        == 1
    )
    assert health.status == "partial"
    assert health.issues == ["item_skipped"]
    monkeypatch.delattr(collectors.psutil, "win_service_iter")
    unsupported = CollectionHealth()
    assert collectors._collect_windows_services(10, health=unsupported) == []
    assert unsupported.status == "unavailable"


def test_linux_package_fallback_does_not_inherit_first_tool_failure(monkeypatch):
    def command(argv, **_kwargs):
        if argv[0] == "dpkg-query":
            raise FileNotFoundError
        return SimpleNamespace(returncode=0, stdout="synthetic\t1.0\n")

    monkeypatch.setattr(collectors.subprocess, "run", command)
    health = CollectionHealth()
    rows = collectors._collect_with_health(
        lambda: collectors._collect_linux_packages(10, 1, health=health), health
    )
    assert rows[0].name == "synthetic"
    assert health.status == "ok"
    assert health.issues == []


@pytest.mark.parametrize("output", ["not json", "{}", '[{"Name":"invalid"}]'])
def test_windows_admin_output_has_safe_categories(monkeypatch, output):
    monkeypatch.setattr(collectors, "_IS_WINDOWS", True)
    monkeypatch.setattr(
        collectors.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=output),
    )
    health = CollectionHealth()
    assert collectors._collect_local_admin_identities(1, health=health) == ([], {})
    assert health.status in {"failed", "partial"}
    assert health.issues == ["invalid_output"]
    assert output not in health.model_dump_json()
