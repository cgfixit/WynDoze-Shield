"""Synthetic listener lifecycle regressions using real, disposable SQLite state.

Compatible with pytest and stdlib unittest for restricted/offline environments.
No endpoint collection, subprocesses, network listeners or Windows mutations.
"""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from wyndoze_infoscanoverload.core.listeners import listener_evidence
from wyndoze_infoscanoverload.core.models import (
    CollectionHealth,
    EndpointRole,
    Finding,
    ListeningConnection,
    PlatformInfo,
    ProcessInfo,
    ScanReport,
    dedupe_key,
)
from wyndoze_infoscanoverload.core.rulepacks import default_rule_pack
from wyndoze_infoscanoverload.core.rules import evaluate, load_rule_pack
from wyndoze_infoscanoverload.core.severity import Severity
from wyndoze_infoscanoverload.server.storage import Storage


def report(pid=100, time="2026-10-22T10:00:00Z"):
    return ScanReport(
        hostname="SYNTHETIC-HOST",
        scan_time_utc=time,
        platform=PlatformInfo(system="Windows"),
        processes=[
            ProcessInfo(
                pid=pid,
                name="server.exe",
                exe=r"C:\Program Files\Example\server.exe",
                username=r"NT AUTHORITY\SYSTEM",
                create_time=float(pid),
            )
        ],
        listening_connections=[
            ListeningConnection(
                pid=pid,
                family="2",
                type="1",
                local_ip="127.0.0.1",
                local_port=3389,
                status="LISTEN",
            )
        ],
    )


def finding(scan):
    return next(f for f in evaluate(scan, default_rule_pack()) if f.rule_id == "net-rdp-listener")


def key(scan):
    return dedupe_key(finding(scan), scan.hostname)


class TestListenerIdentity(TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = Storage(Path(directory.name) / "test.sqlite3")
        self.store.init_db()

    def record(self, scan):
        result = finding(scan)
        self.store.record_scan(scan, [result])
        return result

    def review(self, scan, status="flagged"):
        self.record(scan)
        row = self.store.list_findings()[0]
        self.store.set_finding_status(row["id"], status)
        return self.store.get_finding(row["id"])

    def legacy(self, scan, status="flagged"):
        result = finding(scan)
        result.evidence = [
            item[:512] for item in listener_evidence(scan, result.listener_identity.ports)[:100]
        ]
        result.listener_identity = None
        self.store.record_scan(scan, [result])
        row = next(
            r for r in self.store.list_findings()
            if r["dedupe_key"] == dedupe_key(result, scan.hostname)
        )
        self.store.set_finding_status(row["id"], status)
        return self.store.get_finding(row["id"])

    def test_pid_restart_preserves_review_and_refreshes_evidence(self):
        original = self.review(report())
        new_scan = report(200, "2026-10-22T11:00:00Z")
        self.record(new_scan)
        (row,) = self.store.list_findings()
        assert row["id"] == original["id"]
        assert row["first_seen_utc"] == original["first_seen_utc"]
        assert row["status"] == "flagged"
        assert row["seen_count"] == 2
        assert row["scan_id"] != original["scan_id"]
        assert "pid=200" in row["evidence"][0]
        assert "pid=100" not in row["evidence"][0]
        assert len(self.store.list_scans()) == 2

    def test_replay_preserves_every_decision(self):
        for status in ("triage", "flagged", "archived", "suppressed"):
            with self.subTest(status=status):
                scan = report()
                scan.hostname = status
                self.record(scan)
                row = self.store.list_findings(hostname=status)[0]
                self.store.set_finding_status(row["id"], status)
                self.record(scan)
                (replayed,) = self.store.list_findings(hostname=status)
                assert replayed["status"] == status
                assert replayed["seen_count"] == 2

    def test_changed_owner_account_or_behavior_requires_triage(self):
        for field, value in (
            ("exe", r"C:\Other\server.exe"),
            ("name", "other.exe"),
            ("username", r"EXAMPLE\other-user"),
            ("cmdline_flags", ["download-cradle", "invoke-expression"]),
        ):
            with self.subTest(field=field):
                before = report()
                before.hostname = field
                old = self.review(before, "suppressed")
                after = before.model_copy(deep=True)
                setattr(after.processes[0], field, value)
                self.record(after)
                rows = self.store.list_findings(hostname=field)
                assert len(rows) == 2
                assert next(r for r in rows if r["id"] != old["id"])["status"] == "triage"
                assert self.store.get_finding(old["id"])["status"] == "suppressed"
                if field == "exe":
                    assert any(value in evidence for evidence in rows[0]["evidence"])

    def test_material_socket_changes_do_not_inherit_decision(self):
        for field, value in (
            ("local_ip", "0.0.0.0"),  # noqa: S104 - synthetic binding
            ("local_ip", "192.0.2.1"),
            ("local_ip", "::1"),
            ("local_ip", "::"),
            ("family", "23"),
            ("type", "2"),
            ("status", "UNKNOWN"),
        ):
            with self.subTest(field=field, value=value):
                before = report()
                before.hostname = field + value
                old = self.review(before, "archived")
                after = before.model_copy(deep=True)
                setattr(after.listening_connections[0], field, value)
                self.record(after)
                rows = self.store.list_findings(hostname=before.hostname)
                assert len(rows) == 2
                assert next(r for r in rows if r["id"] != old["id"])["status"] == "triage"

    def test_new_mixed_binding_keeps_high_priority(self):
        before = report()
        self.review(before, "suppressed")
        after = before.model_copy(deep=True)
        after.listening_connections.append(
            after.listening_connections[0].model_copy(
                update={"local_ip": "0.0.0.0"}  # noqa: S104 - synthetic binding
            )
        )
        result = self.record(after)
        assert result.severity > Severity.INFO
        rows = self.store.list_findings(status="triage")
        assert len(rows) == 1
        assert rows[0]["severity"] == result.severity.value

    def test_reordering_processes_sockets_and_evidence_is_stable(self):
        before = report()
        before.processes.append(ProcessInfo(pid=999, name="unrelated"))
        before.listening_connections.append(
            before.listening_connections[0].model_copy(update={"local_ip": "::1", "family": "23"})
        )
        self.review(before)
        after = before.model_copy(deep=True)
        after.processes.reverse()
        after.listening_connections.reverse()
        result = finding(after)
        result.evidence.reverse()
        self.store.record_scan(after, [result])
        (row,) = self.store.list_findings()
        assert row["status"] == "flagged"
        assert row["seen_count"] == 2

    def test_ipv6_text_is_normalized_but_family_and_scope_are_distinct(self):
        before = report()
        before.listening_connections[0].local_ip = "0:0:0:0:0:0:0:1"
        before.listening_connections[0].family = "23"
        after = before.model_copy(deep=True)
        after.listening_connections[0].local_ip = "::1"
        assert key(before) == key(after)
        after.listening_connections[0].local_ip = "::ffff:127.0.0.1"
        assert key(before) != key(after)

    def test_port_changes_under_same_rule_are_distinct(self):
        pack = load_rule_pack("""name: test
rules:
  - id: multi-port
    title: Listener
    kind: listening_port
    ports: [3389, 3390]
""")
        before = report()
        after = before.model_copy(deep=True)
        after.listening_connections[0].local_port = 3390
        assert dedupe_key(evaluate(before, pack)[0], before.hostname) != dedupe_key(
            evaluate(after, pack)[0], after.hostname
        )

    def test_second_socket_instance_and_hidden_preview_changes_are_distinct(self):
        before = report()
        first = finding(before)
        before.listening_connections.append(before.listening_connections[0].model_copy())
        assert dedupe_key(first, before.hostname) != key(before)
        before.listening_connections = [
            before.listening_connections[0].model_copy(update={"local_ip": f"192.0.2.{n}"})
            for n in range(1, 102)
        ]
        after = before.model_copy(deep=True)
        after.listening_connections[-1].type = "2"
        assert finding(before).evidence == finding(after).evidence
        assert len(finding(before).evidence) == 100
        assert key(before) != key(after)

    def test_risk_role_and_rule_meaning_changes_require_review(self):
        before = report()
        self.review(before, "suppressed")
        original = finding(before)
        for change in (
            {"severity": Severity.CRITICAL},
            {"category": "changed"},
            {"message": "New risk assessment"},
            {"technique_id": "T1059"},
        ):
            updated = original.model_copy(update=change)
            self.store.record_scan(before, [updated])
            assert dedupe_key(updated, before.hostname) != dedupe_key(original, before.hostname)
        assert len(self.store.list_findings(status="triage")) == 4
        after = before.model_copy(update={"role": EndpointRole.BACKUP_SERVER})
        assert key(before) != key(after)

    def test_incomplete_owner_is_replayable_but_not_reusable_across_scans(self):
        for field, value in (
            ("exe", None),
            ("exe", "server.exe"),
            ("username", None),
            ("name", None),
            ("exe", "C:\\" + "x" * 509),
        ):
            with self.subTest(field=field, value=value):
                before = report()
                before.hostname = field + str(len(value or ""))
                setattr(before.processes[0], field, value)
                first = finding(before)
                assert not first.listener_identity.reusable
                assert dedupe_key(first, before.hostname) == key(before)
                after = before.model_copy(update={"scan_time_utc": "2026-10-22T11:00:00Z"})
                assert dedupe_key(first, before.hostname) != key(after)

    def test_missing_or_ambiguous_pid_never_chooses_arbitrary_owner(self):
        for mode in ("no-process", "no-pid", "duplicate-pid"):
            with self.subTest(mode=mode):
                before = report()
                if mode == "no-process":
                    before.processes = []
                elif mode == "no-pid":
                    before.listening_connections[0].pid = None
                else:
                    before.processes.append(
                        before.processes[0].model_copy(update={"exe": r"C:\Other\server.exe"})
                    )
                first = finding(before)
                assert not first.listener_identity.reusable
                after = before.model_copy(
                    update={"scan_time_utc": "2026-10-22T11:00:00Z"}, deep=True
                )
                assert dedupe_key(first, before.hostname) != key(after)
                before.processes.reverse()
                assert dedupe_key(first, before.hostname) == key(before)

    def test_incomplete_coverage_and_socket_metadata_are_scan_scoped(self):
        before = report()
        for collector in ("processes", "listening_connections"):
            for health in (CollectionHealth(status="partial"), CollectionHealth(truncated=True)):
                before.collection_health = {collector: health}
                assert not finding(before).listener_identity.reusable
        before.collection_health = {}
        for field, value in (("local_ip", "invalid"), ("family", ""), ("type", "")):
            after = before.model_copy(deep=True)
            setattr(after.listening_connections[0], field, value)
            assert not finding(after).listener_identity.reusable

    def test_absent_data_does_not_resolve_existing_finding(self):
        self.review(report())
        empty = report()
        empty.listening_connections = []
        self.store.record_scan(empty, evaluate(empty, default_rule_pack()))
        (row,) = self.store.list_findings()
        assert row["status"] == "flagged"
        assert row["seen_count"] == 1

    def test_legacy_single_occurrence_migrates_each_prior_decision(self):
        for status in ("triage", "flagged", "archived", "suppressed"):
            with self.subTest(status=status):
                before = report()
                before.hostname = status
                old = self.legacy(before, status)
                after = report(200, "2026-10-22T11:00:00Z")
                after.hostname = status
                self.record(after)
                (row,) = self.store.list_findings(hostname=status)
                assert row["id"] == old["id"]
                assert row["first_seen_utc"] == old["first_seen_utc"]
                assert row["status"] == status
                assert row["seen_count"] == 2
                assert row["dedupe_key"].startswith("listener-v1:")
                assert "pid=200" in row["evidence"][0]
                self.store.init_db()
                self.record(after)
                assert self.store.get_finding(row["id"])["seen_count"] == 3

    def test_legacy_changed_path_scope_or_risk_does_not_migrate(self):
        for mode in ("owner", "scope", "risk"):
            before = report()
            before.hostname = mode
            old = self.legacy(before, "suppressed")
            after = before.model_copy(deep=True)
            if mode == "owner":
                after.processes[0].exe = r"C:\Other\server.exe"
            elif mode == "scope":
                after.listening_connections[0].local_ip = "0.0.0.0"  # noqa: S104 - synthetic binding
            result = finding(after)
            if mode == "risk":
                result.severity = Severity.CRITICAL
            self.store.record_scan(after, [result])
            assert self.store.get_finding(old["id"])["dedupe_key"] == old["dedupe_key"]
            assert len(self.store.list_findings(hostname=mode, status="triage")) == 1

    def test_legacy_incomplete_owner_requires_new_review(self):
        before = report()
        before.processes[0].exe = None
        old = self.legacy(before, "suppressed")
        self.record(report(200))
        assert len(self.store.list_findings()) == 2
        assert self.store.get_finding(old["id"])["status"] == "suppressed"

    def test_legacy_multiple_occurrences_have_no_reliable_reviewed_owner(self):
        before = report()
        old = self.legacy(before, "suppressed")
        self.legacy(before, "suppressed")
        self.record(report(200))
        assert len(self.store.list_findings()) == 2
        assert self.store.get_finding(old["id"])["seen_count"] == 2
        assert len(self.store.list_findings(status="triage")) == 1

    def test_legacy_duplicate_decisions_are_not_merged_or_discarded(self):
        one = self.legacy(report(), "suppressed")
        two = self.legacy(report(200), "flagged")
        self.record(report(300))
        assert len(self.store.list_findings()) == 3
        assert self.store.get_finding(one["id"])["status"] == "suppressed"
        assert self.store.get_finding(two["id"])["status"] == "flagged"
        assert len(self.store.list_findings(status="triage")) == 1

    def test_legacy_missing_corrupt_or_mismatched_scan_does_not_abort_ingest(self):
        for value in (None, "broken", '{"hostname":"OTHER"}'):
            before = report()
            before.hostname = str(value)
            old = self.legacy(before)
            with self.store._connect() as conn:
                if value is None:
                    conn.execute("DELETE FROM scans WHERE id = ?", (old["scan_id"],))
                else:
                    conn.execute(
                        "UPDATE scans SET raw_json = ? WHERE id = ?", (value, old["scan_id"])
                    )
            self.record(before)
            assert len(self.store.list_findings(hostname=before.hostname)) == 2

    def test_legacy_truncated_evidence_is_not_auto_migrated(self):
        before = report()
        before.listening_connections = [
            before.listening_connections[0].model_copy(update={"local_ip": f"192.0.2.{n}"})
            for n in range(1, 102)
        ]
        self.legacy(before, "suppressed")
        self.record(before)
        assert len(self.store.list_findings()) == 2
        assert len(self.store.list_findings(status="triage")) == 1

    def test_unrelated_rules_keep_existing_keys(self):
        one = Finding(
            rule_id="process", title="Process", severity=Severity.LOW, evidence=["b", "a"]
        )
        two = one.model_copy(update={"evidence": ["a", "b"]})
        assert dedupe_key(one, "H") == "H::process::a|b"
        assert dedupe_key(one, "H") == dedupe_key(two, "H")

    def test_concurrent_restarts_preserve_one_row_and_count(self):
        self.review(report(), "suppressed")
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(self.record, [report(200), report(300)]))
        (row,) = self.store.list_findings()
        assert row["seen_count"] == 3
        assert row["status"] == "suppressed"

    def test_migration_rolls_back_with_failed_scan(self):
        old = self.legacy(report(), "flagged")
        with self.store._connect() as conn:
            conn.execute("""CREATE TRIGGER fail_insert BEFORE INSERT ON findings
                WHEN NEW.rule_id = 'fail' BEGIN SELECT RAISE(ABORT, 'synthetic'); END""")
        after = report(200)
        failed = Finding(rule_id="fail", title="Synthetic", severity=Severity.INFO)
        try:
            self.store.record_scan(after, [finding(after), failed])
        except sqlite3.IntegrityError:
            pass
        else:
            self.fail("transaction should fail")
        assert len(self.store.list_scans()) == 1
        assert self.store.get_finding(old["id"]) == old

    def test_linux_paths_remain_case_sensitive(self):
        before = report()
        before.platform.system = "Linux"
        before.processes[0].exe = "/opt/Server"
        after = before.model_copy(deep=True)
        after.processes[0].exe = "/opt/server"
        assert key(before) != key(after)
