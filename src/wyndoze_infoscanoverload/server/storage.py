"""SQLite persistence layer.

Three tables:

``endpoints``
    One row per host ever seen. Tracks role, first/last seen, last scan id.
``scans``
    One row per uploaded report, with denormalised severity counts and the
    full raw JSON for drill-down.
``findings``
    One row per authoritative finding produced by the rules engine, carrying
    the triage lifecycle status. Listener identity separates socket/owner posture
    from PID evidence; other rules retain (host, rule, evidence) deduplication.

SQLite stores local inventory and triage state. Capacity depends on inventory
volume, retention, and the host; no endpoint-count guarantee is implied.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from wyndoze_infoscanoverload.core.listeners import listener_evidence, listener_identity
from wyndoze_infoscanoverload.core.models import (
    Finding,
    FindingStatus,
    ScanReport,
    dedupe_key,
    utc_now_iso,
)
from wyndoze_infoscanoverload.core.severity import Severity

_SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoints (
    hostname        TEXT PRIMARY KEY,
    fqdn            TEXT,
    role            TEXT NOT NULL DEFAULT 'unknown',
    first_seen_utc  TEXT NOT NULL,
    last_seen_utc   TEXT NOT NULL,
    last_scan_id    INTEGER
);

CREATE TABLE IF NOT EXISTS scans (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at_utc   TEXT NOT NULL,
    hostname          TEXT NOT NULL,
    fqdn              TEXT,
    role              TEXT NOT NULL DEFAULT 'unknown',
    scan_time_utc     TEXT NOT NULL,
    platform_system   TEXT,
    platform_release  TEXT,
    ip_addresses_json TEXT NOT NULL,
    finding_count     INTEGER NOT NULL DEFAULT 0,
    critical_count    INTEGER NOT NULL DEFAULT 0,
    high_count        INTEGER NOT NULL DEFAULT 0,
    medium_count      INTEGER NOT NULL DEFAULT 0,
    low_count         INTEGER NOT NULL DEFAULT 0,
    raw_json          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    dedupe_key     TEXT NOT NULL UNIQUE,
    hostname       TEXT NOT NULL,
    scan_id        INTEGER NOT NULL,
    rule_id        TEXT NOT NULL,
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL,
    category       TEXT,
    message        TEXT,
    technique_id   TEXT,
    technique_name TEXT,
    tactic         TEXT,
    technique_url  TEXT,
    evidence_json  TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'triage',
    first_seen_utc TEXT NOT NULL,
    last_seen_utc  TEXT NOT NULL,
    seen_count     INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_scans_hostname ON scans(hostname);
CREATE INDEX IF NOT EXISTS idx_scans_received ON scans(received_at_utc);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_hostname ON findings(hostname);
CREATE INDEX IF NOT EXISTS idx_findings_host_rule ON findings(hostname, rule_id);
"""

_VALID_STATUS = {s.value for s in FindingStatus}
_PUBLIC_SCAN_SQL = """
SELECT id, received_at_utc, hostname, fqdn, role, scan_time_utc,
       platform_system, platform_release,
       finding_count, critical_count, high_count, medium_count, low_count
FROM scans
ORDER BY received_at_utc DESC
LIMIT ?
"""

_IS_WINDOWS = os.name == "nt"
# Only the latest scan's collection_health is read for an endpoint row. SQLite's
# JSON functions pull that object out without decoding the whole report in
# Python; a build without them falls back to the full raw_json column.
_ENDPOINT_SQL = """
SELECT e.*, s.scan_time_utc, {health} AS health_json
FROM endpoints e
LEFT JOIN scans s ON s.id = e.last_scan_id
ORDER BY e.last_seen_utc DESC
"""
_HEALTH_EXTRACT = "json_extract(s.raw_json, '$.collection_health')"
_HEALTH_FULL_REPORT = "s.raw_json"


def _prepare_db_parent(path: Path) -> None:
    """Create private state without changing an operator-provisioned directory."""
    parent = path.parent
    try:
        parent.mkdir(parents=True, mode=0o700)
    except FileExistsError:
        return
    if _IS_WINDOWS:
        icacls = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "icacls.exe"
        try:
            subprocess.run(  # noqa: S603 - fixed tool path and SID arguments, no shell
                [
                    os.fspath(icacls),
                    os.fspath(parent),
                    "/inheritance:r",
                    "/grant:r",
                    "*S-1-5-18:(OI)(CI)F",
                    "*S-1-5-32-544:(OI)(CI)F",
                    "*S-1-3-4:(OI)(CI)F",
                ],
                check=True,
                capture_output=True,
                timeout=20,
            )
        except (OSError, subprocess.SubprocessError):
            parent.rmdir()
            raise


class Storage:
    """Thin SQLite wrapper. All methods open a short-lived connection."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._json_functions: bool | None = None

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_db(self) -> None:
        """Create tables and indexes if absent."""
        _prepare_db_parent(self._db_path)
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL").fetchone()
            conn.executescript(_SCHEMA)

    # -- ingest ------------------------------------------------------------
    def record_scan(self, report: ScanReport, findings: list[Finding]) -> int:
        """Persist a scan + its findings; upsert the endpoint. Returns scan id."""
        now = utc_now_iso()
        counts = _severity_counts(findings)
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (
                    received_at_utc, hostname, fqdn, role, scan_time_utc,
                    platform_system, platform_release, ip_addresses_json,
                    finding_count, critical_count, high_count, medium_count,
                    low_count, raw_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    now,
                    report.hostname,
                    report.fqdn,
                    report.role.value,
                    report.scan_time_utc,
                    report.platform.system,
                    report.platform.release,
                    json.dumps(report.ip_addresses),
                    len(findings),
                    counts[Severity.CRITICAL],
                    counts[Severity.HIGH],
                    counts[Severity.MEDIUM],
                    counts[Severity.LOW],
                    report.model_dump_json(),
                ),
            )
            scan_id = int(cursor.lastrowid or 0)

            conn.execute(
                """
                INSERT INTO endpoints (hostname, fqdn, role, first_seen_utc,
                                       last_seen_utc, last_scan_id)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(hostname) DO UPDATE SET
                    fqdn=excluded.fqdn,
                    role=excluded.role,
                    last_seen_utc=excluded.last_seen_utc,
                    last_scan_id=excluded.last_scan_id
                """,
                (report.hostname, report.fqdn, report.role.value, now, now, scan_id),
            )

            for finding in findings:
                self._upsert_finding(conn, report.hostname, scan_id, finding, now)

        return scan_id

    @staticmethod
    def _upsert_finding(
        conn: sqlite3.Connection,
        hostname: str,
        scan_id: int,
        finding: Finding,
        now: str,
    ) -> None:
        key = dedupe_key(finding, hostname)
        if finding.listener_identity is not None:
            Storage._adopt_legacy_listener(conn, hostname, finding, key)
        # Identical posture preserves the decision while refreshing PID evidence.
        conn.execute(
            """
            INSERT INTO findings (
                dedupe_key, hostname, scan_id, rule_id, title, severity,
                category, message, technique_id, technique_name, tactic,
                technique_url, evidence_json, status, first_seen_utc,
                last_seen_utc, seen_count
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
            ON CONFLICT(dedupe_key) DO UPDATE SET
                scan_id=excluded.scan_id,
                last_seen_utc=excluded.last_seen_utc,
                seen_count=findings.seen_count + 1,
                severity=excluded.severity,
                evidence_json=excluded.evidence_json,
                status=findings.status
            """,
            (
                key,
                hostname,
                scan_id,
                finding.rule_id,
                finding.title,
                finding.severity.value,
                finding.category,
                finding.message,
                finding.technique_id,
                finding.technique_name,
                finding.tactic,
                finding.technique_url,
                json.dumps(finding.evidence),
                FindingStatus.TRIAGE.value,
                now,
                now,
            ),
        )

    @staticmethod
    def _adopt_legacy_listener(
        conn: sqlite3.Connection, hostname: str, finding: Finding, key: str
    ) -> None:
        """Lazily rekey only one provably equivalent, unambiguous legacy row.

        No bulk merge or deletion. Older upserts replaced scan_id without tracking
        ownership; after multiple occurrences the reviewed owner is unknowable.
        Such histories, duplicate rows, incomplete/truncated evidence and corrupt
        or missing scans retain their decisions separately and require fresh triage.
        """
        identity = finding.listener_identity
        if identity is None or not identity.reusable:
            return
        if conn.execute("SELECT 1 FROM findings WHERE dedupe_key = ?", (key,)).fetchone():
            return
        # Bound candidate work before loading any potentially large scan JSON.
        candidates = conn.execute(
            """SELECT * FROM findings WHERE hostname = ? AND rule_id = ?
               AND dedupe_key NOT LIKE 'listener-v1:%' ORDER BY id LIMIT 2""",
            (hostname, finding.rule_id),
        ).fetchall()
        if len(candidates) != 1 or candidates[0]["seen_count"] != 1:
            return
        row = candidates[0]
        scan = conn.execute(
            """SELECT raw_json FROM scans WHERE id = ? AND hostname = ?
               AND length(CAST(raw_json AS BLOB)) <= 8388608""",
            (row["scan_id"], hostname),
        ).fetchone()
        if scan is None:
            return
        try:
            report = ScanReport.model_validate_json(scan["raw_json"])
            old = Finding.model_validate(
                {**dict(row), "evidence": json.loads(row["evidence_json"])}
            )
        except (ValueError, TypeError):
            return
        if report.hostname != hostname or dedupe_key(old, hostname) != row["dedupe_key"]:
            return
        # Exact uncapped evidence equality rejects old preview-only decisions.
        if sorted(old.evidence) != listener_evidence(report, identity.ports):
            return
        old.listener_identity = listener_identity(report, identity.ports)
        if not old.listener_identity.reusable or dedupe_key(old, hostname) != key:
            return
        conn.execute("UPDATE findings SET dedupe_key = ? WHERE id = ?", (key, row["id"]))

    # -- reads -------------------------------------------------------------
    def list_scans_public(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent scans without raw JSON or IP address blobs."""
        with self._connect() as conn:
            rows = conn.execute(_PUBLIC_SCAN_SQL, (limit,)).fetchall()
        return [dict(row) for row in rows]

    def list_scans(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent scans, newest first."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY received_at_utc DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [_row_to_scan(dict(r)) for r in rows]

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        """Return a single scan by id, or ``None`` if not found."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return _row_to_scan(dict(row)) if row else None

    def list_endpoint_names(self) -> list[str]:
        """Return hostnames, most recently seen first, without reading any scan."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT hostname FROM endpoints ORDER BY last_seen_utc DESC, hostname"
            )
            return [str(row["hostname"]) for row in rows]

    def _supports_json_functions(self, conn: sqlite3.Connection) -> bool:
        """Probe once for SQLite JSON support (built in since 3.38, optional before)."""
        if self._json_functions is None:
            try:
                conn.execute("SELECT json_extract('{}', '$.probe')")
            except sqlite3.OperationalError:
                self._json_functions = False
            else:
                self._json_functions = True
        return self._json_functions

    def list_endpoints(self, stale_after_hours: int = 36) -> list[dict[str, Any]]:
        """Show collection age separately from upload receipt, including replayed reports.

        Each row carries only its latest scan's ``collection_health``; the rest
        of the stored report is not decoded for this page.
        """
        endpoints = []
        with self._connect() as conn:
            extracted = self._supports_json_functions(conn)
            query = _ENDPOINT_SQL.format(
                health=_HEALTH_EXTRACT if extracted else _HEALTH_FULL_REPORT
            )
            for row in conn.execute(query):
                endpoint = dict(row)
                stored = json.loads(endpoint.pop("health_json") or "{}")
                if not extracted and isinstance(stored, dict):
                    stored = stored.get("collection_health", {})
                endpoint["collection_health"] = stored if isinstance(stored, dict) else {}
                endpoint["freshness"] = "unknown"
                try:
                    collected = datetime.fromisoformat(endpoint["scan_time_utc"])
                    if collected.tzinfo is not None:
                        age = (datetime.now(UTC) - collected).total_seconds()
                        if age >= 0:
                            endpoint["freshness"] = (
                                "overdue" if age > stale_after_hours * 3600 else "current"
                            )
                except (TypeError, ValueError, AttributeError):
                    endpoint["freshness"] = "unknown"
                endpoints.append(endpoint)
        return endpoints

    def open_finding_counts(self) -> dict[str, int]:
        """Count triage and flagged findings for each hostname.

        The predicate matches ``summary``: ``status IN ('triage','flagged')``.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT hostname, COUNT(*) AS c FROM findings
                   WHERE status IN ('triage','flagged')
                   GROUP BY hostname"""
            ).fetchall()
        return {str(row["hostname"]): int(row["c"]) for row in rows}

    def list_findings(
        self,
        status: str | None = None,
        limit: int | None = 500,
        *,
        hostname: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        scan_id: int | None = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return a stable page; None explicitly selects every row for exports."""
        query = "SELECT * FROM findings WHERE 1=1"
        params: list[Any] = []
        if status == "active":
            query += " AND status IN ('triage','flagged')"
            status = None
        for column, value in (
            ("status", status),
            ("hostname", hostname),
            ("severity", severity),
            ("rule_id", rule_id),
            ("scan_id", scan_id),
        ):
            if value is not None:
                query += f" AND {column} = ?"
                params.append(value)
        query += """
            ORDER BY CASE severity
                WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
            last_seen_utc DESC, id DESC
        """
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params.extend((limit, offset))
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [_row_to_finding(dict(r)) for r in rows]

    def get_finding(self, finding_id: int) -> dict[str, Any] | None:
        """Return a single finding by id, or ``None`` if not found."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return _row_to_finding(dict(row)) if row else None

    def set_finding_status(self, finding_id: int, status: str) -> bool:
        """Update a finding's lifecycle status. Returns True if a row changed."""
        if status not in _VALID_STATUS:
            msg = f"invalid status: {status!r}"
            raise ValueError(msg)
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE findings SET status = ? WHERE id = ?",
                (status, finding_id),
            )
        return cursor.rowcount > 0

    def summary(self) -> dict[str, Any]:
        """Aggregate counts for the Summary report."""
        with self._connect() as conn:
            endpoints = conn.execute("SELECT COUNT(*) AS c FROM endpoints").fetchone()["c"]
            scans = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
            by_status = {
                row["status"]: row["c"]
                for row in conn.execute(
                    "SELECT status, COUNT(*) AS c FROM findings GROUP BY status"
                ).fetchall()
            }
            by_severity = {
                row["severity"]: row["c"]
                for row in conn.execute(
                    """SELECT severity, COUNT(*) AS c FROM findings
                       WHERE status IN ('triage','flagged') GROUP BY severity"""
                ).fetchall()
            }
        return {
            "endpoints": endpoints,
            "scans": scans,
            "findings_by_status": by_status,
            "active_findings_by_severity": by_severity,
        }


def _severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    counts = dict.fromkeys(Severity, 0)
    for f in findings:
        counts[f.severity] += 1
    return counts


def _row_to_scan(row: dict[str, Any]) -> dict[str, Any]:
    try:
        row["ip_addresses"] = json.loads(row.get("ip_addresses_json", "[]"))
    except (json.JSONDecodeError, TypeError):
        row["ip_addresses"] = []
    return row


def _row_to_finding(row: dict[str, Any]) -> dict[str, Any]:
    try:
        row["evidence"] = json.loads(row.get("evidence_json", "[]"))
    except (json.JSONDecodeError, TypeError):
        row["evidence"] = []
    return row


__all__ = ["Storage"]
