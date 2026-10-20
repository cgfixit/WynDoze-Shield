"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from wyndoze_infoscanoverload.core.models import (
    EndpointRole,
    ListeningConnection,
    PlatformInfo,
    ProcessInfo,
    ScanReport,
    ServiceInfo,
    utc_now_iso,
)


@pytest.fixture
def backup_server_report() -> ScanReport:
    """A backup-server report that trips several rules."""
    return ScanReport(
        scan_time_utc=utc_now_iso(),
        hostname="BACKUPSRV01",
        fqdn="backupsrv01.lab.local",
        role=EndpointRole.BACKUP_SERVER,
        platform=PlatformInfo(system="Windows", release="2022"),
        ip_addresses=["192.0.2.10"],
        listening_connections=[
            ListeningConnection(local_port=3389, status="LISTEN"),
        ],
        processes=[ProcessInfo(pid=10, name="mimikatz.exe")],
        services=[ServiceInfo(name="Spooler", display_name="Print Spooler", state="running")],
        local_admins=["Administrator", "eviluser"],
    )


@pytest.fixture
def clean_report() -> ScanReport:
    """A workstation report that should trip no rules."""
    return ScanReport(
        scan_time_utc=utc_now_iso(),
        hostname="WS-001",
        role=EndpointRole.WORKSTATION,
        platform=PlatformInfo(system="Linux", release="6.1"),
        ip_addresses=["10.0.1.5"],
        local_admins=["root"],
    )


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    """Path to a throwaway SQLite database."""
    return tmp_path / "test.sqlite3"
