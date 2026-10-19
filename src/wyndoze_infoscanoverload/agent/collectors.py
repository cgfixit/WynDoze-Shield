"""Cross-platform, read-only telemetry collectors.

Every collector is defensive: it swallows per-item permission errors and never
raises out of the collection loop, so one inaccessible process cannot abort a
scan. Windows-specific collectors short-circuit to an empty list off-Windows.

Security invariants (do not weaken without review):
- No file *content* is ever read.
- Command lines are off unless ``collect_cmdline`` is set, and then they are
  sealed before this function returns.
- ``subprocess`` is invoked with list args only, never ``shell=True``.
"""

from __future__ import annotations

import json
import logging
import platform
import socket
import subprocess
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

import psutil

from wyndoze_infoscanoverload.agent.cmdline import seal_command_lines
from wyndoze_infoscanoverload.core.models import (
    CollectionHealth,
    CollectionIssue,
    CollectionState,
    EndpointRole,
    ListeningConnection,
    Observation,
    PlatformInfo,
    ProcessInfo,
    ScanReport,
    ServiceInfo,
    SoftwareInfo,
    utc_now_iso,
)
from wyndoze_infoscanoverload.core.severity import Severity

if TYPE_CHECKING:
    from wyndoze_infoscanoverload.agent.config import AgentConfig

logger = logging.getLogger("wyndoze_infoscanoverload.agent.collectors")

_IS_WINDOWS = platform.system().lower() == "windows"
_IS_LINUX = platform.system().lower() == "linux"
_SYSTEMCTL_MIN_FIELDS = 4
_SHORT_LEN = 512
_MAX_COMMAND_CHARS = 200_000
_ADMIN_LIMIT = 1000
_ADMIN_SID = "S-1-5-32-544"
# Native uninstall view, then the 32-bit view. Stop once software_limit is full.
_SOFTWARE_HIVES = (
    (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall", "/reg:64"),
    (r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "/reg:32"),
)


def _clip(value: object, limit: int = _SHORT_LEN) -> str | None:
    """Fit a collector string to the model cap. None stays None."""
    if value is None:
        return None
    return str(value)[:limit]


def local_admin_argv() -> list[str]:
    """Argv for local Administrators. The SID is stable. The group name is not."""
    script = (
        "$ErrorActionPreference = 'Stop'; "
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
        "ConvertTo-Json -Compress -InputObject @("
        f"Get-LocalGroupMember -SID '{_ADMIN_SID}' | "
        "Select-Object Name,@{Name='Sid';Expression={$_.SID.Value}})"
    )
    return [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        script,
    ]


def _note(
    health: CollectionHealth | None,
    issue: CollectionIssue,
    status: CollectionState = "partial",
) -> None:
    if health is not None:
        health.status = status
        if issue not in health.issues:
            health.issues.append(issue)
        if issue in {"limit_reached", "output_truncated"}:
            health.truncated = True


def _collect_with_health[T](
    collect: Callable[[], list[T]],
    health: CollectionHealth,
    limit: int | None = None,
) -> list[T]:
    start = time.monotonic()
    try:
        rows = collect()
    except (PermissionError, psutil.AccessDenied):
        _note(health, "access_denied", "failed")
        rows = []
    except (OSError, psutil.Error, subprocess.SubprocessError):
        _note(health, "command_failed", "failed")
        rows = []
    except NotImplementedError:
        _note(health, "not_supported", "unavailable")
        rows = []
    health.duration_ms = max(0, int((time.monotonic() - start) * 1000))
    health.item_count = len(rows)
    if rows and health.status in {"failed", "unavailable"}:
        health.status = "partial"
    if limit is not None and len(rows) >= limit:
        _note(health, "limit_reached")
    return rows


def _run_command(
    command: list[str],
    timeout: int,
    *,
    encoding: str = "utf-8",
    health: CollectionHealth | None = None,
) -> str:
    """Run a read-only command safely and return stdout (bounded).

    Uses list arguments and a hard timeout. Reports fixed issue categories
    when coverage is incomplete. Callers must tolerate missing data.
    Windows console tools speak the OEM code page. Pass encoding='oem' for those.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - list args, no shell, trusted argv
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding=encoding,
            errors="replace",
        )
    except FileNotFoundError:
        _note(health, "not_supported", "unavailable")
        return ""
    except PermissionError:
        _note(health, "access_denied", "failed")
        return ""
    except subprocess.TimeoutExpired:
        _note(health, "timeout", "failed")
        return ""
    except (OSError, subprocess.SubprocessError):
        _note(health, "command_failed", "failed")
        return ""
    if completed.returncode != 0:
        _note(health, "command_failed", "failed")
    if len(completed.stdout) > _MAX_COMMAND_CHARS:
        _note(health, "output_truncated")
    return completed.stdout[:_MAX_COMMAND_CHARS]


def collect_platform() -> PlatformInfo:
    """Collect the OS fingerprint."""
    return PlatformInfo(
        system=platform.system(),
        release=platform.release(),
        version=platform.version(),
        machine=platform.machine(),
        python_version=platform.python_version(),
    )


def collect_ip_addresses() -> list[str]:
    """Collect non-loopback IPv4/IPv6 addresses."""
    addresses: set[str] = set()
    for iface_addrs in psutil.net_if_addrs().values():
        for addr in iface_addrs:
            if addr.family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            value = addr.address
            if value and not value.startswith(("127.", "::1")):
                # Strip IPv6 zone id (e.g. fe80::1%eth0) for cleanliness.
                addresses.add(value.split("%", 1)[0])
    return sorted(addresses)


def _cmdline_text(value: object) -> str | None:
    if isinstance(value, list):
        # Preserve Windows argv boundaries consistently when fixtures run off Windows.
        text = subprocess.list2cmdline([str(part) for part in value if part])
    elif value:
        text = str(value)
    else:
        return None
    text = text.strip()
    return text[:800] or None


def collect_processes(
    limit: int,
    *,
    include_cmdline: bool = False,
    health: CollectionHealth | None = None,
) -> list[ProcessInfo]:
    """Collect running processes. Command lines stay unset unless opted in."""
    attrs = ["pid", "name", "username", "exe", "create_time"]
    if include_cmdline:
        attrs.append("cmdline")
    processes: list[ProcessInfo] = []
    for proc in psutil.process_iter(attrs=attrs):
        try:
            info = proc.info
            processes.append(
                ProcessInfo(
                    pid=info.get("pid"),
                    name=info.get("name"),
                    username=info.get("username"),
                    exe=_clip(info.get("exe")),
                    cmdline=_cmdline_text(info.get("cmdline")) if include_cmdline else None,
                    create_time=info.get("create_time"),
                )
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            _note(health, "item_skipped")
            logger.debug("Skipping inaccessible process")
            continue
        if len(processes) >= limit:
            break
    return processes


def collect_listening_connections(
    limit: int, *, health: CollectionHealth | None = None
) -> list[ListeningConnection]:
    """Collect listening sockets (no active scanning — read local state only)."""
    connections: list[ListeningConnection] = []
    try:
        net_connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        _note(health, "access_denied", "failed")
        logger.warning("Access denied reading network connections.")
        return connections

    for conn in net_connections:
        if conn.status != psutil.CONN_LISTEN:
            continue
        local = conn.laddr or None
        connections.append(
            ListeningConnection(
                pid=conn.pid,
                family=str(conn.family),
                type=str(conn.type),
                local_ip=getattr(local, "ip", None),
                local_port=getattr(local, "port", None),
                status=conn.status,
            )
        )
        if len(connections) >= limit:
            break
    return connections


def collect_services(
    limit: int, timeout: int, *, health: CollectionHealth | None = None
) -> list[ServiceInfo]:
    """Collect system services (Windows) or systemd units (Linux)."""
    if _IS_WINDOWS:
        return _collect_windows_services(limit, health=health)
    if _IS_LINUX:
        return _collect_linux_units(limit, timeout, health=health)
    _note(health, "not_supported", "unavailable")
    return []


def _collect_windows_services(
    limit: int, *, health: CollectionHealth | None = None
) -> list[ServiceInfo]:
    services: list[ServiceInfo] = []
    try:
        for svc in psutil.win_service_iter():
            try:
                # as_dict() also reads binpath and the service description.
                name = svc.name()
                display_name = svc.display_name()
                state = svc.status()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                _note(health, "item_skipped")
                logger.debug("Skipping inaccessible service")
                continue
            services.append(
                ServiceInfo(
                    name=name or "",
                    display_name=_clip(display_name) or "",
                    state=_clip(state) or "",
                )
            )
            if len(services) >= limit:
                break
    except (AttributeError, NotImplementedError):
        _note(health, "not_supported", "unavailable")
        logger.debug("win_service_iter unavailable")
    return services


def _collect_linux_units(
    limit: int, timeout: int, *, health: CollectionHealth | None = None
) -> list[ServiceInfo]:
    output = _run_command(
        ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain"],
        timeout=timeout,
        health=health,
    )
    services: list[ServiceInfo] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or (not line.endswith(".service") and ".service " not in line):
            continue
        parts = line.split(None, _SYSTEMCTL_MIN_FIELDS)
        if len(parts) < _SYSTEMCTL_MIN_FIELDS or not parts[0].endswith(".service"):
            continue
        unit, _load, active, sub, *rest = (*parts, "")
        services.append(
            ServiceInfo(
                name=unit,
                display_name=rest[0] if rest and rest[0] else unit,
                state=f"{active}/{sub}",
            )
        )
        if len(services) >= limit:
            break
    return services


def collect_software(
    limit: int, timeout: int, *, health: CollectionHealth | None = None
) -> list[SoftwareInfo]:
    """Collect installed software (Windows registry / Linux package manager)."""
    if _IS_WINDOWS:
        return _collect_windows_software(limit, timeout, health=health)
    if _IS_LINUX:
        return _collect_linux_packages(limit, timeout, health=health)
    _note(health, "not_supported", "unavailable")
    return []


def _consume_software_lines(output: str, limit: int, software: dict[str, SoftwareInfo]) -> bool:
    """Parse one hive export. Return True when ``limit`` names are stored."""
    for raw in output.splitlines():
        clean = raw.strip()
        if "DisplayName" in clean and "REG_" in clean:
            parts = clean.split()
            try:
                idx = next(i for i, value in enumerate(parts) if value.startswith("REG_"))
            except StopIteration:
                logger.debug("No REG_ token in registry line")
                continue
            name = " ".join(parts[idx + 1 :]).strip()
            if name and name not in software:
                software[name] = SoftwareInfo(name=name[:_SHORT_LEN], source="registry")
        if len(software) >= limit:
            return True
    return False


def _collect_windows_software(
    limit: int, timeout: int, *, health: CollectionHealth | None = None
) -> list[SoftwareInfo]:
    software: dict[str, SoftwareInfo] = {}
    for reg_path, view in _SOFTWARE_HIVES:
        output = _run_command(
            ["reg", "query", reg_path, "/s", view],
            timeout=timeout,
            encoding="oem",
            health=health,
        )
        if _consume_software_lines(output, limit, software):
            break
    return list(software.values())[:limit]


def _collect_linux_packages(
    limit: int, timeout: int, *, health: CollectionHealth | None = None
) -> list[SoftwareInfo]:
    # Try dpkg (Debian/Ubuntu) then rpm (RHEL/SUSE). Read-only queries.
    first = CollectionHealth()
    dpkg = _run_command(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], timeout=timeout, health=first
    )
    if dpkg or first.status == "ok":
        if health is not None:
            health.status, health.issues, health.truncated = (
                first.status,
                first.issues,
                first.truncated,
            )
        return _parse_pkg_lines(dpkg, "dpkg", limit)
    rpm = _run_command(
        ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n"], timeout=timeout, health=health
    )
    if rpm:
        return _parse_pkg_lines(rpm, "rpm", limit)
    return []


def _parse_pkg_lines(text: str, source: str, limit: int) -> list[SoftwareInfo]:
    out: list[SoftwareInfo] = []
    for line in text.splitlines():
        name, _, version = line.partition("\t")
        name = name.strip()
        if name:
            out.append(SoftwareInfo(name=name[:512], version=version.strip()[:512], source=source))
        if len(out) >= limit:
            break
    return out


def collect_local_admins(timeout: int) -> list[str]:
    """Collect local administrator / sudo-capable accounts (names only)."""
    return _collect_local_admin_identities(timeout)[0]


def _collect_local_admin_identities(
    timeout: int,
    *,
    health: CollectionHealth | None = None,
) -> tuple[list[str], dict[str, str]]:
    """Keep display names and Windows SIDs from the same bounded snapshot."""
    if _IS_WINDOWS:
        output = _run_command(
            local_admin_argv(), timeout=timeout, encoding="utf-8-sig", health=health
        )
        if not output and health is not None and health.status != "ok":
            return [], {}
        try:
            rows = json.loads(output)
        except ValueError:
            _note(health, "invalid_output", "failed")
            return [], {}
        if not isinstance(rows, list):
            _note(health, "invalid_output", "failed")
            return [], {}
        if len(rows) >= _ADMIN_LIMIT:
            _note(health, "limit_reached")
        identities = {
            str(row["Name"])[:_SHORT_LEN]: str(row["Sid"])[:_SHORT_LEN]
            for row in rows[:_ADMIN_LIMIT]
            if isinstance(row, dict)
            and isinstance(row.get("Name"), str)
            and isinstance(row.get("Sid"), str)
        }
        if len(identities) < min(len(rows), _ADMIN_LIMIT):
            _note(health, "invalid_output")
        return list(identities), identities
    if _IS_LINUX:
        # Members of the sudo/wheel groups. Names only — never passwords.
        members: set[str] = set()
        for group in ("sudo", "wheel"):
            out = _run_command(["getent", "group", group], timeout=timeout, health=health)
            if ":" in out:
                tail = out.rsplit(":", 1)[-1].strip()
                members.update(m for m in tail.split(",") if m)
        return sorted(members), {}
    _note(health, "not_supported", "unavailable")
    return [], {}


def _local_observations(report: ScanReport) -> list[Observation]:
    """Cheap agent-side hints so isolated bundles carry signal pre-server.

    These are intentionally coarse; the server rules engine is authoritative.
    """
    observations: list[Observation] = []
    listening = {c.local_port for c in report.listening_connections if c.local_port}
    for port, msg, sev in (
        (3389, "RDP listener detected", Severity.MEDIUM),
        (23, "Telnet listener detected", Severity.HIGH),
        (21, "FTP listener detected", Severity.HIGH),
    ):
        if port in listening:
            observations.append(
                Observation(
                    severity=sev,
                    category="listening_port",
                    message=msg,
                    detail=f"Port {port} is listening locally.",
                )
            )
    return observations


def collect_report(config: AgentConfig) -> ScanReport:
    """Run all collectors and assemble a :class:`ScanReport`."""
    if config.collect_cmdline and not config.encryption_key:
        msg = "command lines require an encryption key"
        raise ValueError(msg)
    health = {
        name: CollectionHealth()
        for name in (
            "ip_addresses",
            "processes",
            "listening_connections",
            "services",
            "installed_software",
            "local_admins",
        )
    }
    admin_sids: dict[str, str] = {}

    def get_admins() -> list[str]:
        nonlocal admin_sids
        admins, admin_sids = _collect_local_admin_identities(
            config.command_timeout_s,
            health=health["local_admins"],
        )
        return admins

    admins = _collect_with_health(get_admins, health["local_admins"], _ADMIN_LIMIT)
    report = ScanReport(
        scan_time_utc=utc_now_iso(),
        hostname=socket.gethostname(),
        fqdn=socket.getfqdn(),
        role=config.role or EndpointRole.UNKNOWN,
        platform=collect_platform(),
        ip_addresses=_collect_with_health(collect_ip_addresses, health["ip_addresses"]),
        processes=_collect_with_health(
            lambda: collect_processes(
                config.process_limit,
                include_cmdline=config.collect_cmdline,
                health=health["processes"],
            ),
            health["processes"],
            config.process_limit,
        ),
        listening_connections=_collect_with_health(
            lambda: collect_listening_connections(
                config.connection_limit, health=health["listening_connections"]
            ),
            health["listening_connections"],
            config.connection_limit,
        ),
        services=_collect_with_health(
            lambda: collect_services(
                config.service_limit, config.command_timeout_s, health=health["services"]
            ),
            health["services"],
            config.service_limit,
        ),
        installed_software=_collect_with_health(
            lambda: collect_software(
                config.software_limit, config.command_timeout_s, health=health["installed_software"]
            ),
            health["installed_software"],
            config.software_limit,
        ),
        local_admins=admins,
        local_admin_sids=admin_sids,
        collection_health=health,
    )
    if config.collect_cmdline and config.encryption_key:
        seal_command_lines(report, config.encryption_key)
    report.observations = _local_observations(report)
    return report


__all__ = [
    "collect_ip_addresses",
    "collect_listening_connections",
    "collect_local_admins",
    "collect_platform",
    "collect_processes",
    "collect_report",
    "collect_services",
    "collect_software",
]
