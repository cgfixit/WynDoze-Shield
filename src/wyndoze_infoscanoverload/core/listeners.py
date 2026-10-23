"""Bounded socket identity, independent of display evidence and process lifetime."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import defaultdict
from collections.abc import Collection
from pathlib import PurePosixPath, PureWindowsPath

from wyndoze_infoscanoverload.core.models import ListenerIdentity, ProcessInfo, ScanReport

_SHORT_STR_LIMIT = 512


def bind_scope(address: str | None) -> str:
    """Describe binding scope without claiming network reachability."""
    try:
        ip = ipaddress.ip_address(address or "")
    except ValueError:
        return "unknown"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return "loopback"
    return "wildcard" if ip.is_unspecified else "interface"


def listener_evidence(report: ScanReport, ports: Collection[int]) -> list[str]:
    """Keep the pre-v1 evidence format, including PID, for display and migration."""
    owners = {p.pid: p.name for p in report.processes if p.pid is not None}
    return sorted(
        {
            f"port {c.local_port} listening on {(c.local_ip or 'unknown')[:128]} "
            f"({bind_scope(c.local_ip)}); pid={c.pid if c.pid is not None else 'unknown'}; "
            f"process={(owners.get(c.pid) if c.pid is not None else None) or 'unknown'}"
            for c in report.listening_connections
            if c.local_port in ports
        }
    )


def _owner_context(process: ProcessInfo, system: str) -> tuple[str, bool]:
    # Do not resolve paths, follow symlinks, hash files, or infer trust from names.
    # Preserve path case: Windows can enable case-sensitive directories too.
    exe = process.exe or ""
    path = PureWindowsPath(exe) if system == "windows" else PurePosixPath(exe)
    complete = bool(
        system in {"windows", "linux", "darwin"}
        and path.is_absolute()
        and all(
            value and value.strip() and len(value) < _SHORT_STR_LIMIT
            for value in (process.name, process.exe, process.username)
        )
    )
    context = [process.name, exe, process.username, sorted(set(process.cmdline_flags))]
    return json.dumps(context, ensure_ascii=True), complete


def listener_owner_evidence(report: ScanReport, ports: Collection[int]) -> list[str]:
    """Expose observed paths/accounts so same-name owner changes can be reviewed."""
    pids = {conn.pid for conn in report.listening_connections if conn.local_port in ports}
    return sorted(
        {
            f"owner pid={process.pid}; executable={(process.exe or 'unknown')[:380]}; "
            f"account={(process.username or 'unknown')[:80]}"
            for process in report.processes
            if process.pid is not None and process.pid in pids
        }
    )


def listener_identity(report: ScanReport, ports: Collection[int]) -> ListenerIdentity:
    """Fingerprint all matching sockets before display caps, not just the preview.

    Only an unambiguous owner with full name, absolute executable and account
    permits cross-scan reuse. Unknown/partial context is scan-scoped: replay is
    stable, but a later scan must be reviewed. Metadata is not binary identity.
    """
    owners: dict[int, list[ProcessInfo]] = defaultdict(list)
    for process in report.processes:
        if process.pid is not None:
            owners[process.pid].append(process)
    reusable = all(
        health.status == "ok" and not health.truncated
        for name, health in report.collection_health.items()
        if name in {"processes", "listening_connections"}
    )
    system = report.platform.system.lower()
    sockets: list[str] = []
    matched_ports: set[int] = set()
    for conn in report.listening_connections:
        if conn.local_port is None or conn.local_port not in ports:
            continue
        matched_ports.add(conn.local_port)
        try:
            address = str(ipaddress.ip_address(conn.local_ip or ""))
        except ValueError:
            address = conn.local_ip or ""
            reusable = False
        processes = owners.get(conn.pid, []) if conn.pid is not None else []
        contexts = [_owner_context(process, system) for process in processes]
        owner_complete = len(contexts) == 1 and contexts[0][1]
        socket_complete = (
            conn.family in {"2", "10", "23", "AF_INET", "AF_INET6"}
            and conn.type in {"1", "2", "SOCK_STREAM", "SOCK_DGRAM"}
            and conn.status == "LISTEN"
        )
        reusable = reusable and owner_complete and socket_complete
        sockets.append(
            json.dumps(
                [
                    conn.family,
                    conn.type,
                    address,
                    conn.local_port,
                    conn.status,
                    sorted(context for context, _ in contexts),
                    # Missing ownership never silently becomes a trusted basename.
                    None if owner_complete else conn.pid,
                    [] if owner_complete else sorted(str(p.create_time) for p in processes),
                ],
                ensure_ascii=True,
            )
        )
    # Preserve multiplicity: a second owner instance/socket is a changed posture.
    context = [
        system, report.role.value, sorted(sockets), None if reusable else report.scan_time_utc
    ]
    fingerprint = hashlib.sha256(json.dumps(context, ensure_ascii=True).encode()).hexdigest()
    return ListenerIdentity(
        ports=sorted(matched_ports), fingerprint=fingerprint, reusable=reusable and bool(sockets)
    )
