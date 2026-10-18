"""Pydantic v2 domain models shared across the wire boundary.

These models are the contract between the agent (producer) and the server
(consumer). Nested telemetry drops unknown keys. Envelope fields the server
indexes stay strict.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from wyndoze_infoscanoverload.core.severity import Severity

SCHEMA_VERSION = "1.0"

# Bounded strings keep a hostile agent from flooding the DB with a giant field.
ShortStr = Annotated[str, Field(max_length=512)]
Hostname = Annotated[str, Field(min_length=1, max_length=255)]


class EndpointRole(StrEnum):
    """Role an endpoint plays in the backup estate.

    Rules can be scoped to backup servers, proxies, repositories, workstations,
    and the other roles listed below.
    """

    UNKNOWN = "unknown"
    BACKUP_SERVER = "backup_server"
    PROXY = "proxy"
    REPOSITORY = "repository"
    DOMAIN_CONTROLLER = "domain_controller"
    JUMPBOX = "jumpbox"
    WORKSTATION = "workstation"
    OTHER = "other"


class PlatformInfo(BaseModel):
    """Operating-system fingerprint."""

    model_config = ConfigDict(extra="ignore")

    system: ShortStr = ""
    release: ShortStr = ""
    version: ShortStr = ""
    machine: ShortStr = ""
    python_version: ShortStr = ""


class ProcessInfo(BaseModel):
    """A single observed process (safe metadata only, no memory contents)."""

    model_config = ConfigDict(extra="ignore")

    pid: int | None = None
    name: ShortStr | None = None
    username: ShortStr | None = None
    exe: ShortStr | None = None
    # Sealed Fernet token when collection is on. Never the raw command line.
    cmdline: Annotated[str, Field(max_length=4096)] | None = None
    create_time: float | None = None


class ListeningConnection(BaseModel):
    """A listening socket."""

    model_config = ConfigDict(extra="ignore")

    pid: int | None = None
    family: ShortStr = ""
    type: ShortStr = ""
    local_ip: ShortStr | None = None
    local_port: int | None = None
    status: ShortStr = ""


class ServiceInfo(BaseModel):
    """A system service / daemon."""

    model_config = ConfigDict(extra="ignore")

    name: ShortStr = ""
    display_name: ShortStr = ""
    state: ShortStr = ""


class SoftwareInfo(BaseModel):
    """Installed software entry."""

    model_config = ConfigDict(extra="ignore")

    name: ShortStr = ""
    version: ShortStr = ""
    source: ShortStr = ""


class Observation(BaseModel):
    """A finding the agent flagged locally, before server-side rule scoring.

    The agent emits *cheap* observations; the server rules engine produces the
    authoritative :class:`Finding` set. Keeping both means an isolated bundle
    still carries useful signal even before it reaches the server.
    """

    model_config = ConfigDict(extra="ignore")

    severity: Severity = Severity.INFO
    category: ShortStr = ""
    message: ShortStr = ""
    detail: Annotated[str, Field(max_length=2000)] = ""
    technique_id: ShortStr | None = None

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, value: object) -> Severity:
        if isinstance(value, (str, Severity)):
            return Severity.coerce(value)
        return Severity.INFO


type CollectionState = Literal["ok", "partial", "unavailable", "failed"]
type CollectionIssue = Literal[
    "access_denied",
    "timeout",
    "command_failed",
    "not_supported",
    "invalid_output",
    "item_skipped",
    "limit_reached",
    "output_truncated",
]
type CollectorName = Literal[
    "ip_addresses",
    "processes",
    "listening_connections",
    "services",
    "installed_software",
    "local_admins",
]


class CollectionHealth(BaseModel):
    """Bounded coverage metadata; never command text, stderr, or credentials."""

    model_config = ConfigDict(extra="ignore")

    status: CollectionState = "ok"
    item_count: int = Field(default=0, ge=0, le=20000)
    duration_ms: int = Field(default=0, ge=0)
    truncated: bool = False
    issues: list[CollectionIssue] = Field(default_factory=list, max_length=8)


class ScanReport(BaseModel):
    """The full telemetry envelope an agent uploads.

    Envelope fields (hostname, scan time, schema version) are strict; nested
    telemetry lists accept unknown keys so a newer agent talking to an older
    server does not hard-fail.
    """

    model_config = ConfigDict(extra="ignore")

    schema_version: ShortStr = SCHEMA_VERSION
    scanner: ShortStr = "local_recon_scanner"
    scan_time_utc: Annotated[str, Field(max_length=64)]
    hostname: Hostname
    fqdn: ShortStr | None = None
    role: EndpointRole = EndpointRole.UNKNOWN
    platform: PlatformInfo = Field(default_factory=PlatformInfo)
    ip_addresses: list[ShortStr] = Field(default_factory=list, max_length=256)
    processes: list[ProcessInfo] = Field(default_factory=list, max_length=5000)
    listening_connections: list[ListeningConnection] = Field(default_factory=list, max_length=5000)
    services: list[ServiceInfo] = Field(default_factory=list, max_length=5000)
    installed_software: list[SoftwareInfo] = Field(default_factory=list, max_length=5000)
    local_admins: list[ShortStr] = Field(default_factory=list, max_length=1000)
    local_admin_sids: dict[ShortStr, ShortStr] = Field(default_factory=dict, max_length=1000)
    cmdline_flags: list[ShortStr] = Field(default_factory=list, max_length=32)
    observations: list[Observation] = Field(default_factory=list, max_length=5000)
    collection_health: dict[CollectorName, CollectionHealth] = Field(
        default_factory=dict, max_length=6
    )

    @field_validator("scan_time_utc")
    @classmethod
    def _validate_scan_time(cls, value: str) -> str:
        # Accept ISO-8601; normalise a trailing Z to +00:00 for datetime.fromisoformat.
        candidate = value.replace("Z", "+00:00")
        datetime.fromisoformat(candidate)  # raises ValueError if malformed
        return value


class FindingStatus(StrEnum):
    """Lifecycle of a server-side finding.

    Fresh findings land in the triage inbox; operators can flag, archive,
    or suppress them.
    """

    TRIAGE = "triage"
    FLAGGED = "flagged"
    ARCHIVED = "archived"
    SUPPRESSED = "suppressed"


class Finding(BaseModel):
    """An authoritative detection produced by the server rules engine."""

    model_config = ConfigDict(extra="ignore")

    rule_id: ShortStr
    title: ShortStr
    severity: Severity
    category: ShortStr = ""
    message: Annotated[str, Field(max_length=2000)] = ""
    technique_id: ShortStr | None = None
    technique_name: ShortStr | None = None
    tactic: ShortStr | None = None
    technique_url: ShortStr | None = None
    evidence: list[ShortStr] = Field(default_factory=list, max_length=100)


def utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp with offset."""
    return datetime.now(UTC).isoformat()


def dedupe_key(finding: Finding, hostname: str) -> str:
    """Stable identity for a finding on a host, used to dedupe across scans."""
    joined = "|".join(sorted(finding.evidence)) if finding.evidence else finding.message
    return f"{hostname}::{finding.rule_id}::{joined}"


__all__ = [
    "SCHEMA_VERSION",
    "EndpointRole",
    "Finding",
    "FindingStatus",
    "ListeningConnection",
    "Observation",
    "PlatformInfo",
    "ProcessInfo",
    "ScanReport",
    "ServiceInfo",
    "SoftwareInfo",
    "dedupe_key",
    "utc_now_iso",
]
