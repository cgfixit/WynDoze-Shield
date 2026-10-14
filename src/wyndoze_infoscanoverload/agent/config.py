"""Agent runtime configuration via Pydantic Settings.

All configuration can come from CLI flags, environment variables, or a mix.
Secrets (tokens, encryption keys) are read from the environment only — never
from a file that might get committed.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from wyndoze_infoscanoverload.core.models import EndpointRole


class AgentConfig(BaseSettings):
    """Configuration for a single agent run."""

    model_config = SettingsConfigDict(
        env_prefix="RECON_AGENT_",
        extra="ignore",
    )

    server_url: str | None = None
    token: str | None = Field(default=None, repr=False)
    role: EndpointRole = EndpointRole.UNKNOWN

    # Collection tunables (defense against runaway payloads).
    process_limit: int = Field(default=1000, ge=1, le=10000)
    connection_limit: int = Field(default=1000, ge=1, le=10000)
    service_limit: int = Field(default=1000, ge=1, le=10000)
    software_limit: int = Field(default=2000, ge=1, le=20000)
    command_timeout_s: int = Field(default=30, ge=1, le=300)
    collect_cmdline: bool = False

    # Deferred upload / isolated machine.
    cache_dir: Path = Field(default=Path("WynDoze-InfoScanOverload-cache"))
    encryption_key: str | None = Field(default=None, repr=False)

    # HTTP.
    upload_timeout_s: int = Field(default=60, ge=1, le=600)
    verify_tls: bool = True
