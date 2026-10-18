"""Server configuration via Pydantic Settings."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def default_db_path() -> Path:
    """Return the dashboard database path. On Windows this is not the process cwd."""
    if os.name == "nt":
        root = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        return Path(root) / "WynDoze-InfoScanOverload" / "WynDoze-InfoScanOverload.sqlite3"
    return Path("WynDoze-InfoScanOverload.sqlite3")


class ServerConfig(BaseSettings):
    """Server runtime configuration (env prefix ``RECON_``)."""

    model_config = SettingsConfigDict(env_prefix="RECON_", extra="ignore")

    db_path: Path = Field(default_factory=default_db_path)

    # Ingest auth (agents).
    ingest_token: str | None = Field(default=None, repr=False)

    # Dashboard auth (humans). Basic auth for lab use; front with SSO in prod.
    dashboard_user: str = "admin"
    dashboard_password: str | None = Field(default=None, repr=False)

    # Rule pack path (defaults to the bundled pack when unset).
    rules_path: Path | None = None

    stale_after_hours: int = Field(default=36, ge=1, le=8760)

    def dashboard_auth_enabled(self) -> bool:
        """Return whether a non-empty dashboard password is configured.

        Routes still reject when this is false. An empty password is not a
        successful login.
        """
        return bool(self.dashboard_password)
