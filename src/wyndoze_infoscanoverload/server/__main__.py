"""Dashboard launcher entry point.

Run via ``python -m wyndoze_infoscanoverload.server`` or the
``WynDoze-InfoScanOverload-server`` script. Thin wrapper around uvicorn
so operators don't need to know the app-factory path.
"""

from __future__ import annotations

import os
import sys

import uvicorn

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})


def main() -> None:
    """Launch uvicorn with the app factory. Bind is loopback only."""
    host = os.environ.get("RECON_HOST", "127.0.0.1")
    if host not in _LOOPBACK_HOSTS:
        sys.stderr.write(f"RECON_HOST must be 127.0.0.1 or ::1, got {host!r}\n")
        raise SystemExit(2)
    port = int(os.environ.get("RECON_PORT", "8000"))
    uvicorn.run(
        "wyndoze_infoscanoverload.server.app:create_app",
        factory=True,
        host=host,
        port=port,
        log_level=os.environ.get("RECON_LOG_LEVEL", "info"),
    )


if __name__ == "__main__":
    main()
