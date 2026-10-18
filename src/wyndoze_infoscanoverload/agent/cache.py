"""On-disk cache for deferred uploads and isolated-machine bundles.

When an upload fails (or the endpoint is isolated), the report is written to
``cache_dir`` as an encrypted ``.WynDoze-InfoScanOverload-bundle`` file. A later run, or the
jumpbox tooling on a machine with internet access — can replay the cache.

File format: raw Fernet token of the UTF-8 JSON report. One report per file.
Filenames include the hostname, timestamp, and an exclusive random suffix.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from wyndoze_infoscanoverload.agent.crypto import decrypt_bytes, encrypt_bytes
from wyndoze_infoscanoverload.core.models import ScanReport

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = logging.getLogger("wyndoze_infoscanoverload.agent.cache")

BUNDLE_SUFFIX = ".WynDoze-InfoScanOverload-bundle"
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_component(value: str) -> str:
    """Sanitise a filename component to prevent path traversal / odd chars."""
    cleaned = _SAFE_NAME.sub("_", value).strip("._") or "host"
    return cleaned[:100]


def _restrict_bundle(path: Path) -> None:
    """Keep the bundle readable by SYSTEM, Administrators, and the current user."""
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            logger.debug("chmod not supported for %s", path.name)
        return
    grants = ["*S-1-5-18:F", "*S-1-5-32-544:F"]
    user = os.environ.get("USERNAME")
    if user:
        grants.append(f"{user}:F")
    system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
    icacls = Path(system_root) / "System32" / "icacls.exe"
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [os.fspath(icacls), os.fspath(path), "/inheritance:r", "/grant:r", *grants],
        check=False,
        capture_output=True,
        timeout=20,
    )
    if completed.returncode != 0:
        logger.warning("Could not restrict bundle ACL for %s", path.name)


class BundleCache:
    """Manages encrypted report bundles on disk."""

    def __init__(self, cache_dir: Path, key: str) -> None:
        self._dir = cache_dir
        self._key = key

    @property
    def directory(self) -> Path:
        """The cache directory (created lazily on first write)."""
        return self._dir

    def save(self, report: ScanReport) -> Path:
        """Encrypt and persist ``report``; return the bundle path."""
        self._dir.mkdir(parents=True, exist_ok=True)
        timestamp = report.scan_time_utc.replace(":", "").replace("-", "")[:15]
        payload = report.model_dump_json().encode("utf-8")
        token = encrypt_bytes(payload, self._key)
        descriptor, name = tempfile.mkstemp(
            prefix=f"{_safe_component(report.hostname)}-{_safe_component(timestamp)}-",
            suffix=BUNDLE_SUFFIX,
            dir=self._dir,
        )
        path = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as bundle:
                bundle.write(token)
            _restrict_bundle(path)
        except (OSError, subprocess.SubprocessError):
            path.unlink(missing_ok=True)
            raise
        logger.info("Saved encrypted bundle: %s", path.name)
        return path

    def load(self, path: Path) -> ScanReport:
        """Decrypt and parse a single bundle file."""
        token = path.read_bytes()
        raw = decrypt_bytes(token, self._key)
        return ScanReport.model_validate_json(raw)

    def iter_bundles(self) -> Iterator[Path]:
        """Yield bundle paths in filename (time) order."""
        if not self._dir.exists():
            return
        yield from sorted(self._dir.glob(f"*{BUNDLE_SUFFIX}"))

    def pending_count(self) -> int:
        """Return the number of bundles awaiting upload."""
        return sum(1 for _ in self.iter_bundles())


__all__ = ["BUNDLE_SUFFIX", "BundleCache"]
