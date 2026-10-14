"""Tests for the encrypted bundle cache and crypto helpers."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from wyndoze_infoscanoverload.agent.cache import BUNDLE_SUFFIX, BundleCache
from wyndoze_infoscanoverload.agent.cli import default_cache_dir
from wyndoze_infoscanoverload.agent.crypto import (
    CryptoError,
    decrypt_bytes,
    encrypt_bytes,
    generate_key,
)
from wyndoze_infoscanoverload.core.models import ScanReport


def test_encrypt_round_trip() -> None:
    key = generate_key()
    token = encrypt_bytes(b"secret payload", key)
    assert token != b"secret payload"
    assert decrypt_bytes(token, key) == b"secret payload"


def test_decrypt_with_wrong_key_fails() -> None:
    token = encrypt_bytes(b"data", generate_key())
    with pytest.raises(CryptoError):
        decrypt_bytes(token, generate_key())


def test_invalid_key_raises() -> None:
    with pytest.raises(CryptoError):
        encrypt_bytes(b"x", "not-a-valid-key")


def test_bundle_suffix_name() -> None:
    assert BUNDLE_SUFFIX == ".WynDoze-InfoScanOverload-bundle"
    assert "recon" not in BUNDLE_SUFFIX.lower()


def test_posix_cache_dir_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("wyndoze_infoscanoverload.agent.cli.os.name", "posix")
    assert default_cache_dir() == Path("WynDoze-InfoScanOverload-cache")


def test_bundle_save_and_load(tmp_path: Path, backup_server_report: ScanReport) -> None:
    key = generate_key()
    cache = BundleCache(tmp_path, key)
    path = cache.save(backup_server_report)
    assert path.suffix == BUNDLE_SUFFIX
    assert path.exists()
    # Raw bytes must not contain the hostname in cleartext.
    assert b"VBRSRV01" not in path.read_bytes()
    restored = cache.load(path)
    assert restored.hostname == "VBRSRV01"


def test_pending_count(tmp_path: Path, backup_server_report: ScanReport) -> None:
    cache = BundleCache(tmp_path, generate_key())
    assert cache.pending_count() == 0
    cache.save(backup_server_report)
    assert cache.pending_count() == 1


def test_windows_bundle_acl_drops_users(tmp_path: Path, backup_server_report: ScanReport) -> None:
    if os.name != "nt":
        pytest.skip("Windows ACL")
    path = BundleCache(tmp_path, generate_key()).save(backup_server_report)
    system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
    icacls = Path(system_root) / "System32" / "icacls.exe"
    listed = subprocess.run(  # noqa: S603 - fixed icacls path, no shell
        [os.fspath(icacls), os.fspath(path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert listed.returncode == 0
    assert "BUILTIN\\Users" not in listed.stdout
