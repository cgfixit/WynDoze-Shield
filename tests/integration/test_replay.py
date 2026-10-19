"""Exercise replay retention and acknowledgement through the real CLI."""

from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from wyndoze_infoscanoverload.agent.cache import BundleCache
from wyndoze_infoscanoverload.agent.cli import app
from wyndoze_infoscanoverload.agent.crypto import generate_key
from wyndoze_infoscanoverload.core.models import ScanReport


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (302, {}),
        (200, {"status": "accepted", "scan_id": 1, "hostname": "H"}),
        (201, {"status": "ok"}),
        (201, {"status": "accepted", "scan_id": True, "hostname": "H"}),
        (201, {"status": "accepted", "scan_id": 1, "hostname": "other"}),
    ],
)
def test_replay_retains_unacknowledged_bundle(tmp_path, monkeypatch, status, body):
    key = generate_key()
    cache = BundleCache(tmp_path, key)
    path = cache.save(ScanReport(hostname="H", scan_time_utc="2026-10-18T12:00:00Z"))
    monkeypatch.setattr(
        "wyndoze_infoscanoverload.agent.uploader.httpx.post",
        lambda *_args, **_kwargs: httpx.Response(status, json=body),
    )
    result = CliRunner().invoke(
        app,
        [
            "replay",
            "--server-url",
            "https://example.invalid/api/scans",
            "--cache-dir",
            str(tmp_path),
        ],
        env={"RECON_AGENT_TOKEN": "synthetic", "RECON_AGENT_ENCRYPTION_KEY": key},
    )
    assert result.exit_code == 1
    assert path.exists()


def test_replay_continues_after_corrupt_bundle(tmp_path, monkeypatch):
    key = generate_key()
    corrupt = tmp_path / "000-corrupt.WynDoze-InfoScanOverload-bundle"
    corrupt.write_bytes(b"invalid synthetic bundle")
    cache = BundleCache(tmp_path, key)
    valid = cache.save(ScanReport(hostname="H", scan_time_utc="2026-10-18T12:00:00Z"))
    monkeypatch.setattr(
        "wyndoze_infoscanoverload.agent.uploader.httpx.post",
        lambda *_args, **_kwargs: httpx.Response(
            201, json={"status": "accepted", "scan_id": 1, "hostname": "H"}
        ),
    )
    result = CliRunner().invoke(
        app,
        [
            "replay",
            "--server-url",
            "https://example.invalid/api/scans",
            "--cache-dir",
            str(tmp_path),
        ],
        env={"RECON_AGENT_TOKEN": "synthetic", "RECON_AGENT_ENCRYPTION_KEY": key},
    )
    assert result.exit_code == 1
    assert corrupt.exists()
    assert not valid.exists()
    assert "1 uploaded, 1 failed" in result.output


def test_same_second_saves_preserve_both_reports(tmp_path: Path):
    cache = BundleCache(tmp_path, generate_key())
    reports = [
        ScanReport(hostname="H", scan_time_utc=f"2026-10-18T12:00:00.{n}Z") for n in (100, 900)
    ]
    paths = [cache.save(report) for report in reports]
    assert paths[0] != paths[1]
    assert cache.pending_count() == 2
    assert [cache.load(path).scan_time_utc for path in paths] == [r.scan_time_utc for r in reports]


@pytest.mark.parametrize("keep", [False, True])
def test_replay_continues_when_acknowledged_bundle_cannot_be_deleted(tmp_path, monkeypatch, keep):
    key = generate_key()
    cache = BundleCache(tmp_path, key)
    paths = [
        cache.save(ScanReport(hostname=host, scan_time_utc="2026-10-18T12:00:00Z"))
        for host in ("A", "B")
    ]
    uploaded = []

    def accept(_url, **kwargs):
        host = kwargs["json"]["hostname"]
        uploaded.append(host)
        return httpx.Response(201, json={"status": "accepted", "scan_id": 1, "hostname": host})

    unlink = Path.unlink

    def deny_first(path, **kwargs):
        if path == paths[0]:
            msg = "synthetic read-only bundle"
            raise PermissionError(msg)
        return unlink(path, **kwargs)

    monkeypatch.setattr("wyndoze_infoscanoverload.agent.uploader.httpx.post", accept)
    monkeypatch.setattr(Path, "unlink", deny_first)
    args = [
        "replay",
        "--server-url",
        "https://example.invalid/api/scans",
        "--cache-dir",
        str(tmp_path),
    ]
    if keep:
        args.append("--keep")
    result = CliRunner().invoke(
        app, args, env={"RECON_AGENT_TOKEN": "synthetic", "RECON_AGENT_ENCRYPTION_KEY": key}
    )
    assert uploaded == ["A", "B"]
    assert result.exit_code == (0 if keep else 1)
    assert paths[0].exists()
    assert paths[1].exists() is keep
    assert "2 uploaded" in result.output
    if not keep:
        assert "could not delete" in result.output
