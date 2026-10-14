"""Integration tests for the agent CLI via Typer's CliRunner."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from wyndoze_infoscanoverload.agent.cli import app
from wyndoze_infoscanoverload.agent.crypto import encrypt_bytes
from wyndoze_infoscanoverload.agent.uploader import UploadError, assert_upload_url, upload_report
from wyndoze_infoscanoverload.core.models import EndpointRole, PlatformInfo, ScanReport

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip()


def test_gen_key_roundtrips() -> None:
    result = runner.invoke(app, ["gen-key"])
    assert result.exit_code == 0
    key = result.stdout.strip()
    assert encrypt_bytes(b"x", key)  # key is usable


def test_scan_no_upload_needs_no_server_url(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["scan", "--no-upload", "--output-json", str(out), "--role", "workstation"],
    )
    assert result.exit_code == 0, result.stdout
    assert out.exists()


def test_scan_requires_server_url_when_uploading() -> None:
    # Ensure no token is picked up from the ambient environment.
    result = runner.invoke(app, ["scan", "--role", "workstation"], env={"RECON_AGENT_TOKEN": ""})
    assert result.exit_code == 2


def test_disable_skips_collect(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["scan", "--no-upload", "--output-json", str(out), "--role", "workstation"],
        env={"RECON_AGENT_DISABLE": "1"},
    )
    assert result.exit_code == 0
    assert not out.exists()
    assert "RECON_AGENT_DISABLE" in result.stdout


def test_upload_url_policy() -> None:
    assert_upload_url("http://127.0.0.1:8000/api/scans")
    assert_upload_url("http://[::1]:8000/api/scans")
    assert_upload_url("https://recon.example/api/scans")
    for bad in (
        "http://192.0.2.1/api/scans",
        "http://localhost/api/scans",
        "ftp://127.0.0.1/x",
    ):
        with pytest.raises(UploadError):
            assert_upload_url(bad)


def test_upload_ignores_proxy_env(
    monkeypatch: pytest.MonkeyPatch, clean_report: ScanReport
) -> None:
    seen: dict[str, object] = {}

    class _Resp:
        status_code = 201
        text = "{}"

        def json(self) -> dict[str, str]:
            return {"status": "accepted"}

    def fake_post(_url: str, **kwargs: object) -> _Resp:
        seen["trust_env"] = kwargs.get("trust_env")
        return _Resp()

    monkeypatch.setattr("wyndoze_infoscanoverload.agent.uploader.httpx.post", fake_post)
    upload_report(clean_report, "http://127.0.0.1:8000/api/scans", "tok")
    assert seen["trust_env"] is False


def test_defer_requires_key_before_upload(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "wyndoze_infoscanoverload.agent.cli.collect_report",
        lambda _config: clean_report_stub(),
    )
    called: dict[str, bool] = {}

    def boom(*_args: object, **_kwargs: object) -> dict[str, str]:
        called["upload"] = True
        return {"status": "accepted"}

    monkeypatch.setattr("wyndoze_infoscanoverload.agent.cli.upload_report", boom)
    result = runner.invoke(
        app,
        [
            "scan",
            "--server-url",
            "http://127.0.0.1:8000/api/scans",
            "--role",
            "workstation",
            "--cache-dir",
            str(tmp_path),
        ],
        env={"RECON_AGENT_TOKEN": "t", "RECON_AGENT_ENCRYPTION_KEY": ""},
    )
    assert result.exit_code == 2
    assert "upload" not in called
    assert list(tmp_path.iterdir()) == []


def clean_report_stub() -> ScanReport:
    return ScanReport(
        scan_time_utc="2026-01-01T00:00:00Z",
        hostname="WS-001",
        role=EndpointRole.WORKSTATION,
        platform=PlatformInfo(system="Windows", release="11"),
    )


def test_cmdline_flag_requires_key_before_collect(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def boom(_config: object) -> None:
        msg = "collect should not run"
        raise AssertionError(msg)

    monkeypatch.setattr("wyndoze_infoscanoverload.agent.cli.collect_report", boom)
    out = tmp_path / "report.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "--no-upload",
            "--cmdline",
            "--output-json",
            str(out),
            "--role",
            "workstation",
        ],
        env={"RECON_AGENT_ENCRYPTION_KEY": ""},
    )
    assert result.exit_code == 2
    assert not out.exists()


def test_scan_rejects_cleartext_non_loopback() -> None:
    result = runner.invoke(
        app,
        ["scan", "--server-url", "http://192.0.2.1/api/scans", "--role", "workstation"],
        env={"RECON_AGENT_TOKEN": "t"},
    )
    assert result.exit_code == 2
    assert "https" in result.output.lower()


def test_evaluate_local(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    runner.invoke(
        app,
        ["scan", "--no-upload", "--output-json", str(out), "--role", "backup_server"],
    )
    result = runner.invoke(app, ["evaluate-local", str(out)])
    assert result.exit_code == 0
    assert result.stdout.strip().startswith("[")
