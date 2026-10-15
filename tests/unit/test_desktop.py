"""Launcher command builders. They do not register a task or open a window."""

from __future__ import annotations

from pathlib import Path

import pytest

from wyndoze_infoscanoverload.desktop import (
    ABOUT,
    AlertMail,
    documentation_message,
    scan_argv,
    schtasks_create_argv,
    schtasks_delete_argv,
    server_env,
    task_command,
)


def test_about_names_the_product() -> None:
    assert ABOUT.count(".") >= 3
    assert "WynDoze-InfoScanOverload" in ABOUT
    assert "vendor" in ABOUT


def test_scan_argv_does_not_upload(tmp_path: Path) -> None:
    argv = scan_argv(Path("agent.exe"), "workstation", tmp_path / "out.json")
    assert argv[1:5] == ["scan", "--no-upload", "--role", "workstation"]
    assert "SYSTEM" not in " ".join(argv)


def test_unknown_role_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown role"):
        scan_argv(Path("agent.exe"), "laptop", tmp_path / "out.json")


def test_weekly_task_is_current_user_and_has_no_secret(tmp_path: Path) -> None:
    command = task_command(Path("C:/agent.exe"), "proxy", tmp_path / "out.json")
    argv = schtasks_create_argv(command, "weekly")
    text = " ".join(argv)
    assert "/SC" in argv
    assert "WEEKLY" in argv
    assert "/D" in argv
    assert "MON" in argv
    assert "LIMITED" in argv
    assert "SYSTEM" not in text
    assert "PASSWORD" not in text
    assert "--no-upload" in command


def test_monthly_and_daily_flags() -> None:
    daily = schtasks_create_argv("agent.exe scan --no-upload", "daily")
    monthly = schtasks_create_argv("agent.exe scan --no-upload", "monthly")
    assert "DAILY" in daily
    assert "/D" not in daily
    assert "MONTHLY" in monthly
    assert "1" in monthly


def test_delete_argv() -> None:
    assert schtasks_delete_argv("WynDoze-InfoScanOverload-verify")[-2:] == [
        "WynDoze-InfoScanOverload-verify",
        "/F",
    ]


def test_missing_pdf_does_not_invent_one(tmp_path: Path) -> None:
    path, message = documentation_message(tmp_path)
    assert path.name == "documentation.pdf"
    assert not path.exists()
    assert "not in the project folder" in message


def test_server_env_omits_mail_unless_requested() -> None:
    plain = server_env(token="tok", password="pw", port="8765", alerts=None)  # noqa: S106
    assert plain["RECON_HOST"] == "127.0.0.1"
    assert "RECON_ALERTS" not in plain
    assert "RECON_SMTP_PASSWORD" not in plain
    mail = AlertMail("smtp.example.test", 587, "u", "p", "to@example.test")
    alerted = server_env(token="tok", password="pw", port="8765", alerts=mail)  # noqa: S106
    assert alerted["RECON_ALERTS"] == "1"
    assert alerted["RECON_SMTP_PASSWORD"] == mail.password
