"""Launcher command builders. They do not register a task or open a window."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from wyndoze_infoscanoverload.desktop import (
    ABOUT,
    AlertMail,
    DashboardProcess,
    documentation_message,
    register_scheduled_task,
    scan_argv,
    schtasks_create_argv,
    schtasks_delete_argv,
    server_env,
    status_from_server_log,
    task_command,
    tool_path,
    wait_until_healthy,
)
from wyndoze_infoscanoverload.server.app import create_app
from wyndoze_infoscanoverload.server.config import ServerConfig

# ``start`` runs the server path with no arguments, so a stand-in child must do its
# work at interpreter start-up. ``sitecustomize`` on PYTHONPATH gives that hook.
_SLEEPER = (
    "import sys, time\n"
    "print('Error: unable to open database file')\n"
    "sys.stdout.flush()\n"
    "time.sleep(30)\n"
)


def test_dashboard_process_logs_child_output_and_stops(tmp_path: Path) -> None:
    (tmp_path / "sitecustomize.py").write_text(_SLEEPER, encoding="utf-8")
    env = {**os.environ, "LOCALAPPDATA": str(tmp_path), "PYTHONPATH": str(tmp_path)}
    dashboard = DashboardProcess()
    dashboard.start(Path(sys.executable), env)
    assert dashboard.running()
    deadline = time.monotonic() + 10
    while "Error" not in dashboard.log_text() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert "unable to open database file" in dashboard.log_text()
    first = dashboard.process
    dashboard.start(Path(sys.executable), env)
    assert dashboard.process is first
    dashboard.stop()
    assert not dashboard.running()
    assert dashboard.process is None
    assert dashboard.log_file is None
    assert dashboard.log_path == tmp_path / "WynDoze-InfoScanOverload" / "server.log"


def test_dashboard_process_closes_log_when_spawn_fails(tmp_path: Path) -> None:
    dashboard = DashboardProcess()
    with pytest.raises(FileNotFoundError):
        dashboard.start(tmp_path / "missing-server.exe", {"LOCALAPPDATA": str(tmp_path)})
    assert dashboard.log_file is None
    assert dashboard.process is None
    assert dashboard.log_text() == ""


def test_wait_until_healthy_stops_when_child_exits() -> None:
    popen = subprocess.Popen([sys.executable, "-c", "pass"])
    popen.wait()
    started = time.monotonic()
    assert wait_until_healthy("9", timeout_s=5, process=popen) is False
    assert time.monotonic() - started < 4


def test_wait_until_healthy_times_out_on_closed_port() -> None:
    assert wait_until_healthy("9", timeout_s=0.5) is False


def test_status_from_server_log_without_error_lines() -> None:
    assert status_from_server_log("INFO: started\n", alive=True, healthy=False) == (
        "Dashboard did not answer."
    )
    assert status_from_server_log("INFO: bye\n", alive=False, healthy=False) == (
        "Server exited before it answered."
    )
    long_error = "error " + "x" * 400
    assert len(status_from_server_log(long_error, alive=True, healthy=False)) == 180


def test_dead_server_status_shows_the_sqlite_error() -> None:
    text = "sqlite3.OperationalError: unable to open database file\n"
    assert status_from_server_log(text, alive=False, healthy=False).startswith(
        "sqlite3.OperationalError"
    )
    assert status_from_server_log("", alive=True, healthy=True) == "Dashboard is up."


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


@pytest.mark.parametrize(
    ("outcome", "message"),
    [
        (0, "Registered WynDoze-InfoScanOverload-scan (weekly at 02:30)"),
        (1, "schtasks could not register the task."),
        (FileNotFoundError(), "Could not run schtasks: FileNotFoundError."),
        (PermissionError(), "Could not run schtasks: PermissionError."),
        (subprocess.TimeoutExpired("schtasks", 30), "Check Task Scheduler before retrying."),
    ],
)
def test_task_registration_handles_completion_and_failures(tmp_path, monkeypatch, outcome, message):
    def run(argv, **kwargs):
        assert argv == schtasks_create_argv(
            task_command(tmp_path / "agent with spaces.exe", "proxy", tmp_path / "out.json"),
            "weekly",
        )
        assert kwargs["timeout"] == 30
        assert kwargs["stdout"] == subprocess.DEVNULL
        assert kwargs["stderr"] == subprocess.DEVNULL
        if isinstance(outcome, Exception):
            raise outcome
        return subprocess.CompletedProcess(argv, outcome)

    monkeypatch.setattr("wyndoze_infoscanoverload.desktop.subprocess.run", run)
    result = register_scheduled_task(
        tmp_path / "agent with spaces.exe", "proxy", tmp_path / "out.json", "weekly"
    )
    assert message in result


def test_missing_pdf_does_not_invent_one(tmp_path: Path) -> None:
    path, message = documentation_message(tmp_path)
    assert path.name == "documentation.pdf"
    assert not path.exists()
    assert "not in the project folder" in message


def test_server_env_omits_mail_unless_requested() -> None:
    plain = server_env(token="tok", password="pw", port="8765", alerts=None)  # noqa: S106
    assert plain["RECON_HOST"] == "127.0.0.1"
    assert plain["RECON_DB_PATH"].endswith("WynDoze-InfoScanOverload.sqlite3")
    assert "RECON_ALERTS" not in plain
    assert "RECON_SMTP_PASSWORD" not in plain
    mail = AlertMail("smtp.example.test", 587, "u", "p", "to@example.test")
    alerted = server_env(token="tok", password="pw", port="8765", alerts=mail)  # noqa: S106
    assert alerted["RECON_ALERTS"] == "1"
    assert alerted["RECON_SMTP_PASSWORD"] == mail.password


@pytest.mark.parametrize("port", [0, -1, 65536, 70000])
def test_alert_mail_rejects_out_of_range_ports(port):
    with pytest.raises(ValueError, match="between 1 and 65535"):
        AlertMail("smtp.example.test", port, "u", "p", "to@example.test")


@pytest.mark.parametrize("port", [1, 587, 465, 65535])
def test_alert_mail_accepts_valid_ports(port):
    assert AlertMail("smtp.example.test", port, "u", "p", "to@example.test").port == port


def test_tool_path_stays_with_the_virtual_environment(tmp_path, monkeypatch):
    scripts = tmp_path / "venv" / "bin"
    scripts.mkdir(parents=True)
    executable = scripts / "python"
    # Model resolution to the base interpreter without requiring Windows symlink privileges.
    monkeypatch.setattr("wyndoze_infoscanoverload.desktop.sys.executable", str(executable))
    monkeypatch.setattr(Path, "resolve", lambda _self: tmp_path / "base" / "python")
    tool = scripts / "WynDoze-InfoScanOverload-server.exe"
    tool.touch()
    assert tool_path("WynDoze-InfoScanOverload-server") == tool


def test_desktop_login_uses_the_displayed_username(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("RECON_DASHBOARD_USER", "inherited-operator")
    env = server_env(token="synthetic", password="window-password", port="8765", alerts=None)  # noqa: S106
    for name, value in env.items():
        if name.startswith("RECON_"):
            monkeypatch.setenv(name, value)
    client = TestClient(create_app(ServerConfig()))
    assert client.get("/", auth=("admin", "window-password")).status_code == 200
    assert client.get("/", auth=("inherited-operator", "window-password")).status_code == 401
    assert client.get("/", auth=("admin", "wrong-password")).status_code == 401
