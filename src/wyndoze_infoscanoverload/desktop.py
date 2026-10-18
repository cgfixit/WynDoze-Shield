"""Windows desktop launcher for the loopback dashboard.

The window chooses a scan role, starts and stops the server, opens
``documentation.pdf`` when that file exists, and can register a current-user
scheduled task. It does not register a SYSTEM task.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
import threading
import time
import tkinter as tk
import urllib.request
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from tkinter import ttk
from typing import IO

ABOUT = (
    "WynDoze-InfoScanOverload is a local inventory scanner. "
    "An agent reads names, ports, and account names on this PC. "
    "A loopback dashboard scores the report with a YAML rule pack. "
    "You review finding cards in the browser on this machine. "
    "The agent does not call a vendor. "
    "Command lines stay off unless you opt in, and then they are stored as sealed tokens."
)
ROLES = (
    "workstation",
    "backup_server",
    "proxy",
    "repository",
    "domain_controller",
    "jumpbox",
    "other",
)
CADENCES = ("daily", "weekly", "monthly")
TASK_NAME = "WynDoze-InfoScanOverload-scan"
_SCHEDULE_TIME = "02:30"


def project_root() -> Path:
    """Return the checkout that contains ``pyproject.toml``."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file():
            return parent
    return here.parents[2]


def tool_path(name: str) -> Path:
    """Return the venv console script next to the running interpreter."""
    scripts = Path(sys.executable).resolve().parent
    windows = scripts / f"{name}.exe"
    if windows.is_file():
        return windows
    return scripts / name


def documentation_message(root: Path) -> tuple[Path, str]:
    """Return the PDF path and a status line. Do not create the file."""
    path = root / "documentation.pdf"
    if not path.is_file():
        return path, "documentation.pdf is not in the project folder yet."
    if os.name == "nt":
        os.startfile(path)  # noqa: S606 - the operator asked to open this local PDF
        return path, "Opened documentation.pdf."
    return path, "Open documentation.pdf from the project folder."


def scan_argv(agent: Path, role: str, output: Path) -> list[str]:
    """Build a collect-only scan. The scheduled task does not upload."""
    if role not in ROLES:
        msg = f"unknown role: {role}"
        raise ValueError(msg)
    return [
        os.fspath(agent),
        "scan",
        "--no-upload",
        "--role",
        role,
        "--output-json",
        os.fspath(output),
    ]


def schtasks_create_argv(command: str, cadence: str, *, task_name: str = TASK_NAME) -> list[str]:
    """Build a current-user schtasks create. ``command`` is the /TR text."""
    if cadence not in CADENCES:
        msg = f"unknown cadence: {cadence}"
        raise ValueError(msg)
    argv = [
        "schtasks",
        "/Create",
        "/F",
        "/TN",
        task_name,
        "/SC",
        cadence.upper(),
        "/ST",
        _SCHEDULE_TIME,
        "/RL",
        "LIMITED",
        "/TR",
        command,
    ]
    if cadence == "weekly":
        argv.extend(["/D", "MON"])
    elif cadence == "monthly":
        argv.extend(["/D", "1"])
    return argv


def schtasks_delete_argv(task_name: str = TASK_NAME) -> list[str]:
    """Build the delete command for a task this launcher created."""
    return ["schtasks", "/Delete", "/TN", task_name, "/F"]


def task_command(agent: Path, role: str, output: Path) -> str:
    """Quote the agent path for schtasks /TR."""
    argv = scan_argv(agent, role, output)
    return f'"{argv[0]}" scan --no-upload --role {role} --output-json "{argv[-1]}"'


def status_from_server_log(text: str, *, alive: bool, healthy: bool) -> str:
    """Turn a server log into the window status. Healthy wins over a stale error."""
    if healthy:
        return "Dashboard is up."
    for line in reversed(text.splitlines()):
        stripped = line.strip()
        if "Error" in stripped or "error" in stripped:
            return stripped[:180]
    if not alive:
        return "Server exited before it answered."
    return "Dashboard did not answer."


@dataclass
class DashboardProcess:
    """One loopback server child. Stop replaces a second start."""

    process: subprocess.Popen[bytes] | None = None
    log_path: Path | None = None
    log_file: IO[str] | None = None

    def running(self) -> bool:
        """Return whether the child is still alive."""
        return self.process is not None and self.process.poll() is None

    def start(self, server: Path, env: dict[str, str]) -> None:
        """Start the server if it is not already running."""
        if self.running():
            return
        log_dir = Path(env.get("LOCALAPPDATA", ".")) / "WynDoze-InfoScanOverload"
        log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = log_dir / "server.log"
        self._close_log()
        self.log_file = self.log_path.open("w", encoding="utf-8")
        try:
            self.process = subprocess.Popen(  # noqa: S603 - argv is the local console script
                [os.fspath(server)],
                env=env,
                stdout=self.log_file,
                stderr=subprocess.STDOUT,
            )
        except OSError:
            self._close_log()
            raise

    def log_text(self) -> str:
        """Return the server log captured for this start."""
        if self.log_path is None or not self.log_path.is_file():
            return ""
        return self.log_path.read_text(encoding="utf-8", errors="replace")

    def stop(self) -> None:
        """Terminate the child and wait. Kill it if it ignores terminate."""
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=8)
        self.process = None
        self._close_log()

    def _close_log(self) -> None:
        """Close the server log handle after the child no longer needs it."""
        if self.log_file is not None:
            self.log_file.close()
            self.log_file = None


def server_env(
    *,
    token: str,
    password: str,
    port: str,
    alerts: AlertMail | None,
) -> dict[str, str]:
    """Copy the process environment and set loopback server values."""
    env = os.environ.copy()
    data_dir = Path(env.get("LOCALAPPDATA", ".")) / "WynDoze-InfoScanOverload"
    data_dir.mkdir(parents=True, exist_ok=True)
    env["RECON_DB_PATH"] = str(data_dir / "WynDoze-InfoScanOverload.sqlite3")
    env["RECON_HOST"] = "127.0.0.1"
    env["RECON_PORT"] = port
    env["RECON_INGEST_TOKEN"] = token
    env["RECON_DASHBOARD_PASSWORD"] = password
    env.pop("RECON_ALERTS", None)
    for key in (
        "RECON_SMTP_HOST",
        "RECON_SMTP_PORT",
        "RECON_SMTP_USER",
        "RECON_SMTP_PASSWORD",
        "RECON_ALERT_TO",
    ):
        env.pop(key, None)
    if alerts is not None:
        env["RECON_ALERTS"] = "1"
        env["RECON_SMTP_HOST"] = alerts.host
        env["RECON_SMTP_PORT"] = str(alerts.port)
        env["RECON_SMTP_USER"] = alerts.username
        env["RECON_SMTP_PASSWORD"] = alerts.password
        env["RECON_ALERT_TO"] = alerts.recipient
    return env


@dataclass(frozen=True, slots=True)
class AlertMail:
    """Mail fields typed into the window. The password stays in this object."""

    host: str
    port: int
    username: str
    password: str
    recipient: str


def wait_until_healthy(
    port: str,
    timeout_s: float = 15,
    process: subprocess.Popen[bytes] | None = None,
) -> bool:
    """Poll loopback ``/api/health``. Do not send the check through a proxy."""
    url = f"http://127.0.0.1:{port}/api/health"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            return False
        try:
            with opener.open(url, timeout=1) as response:
                if response.status == HTTPStatus.OK:
                    return True
        except OSError:
            time.sleep(0.2)
    return False


def main() -> None:  # noqa: C901, PLR0915 - one window, one place
    """Open the launcher window."""
    root_dir = project_root()
    token = secrets.token_urlsafe(18)
    password = secrets.token_urlsafe(18)
    dashboard = DashboardProcess()
    output = Path(os.environ.get("LOCALAPPDATA", root_dir)) / "WynDoze-InfoScanOverload"
    output.mkdir(parents=True, exist_ok=True)
    scan_file = output / "scheduled-scan.json"

    window = tk.Tk()
    window.title("WynDoze-InfoScanOverload")
    window.geometry("640x640")
    frame = ttk.Frame(window, padding=16)
    frame.pack(fill="both", expand=True)

    ttk.Label(frame, text="WynDoze-InfoScanOverload", font=("Segoe UI", 16)).pack(anchor="w")
    ttk.Label(frame, text=ABOUT, wraplength=580, justify="left").pack(anchor="w", pady=(8, 12))
    ttk.Label(
        frame,
        text=f"Dashboard user admin. Password for this window: {password}",
        wraplength=580,
    ).pack(anchor="w")

    role = tk.StringVar(value="workstation")
    cadence = tk.StringVar(value="daily")
    status = tk.StringVar(value="Server is stopped.")
    alerts_on = tk.BooleanVar(value=False)
    smtp_host = tk.StringVar(value="")
    smtp_port = tk.StringVar(value="587")
    smtp_user = tk.StringVar(value="")
    smtp_password = tk.StringVar(value="")
    smtp_to = tk.StringVar(value="")

    row = ttk.Frame(frame)
    row.pack(anchor="w", pady=8)
    ttk.Label(row, text="Scan role").pack(side="left")
    ttk.Combobox(row, textvariable=role, values=ROLES, state="readonly", width=24).pack(
        side="left", padx=8
    )

    def set_status(text: str) -> None:
        status.set(text)

    def start_dashboard() -> None:
        mail: AlertMail | None = None
        if alerts_on.get():
            try:
                port_num = int(smtp_port.get().strip())
            except ValueError:
                set_status("SMTP port must be an integer.")
                return
            mail = AlertMail(
                host=smtp_host.get().strip(),
                port=port_num,
                username=smtp_user.get().strip(),
                password=smtp_password.get(),
                recipient=smtp_to.get().strip(),
            )
            if not mail.host or not mail.username or not mail.password or not mail.recipient:
                set_status("Email alerts need host, username, password, and recipient.")
                return
        env = server_env(token=token, password=password, port="8000", alerts=mail)
        try:
            dashboard.start(tool_path("WynDoze-InfoScanOverload-server"), env)
        except OSError as exc:
            set_status(f"Could not start the server: {type(exc).__name__}")
            return
        set_status("Starting the dashboard on 127.0.0.1:8000.")

        def _watch() -> None:
            ok = wait_until_healthy("8000", process=dashboard.process)
            message = status_from_server_log(
                dashboard.log_text(),
                alive=dashboard.running(),
                healthy=ok,
            )
            window.after(0, set_status, message)

        threading.Thread(target=_watch, daemon=True).start()

    def stop_dashboard() -> None:
        dashboard.stop()
        set_status("Server is stopped.")

    def run_scan() -> None:
        agent = tool_path("WynDoze-InfoScanOverload-agent")
        argv = scan_argv(agent, role.get(), scan_file)
        env = os.environ.copy()
        env["RECON_AGENT_TOKEN"] = token

        def _run() -> None:
            try:
                completed = subprocess.run(  # noqa: S603 - local agent argv
                    argv,
                    check=False,
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=300,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                window.after(0, set_status, f"Scan failed: {type(exc).__name__}")
                return
            line = "Scan finished." if completed.returncode == 0 else "Scan exited non-zero."
            window.after(0, set_status, line)

        threading.Thread(target=_run, daemon=True).start()
        set_status("Scan is running.")

    def open_docs() -> None:
        _path, message = documentation_message(root_dir)
        set_status(message)

    def register_task() -> None:
        agent = tool_path("WynDoze-InfoScanOverload-agent")
        command = task_command(agent, role.get(), scan_file)
        argv = schtasks_create_argv(command, cadence.get())
        completed = subprocess.run(argv, check=False, capture_output=True, text=True)  # noqa: S603
        if completed.returncode == 0:
            set_status(
                f"Registered {TASK_NAME} ({cadence.get()} at 02:30). "
                "The task collects locally and does not upload or send mail."
            )
            return
        set_status("schtasks could not register the task.")

    buttons = ttk.Frame(frame)
    buttons.pack(anchor="w", pady=8)
    ttk.Button(buttons, text="Run scan", command=run_scan).pack(side="left", padx=(0, 8))
    ttk.Button(buttons, text="Start dashboard", command=start_dashboard).pack(
        side="left", padx=(0, 8)
    )
    ttk.Button(buttons, text="Stop dashboard", command=stop_dashboard).pack(
        side="left", padx=(0, 8)
    )
    ttk.Button(buttons, text="Open documentation", command=open_docs).pack(side="left")

    sched = ttk.Frame(frame)
    sched.pack(anchor="w", pady=8)
    ttk.Label(sched, text="Scheduled collect").pack(side="left")
    ttk.Combobox(sched, textvariable=cadence, values=CADENCES, state="readonly", width=12).pack(
        side="left", padx=8
    )
    ttk.Button(sched, text="Create scheduled task", command=register_task).pack(side="left")

    ttk.Checkbutton(
        frame,
        text="Email alerts while this dashboard is running",
        variable=alerts_on,
    ).pack(anchor="w", pady=(8, 4))
    form = ttk.Frame(frame)
    form.pack(anchor="w")
    for label, variable, secret in (
        ("SMTP host", smtp_host, False),
        ("SMTP port", smtp_port, False),
        ("Username", smtp_user, False),
        ("Password", smtp_password, True),
        ("Recipient", smtp_to, False),
    ):
        line = ttk.Frame(form)
        line.pack(anchor="w", pady=2)
        ttk.Label(line, text=label, width=14).pack(side="left")
        show = "*" if secret else ""
        ttk.Entry(line, textvariable=variable, width=40, show=show).pack(side="left")

    ttk.Label(frame, textvariable=status, wraplength=580).pack(anchor="w", pady=12)

    def on_close() -> None:
        stop_dashboard()
        window.destroy()

    window.protocol("WM_DELETE_WINDOW", on_close)
    window.mainloop()


if __name__ == "__main__":
    main()
