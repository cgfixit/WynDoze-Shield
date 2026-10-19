"""Opt-in command lines. Patterns run in memory. Disk and upload see ciphertext."""

from __future__ import annotations

import ntpath
import re
import shlex

from wyndoze_infoscanoverload.agent.crypto import encrypt_bytes
from wyndoze_infoscanoverload.core.models import ScanReport

# Bound UTF-8 bytes as well as characters so Fernet fits the 4096-character field.
_PLAIN_MAX = 800
_PLAIN_MAX_BYTES = 3000
_POWERSHELL = frozenset({"powershell", "powershell.exe", "pwsh", "pwsh.exe"})
_PROCDUMP = frozenset(
    {"procdump", "procdump.exe", "procdump64", "procdump64.exe", "procdump64a", "procdump64a.exe"}
)


def _executable_name(name: str | None, command_line: str) -> str:
    if name:
        return ntpath.basename(name).lower()
    first = re.match(r'^\s*(?:"([^"]+)"|(\S+))', command_line)
    return ntpath.basename(first.group(1) or first.group(2)).lower() if first else ""


def _arguments(command_line: str) -> list[str]:
    """Split direct Windows invocations enough to identify utility verbs and targets."""
    try:
        parts = shlex.split(command_line, posix=False)
    except ValueError:
        parts = command_line.split()
    return [part.strip('"').lower() for part in parts[1:]]


def _powershell_body(command_line: str) -> str | None:
    """Return an explicit PowerShell command body with string literals removed."""
    try:
        parts = shlex.split(command_line, posix=False)[1:]
    except ValueError:
        return None
    lowered = [part.strip('"').lower() for part in parts]
    if any(arg in {"-file", "-f"} for arg in lowered):
        return None
    try:
        command_at = next(i for i, arg in enumerate(lowered) if arg in {"-command", "-c"})
    except StopIteration:
        # shortcut: parse explicit -Command only, add Windows argv parsing for implicit commands
        return None
    body = " ".join(parts[command_at + 1 :]).strip()
    if len(body) > 1 and body[0] == body[-1] == '"':
        body = body[1:-1]
    body = re.sub(r"'(?:''|[^'])*'|\"(?:`.|[^\"`])*\"", "", body)
    body = re.sub(r"(?s)<#.*?#>", "", body)
    return re.sub(r"(?m)#.*$", "", body)


def _procdump_target(arguments: list[str]) -> str | None:
    """Find a direct ProcDump target, failing closed on unsupported options."""
    no_value = {"-accepteula", "-mm", "-ma", "-mt", "-mp", "-mk", "-64", "-wer", "-o"}
    with_value = {"-mc", "-md"}
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in no_value:
            index += 1
        elif argument in with_value and index + 1 < len(arguments):
            index += 2
        elif argument.startswith("-"):
            return None
        else:
            return argument
    return None


def _is_autorun_key(key: str) -> bool:
    key = key.rstrip("\\")
    roots = ("hklm\\", "hkey_local_machine\\", "hkcu\\", "hkey_current_user\\")
    if not key.startswith(roots):
        return False
    relative = key.split("\\", 1)[1]
    return relative in {
        r"software\microsoft\windows\currentversion\run",
        r"software\microsoft\windows\currentversion\runonce",
        r"software\wow6432node\microsoft\windows\currentversion\run",
        r"software\wow6432node\microsoft\windows\currentversion\runonce",
    }


def _flags_for_process(name: str | None, command_line: str) -> set[str]:  # noqa: C901, PLR0912
    """Return bounded labels for direct, recognized command invocations."""
    executable = _executable_name(name, command_line)
    arguments = _arguments(command_line)
    flags: set[str] = set()

    if executable in _POWERSHELL:
        host_patterns = (
            ("encoded-powershell", r"(?:^|\s)-enc(?:odedcommand)?(?:\s|$)"),
            ("execution-policy-bypass", r"(?:-executionpolicy\s+bypass|-ep\s+bypass)"),
            ("hidden-window", r"-windowstyle\s+hidden"),
        )
        flags.update(
            label
            for label, pattern in host_patterns
            if re.search(pattern, command_line, re.IGNORECASE)
        )
        body = _powershell_body(command_line)
        if body is not None:
            body_patterns = (
                ("encoded-powershell", r"frombase64string"),
                (
                    "invoke-expression",
                    r"(?:^|[;|=(&{]\s*)(?:iex|invoke-expression)\b",
                ),
                ("credential-hive", r"(?:ntds\.dit|hklm\\sam|sekurlsa)"),
                (
                    "download-cradle",
                    (
                        r"(?:\.(?:downloadstring|downloadfile)\s*\("
                        r"|(?:^|[;|=(&{]\s*)(?:iwr|invoke-webrequest)\b)"
                    ),
                ),
            )
            flags.update(
                label for label, pattern in body_patterns if re.search(pattern, body, re.IGNORECASE)
            )

    if executable in _PROCDUMP:
        target = _procdump_target(arguments)
        sensitive_target = target is not None and ntpath.basename(target) in {"lsass", "lsass.exe"}
        dump_type = any(
            arg in {"-mm", "-ma", "-mt", "-mp", "-mc", "-md", "-mk"} for arg in arguments
        )
        if sensitive_target or dump_type:
            flags.add("dump-operation")
        if sensitive_target:
            flags.add("sensitive-target")
    elif executable in {"ntdsutil", "ntdsutil.exe"}:
        try:
            ifm_at = arguments.index("ifm")
        except ValueError:
            ifm_at = -1
        create = arguments[ifm_at + 1] if ifm_at >= 0 and len(arguments) > ifm_at + 1 else ""
        if create == "create" or create.startswith(
            ("create full ", "create rodc ", "create sysvol ")
        ):
            flags.update({"dump-operation", "sensitive-target"})

    if (executable in {"vssadmin", "vssadmin.exe"} and arguments[:2] == ["delete", "shadows"]) or (
        executable in {"wmic", "wmic.exe"} and arguments[:2] == ["shadowcopy", "delete"]
    ):
        flags.add("recovery-delete")

    if (
        executable in {"wevtutil", "wevtutil.exe"}
        and len(arguments) > 1
        and arguments[0] in {"cl", "clear-log"}
        and not arguments[1].startswith("/")
    ):
        flags.add("eventlog-clear")

    if (
        executable in {"reg", "reg.exe"}
        and len(arguments) > 1
        and arguments[0] == "add"
        and _is_autorun_key(arguments[1])
    ):
        flags.update({"autorun-write", "startup-run-key"})

    if executable in {"certutil", "certutil.exe"} and any(
        arg in {"-urlcache", "-decode"} for arg in arguments
    ):
        flags.add("certutil-download")
    if executable in {"bitsadmin", "bitsadmin.exe"} and "/transfer" in arguments:
        flags.add("bitsadmin-transfer")
    return flags


def seal_command_lines(report: ScanReport, key: str) -> None:
    """Replace each command line with a Fernet token and keep only pattern names."""
    flags: set[str] = set()
    for proc in report.processes:
        raw = proc.cmdline
        if not raw:
            continue
        clipped = raw[:_PLAIN_MAX]
        proc.cmdline_flags = sorted(_flags_for_process(proc.name, clipped))
        flags.update(proc.cmdline_flags)
        payload = clipped.encode("utf-8")[:_PLAIN_MAX_BYTES].decode("utf-8", errors="ignore")
        proc.cmdline = encrypt_bytes(payload.encode("utf-8"), key).decode("ascii")
    report.cmdline_flags = sorted(flags)
