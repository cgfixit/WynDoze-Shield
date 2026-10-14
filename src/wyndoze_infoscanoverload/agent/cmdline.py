"""Opt-in command lines. Patterns run in memory. Disk and upload see ciphertext."""

from __future__ import annotations

import re

from wyndoze_infoscanoverload.agent.crypto import encrypt_bytes
from wyndoze_infoscanoverload.core.models import ScanReport

# Clip before encrypt so the Fernet token fits the model field.
_PLAIN_MAX = 800
_FLAG_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("encoded-powershell", re.compile(r"(?i)(?:-enc(?:odedcommand)?\b|frombase64string)")),
    ("invoke-expression", re.compile(r"(?i)\b(?:iex|invoke-expression)\b")),
    ("credential-hive", re.compile(r"(?i)(?:ntds\.dit|hklm\\sam|sekurlsa)")),
    (
        "download-cradle",
        re.compile(r"(?i)(?:downloadstring|downloadfile|\biwr\b|invoke-webrequest)"),
    ),
    (
        "execution-policy-bypass",
        re.compile(r"(?i)(?:-executionpolicy\s+bypass|-ep\s+bypass)"),
    ),
    ("hidden-window", re.compile(r"(?i)-windowstyle\s+hidden")),
    (
        "certutil-download",
        re.compile(r"(?i)certutil(?:\.exe)?\s+.*(?:-urlcache|-decode)"),
    ),
    (
        "bitsadmin-transfer",
        re.compile(r"(?i)bitsadmin(?:\.exe)?\s+.*/transfer"),
    ),
    ("startup-run-key", re.compile(r"(?i)currentversion\\run")),
)


def seal_command_lines(report: ScanReport, key: str) -> None:
    """Replace each command line with a Fernet token and keep only pattern names."""
    flags: set[str] = set()
    for proc in report.processes:
        raw = proc.cmdline
        if not raw:
            continue
        clipped = raw[:_PLAIN_MAX]
        for name, pattern in _FLAG_PATTERNS:
            if pattern.search(clipped):
                flags.add(name)
        proc.cmdline = encrypt_bytes(clipped.encode("utf-8"), key).decode("ascii")
    report.cmdline_flags = sorted(flags)
