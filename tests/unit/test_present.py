"""Unit tests for the public scan reducer."""

from __future__ import annotations

import inspect

import pytest

from wyndoze_infoscanoverload.core.models import ProcessInfo, ScanReport, utc_now_iso
from wyndoze_infoscanoverload.server import present

_TOKEN = "gAAAAA" + ("Z" * 30)


def test_public_facts_drop_the_command_line_and_unknown_flags() -> None:
    report = ScanReport(
        scan_time_utc=utc_now_iso(),
        hostname="VBRSRV01",
        ip_addresses=["10.0.0.10"],
        processes=[
            ProcessInfo(
                pid=10,
                name="mimikatz.exe",
                cmdline=_TOKEN,
                cmdline_flags=["eventlog-clear", "not-in-the-pack-zz"],
            )
        ],
        cmdline_flags=["Encoded-PowerShell", "not-in-the-pack-zz"],
    )
    facts = present.public_scan_facts(
        report.model_dump_json(),
        "2026-01-01T00:00:00+00:00",
        frozenset({"encoded-powershell", "eventlog-clear"}),
    )
    assert facts["sealed_command_line_count"] == 1
    assert facts["patterns"] == ["encoded-powershell", "eventlog-clear"]
    assert facts["process_count"] == 1
    assert facts["ip_addresses"] == ["10.0.0.10"]
    assert _TOKEN not in str(facts)
    assert "not-in-the-pack-zz" not in str(facts)


def test_unreadable_scan_carries_no_payload() -> None:
    raw = "{" + _TOKEN
    with pytest.raises(present.UnreadableScan) as exc:
        present.public_scan_facts(raw, "t", frozenset())
    assert str(exc.value) == "unreadable scan"
    assert exc.value.__cause__ is None
    assert _TOKEN not in str(exc.value)


def test_present_does_not_import_agent_crypto() -> None:
    source = inspect.getsource(present)
    assert "agent.crypto" not in source
    assert "agent.cmdline" not in source
    assert "decrypt" not in source
