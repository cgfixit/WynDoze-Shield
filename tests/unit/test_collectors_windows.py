"""Windows collector edges. Fixtures only. No live registry and no live group."""

from __future__ import annotations

import sys

import pytest

from wyndoze_infoscanoverload.agent.collectors import (
    _ADMIN_SID,
    _clip,
    _collect_windows_software,
    _consume_software_lines,
    local_admin_argv,
)
from wyndoze_infoscanoverload.core.models import SoftwareInfo

# The "oem" codec exists only on Windows. cp437 is the US OEM code page, so the
# round trip still proves OEM bytes are not UTF-8 on the Linux CI leg.
_OEM = "oem" if sys.platform == "win32" else "cp437"


def test_oem_display_name_round_trip() -> None:
    name = "Äpfelbüchse"
    blob = f"    DisplayName    REG_SZ    {name}\n".encode(_OEM)
    as_utf8 = blob.decode("utf-8", errors="replace")
    assert name not in as_utf8
    found: dict[str, SoftwareInfo] = {}
    assert _consume_software_lines(blob.decode(_OEM), 10, found) is False
    assert list(found) == [name]


def test_software_hive_stops_at_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake(command: list[str], timeout: int, *, encoding: str = "utf-8", health=None) -> str:
        assert health is None
        calls.append(command)
        assert encoding == "oem"
        assert timeout == 5
        lines = [f"    DisplayName    REG_SZ    App{index}" for index in range(3)]
        return "\n".join(lines)

    monkeypatch.setattr("wyndoze_infoscanoverload.agent.collectors._run_command", fake)
    rows = _collect_windows_software(2, 5)
    assert len(calls) == 1
    assert calls[0][-1] == "/reg:64"
    assert [row.name for row in rows] == ["App0", "App1"]


def test_local_admin_argv_uses_sid() -> None:
    argv = local_admin_argv()
    assert isinstance(argv, list)
    assert all(isinstance(part, str) for part in argv)
    assert any(_ADMIN_SID in part for part in argv)
    joined = " ".join(argv).lower()
    assert "the command completed" not in joined
    assert "net" not in argv


def test_long_exe_is_clipped() -> None:
    stored = _clip("x" * 600)
    assert stored is not None
    assert len(stored) == 512
    assert _clip(None) is None
