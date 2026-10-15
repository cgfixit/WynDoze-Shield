"""Unit tests for the desk query and the return-path allowlist."""

from __future__ import annotations

import pytest

from wyndoze_infoscanoverload.server.desk import legal_host, safe_next, suppress_confirm_href


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "/triage"),
        ("", "/triage"),
        ("/triage/../scans/4", "/triage"),
        ("/scans/%34", "/triage"),
        ("/scans/4/raw", "/triage"),
        ("/scans/4/", "/triage"),
        ("/scans/4?severity=high", "/triage"),
        ("https://evil.example", "/triage"),
        ("//evil.example", "/triage"),
        ("/triage#frag", "/triage"),
        ("/triage?host=bad%0d%0aX", "/triage"),
        ("/triage?status=triage&status=flagged", "/triage"),
        ("/nope", "/triage"),
        ("/triage?severity=high", "/triage?severity=high"),
        ("/triage?status=active&severity=high", "/triage?status=active&severity=high"),
        ("/triage?host=a%26status%3Darchived", "/triage?host=a%26status%3Darchived"),
        ("/triage?host=a%20b", "/triage?host=a%20b"),
        ("/scans/4", "/scans/4"),
        ("/endpoints", "/endpoints"),
        ("/", "/"),
    ],
)
def test_safe_next(value: object, expected: str) -> None:
    assert safe_next(value) == expected


def test_suppress_href_encodes_the_host_twice() -> None:
    inner = "/triage?status=triage&severity=high&host=a%26b"
    href = suppress_confirm_href(4, inner)
    assert href == (
        "/findings/4/suppress/confirm?next="
        "%2Ftriage%3Fstatus%3Dtriage%26severity%3Dhigh%26host%3Da%2526b"
    )


def test_legal_host_rejects_controls_and_keeps_ampersand() -> None:
    assert legal_host("a&status=archived") is True
    assert legal_host("a b") is True
    assert legal_host("x" * 255) is True
    assert legal_host("bad\r\nhost") is False
    assert legal_host("del\x7f") is False
    assert legal_host("") is False
    assert legal_host("x" * 256) is False
    assert legal_host(None) is False
