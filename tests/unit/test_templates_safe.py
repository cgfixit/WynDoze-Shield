"""Unit tests for technique links and evidence display."""

from __future__ import annotations

import inspect

from wyndoze_infoscanoverload.core.rulepacks import default_rule_pack
from wyndoze_infoscanoverload.server import templates
from wyndoze_infoscanoverload.server.desk import DeskQuery

_CATALOG = "https://attack.mitre.org/techniques/T1021/001/"
_TOKEN = "gAAAAA" + "x" * 20


def test_catalog_technique_href_is_kept() -> None:
    assert templates.safe_technique_href(_CATALOG) == _CATALOG


def test_javascript_technique_href_is_refused() -> None:
    assert templates.safe_technique_href("javascript:alert(1)") is None


def test_sealed_evidence_is_replaced() -> None:
    shown = templates.display_evidence(_TOKEN)
    assert _TOKEN not in shown
    assert shown == "Sealed value. Not shown."


def test_normal_evidence_is_unchanged() -> None:
    assert templates.display_evidence("port 3389 listening") == "port 3389 listening"


def test_card_uses_the_helpers() -> None:
    finding = _card("high", "Title")
    finding["evidence"] = [_TOKEN, "port 3389 listening"]
    page = templates.triage_page([finding], DeskQuery("triage", None, None), [], {})
    assert 'rel="noopener noreferrer"' in page
    assert _CATALOG in page
    assert _TOKEN not in page
    assert "Sealed value. Not shown." in page
    assert "port 3389 listening" in page


def _card(severity: str, title: str, *, finding_id: int = 1, hostname: str = "VBRSRV01") -> dict:
    return {
        "id": finding_id,
        "severity": severity,
        "hostname": hostname,
        "title": title,
        "message": "Message",
        "rule_id": "rule",
        "category": "cat",
        "tactic": "tactic",
        "technique_name": "Name",
        "technique_id": "T1021.001",
        "technique_url": _CATALOG,
        "status": "triage",
        "seen_count": 1,
        "first_seen_utc": "2026-01-01T00:00:00+00:00",
        "last_seen_utc": "2026-01-01T00:00:00+00:00",
        "evidence": ["port 3389 listening"],
        "dedupe_key": "do-not-render",
    }


def test_low_and_info_collapse_unless_filtered() -> None:
    findings = [
        _card("critical", "Crit"),
        _card("low", "Quiet", finding_id=2),
        _card("info", "Note", finding_id=3),
    ]
    page = templates.triage_page(findings, DeskQuery("triage", None, None), [], {})
    assert page.index("Crit") < page.index("<details>")
    details = page.split("<details>", 1)[1]
    assert "Quiet" in details
    assert "Note" in details
    assert "Low and info (2)" in page
    for level in ("low", "info"):
        shown = templates.triage_page(findings, DeskQuery("triage", level, None), [], {})
        assert "<details>" not in shown
        assert "Quiet" in shown
        assert "Note" in shown


def test_paginated_inbox_and_scan_cap_notice() -> None:
    query = DeskQuery("triage", None, None)
    empty = templates.triage_page([], query, [], {})
    assert "No findings for this filter." in empty
    findings = [_card("high", f"T{index}", finding_id=index + 1) for index in range(500)]
    page = templates.triage_page(findings[:50], query, [], {}, has_next=True)
    assert "Page 1" in page
    assert ">Next</a>" in page
    assert "cap was hit" not in page
    assert page.count('class="finding"') == 50
    scan = templates.scan_page({}, findings, "/scans/1", {})
    assert "The 500-finding cap was hit." in scan
    assert scan.count('class="finding"') == 500


def test_detail_keeps_sealed_evidence_hidden() -> None:
    finding = _card("high", "Title")
    finding["evidence"] = [_TOKEN, "<script>" + "X" * 400 + "</script>"]
    page = templates.finding_detail(finding, None, {})
    assert _TOKEN not in page
    assert "Sealed value. Not shown." in page
    assert "&lt;script&gt;" + "X" * 400 + "&lt;/script&gt;" in page


def test_evidence_label_requires_cmdline_rule() -> None:
    names = templates.cmdline_rule_names(default_rule_pack().rules)
    assert templates.evidence_label("cmd-suspicious-line", ["Encoded-PowerShell"], names) == (
        "Matched pattern"
    )
    assert (
        templates.evidence_label("proc-credential-dumping", ["encoded-powershell"], names)
        == "Evidence"
    )
    mixed = ["encoded-powershell", "not-in-pack"]
    assert templates.evidence_label("cmd-suspicious-line", mixed, names) == "Evidence"


def test_templates_do_not_import_agent_crypto() -> None:
    source = inspect.getsource(templates)
    assert "agent.crypto" not in source
    assert "agent.cmdline" not in source
