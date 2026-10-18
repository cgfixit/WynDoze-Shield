"""Server-rendered HTML.

No external template files — pure functions returning safe HTML. All dynamic
values pass through ``html.escape`` to prevent stored XSS from
attacker-controlled telemetry (hostnames, process names, etc.).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from html import escape
from typing import Any

from wyndoze_infoscanoverload.core.rules import Rule
from wyndoze_infoscanoverload.server.desk import (
    DeskQuery,
    desk_path,
    encode_desk_query,
    host_href,
    legal_host,
    suppress_confirm_href,
)

_STYLE = """
:root {
  color-scheme: dark;
  --bg: #0d1117;
  --text: #e6edf3;
  --header-bg: #161b22;
  --border: #30363d;
  --muted: #8b949e;
  --link: #58a6ff;
  --line: #21262d;
  --critical: #da3633;
  --high: #fb8500;
  --medium: #d4a72c;
  --low: #388bfd;
  --ink: #1a1a1a;
  --on-strong: #fff;
}
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    margin: 0; background: var(--bg); color: var(--text); }
.skip { position: absolute; left: 8px; top: 8px; padding: 8px 12px;
    background: var(--header-bg); color: var(--link); z-index: 1;
    transform: translateY(-200%); }
.skip:focus { transform: none; }
header { background: var(--header-bg); padding: 16px 24px;
    border-bottom: 1px solid var(--border); }
header h1 { margin: 0; font-size: 18px; }
header .sub { color: var(--muted); font-size: 12px; margin-top: 4px; }
nav { padding: 12px 24px; background: var(--bg); border-bottom: 1px solid var(--border); }
nav a { color: var(--link); margin-right: 16px; text-decoration: none; font-size: 14px; }
nav a:hover { text-decoration: underline; }
main { padding: 24px; max-width: 1200px; margin: 0 auto; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 11px; }
tr:hover { background: var(--header-bg); }
.badge { padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; }
.critical { background: var(--critical); color: var(--on-strong); }
.high { background: var(--high); color: var(--ink); }
.medium { background: var(--medium); color: var(--ink); }
.low { background: var(--low); color: var(--on-strong); }
.info { background: var(--border); color: var(--text); }
.cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 20px; }
.card { background: var(--header-bg); border: 1px solid var(--border); border-radius: 8px;
    padding: 16px 20px; min-width: 130px; }
.card .n { font-size: 28px; font-weight: 700; }
.card .l { color: var(--muted); font-size: 12px; margin-top: 4px; }
form.inline { display: inline; }
button { background: var(--line); color: var(--text); border: 1px solid var(--border);
    border-radius: 6px; padding: 4px 10px; cursor: pointer; font-size: 12px; }
button:hover { background: var(--border); }
code { background: var(--header-bg); padding: 1px 5px; border-radius: 4px; font-size: 12px; }
.muted { color: var(--muted); }
.finding { max-width: 42rem; background: var(--header-bg); border: 1px solid var(--border);
    border-left: 4px solid var(--border); border-radius: 8px; padding: 16px 20px;
    margin: 0 0 16px; }
.finding[data-severity="critical"] { border-left-color: var(--critical); }
.finding[data-severity="high"] { border-left-color: var(--high); }
.finding[data-severity="medium"] { border-left-color: var(--medium); }
.finding[data-severity="low"] { border-left-color: var(--low); }
.finding[data-severity="info"] { border-left-color: var(--border); }
.finding h3 { margin: 0 0 8px; font-size: 18px; }
.finding h4 { margin: 12px 0 4px; font-size: 12px; color: var(--muted); }
.finding ul { margin: 0; padding-left: 18px; }
.actions { display: flex; gap: 8px; align-items: center; margin-top: 12px; }
.actions-main, .actions-sticky { display: flex; gap: 8px; }
.actions-sticky { margin-left: auto; }
button.flag { border-color: var(--high); }
button.suppress { border-color: var(--critical); background: transparent; }
.filters a { color: var(--link); margin-right: 12px; }
.filters a[aria-current="true"] { text-decoration: underline; }
.scan { border-bottom: 1px solid var(--line); padding: 8px 0; }
"""

_NAV_LINKS: tuple[tuple[str, str], ...] = (
    ("/", "Summary"),
    ("/triage", "Triage Inbox"),
    ("/timeline", "Timeline"),
    ("/endpoints", "Endpoints"),
    ("/reports/summary", "Reports"),
)
_TECHNIQUE_PREFIX = "https://attack.mitre.org/techniques/"
_SEALED_MARK = "gAAAA"
_SEALED_MIN_LEN = 20
_REJECTED_HREF_CHARS = " \"'<>\r\n\\"
_FINDING_CAP = 500
_QUIET_SEVERITIES = frozenset({"low", "info"})
_SEVERITY_CHIPS = ("critical", "high", "medium", "low", "info")
_FLAG_NOTE = (
    "Flag is a mark for this visit. The next scan that sees the same evidence "
    "puts it back in triage. Archive and Suppress stay in those states."
)
_MAIN_ACTIONS: dict[str, tuple[tuple[str, str], ...]] = {
    "triage": (("flag", "Flag"), ("archive", "Archive")),
    "flagged": (("archive", "Archive"),),
    "archived": (("triage", "Re-triage"),),
    "suppressed": (("triage", "Re-triage"),),
}
_STICKY_ACTIONS: dict[str, tuple[tuple[str, str], ...]] = {
    "triage": (("suppress", "Suppress"),),
    "flagged": (("suppress", "Suppress"), ("triage", "Re-triage")),
    "archived": (),
    "suppressed": (),
}
_ACTION_NOTE = {
    "triage": "Suppress asks first, then stays hidden on later scans.",
    "flagged": "Suppress asks first, then stays hidden on later scans.",
    "archived": "Re-triage sends this finding back to the inbox.",
    "suppressed": "Re-triage sends this finding back to the inbox.",
}
_BUTTON_CLASS = {
    "flag": "flag",
    "archive": "archive",
    "suppress": "suppress",
    "triage": "retriage",
}


def safe_technique_href(url: object) -> str | None:
    """Return the URL only when it is an https ATT&CK technique page."""
    if not isinstance(url, str) or not url.startswith(_TECHNIQUE_PREFIX):
        return None
    if any(char in url for char in _REJECTED_HREF_CHARS):
        return None
    return url


def display_evidence(item: object) -> str:
    """Replace a Fernet-looking token with a fixed label. Never decrypt."""
    text = str(item)
    if text.startswith(_SEALED_MARK) and len(text) >= _SEALED_MIN_LEN:
        return "Sealed value. Not shown."
    return text


def _nav(current: str) -> str:
    """Render the primary navigation, marking the current page."""
    links = []
    for href, label in _NAV_LINKS:
        mark = " aria-current='page'" if href == current else ""
        links.append(f"<a href='{href}'{mark}>{escape(label)}</a>")
    return "<nav>" + "".join(links) + "</nav>"


def _severity_badge(severity: str) -> str:
    sev = escape(severity or "info")
    return f'<span class="badge {sev}">{sev.upper()}</span>'


def page(title: str, body: str, *, current: str) -> str:
    """Wrap body content in the full HTML shell."""
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{escape(title)}</title><style>{_STYLE}</style></head><body>"
        "<a class='skip' href='#content'>Skip to content</a>"
        "<header><h1>WynDoze-InfoScanOverload</h1>"
        "<div class='sub'>Local triage</div></header>"
        f"{_nav(current)}<main id='content' tabindex='-1'>{body}</main></body></html>"
    )


_SUMMARY_LEVELS = ("critical", "high", "medium", "low")
_STATUS_LINKS = (
    ("triage", "/triage", "in triage"),
    ("flagged", "/triage?status=flagged", "flagged"),
    ("archived", "/triage?status=archived", "archived"),
    ("suppressed", "/triage?status=suppressed", "suppressed"),
)
_ACTIVE_NOTE = (
    "Active means triage or flagged. Flag does not stick across a later scan. "
    "Archive and Suppress do."
)


def summary_page(summary: dict[str, Any]) -> str:
    """Render the morning count strip. A zero is not painted as an alarm."""
    sev = summary.get("active_findings_by_severity", {})
    status = summary.get("findings_by_status", {})
    cards = [_severity_count_card(level, int(sev.get(level, 0) or 0)) for level in _SUMMARY_LEVELS]
    info = int(sev.get("info", 0) or 0)
    if info:
        cards.append(_severity_count_card("info", info))
    bits = [
        f'<a href="{escape(href)}">{int(status.get(word, 0) or 0)} {escape(label)}</a>'
        for word, href, label in _STATUS_LINKS
    ]
    endpoints = int(summary.get("endpoints", 0) or 0)
    scans = int(summary.get("scans", 0) or 0)
    body = (
        "<h2>Summary</h2>"
        f"<p>{escape(_ACTIVE_NOTE)}</p>"
        f'<div class="cards">{"".join(cards)}</div>'
        f"<p>{' &middot; '.join(bits)} &middot; {endpoints} endpoints"
        f" &middot; {scans} scans</p>"
    )
    return page("WynDoze-InfoScanOverload Summary", body, current="/")


def _severity_count_card(level: str, count: int) -> str:
    """Link an active severity count. A zero does not use the severity class."""
    href = "/triage?" + encode_desk_query("active", level, None)
    card_class = f"card {level}" if count else "card"
    number_class = f"n {level}" if count else "n"
    return (
        f'<a class="{card_class}" href="{escape(href)}">'
        f'<div class="{number_class}">{count}</div>'
        f'<div class="l">{escape(level.capitalize())}</div></a>'
    )


def cmdline_rule_names(rules: Iterable[Rule]) -> dict[str, frozenset[str]]:
    """Index loaded cmdline_flag rules by id. Names are already lowercased."""
    return {rule.rule_id: frozenset(rule.names) for rule in rules if rule.kind == "cmdline_flag"}


def evidence_label(
    rule_id: object,
    evidence: object,
    cmdline_rules: Mapping[str, frozenset[str]],
) -> str:
    """Return Matched pattern only when every item is a name of that rule."""
    if not isinstance(rule_id, str) or not isinstance(evidence, list):
        return "Evidence"
    names = cmdline_rules.get(rule_id)
    if names is None:
        return "Evidence"
    for item in evidence:
        if str(item).strip().lower() not in names:
            return "Evidence"
    return "Matched pattern"


def triage_page(
    findings: list[dict[str, Any]],
    query: DeskQuery,
    endpoints: list[dict[str, Any]],
    cmdline_rules: Mapping[str, frozenset[str]],
) -> str:
    """Render the triage desk as one card per finding."""
    body = (
        "<h2>Triage Inbox</h2>"
        f"{_filter_row(query, endpoints)}"
        f'<p class="muted">{escape(_FLAG_NOTE)}</p>'
        f"{_cap_note(findings)}"
        f"{_finding_stack(findings, query, cmdline_rules)}"
    )
    return page("WynDoze-InfoScanOverload Triage Inbox", body, current="/triage")


def _cap_note(findings: list[dict[str, Any]]) -> str:
    """Say so when the list is the storage cap."""
    if len(findings) != _FINDING_CAP:
        return ""
    return '<p class="muted">The 500-finding cap was hit.</p>'


def _finding_stack(
    findings: list[dict[str, Any]],
    query: DeskQuery,
    cmdline_rules: Mapping[str, frozenset[str]],
    *,
    return_path: str | None = None,
) -> str:
    """Render cards. Low and info stay closed unless that severity is the filter."""
    if not findings:
        if return_path is not None:
            return ""
        return (
            '<p class="muted">No findings for this filter.</p>'
            '<p><a href="/triage">Clear the filter</a></p>'
        )
    next_path = desk_path(query) if return_path is None else return_path
    collapse = query.severity not in _QUIET_SEVERITIES
    primary: list[str] = []
    quiet: list[str] = []
    for finding in findings:
        card = _finding_card(finding, next_path=next_path, query=query, cmdline_rules=cmdline_rules)
        severity = str(finding.get("severity") or "")
        if collapse and severity in _QUIET_SEVERITIES:
            quiet.append(card)
        else:
            primary.append(card)
    quiet_html = ""
    if quiet:
        quiet_html = (
            f"<details><summary>Low and info ({len(quiet)})</summary>{''.join(quiet)}</details>"
        )
    return "".join(primary) + quiet_html


def _filter_row(query: DeskQuery, endpoints: list[dict[str, Any]]) -> str:
    """Render severity and host chips as links."""
    severity_chips = [_filter_chip(query, None, query.host, "Any", current=query.severity is None)]
    severity_chips.extend(
        _filter_chip(query, level, query.host, level, current=query.severity == level)
        for level in _SEVERITY_CHIPS
    )
    host_chips = [_filter_chip(query, query.severity, None, "Any host", current=query.host is None)]
    for endpoint in endpoints:
        name = str(endpoint.get("hostname") or "")
        if not legal_host(name):
            continue
        host_chips.append(
            _filter_chip(query, query.severity, name, name, current=query.host == name)
        )
    return (
        f'<p class="filters">{"".join(severity_chips)}</p>'
        f'<p class="filters">{"".join(host_chips)}</p>'
    )


def _filter_chip(
    query: DeskQuery,
    severity: str | None,
    host: str | None,
    label: str,
    *,
    current: bool,
) -> str:
    """Render one filter link."""
    encoded = encode_desk_query(query.status, severity, host)
    href = "/triage" if not encoded else f"/triage?{encoded}"
    mark = ' aria-current="true"' if current else ""
    return f'<a href="{escape(href)}"{mark}>{escape(label)}</a>'


def _finding_card(
    finding: dict[str, Any],
    *,
    next_path: str,
    query: DeskQuery,
    cmdline_rules: Mapping[str, frozenset[str]],
) -> str:
    """Render one decision card. The button set follows the row status."""
    severity = escape(str(finding.get("severity") or "info"))
    evidence = finding.get("evidence")
    items = evidence if isinstance(evidence, list) else []
    label = evidence_label(finding.get("rule_id"), items, cmdline_rules)
    list_html = "".join(f"<li>{escape(display_evidence(item))}</li>" for item in items)
    return (
        f'<article class="finding" data-severity="{severity}">'
        f"<h3>{escape(str(finding.get('title') or ''))}</h3>"
        f"<p>{_host_html(query, str(finding.get('hostname') or ''))}</p>"
        f"<p>{escape(str(finding.get('message') or ''))}</p>"
        f"<p>{_identity_line(finding)}</p>"
        f"<p>{_seen_line(finding)}</p>"
        f"<h4>{escape(label)}</h4>"
        f"<ul>{list_html}</ul>"
        f"{_action_row(finding, next_path)}"
        "</article>"
    )


def _host_html(query: DeskQuery, hostname: str) -> str:
    """Link a legal host. An illegal name is text only."""
    shown = escape(hostname)
    href = host_href(query, hostname)
    if href is None:
        return shown
    return f'<a href="{escape(href)}">{shown}</a>'


def _identity_line(finding: dict[str, Any]) -> str:
    """Render rule, category, tactic, and technique. The link is allowlisted."""
    technique = escape(str(finding.get("technique_id") or ""))
    href = safe_technique_href(finding.get("technique_url"))
    if href and technique:
        technique = (
            f'<a href="{escape(href)}" target="_blank" rel="noopener noreferrer">{technique}</a>'
        )
    parts = [
        escape(str(finding.get("rule_id") or "")),
        escape(str(finding.get("category") or "")),
        escape(str(finding.get("tactic") or "")),
        escape(str(finding.get("technique_name") or "")),
        technique,
    ]
    return " &middot; ".join(part for part in parts if part)


def _seen_line(finding: dict[str, Any]) -> str:
    """Render the seen count and the stored timestamps."""
    count = int(finding.get("seen_count") or 1)
    first = escape(str(finding.get("first_seen_utc") or ""))
    last = escape(str(finding.get("last_seen_utc") or ""))
    return f"Seen {count} &middot; {first} &middot; {last}"


def _action_row(finding: dict[str, Any], next_path: str) -> str:
    """Render the main and sticky actions for this finding's own status."""
    status = str(finding.get("status") or "")
    finding_id = int(finding.get("id") or 0)
    main = "".join(
        _action_form(finding_id, verb, label, next_path)
        for verb, label in _MAIN_ACTIONS.get(status, ())
    )
    sticky_actions = _STICKY_ACTIONS.get(status, ())
    sticky = "".join(
        _sticky_control(finding_id, verb, label, next_path) for verb, label in sticky_actions
    )
    sticky_html = f'<div class="actions-sticky">{sticky}</div>' if sticky else ""
    note = _ACTION_NOTE.get(status, "")
    note_html = f'<p class="muted">{escape(note)}</p>' if note else ""
    return (
        f'<div class="actions"><div class="actions-main">{main}</div>{sticky_html}</div>{note_html}'
    )


def _sticky_control(finding_id: int, verb: str, label: str, next_path: str) -> str:
    """Render Suppress as a confirm link. Other sticky verbs stay one click."""
    if verb != "suppress":
        return _action_form(finding_id, verb, label, next_path)
    href = suppress_confirm_href(finding_id, next_path)
    return f'<a href="{escape(href)}">{escape(label)}</a>'


def suppress_confirm_page(finding: dict[str, Any], next_path: str) -> str:
    """Render the suppress confirm page. ``next_path`` is already allowlisted."""
    finding_id = int(finding.get("id") or 0)
    title = escape(str(finding.get("title") or ""))
    severity = _severity_badge(str(finding.get("severity") or ""))
    sentence = (
        "Suppress sticks across later scans. The rule still runs. "
        "The same evidence stays suppressed instead of returning to triage."
    )
    body = (
        "<h2>Suppress</h2>"
        f"<p>{severity} {title}</p>"
        f"<p>{escape(sentence)}</p>"
        f'<p><a href="{escape(next_path)}">Cancel</a></p>'
        f'<form method="post" action="/findings/{finding_id}/suppress">'
        f'<input type="hidden" name="next" value="{escape(next_path)}">'
        '<button type="submit" class="suppress">Suppress</button>'
        "</form>"
    )
    return page("WynDoze-InfoScanOverload Suppress", body, current="/triage")


def _action_form(finding_id: int, verb: str, label: str, next_path: str) -> str:
    """Render one one-click status form."""
    kind = _BUTTON_CLASS[verb]
    return (
        f'<form class="inline" method="post" action="/findings/{finding_id}/{verb}">'
        f'<input type="hidden" name="next" value="{escape(next_path)}">'
        f'<button type="submit" class="{kind}">{escape(label)}</button>'
        "</form>"
    )


def timeline_page(scans: list[dict[str, Any]]) -> str:
    """Render recent scans as text rows that link to the scan page."""
    if not scans:
        stack = "<p class='muted'>No scans.</p>"
    else:
        stack = "".join(_scan_block(scan) for scan in scans)
    return page(
        "WynDoze-InfoScanOverload Timeline",
        f"<h2>Timeline</h2>{stack}",
        current="/timeline",
    )


def _scan_block(scan: dict[str, Any]) -> str:
    """Render one public scan row without raw JSON."""
    scan_id = int(scan.get("id") or 0)
    fields = (
        "received_at_utc",
        "hostname",
        "fqdn",
        "role",
        "scan_time_utc",
        "platform_system",
        "platform_release",
    )
    bits = [escape(str(scan.get(name) or "")) for name in fields]
    counts = " ".join(
        f"{label} {int(scan.get(column) or 0)}"
        for label, column in (
            ("findings", "finding_count"),
            ("critical", "critical_count"),
            ("high", "high_count"),
            ("medium", "medium_count"),
            ("low", "low_count"),
        )
    )
    return (
        '<article class="scan">'
        f'<p><a href="/scans/{scan_id}">{scan_id}</a></p>'
        f"<p>{' &middot; '.join(bits)}</p>"
        f"<p>{escape(counts)}</p>"
        "</article>"
    )


def scan_page(
    facts: dict[str, Any],
    findings: list[dict[str, Any]],
    next_path: str,
    cmdline_rules: Mapping[str, frozenset[str]],
) -> str:
    """Render redacted scan facts and the findings this scan last touched."""
    query = DeskQuery(status="triage", severity=None, host=None)
    cards = _finding_stack(findings, query, cmdline_rules, return_path=next_path)
    body = (
        f"<h2>Scan</h2>{_scan_facts(facts)}<p>Findings were last updated by this scan.</p>{cards}"
    )
    return page("WynDoze-InfoScanOverload Scan", body, current="/timeline")


def _scan_facts(facts: dict[str, Any]) -> str:
    """Render public scan fields. Callers must not pass a command line."""
    rows = [
        f"<li>{escape(label)}: {escape(str(facts.get(key) or ''))}</li>"
        for label, key in (
            ("Hostname", "hostname"),
            ("FQDN", "fqdn"),
            ("Role", "role"),
            ("Scan time", "scan_time_utc"),
            ("Received", "received_at_utc"),
            ("Platform", "platform_system"),
            ("Release", "platform_release"),
        )
    ]
    addresses = facts.get("ip_addresses")
    ip_list = addresses if isinstance(addresses, list) else []
    ip_html = ", ".join(escape(str(ip)) for ip in ip_list)
    rows.append(f"<li>Addresses: {ip_html}</li>")
    rows.extend(
        f"<li>{escape(label)}: {int(facts.get(key) or 0)}</li>"
        for label, key in (
            ("Processes", "process_count"),
            ("Listening sockets", "listening_count"),
            ("Services", "service_count"),
            ("Software", "software_count"),
            ("Local admins", "local_admin_count"),
        )
    )
    patterns = facts.get("patterns")
    names = patterns if isinstance(patterns, list) else []
    chips = "".join(f"<li>{escape(str(name))}</li>" for name in names)
    pattern_html = ""
    if names:
        pattern_html = f"<h3>Matched pattern, not the command line</h3><ul>{chips}</ul>"
    sealed = int(facts.get("sealed_command_line_count") or 0)
    sealed_html = ""
    if sealed:
        sealed_html = (
            f"<p>{sealed} command lines are stored as sealed tokens. "
            "This page does not show them and cannot decrypt them.</p>"
        )
    return f"<ul>{''.join(rows)}</ul>{pattern_html}{sealed_html}"


def _endpoint_name(hostname: str) -> str:
    """Return a desk link for a legal hostname, or escaped text."""
    shown = escape(hostname)
    if not legal_host(hostname):
        return shown
    encoded = encode_desk_query("active", None, hostname)
    return f'<a href="{escape("/triage?" + encoded)}">{shown}</a>'


def _endpoint_row(endpoint: Mapping[str, Any], open_counts: Mapping[str, int]) -> str:
    """Render one endpoint row, including its open finding count."""
    hostname = str(endpoint.get("hostname") or "")
    open_count = int(open_counts.get(hostname, 0))
    return (
        "<tr>"
        f"<td>{_endpoint_name(hostname)}</td>"
        f"<td>{escape(str(endpoint.get('fqdn') or ''))}</td>"
        f"<td><code>{escape(str(endpoint.get('role') or 'unknown'))}</code></td>"
        f"<td>{escape(str(endpoint.get('first_seen_utc') or ''))}</td>"
        f"<td>{escape(str(endpoint.get('last_seen_utc') or ''))}</td>"
        f"<td>{open_count}</td>"
        "</tr>"
    )


def endpoints_table(
    endpoints: list[dict[str, Any]],
    open_counts: Mapping[str, int],
) -> str:
    """Render the endpoint registry and each host's open finding count."""
    if not endpoints:
        return page(
            "WynDoze-InfoScanOverload Endpoints",
            "<h2>Endpoints</h2><p class='muted'>None yet.</p>",
            current="/endpoints",
        )
    rows = "".join(_endpoint_row(endpoint, open_counts) for endpoint in endpoints)
    body = (
        "<h2>Endpoints</h2><table><thead><tr>"
        "<th>Hostname</th><th>FQDN</th><th>Role</th>"
        "<th>First Seen</th><th>Last Seen</th><th>Open</th>"
        "</tr></thead><tbody>"
        f"{rows}</tbody></table>"
    )
    return page("WynDoze-InfoScanOverload Endpoints", body, current="/endpoints")


_EXPORTS = (
    (
        "CSV",
        "/export/findings.csv",
        (
            "Columns are id, hostname, severity, rule_id, title, technique_id, "
            "technique_name, tactic, status, seen_count, first_seen_utc, and "
            "last_seen_utc. Formula-looking cells are prefixed."
        ),
    ),
    (
        "Markdown",
        "/export/findings.md",
        "A severity table. Evidence is clipped at 160 characters.",
    ),
    (
        "JSON",
        "/export/findings.json",
        "Finding objects without *_json columns.",
    ),
    (
        "Sentinel",
        "/export/findings.sentinel",
        "NDJSON, one object per finding.",
    ),
)


def reports_page() -> str:
    """Describe the four finding exports. Each export includes every status."""
    items = "".join(
        f'<li><a href="{escape(href)}">{escape(name)}</a>. {escape(sentence)}</li>'
        for name, href, sentence in _EXPORTS
    )
    body = (
        "<h2>Reports</h2>"
        "<p>Active means triage or flagged.</p>"
        f"<ul>{items}</ul>"
        "<p>Exports include every status, not the current desk filter.</p>"
    )
    return page("WynDoze-InfoScanOverload Reports", body, current="/reports/summary")


__all__ = [
    "cmdline_rule_names",
    "display_evidence",
    "endpoints_table",
    "evidence_label",
    "page",
    "reports_page",
    "safe_technique_href",
    "scan_page",
    "summary_page",
    "suppress_confirm_page",
    "timeline_page",
    "triage_page",
]
