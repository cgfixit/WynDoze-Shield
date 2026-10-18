"""Server-rendered HTML.

No external template files — pure functions returning safe HTML. All dynamic
values pass through ``html.escape`` to prevent stored XSS from
attacker-controlled telemetry (hostnames, process names, etc.).
"""

from __future__ import annotations

from html import escape
from typing import Any
from urllib.parse import urlencode

_STYLE = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    margin: 0; background: #0d1117; color: #e6edf3; }
header { background: #161b22; padding: 16px 24px; border-bottom: 1px solid #30363d; }
header h1 { margin: 0; font-size: 18px; }
header .sub { color: #8b949e; font-size: 12px; margin-top: 4px; }
nav { padding: 12px 24px; background: #0d1117; border-bottom: 1px solid #30363d; }
nav a { color: #58a6ff; margin-right: 16px; text-decoration: none; font-size: 14px; }
nav a:hover { text-decoration: underline; }
main { padding: 24px; max-width: 1200px; margin: 0 auto; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #21262d; }
th { color: #8b949e; font-weight: 600; text-transform: uppercase; font-size: 11px; }
tr:hover { background: #161b22; }
.badge { padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; }
.critical { background: #da3633; color: #fff; }
.high { background: #fb8500; color: #1a1a1a; }
.medium { background: #d4a72c; color: #1a1a1a; }
.low { background: #388bfd; color: #fff; }
.info { background: #30363d; color: #e6edf3; }
.cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 20px; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    padding: 16px 20px; min-width: 130px; }
.card .n { font-size: 28px; font-weight: 700; }
.card .l { color: #8b949e; font-size: 12px; margin-top: 4px; }
form.inline { display: inline; }
button { background: #21262d; color: #e6edf3; border: 1px solid #30363d;
    border-radius: 6px; padding: 4px 10px; cursor: pointer; font-size: 12px; }
button:hover { background: #30363d; }
code { background: #161b22; padding: 1px 5px; border-radius: 4px; font-size: 12px; }
.muted { color: #8b949e; }
"""

_NAV = """
<nav>
  <a href="/">Summary</a>
  <a href="/triage">Triage Inbox</a>
  <a href="/timeline">Timeline</a>
  <a href="/endpoints">Endpoints</a>
  <a href="/reports/summary">Reports</a>
</nav>
"""


def _severity_badge(severity: str) -> str:
    sev = escape(severity or "info")
    return f'<span class="badge {sev}">{sev.upper()}</span>'


def page(title: str, body: str) -> str:
    """Wrap body content in the full HTML shell."""
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{escape(title)}</title><style>{_STYLE}</style></head><body>"
        "<header><h1>WynDoze-InfoScanOverload</h1>"
        "<div class='sub'>Internal endpoint scanner</div></header>"
        f"{_NAV}<main>{body}</main></body></html>"
    )


def summary_page(summary: dict[str, Any]) -> str:
    """Render the Summary report landing page."""
    sev = summary.get("active_findings_by_severity", {})
    status = summary.get("findings_by_status", {})
    cards = [
        ("Endpoints", summary.get("endpoints", 0), "info"),
        ("Scans", summary.get("scans", 0), "info"),
        ("Critical", sev.get("critical", 0), "critical"),
        ("High", sev.get("high", 0), "high"),
        ("Medium", sev.get("medium", 0), "medium"),
        ("Triage", status.get("triage", 0), "info"),
        ("Flagged", status.get("flagged", 0), "high"),
    ]
    card_html = "".join(
        f"<div class='card'><div class='n'>{escape(str(n))}</div>"
        f"<div class='l'>{escape(label)}</div></div>"
        for label, n, _ in cards
    )
    body = (
        "<h2>Summary</h2>"
        f"<div class='cards'>{card_html}</div>"
        "<p class='muted'>Active findings are those in <code>triage</code> or "
        "<code>flagged</code> state. Use the Triage Inbox to work them.</p>"
    )
    return page("WynDoze-InfoScanOverload Summary", body)


def _finding_row(f: dict[str, Any], *, actions: bool = True) -> str:
    evidence = "; ".join(str(e) for e in f.get("evidence", []))[:200]
    technique = escape(f.get("technique_id") or "")
    if f.get("technique_url"):
        technique = (
            f"<a href='{escape(f['technique_url'])}' target='_blank' "
            f"rel='noopener noreferrer'>{technique}</a>"
        )
    action_cell = ""
    if actions:
        fid = int(f.get("id", 0))
        action_cell = (
            "<td>"
            + "".join(
                f"<form class='inline' method='post' action='/findings/{fid}/{verb}'>"
                f"<button type='submit'>{label}</button></form> "
                for verb, label in (
                    ("flag", "Flag"),
                    ("archive", "Archive"),
                    ("suppress", "Suppress"),
                    ("triage", "Re-triage"),
                )
            )
            + "</td>"
        )
    return (
        "<tr>"
        f"<td>{_severity_badge(f.get('severity', ''))}</td>"
        f"<td>{escape(f.get('hostname', ''))}</td>"
        f"<td><a href='/findings/{int(f.get('id', 0))}'>"
        f"{escape(f.get('title', ''))}</a><br><span class='muted'>"
        f"{escape(f.get('message') or '')}</span></td>"
        f"<td>{technique}</td>"
        f"<td><code>{escape(f.get('status', ''))}</code> "
        f"<span class='muted'>&times;{escape(str(f.get('seen_count', 1)))}</span></td>"
        f"<td>{escape(evidence)}</td>"
        f"{action_cell}"
        "</tr>"
    )


def _filters_form(filters: dict[str, str | None]) -> str:
    fields = []
    for key, label in (("hostname", "Host (exact)"), ("rule_id", "Rule ID (exact)")):
        fields.append(
            f"<label>{label} <input name='{key}' value='{escape(filters.get(key) or '')}'></label> "
        )
    for key, values in (
        ("status", ("triage", "flagged", "archived", "suppressed")),
        ("severity", ("critical", "high", "medium", "low", "info")),
    ):
        options = "<option value=''>All</option>" + "".join(
            f"<option value='{value}'"
            + (" selected" if filters.get(key) == value else "")
            + f">{value}</option>"
            for value in values
        )
        fields.append(f"<label>{key.title()} <select name='{key}'>{options}</select></label> ")
    return (
        "<form method='get' action='/timeline'>"
        + "".join(fields)
        + "<button type='submit'>Filter</button> <a href='/timeline'>Clear filters</a></form>"
    )


def findings_table(
    findings: list[dict[str, Any]],
    title: str,
    *,
    actions: bool = True,
    filters: dict[str, str | None] | None = None,
    page_number: int = 1,
    has_next: bool = False,
) -> str:
    """Render one stable filtered page; exports continue to include every finding."""
    filters = filters or {}
    navigation = []
    for label, number in (("Previous", page_number - 1), ("Next", page_number + 1)):
        if number < 1 or (label == "Next" and not has_next):
            continue
        query = {key: value for key, value in filters.items() if value}
        query["page"] = str(number)
        navigation.append(f"<a href='/timeline?{escape(urlencode(query))}'>{label}</a>")
    body = (
        f"<h2>{escape(title)}</h2>"
        + _filters_form(filters)
        + f"<p>Page {page_number}; {len(findings)} shown. "
        + " &middot; ".join(navigation)
        + "</p>"
        "<p class='muted'>Exports include all stored findings, regardless of these filters.</p>"
        "<p><a href='/export/findings.csv'>CSV</a> &middot; "
        "<a href='/export/findings.md'>Markdown</a> &middot; "
        "<a href='/export/findings.json'>JSON</a> &middot; "
        "<a href='/export/findings.sentinel'>Sentinel</a></p>"
    )
    if findings:
        action_th = "<th>Actions</th>" if actions else ""
        rows = "".join(_finding_row(f, actions=actions) for f in findings)
        body += (
            "<table><thead><tr><th>Sev</th><th>Host</th><th>Finding</th><th>Technique</th>"
            f"<th>Status</th><th>Evidence</th>{action_th}</tr></thead><tbody>{rows}</tbody></table>"
        )
    else:
        body += "<p class='muted'>No findings match these filters.</p>"
    return page(f"WynDoze-InfoScanOverload {title}", body)


def finding_detail(finding: dict[str, Any], scan: dict[str, Any] | None) -> str:
    """Display complete escaped finding evidence, without decrypting command lines."""
    body = (
        f"<h2>{escape(finding.get('title', ''))}</h2>"
        "<table><thead><tr><th>Sev</th><th>Host</th><th>Finding</th><th>Technique</th>"
        "<th>Status</th><th>Evidence preview</th><th>Actions</th></tr></thead><tbody>"
        + _finding_row(finding)
        + "</tbody></table>"
    )
    body += (
        "<h3>Complete evidence</h3><ul>"
        + "".join(
            f"<li><code>{escape(str(value))}</code></li>" for value in finding.get("evidence", [])
        )
        + "</ul>"
    )
    for label, value in (
        ("Rule ID", finding.get("rule_id")),
        ("First seen", finding.get("first_seen_utc")),
        ("Last seen", finding.get("last_seen_utc")),
        ("Occurrences", finding.get("seen_count")),
        ("Latest matching scan", finding.get("scan_id")),
        ("Collected", scan.get("scan_time_utc") if scan else None),
        ("Received", scan.get("received_at_utc") if scan else None),
    ):
        body += f"<p><strong>{label}:</strong> {escape(str(value or 'Unknown'))}</p>"
    body += "<p>Times describe matching observations, not proof of resolution. "
    body += "<a href='/timeline'>Back to findings</a></p>"
    return page("Finding details", body)


def endpoints_table(endpoints: list[dict[str, Any]]) -> str:
    """Render the endpoints registry page."""
    if not endpoints:
        return page(
            "WynDoze-InfoScanOverload Endpoints", "<h2>Endpoints</h2><p class='muted'>None yet.</p>"
        )
    rows = "".join(
        "<tr>"
        f"<td>{escape(e.get('hostname', ''))}</td>"
        f"<td>{escape(e.get('fqdn') or '')}</td>"
        f"<td><code>{escape(e.get('role', 'unknown'))}</code></td>"
        f"<td>{escape(e.get('first_seen_utc', ''))}</td>"
        f"<td>{escape(e.get('last_seen_utc', ''))}</td>"
        "</tr>"
        for e in endpoints
    )
    body = (
        "<h2>Endpoints</h2><table><thead><tr>"
        "<th>Hostname</th><th>FQDN</th><th>Role</th>"
        "<th>First Seen</th><th>Last Seen</th>"
        "</tr></thead><tbody>"
        f"{rows}</tbody></table>"
    )
    return page("WynDoze-InfoScanOverload Endpoints", body)


__all__ = [
    "endpoints_table",
    "findings_table",
    "page",
    "summary_page",
]
