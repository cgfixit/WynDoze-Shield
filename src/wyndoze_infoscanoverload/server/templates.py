"""Server-rendered HTML.

No external template files — pure functions returning safe HTML. All dynamic
values pass through ``html.escape`` to prevent stored XSS from
attacker-controlled telemetry (hostnames, process names, etc.).
"""

from __future__ import annotations

from html import escape
from typing import Any

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


def _coverage_html(health: dict[str, Any]) -> str:
    if not health:
        return "Unknown (older agent)"
    parts = []
    names = (
        "ip_addresses",
        "processes",
        "listening_connections",
        "services",
        "installed_software",
        "local_admins",
    )
    for name in names:
        result = health.get(name)
        if not isinstance(result, dict):
            parts.append(f"{name}: unknown")
            continue
        issues = ", ".join(str(issue) for issue in result.get("issues", []))
        parts.append(
            f"{name}: {result.get('status', 'unknown')} "
            f"({result.get('item_count', 0)} items, {result.get('duration_ms', 0)} ms)"
            + (f"; {issues}" if issues else "")
        )
    incomplete = any(
        isinstance(result, dict) and (result.get("status") != "ok" or result.get("truncated"))
        for result in health.values()
    )
    label = "Incomplete collection" if incomplete else "Collection reported complete"
    if not incomplete and len(health) != len(names):
        label = "Unknown coverage"
    return (
        f"<details><summary>{label}</summary><ul>"
        + "".join(f"<li>{escape(part)}</li>" for part in parts)
        + "</ul></details>"
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
        f"<td>{escape(f.get('title', ''))}<br><span class='muted'>"
        f"{escape(f.get('message') or '')}</span></td>"
        f"<td>{technique}</td>"
        f"<td><code>{escape(f.get('status', ''))}</code> "
        f"<span class='muted'>&times;{escape(str(f.get('seen_count', 1)))}</span></td>"
        f"<td>{escape(evidence)}</td>"
        f"{action_cell}"
        "</tr>"
    )


def findings_table(findings: list[dict[str, Any]], title: str, *, actions: bool = True) -> str:
    """Render a findings table page."""
    if not findings:
        body = f"<h2>{escape(title)}</h2><p class='muted'>No findings.</p>"
        return page(f"WynDoze-InfoScanOverload {title}", body)
    action_th = "<th>Actions</th>" if actions else ""
    rows = "".join(_finding_row(f, actions=actions) for f in findings)
    body = (
        f"<h2>{escape(title)}</h2>"
        "<p class='muted'>Showing up to 500 findings. Exports include all stored findings.</p>"
        "<p class='muted'>"
        "<a href='/export/findings.csv'>CSV</a> &middot; "
        "<a href='/export/findings.md'>Markdown</a> &middot; "
        "<a href='/export/findings.json'>JSON</a> &middot; "
        "<a href='/export/findings.sentinel'>Sentinel</a></p>"
        "<table><thead><tr>"
        "<th>Sev</th><th>Host</th><th>Finding</th><th>Technique</th>"
        f"<th>Status</th><th>Evidence</th>{action_th}"
        "</tr></thead><tbody>"
        f"{rows}</tbody></table>"
    )
    return page(f"WynDoze-InfoScanOverload {title}", body)


def endpoints_table(endpoints: list[dict[str, Any]]) -> str:
    """Render endpoint collection coverage and age, independently of upload time."""
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
        f"<td>{escape(e.get('scan_time_utc') or 'Unknown')}</td>"
        f"<td>{escape(e.get('last_seen_utc', ''))}</td>"
        f"<td>{escape(e.get('freshness', 'unknown'))}</td>"
        f"<td>{_coverage_html(e.get('collection_health', {}))}</td>"
        "</tr>"
        for e in endpoints
    )
    body = (
        "<h2>Endpoints</h2>"
        "<p>Coverage describes reported collection, not a security verdict. "
        "Replaying an old bundle updates receipt time without refreshing its inventory age.</p>"
        "<table><thead><tr>"
        "<th>Hostname</th><th>FQDN</th><th>Role</th>"
        "<th>First received</th><th>Collected</th><th>Received</th><th>Freshness</th><th>Collection coverage</th>"
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
