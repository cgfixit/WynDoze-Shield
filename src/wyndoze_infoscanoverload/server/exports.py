"""Export findings to CSV, Markdown, JSON, and Microsoft Sentinel formats.

The Sentinel exporter emits newline-delimited JSON shaped for a Log Analytics
custom table (``Recon_CL``). The operator is responsible for configuring
ingestion into their own workspace.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

_CSV_COLUMNS = (
    "id",
    "hostname",
    "severity",
    "rule_id",
    "title",
    "technique_id",
    "technique_name",
    "tactic",
    "status",
    "seen_count",
    "first_seen_utc",
    "last_seen_utc",
)


_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_MARKDOWN_ESCAPES = str.maketrans({char: f"&#{ord(char)};" for char in "\\`*_[]<>&|~"})


def _csv_cell(value: object) -> object:
    """Prefix formula-like text so a spreadsheet does not execute it."""
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def findings_to_csv(findings: list[dict[str, Any]]) -> str:
    """Render findings as CSV text."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for finding in findings:
        writer.writerow({key: _csv_cell(finding.get(key, "")) for key in _CSV_COLUMNS})
    return buffer.getvalue()


def findings_to_markdown(findings: list[dict[str, Any]]) -> str:
    """Render findings as a Markdown table with a severity summary."""
    if not findings:
        return "# WynDoze-InfoScanOverload findings\n\n_No findings._\n"
    lines = ["# WynDoze-InfoScanOverload findings", "", f"Total: **{len(findings)}**", ""]
    header = "| Severity | Host | Rule | Technique | Status | Evidence |"
    sep = "|---|---|---|---|---|---|"
    lines += [header, sep]
    for f in findings:
        evidence = "; ".join(str(e) for e in f.get("evidence", []))[:160]
        technique = f.get("technique_id") or ""
        if f.get("technique_name"):
            technique = f"{technique} {f['technique_name']}".strip()
        cells = (
            f.get("severity", ""),
            f.get("hostname", ""),
            f.get("title", ""),
            technique,
            f.get("status", ""),
            evidence,
        )
        # Entities remain text when Markdown is parsed; line breaks cannot split the row.
        escaped = [" ".join(str(cell).splitlines()).translate(_MARKDOWN_ESCAPES) for cell in cells]
        lines.append("| " + " | ".join(escaped) + " |")
    return "\n".join(lines) + "\n"


def findings_to_json(findings: list[dict[str, Any]]) -> str:
    """Render findings as a JSON array (drops internal *_json columns)."""
    cleaned = [{k: v for k, v in f.items() if not k.endswith("_json")} for f in findings]
    return json.dumps(cleaned, indent=2)


def findings_to_sentinel(findings: list[dict[str, Any]]) -> str:
    """Render findings as newline-delimited JSON for Microsoft Sentinel ingest."""
    rows = [
        json.dumps(
            {
                "TimeGenerated": f.get("last_seen_utc"),
                "Hostname": f.get("hostname"),
                "Severity": f.get("severity"),
                "RuleId": f.get("rule_id"),
                "Title": f.get("title"),
                "TechniqueId": f.get("technique_id"),
                "TechniqueName": f.get("technique_name"),
                "Tactic": f.get("tactic"),
                "Status": f.get("status"),
                "Evidence": f.get("evidence", []),
                "SeenCount": f.get("seen_count"),
            }
        )
        for f in findings
    ]
    return "\n".join(rows) + ("\n" if rows else "")


EXPORTERS = {
    "csv": (findings_to_csv, "text/csv"),
    "markdown": (findings_to_markdown, "text/markdown"),
    "json": (findings_to_json, "application/json"),
    "sentinel": (findings_to_sentinel, "application/x-ndjson"),
}

__all__ = [
    "EXPORTERS",
    "findings_to_csv",
    "findings_to_json",
    "findings_to_markdown",
    "findings_to_sentinel",
]
