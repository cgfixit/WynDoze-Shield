"""A small, offline MITRE ATT&CK technique catalog.

The official Recon product classifies detections against the MITRE ATT&CK
framework. We ship a curated, static subset relevant to the checks this MVP
performs. IDs and names are stable public identifiers; the catalog is
intentionally tiny and hand-maintained rather than a full framework mirror.

Reference: https://attack.mitre.org/
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Technique:
    """A single ATT&CK technique reference."""

    technique_id: str
    name: str
    tactic: str
    url: str


def _t(technique_id: str, name: str, tactic: str) -> Technique:
    base = technique_id.replace(".", "/")
    return Technique(
        technique_id=technique_id,
        name=name,
        tactic=tactic,
        url=f"https://attack.mitre.org/techniques/{base}/",
    )


CATALOG: dict[str, Technique] = {
    t.technique_id: t
    for t in (
        _t("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement"),
        _t("T1021.006", "Remote Services: Windows Remote Management", "Lateral Movement"),
        _t("T1219", "Remote Access Software", "Command and Control"),
        _t("T1570", "Lateral Tool Transfer", "Lateral Movement"),
        _t("T1003", "OS Credential Dumping", "Credential Access"),
        _t("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
        _t("T1560", "Archive Collected Data", "Collection"),
        _t("T1543.003", "Create or Modify System Process: Windows Service", "Persistence"),
        _t("T1136", "Create Account", "Persistence"),
        _t("T1098", "Account Manipulation", "Persistence"),
        _t("T1078", "Valid Accounts", "Defense Evasion"),
        _t("T1490", "Inhibit System Recovery", "Impact"),
        _t("T1486", "Data Encrypted for Impact", "Impact"),
        _t("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
        _t("T1071", "Application Layer Protocol", "Command and Control"),
    )
}


def lookup(technique_id: str | None) -> Technique | None:
    """Return the catalog entry for ``technique_id`` or ``None``."""
    if not technique_id:
        return None
    return CATALOG.get(technique_id.strip())
