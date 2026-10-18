"""YAML-driven rules engine.

The engine loads a declarative rule pack and evaluates it against a
:class:`~wyndoze_infoscanoverload.core.models.ScanReport`, producing :class:`Finding` objects.
Rules are pure data — no code execution — so a rule pack is safe to ship,
edit, and review without touching Python.

Supported rule kinds
---------------------
``listening_port``
    Fires when any listed TCP/UDP port is listening locally.
``process_name``
    Fires when a process whose name matches (case-insensitive, exact) any
    listed value is running.
``service_present``
    Fires when a service whose name/display-name contains a listed substring
    exists (optionally scoped to states, e.g. RUNNING).
``software_present``
    Fires when installed software matches a listed substring.
``local_admin_unexpected``
    Fires when a local administrator is present who is not on an allow-list.
``missing_expected_service``
    Fires when an expected service is absent. Used for posture checks.

Every rule may declare a ``roles`` list to scope it to specific endpoint
roles, and a ``technique`` (MITRE ATT&CK id) for classification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from wyndoze_infoscanoverload.core.mitre import lookup
from wyndoze_infoscanoverload.core.models import EndpointRole, Finding, ScanReport
from wyndoze_infoscanoverload.core.severity import Severity

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

_VALID_KINDS = frozenset(
    {
        "listening_port",
        "process_name",
        "service_present",
        "software_present",
        "local_admin_unexpected",
        "missing_expected_service",
        "cmdline_flag",
    }
)


class RuleError(ValueError):
    """Raised when a rule pack is malformed."""


@dataclass(frozen=True, slots=True)
class Rule:
    """A single validated rule."""

    rule_id: str
    title: str
    kind: str
    severity: Severity
    category: str = ""
    message: str = ""
    technique: str | None = None
    roles: frozenset[EndpointRole] = field(default_factory=frozenset)
    # Kind-specific payloads:
    ports: frozenset[int] = field(default_factory=frozenset)
    names: tuple[str, ...] = ()
    substrings: tuple[str, ...] = ()
    states: frozenset[str] = field(default_factory=frozenset)
    allow: frozenset[str] = field(default_factory=frozenset)

    def applies_to_role(self, role: EndpointRole) -> bool:
        """Return True if this rule should run for ``role``."""
        return not self.roles or role in self.roles


@dataclass(frozen=True, slots=True)
class RulePack:
    """An immutable, validated collection of rules."""

    name: str
    version: str
    rules: tuple[Rule, ...]


def _as_severity(value: object) -> Severity:
    if not isinstance(value, str):
        msg = f"severity must be a string, got {type(value).__name__}"
        raise RuleError(msg)
    try:
        return Severity(value.strip().lower())
    except ValueError as exc:
        msg = f"unknown severity: {value}"
        raise RuleError(msg) from exc


def _as_roles(value: object) -> frozenset[EndpointRole]:
    if value is None:
        return frozenset()
    if not isinstance(value, list):
        msg = "roles must be a list"
        raise RuleError(msg)
    out: set[EndpointRole] = set()
    for item in value:
        try:
            out.add(EndpointRole(str(item)))
        except ValueError as exc:
            msg = f"unknown role: {item!r}"
            raise RuleError(msg) from exc
    return frozenset(out)


def _str_tuple(value: object, *, lower: bool = False) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        msg = "expected a list of strings"
        raise RuleError(msg)
    items = [str(v).strip() for v in value if str(v).strip()]
    if lower:
        items = [v.lower() for v in items]
    return tuple(items)


def _parse_rule(raw: dict[str, Any]) -> Rule:
    try:
        rule_id = str(raw["id"]).strip()
        title = str(raw["title"]).strip()
        kind = str(raw["kind"]).strip()
    except KeyError as exc:
        msg = f"rule missing required field: {exc.args[0]!r}"
        raise RuleError(msg) from exc

    if not rule_id:
        msg = "rule id must be non-empty"
        raise RuleError(msg)
    if kind not in _VALID_KINDS:
        msg = f"rule {rule_id!r}: unknown kind {kind!r} (valid: {sorted(_VALID_KINDS)})"
        raise RuleError(msg)

    ports_raw = raw.get("ports") or []
    if not isinstance(ports_raw, list):
        msg = f"rule {rule_id!r}: ports must be a list"
        raise RuleError(msg)
    try:
        ports = frozenset(int(p) for p in ports_raw)
    except (TypeError, ValueError) as exc:
        msg = f"rule {rule_id!r}: ports must be integers"
        raise RuleError(msg) from exc

    return Rule(
        rule_id=rule_id,
        title=title,
        kind=kind,
        severity=_as_severity(raw.get("severity", "medium")),
        category=str(raw.get("category", "")),
        message=str(raw.get("message", "")),
        technique=(str(raw["technique"]).strip() if raw.get("technique") else None),
        roles=_as_roles(raw.get("roles")),
        ports=ports,
        names=_str_tuple(raw.get("names"), lower=True),
        substrings=_str_tuple(raw.get("substrings"), lower=True),
        states=frozenset(_str_tuple(raw.get("states"), lower=True)),
        allow=frozenset(_str_tuple(raw.get("allow"), lower=True)),
    )


def load_rule_pack(source: str | Path) -> RulePack:
    """Load and validate a rule pack from a YAML file path or YAML string."""
    text = Path(source).read_text(encoding="utf-8") if _looks_like_path(source) else str(source)
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        msg = f"invalid YAML in rule pack: {exc}"
        raise RuleError(msg) from exc

    if not isinstance(data, dict):
        msg = "rule pack root must be a mapping"
        raise RuleError(msg)

    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        msg = "rule pack must contain a non-empty 'rules' list"
        raise RuleError(msg)

    rules = tuple(_parse_rule(r) for r in raw_rules)
    seen: set[str] = set()
    for rule in rules:
        if rule.rule_id in seen:
            msg = f"duplicate rule id: {rule.rule_id!r}"
            raise RuleError(msg)
        seen.add(rule.rule_id)

    return RulePack(
        name=str(data.get("name", "unnamed")),
        version=str(data.get("version", "0")),
        rules=rules,
    )


def _looks_like_path(source: str | Path) -> bool:
    if isinstance(source, Path):
        return True
    # A YAML document contains newlines/colons; a path realistically does not
    # start with 'name:' or 'rules:'. Treat single-line strings ending in
    # .yml/.yaml as paths.
    stripped = source.strip()
    return "\n" not in stripped and stripped.endswith((".yml", ".yaml"))


def _finding_from_rule(rule: Rule, evidence: Sequence[str]) -> Finding:
    technique = lookup(rule.technique)
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        message=rule.message,
        technique_id=technique.technique_id if technique else rule.technique,
        technique_name=technique.name if technique else None,
        tactic=technique.tactic if technique else None,
        technique_url=technique.url if technique else None,
        evidence=list(evidence)[:100],
    )


def _eval_listening_port(rule: Rule, report: ScanReport) -> list[str]:
    listening = {c.local_port for c in report.listening_connections if c.local_port}
    return [f"port {p} listening" for p in sorted(rule.ports & listening)]


def _eval_process_name(rule: Rule, report: ScanReport) -> list[str]:
    names = {(p.name or "").lower() for p in report.processes}
    wanted = set(rule.names)
    return sorted(names & wanted)


def _eval_service_present(rule: Rule, report: ScanReport) -> list[str]:
    hits: list[str] = []
    for svc in report.services:
        haystack = f"{svc.name} {svc.display_name}".lower()
        if any(sub in haystack for sub in rule.substrings):
            if rule.states and svc.state.lower() not in rule.states:
                continue
            hits.append(svc.name or svc.display_name)
    return hits


def _software_exact(hay: str, names: tuple[str, ...]) -> bool:
    """Match a whole name or a name plus a version.

    A short name must not match inside a longer word.
    """
    if not names:
        return False
    compact = " ".join(re.findall(r"[a-z0-9]+", hay))
    return any(compact == name or compact.startswith(name + " ") for name in names)


def _eval_software_present(rule: Rule, report: ScanReport) -> list[str]:
    hits: list[str] = []
    for sw in report.installed_software:
        hay = sw.name.lower()
        if any(sub in hay for sub in rule.substrings) or _software_exact(hay, rule.names):
            hits.append(sw.name)
    return hits


def _eval_local_admin_unexpected(rule: Rule, report: ScanReport) -> list[str]:
    return sorted(admin for admin in report.local_admins if admin.lower() not in rule.allow)


def _eval_cmdline_flag(rule: Rule, report: ScanReport) -> list[str]:
    have = {flag.lower() for flag in report.cmdline_flags}
    return sorted(have & set(rule.names))


def _eval_missing_expected_service(rule: Rule, report: ScanReport) -> list[str]:
    present = " ".join(f"{s.name} {s.display_name}" for s in report.services).lower()
    missing = [sub for sub in rule.substrings if sub not in present]
    # Fires only if ALL expected services are missing would be too weak; we
    # fire when ANY expected service is absent.
    return [f"expected service matching {sub!r} not found" for sub in missing]


_EVALUATORS = {
    "listening_port": _eval_listening_port,
    "process_name": _eval_process_name,
    "service_present": _eval_service_present,
    "software_present": _eval_software_present,
    "local_admin_unexpected": _eval_local_admin_unexpected,
    "missing_expected_service": _eval_missing_expected_service,
    "cmdline_flag": _eval_cmdline_flag,
}


def evaluate(report: ScanReport, pack: RulePack) -> list[Finding]:
    """Evaluate ``pack`` against ``report`` and return sorted findings.

    Findings are sorted by descending severity, then rule id, for stable,
    triage-friendly ordering.
    """
    findings: list[Finding] = []
    for rule in pack.rules:
        if not rule.applies_to_role(report.role):
            continue
        evaluator = _EVALUATORS[rule.kind]
        evidence = evaluator(rule, report)
        if evidence:
            findings.append(_finding_from_rule(rule, evidence))

    findings.sort(key=lambda f: (-f.severity.rank, f.rule_id))
    return findings


def evaluate_many(reports: Iterable[ScanReport], pack: RulePack) -> dict[str, list[Finding]]:
    """Evaluate several reports, keyed by hostname (last write wins)."""
    return {report.hostname: evaluate(report, pack) for report in reports}


__all__ = [
    "Rule",
    "RuleError",
    "RulePack",
    "evaluate",
    "evaluate_many",
    "load_rule_pack",
]
