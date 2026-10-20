"""Check a pull request title and body against .github/PULL_REQUEST_TEMPLATE.md.

Runs in CI from pr-template-check.yml and locally:

    python .github/scripts/check_pr_template.py --title "[docs] - Title" --body-file body.md
    python .github/scripts/check_pr_template.py --self-test

Exit codes: 0 all checks pass, 1 one or more checks fail (each on its own
line), 2 bad invocation. The checker reads only the text it is given; it
never contacts GitHub.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

TITLE_RE = re.compile(
    r"^\[(invariant|security|infra|fix|docs|rules|deploy|agentic|test|feat)\] - \S.*$"
)
REQUIRED_HEADINGS = (
    "Proposed changes",
    "Types of changes",
    "Benefits / why",
    "Risks to monitor",
    "Checklist",
    "Further comments",
    "Suggested merge order of open PRs",
    "ELI5",
)
STAMP_RE = re.compile(r"^🤖 Last updated: \d{4}-\d{2}-\d{2} \d{2}:\d{2} ET$")
STAMP_PLACEHOLDER = "🤖 Last updated: YYYY-MM-DD HH:MM ET"
# Lines an automated PR tool may append after the stamp, whichever tool it is:
# a rule, an optionally italic or robot-prefixed "Generated/Created/Authored by|with"
# line, or a bare link. A Cursor badge div is checked separately, without a
# nested regex. Nothing else may follow the stamp.
FOOTER_RES = (
    re.compile(r"^---$"),
    re.compile(r"^_?(🤖 )?(Generated|Created|Authored) (by|with) .+?_?$"),
    re.compile(r"^https?://\S+$"),
)
_CURSOR_HREF = '<a href="https://cursor.com/'
_CURSOR_PICTURE = "><picture>"
_CURSOR_ANCHOR_END = "</picture></a>"
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
CHECKED_BOX_RE = re.compile(r"^\s*[-*]\s+\[[xX]\]\s+\S")
SHA_RE = re.compile(r"\b[0-9a-f]{40}\b")
# An entry looks like `**#45** · Safe`; the template's instruction bullets start with `- `.
MERGE_ENTRY_RE = re.compile(r"^\s*\*\*[^*\n]+\*\*\s*·\s*(Safe|Dirty|Blocked)\b", re.MULTILINE)
# One verbatim instruction sentence per template section. A body that still contains
# one has not replaced the template's scaffolding with its own content.
SCAFFOLD = (
    "Describe the big picture of your changes here.",
    "Why make this change? What is the concrete upside",
    "What are the potential regressions, negative side-effects",
    "Required on every PR, including a lone one",
    "Explain the **whole** diff against `main`",
)
TEMPLATE_PATH = Path(__file__).resolve().parents[1] / "PULL_REQUEST_TEMPLATE.md"
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
FENCE_RE = re.compile(r"^\s*(```|~~~)")
SECTION_LEVEL = 2
MIN_ELI5_LINES = 2
MERGE_HEADING = "Suggested merge order of open PRs"


def emit(message: str, *, error: bool = False) -> None:
    """Write one line to stdout, or to stderr for usage errors."""
    stream = sys.stderr if error else sys.stdout
    stream.write(f"{message}\n")


def strip_fences(lines: list[str]) -> list[str]:
    """Blank out fenced code so an example heading inside a fence is not counted."""
    out: list[str] = []
    in_fence = False
    for line in lines:
        if FENCE_RE.match(line):
            in_fence = not in_fence
            out.append("")
        else:
            out.append("" if in_fence else line)
    return out


def sections(lines: list[str]) -> dict[str, list[str]]:
    """Map each level-2 heading to the lines under it, up to the next level-2 heading."""
    found: dict[str, list[str]] = {}
    current: str | None = None
    for line in lines:
        match = HEADING_RE.match(line)
        if match and len(match.group(1)) == SECTION_LEVEL:
            current = match.group(2)
            found.setdefault(current, [])
        elif current is not None:
            found[current].append(line)
    return found


def _is_cursor_anchor(piece: str) -> bool:
    """Return True for one cursor.com anchor wrapping a single picture element."""
    if not piece.startswith(_CURSOR_HREF) or not piece.endswith(_CURSOR_ANCHOR_END):
        return False
    href, quote, rest = piece[len(_CURSOR_HREF) :].partition('"')
    if quote != '"' or not href or any(char in href for char in " <>"):
        return False
    if not rest.startswith(_CURSOR_PICTURE):
        return False
    picture = rest[len(_CURSOR_PICTURE) : -len(_CURSOR_ANCHOR_END)]
    return bool(picture) and all(
        token not in picture for token in ("<picture>", "</picture>", "</a>", "</div>")
    )


def _is_cursor_badge(line: str) -> bool:
    """Return True for one div of cursor.com picture links joined by ``&nbsp;``."""
    if not line.startswith("<div>") or not line.endswith("</div>"):
        return False
    inner = line[len("<div>") : -len("</div>")]
    if not inner.endswith("&nbsp;"):
        return False
    pieces = inner[: -len("&nbsp;")].split("&nbsp;")
    return bool(pieces) and all(piece and _is_cursor_anchor(piece) for piece in pieces)


def is_footer(line: str) -> bool:
    """Return True for a line a hosting tool may append after the stamp."""
    stripped = line.strip()
    return _is_cursor_badge(stripped) or any(pattern.match(stripped) for pattern in FOOTER_RES)


def check_title(title: str) -> list[str]:
    """Require `[prefix] - Short descriptive sentence` with a listed prefix."""
    if TITLE_RE.match(title.strip()):
        return []
    return ["title must be `[prefix] - Short descriptive sentence` with a listed prefix"]


def check_headings(lines: list[str], secs: dict[str, list[str]]) -> list[str]:
    """Require every template heading, with ELI5 last."""
    failures = [
        f"missing required heading `## {heading}`"
        for heading in REQUIRED_HEADINGS
        if heading not in secs
    ]
    titles = [m.group(2) for m in map(HEADING_RE.match, lines) if m]
    if "ELI5" in titles and titles[-1] != "ELI5":
        failures.append("`## ELI5` must be the last heading in the body")
    return failures


def check_stamp(lines: list[str]) -> list[str]:
    """Require the dated stamp as the last content line, allowing only a tool footer after it."""
    non_blank = [line.rstrip() for line in lines if line.strip()]
    stamp_at = next(
        (i for i in range(len(non_blank) - 1, -1, -1) if STAMP_RE.match(non_blank[i])),
        None,
    )
    if stamp_at is not None:
        stray = next((x for x in non_blank[stamp_at + 1 :] if not is_footer(x)), None)
        if stray is None:
            return []
        return [f"only a tool attribution footer may follow the stamp, found: {stray[:60]!r}"]
    if any(line.strip() == STAMP_PLACEHOLDER for line in non_blank):
        return ["replace the `🤖 Last updated: YYYY-MM-DD HH:MM ET` placeholder"]
    return ["body must end with a `🤖 Last updated: YYYY-MM-DD HH:MM ET` stamp"]


def check_content(secs: dict[str, list[str]]) -> list[str]:
    """Check the sections that must carry specific evidence."""
    failures: list[str] = []
    types_lines = secs.get("Types of changes")
    if types_lines is not None and not any(CHECKED_BOX_RE.match(x) for x in types_lines):
        failures.append("check at least one box under `## Types of changes`")
    further = secs.get("Further comments")
    if further is not None and not SHA_RE.search("\n".join(further)):
        failures.append("`## Further comments` must record the 40-character head SHA")
    merge = secs.get(MERGE_HEADING)
    if merge is not None and not MERGE_ENTRY_RE.search("\n".join(merge)):
        failures.append(
            f"`## {MERGE_HEADING}` needs an entry such as `**#45** · Safe` "
            "(Safe, Dirty, or Blocked)"
        )
    eli5 = secs.get("ELI5")
    if eli5 is not None:
        prose = [x for x in eli5 if x.strip() and not STAMP_RE.match(x) and not is_footer(x)]
        if len(prose) < MIN_ELI5_LINES:
            failures.append("`## ELI5` must explain the diff, not only carry the stamp")
    return failures


def check_scaffold(lines: list[str]) -> list[str]:
    """Reject a body that still carries the template's own instruction sentences."""
    text = "\n".join(lines)
    left = [phrase for phrase in SCAFFOLD if phrase in text]
    if not left:
        return []
    return [f"template instructions left in the body, replace them with content: {left[0]!r}"]


def check(title: str, body: str) -> list[str]:
    """Return one message per failed check; an empty list means the PR conforms."""
    raw_lines = HTML_COMMENT_RE.sub("", body.replace("\r\n", "\n")).split("\n")
    lines = strip_fences(raw_lines)
    secs = sections(lines)
    return [
        *check_title(title),
        *check_headings(lines, secs),
        # The stamp rule reads fenced lines too, so code after the stamp cannot hide.
        *check_stamp(raw_lines),
        *check_content(secs),
        *check_scaffold(lines),
    ]


GOOD_TITLE = "[docs] - Retarget PR template"
GOOD_BODY = """## Proposed changes
Text.
## Types of changes
- [ ] Bugfix
- [x] Documentation Update
## Benefits / why
Text.
## Risks to monitor
Text.
## Checklist
- [x] read
## Further comments
Head SHA: `85614838cae21e81a982c2f697ac6a9e7b21864e`.
## Suggested merge order of open PRs
**This PR** · Safe ✅
Impact: independent, only open PR.
```markdown
## ELI5: Merge Order
example inside a fence
```
## ELI5
Plain words about the whole diff.
What could still go wrong and what was run.

🤖 Last updated: 2026-10-19 07:49 ET

---
_Generated by [Claude Code](https://claude.ai/code/session_01JYZmgGRjA5FDmqpFLBdQ9h)_
"""
GOOD_SHA = "85614838cae21e81a982c2f697ac6a9e7b21864e"
GOOD_STAMP = "🤖 Last updated: 2026-10-19 07:49 ET"
ELI5_PROSE = "Plain words about the whole diff.\nWhat could still go wrong and what was run.\n"


def planted_violations() -> dict[str, tuple[str, str, str]]:
    """Return (title, body, expected message fragment) per rule the checker must reject."""
    before_stamp = GOOD_BODY.replace("🤖 Last updated", "## Afterword\nmore\n\n🤖 Last updated")
    scaffold = GOOD_BODY.replace(ELI5_PROSE, SCAFFOLD[-1] + "\nmore words\n")
    return {
        "title": ("docs: no prefix", GOOD_BODY, "title must be"),
        "missing heading": (
            GOOD_TITLE,
            GOOD_BODY.replace("## Risks to monitor\nText.\n", ""),
            "missing required heading",
        ),
        "ELI5 not last": (GOOD_TITLE, before_stamp, "last heading"),
        "placeholder stamp": (
            GOOD_TITLE,
            GOOD_BODY.replace(GOOD_STAMP, STAMP_PLACEHOLDER),
            "placeholder",
        ),
        "text after stamp": (GOOD_TITLE, GOOD_BODY + "\nPS: one more thing\n", "follow the stamp"),
        "fenced text after stamp": (
            GOOD_TITLE,
            GOOD_BODY + "\n```\nhidden trailing content\n```\n",
            "follow the stamp",
        ),
        "no type checked": (
            GOOD_TITLE,
            GOOD_BODY.replace("- [x] Doc", "- [ ] Doc"),
            "Types of changes",
        ),
        "no head SHA": (GOOD_TITLE, GOOD_BODY.replace(GOOD_SHA, "8561483"), "40-character"),
        "no merge entry": (
            GOOD_TITLE,
            GOOD_BODY.replace("**This PR** · Safe ✅", "- **Status:** `Safe ✅`"),
            "needs an entry",
        ),
        "empty ELI5": (GOOD_TITLE, GOOD_BODY.replace(ELI5_PROSE, ""), "must explain"),
        "template instructions left": (GOOD_TITLE, scaffold, "template instructions left"),
    }


def template_drift() -> list[str]:
    """Return a problem for each scaffold sentence the real template no longer contains."""
    if not TEMPLATE_PATH.is_file():
        return []
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    return [
        f"scaffold sentence missing from the template: {x!r}" for x in SCAFFOLD if x not in template
    ]


def self_test() -> int:
    """Prove the checker accepts good bodies and fails each planted violation for its reason."""
    problems: list[str] = []
    other_tool = (
        GOOD_BODY.split("\n---\n", maxsplit=1)[0]
        + "\n---\n_Created with [Codex](https://chatgpt.com/codex)_\n"
    )
    cursor_badge = (
        '<div><a href="https://cursor.com/agents/bc-example?cursor_ref=pr_footer">'
        '<picture><source media="(prefers-color-scheme: dark)" '
        'srcset="https://cursor.com/assets/images/open-in-web-dark.png">'
        '<img alt="Open in Web" width="114" height="28" '
        'src="https://cursor.com/assets/images/open-in-web-dark.png"></picture></a>&nbsp;</div>'
    )
    cursor_tool = GOOD_BODY.rstrip() + "\n\n" + cursor_badge + "\n"
    for name, body in (
        ("good body", GOOD_BODY),
        ("other tool footer", other_tool),
        ("cursor badge footer", cursor_tool),
    ):
        problems.extend(f"{name} rejected: {f}" for f in check(GOOD_TITLE, body))
    planted = planted_violations()
    for name, (title, body, expected) in planted.items():
        failures = check(title, body)
        if not any(expected in failure for failure in failures):
            problems.append(f"planted violation not caught for its own reason: {name} ({failures})")
    problems.extend(template_drift())
    for problem in problems:
        emit(f"SELF-TEST FAIL {problem}")
    if problems:
        return 1
    emit(f"self-test passed: good bodies accepted, {len(planted)} planted violations caught")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the checks, and return the process exit code."""
    parser = argparse.ArgumentParser(description="Check a PR title and body against the template.")
    parser.add_argument("--title", default=os.environ.get("PR_TITLE"))
    parser.add_argument("--body-file", type=Path, help="file holding the PR body")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.body_file is not None:
        body: str | None = args.body_file.read_text(encoding="utf-8")
    else:
        body = os.environ.get("PR_BODY")
    if args.title is None or body is None:
        emit("need --title/--body-file or PR_TITLE/PR_BODY in the environment", error=True)
        return 2

    failures = check(args.title, body)
    for failure in failures:
        emit(f"FAIL {failure}")
    if failures:
        emit(f"{len(failures)} PR template check(s) failed; see .github/PULL_REQUEST_TEMPLATE.md")
        return 1
    emit("PR template checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
