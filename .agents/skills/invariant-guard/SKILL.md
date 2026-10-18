---
name: invariant-guard
description: Assert WynDoze-InfoScanOverload's design invariants still hold (loopback-only bind and upload, no docs routes or telemetry, strict CSP, safe YAML, no shell, module isolation, metadata-only collectors, pinned caps, twin rule pack, closed rule kinds, deployment names, dependency fence) against the current tree. Use before merging any change to src/, rules/, deploy/, or pyproject.toml, when asked to "check invariants", or as the first gate of a security review.
---

# Invariant Guard

**Job:** answer one question: *do this tree's invariants still hold after the change?* Style, speed, and coverage belong to other gates (ruff, mypy, pytest). The checker covers what it can see. Your reading of the diff covers the rest.

**Why it exists:** the invariants in `AGENTS.md` ("Boundaries to preserve") live in constants, keyword arguments, and import edges spread across `server/`, `agent/`, `core/`, `rules/`, and `deploy/`. Unit tests check behavior one function at a time, so they miss a quiet edit such as `docs_url="/docs"`, a third host in `_LOOPBACK_HOSTS`, or one rule-pack copy drifting from the other.

## Run

### Step 1: deterministic checker (stdlib only, under a second)

```bash
python3 .agents/skills/invariant-guard/check_invariants.py
```

It parses source with `ast` and never imports project code, so it runs before `pip install`. CI runs it as the `invariants` job. Exit codes: `0` all pass, `2` an invariant is violated, `3` wrong root or an unparseable file.

| ID | Invariant | What is checked |
|---|---|---|
| L1 | Loopback bind | `server/__main__._LOOPBACK_HOSTS` is exactly `{127.0.0.1, ::1}`, and `main()` raises `SystemExit` for any other `RECON_HOST` |
| L2 | Loopback upload | `agent/uploader._LOOPBACK_HTTP` is the same set, and `assert_upload_url` gates `http` on it and raises `UploadError` otherwise |
| T1 | No docs, no telemetry | `create_app` passes `docs_url`/`redoc_url`/`openapi_url=None` and `telemetry=_TELEMETRY_OFF` (every signal `False`), and sets `OTEL_SDK_DISABLED=true` before `FastAPI(...)` |
| T2 | Strict CSP | `_HTML_HEADERS` carries `script-src 'none'` |
| A1 | Constant-time auth | `server/app.py` uses `secrets.compare_digest` |
| S1 | Safe YAML | no `yaml.load`/`full_load`/`unsafe_load`/`load_all`, and no `Loader`/`FullLoader`/`UnsafeLoader`, anywhere in `src/` |
| S2 | No shell | no `shell=` other than `False`, and no `os.system`/`popen`/`exec*`/`spawn*` |
| S3 | No code loading | no `pickle`/`marshal`/`shelve`/`dill` import, no `eval`/`exec` |
| M1 | Module isolation | `core/` imports none of `agent`, `server`, `desktop`, `alerts`; `agent/` imports none of `server`, `desktop`, `alerts`; `server/` imports none of `agent`, `desktop` |
| C1 | Metadata only | `agent/collectors.py` calls no `open`, `read_text`, `read_bytes`, `iterdir`, `glob`, or `rglob` |
| C2 | Pinned caps | `_MAX_INGEST_BYTES == 8 MiB`, `_MAX_ACTION_BODY == 2048`, `_PLAIN_MAX == 800`, `_PLAIN_MAX_BYTES == 3000` |
| R1 | Twin rule pack | `rules/windows_default.yaml` equals `core/rulepacks/windows_default.yaml` (line endings normalized) |
| R2 | Closed rule kinds | `core/rules._VALID_KINDS` is exactly the seven documented kinds |
| D1 | Deployment names | the systemd unit keeps `User=recon` and `/opt/recon/`; the Windows script keeps `"ScanzAgentDailyScan"` |
| P1 | Dependency fence | every base and extra dependency in `pyproject.toml` is in `ALLOWED_DEPS` |

### Step 2: read the failures

A `FAIL` line names the check and shows what it found. There are three cases.

1. **The diff broke an invariant.** This is the usual case. Fix the code, not the checker, and rerun until exit 0.
2. **The user approved a design change** that moves something the checker pins, such as a measured cap raise or a reviewed new dependency. Update the constant in `check_invariants.py` in the same commit, and say so in the PR body. Do not loosen a check to get to green.
3. **A refactor moved a pinned name**, for example `_LOOPBACK_HOSTS` renamed. Update the checker in the same commit so it keeps checking the same property, then run Step 3.

### Step 3: prove the checker still bites (after editing it)

```bash
bash .agents/skills/invariant-guard/verify.sh
```

This passes the clean tree, then plants ten violations in a temp copy and requires exit `2` with each `FAIL` line. It also requires a wrong root to exit `3`. Run it whenever `check_invariants.py` changes. A checker that cannot go red proves nothing.

### Step 4: what the checker cannot see (read the diff)

- **Sealing order.** `agent/cmdline.seal_command_lines` must run before a report is written or uploaded, and a raw command line must never reach `ScanReport.cmdline` in plaintext. `tests/unit/test_cmdline.py` and `tests/integration/test_cli.py` cover this.
- **HTML escaping.** Every dynamic value in `server/templates.py` goes through `html.escape`. `tests/unit/test_templates_safe.py` guards it.
- **Redirect allowlist.** New `next=` targets belong in `server/desk.safe_next`.
- **Origin check.** `POST /findings/{id}/{action}` keeps `_reject_foreign_origin`.
- **Upsert status rule.** Re-ingest preserves the operator status for identical evidence; changed evidence starts in `triage` (`server/storage.py`).
- **Collector reach.** New collectors read names, ports, and account names only. No file bytes, credentials, or network scans.

## Gotchas

- The checker reads source text. A constant built at runtime, such as `frozenset(some_list)`, reads as "not a literal" and fails L1/L2/R2. Keep the pinned values literal.
- R1 normalizes CRLF so a Windows checkout passes. Any other byte difference fails.
- P1 matches the project name before any `[extra]` or version marker, lowercased. `types-PyYAML` is `types-pyyaml`.
