#!/usr/bin/env python3
"""check_invariants.py - static checker for WynDoze-InfoScanOverload's design invariants.

Usage: python3 .agents/skills/invariant-guard/check_invariants.py [--repo-root PATH]

Stdlib only. It parses source with ``ast`` and never imports project code, so it
runs in a fresh container or a CI job before ``pip install``.

  L1  Loopback bind       server/__main__ exits unless RECON_HOST is 127.0.0.1 or ::1
  L2  Loopback upload     agent/uploader allows http only to 127.0.0.1 or ::1
  T1  No docs, no OTel    create_app nulls docs/redoc/openapi and turns telemetry off
  T2  Strict CSP          HTML responses carry script-src 'none'
  A1  Constant-time auth  server/app compares secrets with secrets.compare_digest
  S1  Safe YAML           no yaml.load / full_load / unsafe_load or unsafe Loader classes
  S2  No shell            no shell=True, os.system, os.popen, os.exec*, os.spawn*
  S3  No code loading     no pickle / marshal / shelve imports, no eval / exec
  M1  Module isolation    core imports no agent/server; agent and server never meet
  C1  Metadata only       agent/collectors opens no files
  C2  Pinned caps         ingest 8 MiB, action body 2048 B, sealed cmdline 800 chars
  R1  Twin rule pack      both windows_default.yaml copies are identical
  R2  Closed rule kinds   _VALID_KINDS is exactly the seven documented kinds
  D1  Deployment names         deploy keeps User=recon, /opt/recon, ScanzAgentDailyScan
  P1  Dependency fence    runtime dependencies stay inside a reviewed allowlist

Exit codes: 0 all pass, 2 an invariant is violated, 3 wrong root or unparseable file.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
import tomllib
from collections.abc import Iterator
from pathlib import Path

PKG = Path("src/wyndoze_infoscanoverload")
PKG_NAME = "wyndoze_infoscanoverload"
LOOPBACK = frozenset({"127.0.0.1", "::1"})
EXPECTED_KINDS = frozenset(
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
# Caps the docs promise. Raising one needs a measurement, then an edit here.
EXPECTED_CAPS = {
    ("server/app.py", "_MAX_INGEST_BYTES"): 8 * 1024 * 1024,
    ("server/app.py", "_MAX_ACTION_BODY"): 2048,
    ("agent/cmdline.py", "_PLAIN_MAX"): 800,
    ("agent/cmdline.py", "_PLAIN_MAX_BYTES"): 3000,
}
# Base and extra dependency names reviewed as local-only. A new name is a
# deliberate review: "no dependency that sends data off the machine".
ALLOWED_DEPS = frozenset(
    {
        "pydantic",
        "pydantic-settings",
        "psutil",
        "httpx",
        "cryptography",
        "pyyaml",
        "typer",
        "fastapi",
        "uvicorn",
        "jinja2",
        "pytest",
        "pytest-asyncio",
        "pytest-cov",
        "hypothesis",
        "mypy",
        "ruff",
        "types-pyyaml",
    }
)
UNSAFE_YAML_ATTRS = frozenset({"load", "full_load", "unsafe_load", "load_all", "unsafe_load_all"})
UNSAFE_YAML_LOADERS = frozenset({"Loader", "FullLoader", "UnsafeLoader"})
BANNED_IMPORTS = frozenset({"pickle", "marshal", "shelve", "dill"})
OS_SHELLISH = re.compile(r"^(system|popen|exec[lv]p?e?|spawn[lv]p?e?)$")


class Checker:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.passed = 0
        self.failed = 0
        self._trees: dict[Path, ast.Module] = {}

    def check(self, code: str, ok: bool, label: str, detail: str = "") -> None:  # noqa: FBT001
        if ok:
            self.passed += 1
            print(f"  PASS {code} {label}")
        else:
            self.failed += 1
            suffix = f" -- {detail}" if detail else ""
            print(f"  FAIL {code} {label}{suffix}")

    def tree(self, rel: Path) -> ast.Module:
        path = self.root / rel
        if path not in self._trees:
            self._trees[path] = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        return self._trees[path]

    def sources(self) -> Iterator[Path]:
        for path in sorted((self.root / PKG).rglob("*.py")):
            yield path.relative_to(self.root)


def module_constant(tree: ast.Module, name: str) -> ast.expr | None:
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                return node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ):
            return node.value
    return None


def literal_str_set(node: ast.expr | None) -> frozenset[str] | None:
    """Read ``frozenset({...})``, ``{...}``, or a tuple/list of string literals."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.args:
        node = node.args[0]
    if isinstance(node, ast.Set | ast.Tuple | ast.List):
        values = [
            e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
        ]
        if len(values) == len(node.elts):
            return frozenset(values)
    return None


def int_value(node: ast.expr | None) -> int | None:
    """Evaluate an int literal or a product of int literals (``8 * 1024 * 1024``)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        left, right = int_value(node.left), int_value(node.right)
        if left is not None and right is not None:
            return left * right
    return None


def find_function(tree: ast.Module, name: str) -> ast.FunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def dotted(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{dotted(node.value)}.{node.attr}"
    return ""


def absolute_import(rel: Path, node: ast.ImportFrom) -> str:
    """Resolve ``from .x import y`` against the importing module's package."""
    if node.level == 0:
        return node.module or ""
    parts = list(rel.with_suffix("").parts[1:])  # drop "src"
    base = parts[: len(parts) - node.level]
    return ".".join([*base, node.module] if node.module else base)


def imported_modules(rel: Path, tree: ast.Module) -> Iterator[tuple[int, str]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name
        elif isinstance(node, ast.ImportFrom):
            yield node.lineno, absolute_import(rel, node)


def check_loopback(c: Checker) -> None:
    print("L  loopback")
    main_rel = PKG / "server/__main__.py"
    tree = c.tree(main_rel)
    hosts = literal_str_set(module_constant(tree, "_LOOPBACK_HOSTS"))
    c.check("L1", hosts == LOOPBACK, "server _LOOPBACK_HOSTS is {127.0.0.1, ::1}", f"{hosts}")
    fn = find_function(tree, "main")
    guarded = False
    if fn is not None:
        for node in ast.walk(fn):
            if (
                isinstance(node, ast.If)
                and isinstance(node.test, ast.Compare)
                and isinstance(node.test.ops[0], ast.NotIn)
                and dotted(node.test.comparators[0]) == "_LOOPBACK_HOSTS"
            ):
                guarded = any(
                    isinstance(n, ast.Raise) and "SystemExit" in ast.unparse(n)
                    for n in ast.walk(node)
                )
    c.check("L1", guarded, "main() raises SystemExit when host not in _LOOPBACK_HOSTS")

    up_rel = PKG / "agent/uploader.py"
    tree = c.tree(up_rel)
    hosts = literal_str_set(module_constant(tree, "_LOOPBACK_HTTP"))
    c.check("L2", hosts == LOOPBACK, "uploader _LOOPBACK_HTTP is {127.0.0.1, ::1}", f"{hosts}")
    fn = find_function(tree, "assert_upload_url")
    body = ast.unparse(fn) if fn else ""
    c.check(
        "L2",
        "'http'" in body and "_LOOPBACK_HTTP" in body and "raise UploadError" in body,
        "assert_upload_url gates http on _LOOPBACK_HTTP and raises otherwise",
    )


def check_telemetry(c: Checker) -> None:
    print("T  docs, telemetry, CSP")
    tree = c.tree(PKG / "server/app.py")
    fn = find_function(tree, "create_app")
    if fn is None:
        c.check("T1", ok=False, label="create_app exists")
        return
    fastapi_call = next(
        (
            n
            for n in ast.walk(fn)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "FastAPI"
        ),
        None,
    )
    kwargs = {k.arg: k.value for k in fastapi_call.keywords} if fastapi_call else {}
    for key in ("docs_url", "redoc_url", "openapi_url"):
        value = kwargs.get(key)
        c.check(
            "T1",
            isinstance(value, ast.Constant) and value.value is None,
            f"FastAPI({key}=None)",
        )
    telemetry = kwargs.get("telemetry")
    c.check(
        "T1",
        isinstance(telemetry, ast.Name) and telemetry.id == "_TELEMETRY_OFF",
        "FastAPI(telemetry=_TELEMETRY_OFF)",
    )
    off = module_constant(tree, "_TELEMETRY_OFF")
    all_false = (
        isinstance(off, ast.Dict)
        and bool(off.values)
        and all(isinstance(v, ast.Constant) and v.value is False for v in off.values)
    )
    c.check("T1", all_false, "_TELEMETRY_OFF sets every signal False")
    env_sets = {
        ast.unparse(n.targets[0]): ast.unparse(n.value)
        for n in fn.body
        if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Subscript)
    }
    c.check(
        "T1",
        env_sets.get("os.environ['OTEL_SDK_DISABLED']") == "'true'",
        "create_app sets OTEL_SDK_DISABLED=true",
    )
    first_stmt_line = fastapi_call.lineno if fastapi_call else 0
    otel_line = next(
        (
            n.lineno
            for n in fn.body
            if isinstance(n, ast.Assign) and "OTEL_SDK_DISABLED" in ast.unparse(n.targets[0])
        ),
        10**9,
    )
    c.check("T1", otel_line < first_stmt_line, "OTEL_SDK_DISABLED is set before FastAPI(...)")
    headers = ast.unparse(module_constant(tree, "_HTML_HEADERS") or ast.Constant(""))
    c.check("T2", "script-src 'none'" in headers, "_HTML_HEADERS CSP has script-src 'none'")
    c.check(
        "A1",
        "secrets.compare_digest" in ast.unparse(tree),
        "server/app uses secrets.compare_digest",
    )


def check_dangerous_calls(c: Checker) -> None:
    print("S  YAML, shell, code loading")
    yaml_hits: list[str] = []
    shell_hits: list[str] = []
    load_hits: list[str] = []
    for rel in c.sources():
        tree = c.tree(rel)
        for node in ast.walk(tree):
            where = f"{rel}:{getattr(node, 'lineno', '?')}"
            if isinstance(node, ast.Attribute):
                name = dotted(node)
                if name.startswith("yaml.") and (
                    node.attr in UNSAFE_YAML_ATTRS or node.attr in UNSAFE_YAML_LOADERS
                ):
                    yaml_hits.append(f"{where} {name}")
                if name.startswith("os.") and OS_SHELLISH.match(node.attr):
                    shell_hits.append(f"{where} {name}")
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "shell" and not (
                        isinstance(kw.value, ast.Constant) and kw.value.value is False
                    ):
                        shell_hits.append(f"{where} shell={ast.unparse(kw.value)}")
                if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                    load_hits.append(f"{where} {node.func.id}()")
            if isinstance(node, ast.ImportFrom) and node.module == "yaml":
                for alias in node.names:
                    if alias.name in UNSAFE_YAML_ATTRS | UNSAFE_YAML_LOADERS:
                        yaml_hits.append(f"{where} from yaml import {alias.name}")
        for line, mod in imported_modules(rel, tree):
            if mod.split(".")[0] in BANNED_IMPORTS:
                load_hits.append(f"{rel}:{line} import {mod}")
    c.check("S1", not yaml_hits, "no unsafe yaml loader in src", "; ".join(yaml_hits))
    c.check(
        "S2", not shell_hits, "no shell=True or os shell/exec/spawn in src", "; ".join(shell_hits)
    )
    c.check("S3", not load_hits, "no pickle/marshal/shelve/eval/exec in src", "; ".join(load_hits))


def check_isolation(c: Checker) -> None:
    print("M  module isolation")
    rules = {
        "core": ("agent", "server", "desktop", "alerts"),
        "agent": ("server", "desktop", "alerts"),
        "server": ("agent", "desktop"),
    }
    for area, banned in rules.items():
        hits: list[str] = []
        for rel in c.sources():
            if rel.parts[2] != area:
                continue
            for line, mod in imported_modules(rel, c.tree(rel)):
                parts = mod.split(".")
                if parts[0] == PKG_NAME and len(parts) > 1 and parts[1] in banned:
                    hits.append(f"{rel}:{line} -> {mod}")
        c.check("M1", not hits, f"{area}/ imports none of {', '.join(banned)}", "; ".join(hits))


def check_collectors(c: Checker) -> None:
    print("C  collectors and caps")
    rel = PKG / "agent/collectors.py"
    hits = [
        f"{rel}:{n.lineno} {ast.unparse(n.func)}"
        for n in ast.walk(c.tree(rel))
        if isinstance(n, ast.Call)
        and (
            (isinstance(n.func, ast.Name) and n.func.id == "open")
            or (
                isinstance(n.func, ast.Attribute)
                and n.func.attr in {"read_text", "read_bytes", "open", "iterdir", "rglob", "glob"}
            )
        )
    ]
    c.check("C1", not hits, "agent/collectors.py opens or walks no files", "; ".join(hits))
    for (file, name), expected in EXPECTED_CAPS.items():
        value = int_value(module_constant(c.tree(PKG / file), name))
        c.check("C2", value == expected, f"{file} {name} == {expected}", f"found {value}")


def check_rule_pack(c: Checker) -> None:
    print("R  rule pack")
    bundled = c.root / PKG / "core/rulepacks/windows_default.yaml"
    operator = c.root / "rules/windows_default.yaml"

    def norm(p: Path) -> bytes:
        return p.read_bytes().replace(b"\r\n", b"\n")

    same = bundled.is_file() and operator.is_file() and norm(bundled) == norm(operator)
    c.check("R1", same, "rules/ and core/rulepacks/ windows_default.yaml are identical")
    kinds = literal_str_set(module_constant(c.tree(PKG / "core/rules.py"), "_VALID_KINDS"))
    extra = sorted((kinds or frozenset()) - EXPECTED_KINDS)
    missing = sorted(EXPECTED_KINDS - (kinds or frozenset()))
    c.check(
        "R2",
        kinds == EXPECTED_KINDS,
        "_VALID_KINDS is exactly the seven documented kinds",
        f"extra={extra} missing={missing}",
    )


def check_deploy(c: Checker) -> None:
    print("D  deploy names")
    service = (c.root / "deploy/systemd/WynDoze-InfoScanOverload-agent.service").read_text(
        encoding="utf-8"
    )
    task = (c.root / "deploy/windows/Install-ScanneragentTask.ps1").read_text(encoding="utf-8")
    c.check("D1", "User=recon" in service, "systemd unit runs as User=recon")
    c.check("D1", "/opt/recon/" in service, "systemd unit lives under /opt/recon")
    c.check("D1", '"ScanzAgentDailyScan"' in task, "Windows task is named ScanzAgentDailyScan")


def check_dependencies(c: Checker) -> None:
    print("P  dependencies")
    project = tomllib.loads((c.root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    specs = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        specs.extend(extra)
    names = {re.split(r"[\s\[<>=!~;]", spec, maxsplit=1)[0].lower() for spec in specs}
    unknown = sorted(names - ALLOWED_DEPS)
    c.check("P1", not unknown, "every dependency is in the reviewed allowlist", f"{unknown}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    default_root = Path(__file__).resolve().parents[3]
    parser.add_argument("--repo-root", type=Path, default=default_root)
    args = parser.parse_args()
    root: Path = args.repo_root.resolve()
    if not (root / PKG / "__init__.py").is_file():
        print(f"env error: {root} is not a WynDoze-InfoScanOverload checkout", file=sys.stderr)
        return 3
    c = Checker(root)
    try:
        for step in (
            check_loopback,
            check_telemetry,
            check_dangerous_calls,
            check_isolation,
            check_collectors,
            check_rule_pack,
            check_deploy,
            check_dependencies,
        ):
            step(c)
    except (OSError, SyntaxError, KeyError, tomllib.TOMLDecodeError) as exc:
        print(f"env error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    print(f"{c.passed} passed, {c.failed} failed")
    return 2 if c.failed else 0


if __name__ == "__main__":
    sys.exit(main())
