"""Typer CLI for the endpoint agent.

Commands
--------
``scan``      Collect telemetry and upload (or defer to the encrypted cache).
``replay``    Re-send any cached bundles (used on the jumpbox / after outage).
``bundle``    Collect telemetry to an encrypted bundle only (isolated machine).
``evaluate``  Run the local rules engine against a bundle/JSON and print findings.
``gen-key``   Print a fresh Fernet key for the deferred-upload cache.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Annotated

import typer

from wyndoze_infoscanoverload._version import __version__
from wyndoze_infoscanoverload.agent.cache import BUNDLE_SUFFIX, BundleCache
from wyndoze_infoscanoverload.agent.collectors import collect_report
from wyndoze_infoscanoverload.agent.config import AgentConfig
from wyndoze_infoscanoverload.agent.crypto import CryptoError, generate_key
from wyndoze_infoscanoverload.agent.uploader import UploadError, assert_upload_url, upload_report
from wyndoze_infoscanoverload.core.models import EndpointRole, ScanReport
from wyndoze_infoscanoverload.core.rulepacks import default_rule_pack
from wyndoze_infoscanoverload.core.rules import evaluate, load_rule_pack

app = typer.Typer(
    name="WynDoze-InfoScanOverload-agent",
    help="WynDoze-InfoScanOverload endpoint scanner.",
    no_args_is_help=True,
    add_completion=False,
)

logger = logging.getLogger("wyndoze_infoscanoverload.agent")

TOKEN_ENV = "RECON_AGENT_TOKEN"  # noqa: S105 - env var *name*, not a secret
KEY_ENV = "RECON_AGENT_ENCRYPTION_KEY"
DISABLE_ENV = "RECON_AGENT_DISABLE"


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )


def _want_cmdline(flag: bool) -> bool:
    if flag:
        return True
    raw = os.environ.get("RECON_AGENT_CMDLINE", "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _build_config(
    role: EndpointRole,
    server_url: str | None,
    cache_dir: Path,
    *,
    verify_tls: bool = True,
    collect_cmdline: bool = False,
) -> AgentConfig:
    return AgentConfig(
        server_url=server_url,
        token=os.environ.get(TOKEN_ENV),
        role=role,
        cache_dir=cache_dir,
        encryption_key=os.environ.get(KEY_ENV),
        verify_tls=verify_tls,
        collect_cmdline=collect_cmdline,
    )


def _exit_if_disabled() -> None:
    raw = os.environ.get(DISABLE_ENV, "")
    if raw.strip().lower() in {"1", "true", "yes", "on"}:
        typer.echo(f"{DISABLE_ENV} is set. No collection and no upload.")
        raise typer.Exit(code=0)


def _require_upload_url(server_url: str | None) -> str:
    if not server_url:
        typer.secho(
            "--server-url is required unless --no-upload is set.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)
    try:
        assert_upload_url(server_url)
    except UploadError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    return server_url


def default_cache_dir() -> Path:
    """Return the bundle cache. On Windows this is not a relative System32 path."""
    if os.name == "nt":
        root = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        return Path(root) / "WynDoze-InfoScanOverload" / "cache"
    return Path("WynDoze-InfoScanOverload-cache")


_DEFAULT_CACHE = default_cache_dir()


def _require_key(config: AgentConfig) -> str:
    if not config.encryption_key:
        typer.secho(
            f"Encryption key required. Set {KEY_ENV} "
            "(see `WynDoze-InfoScanOverload-agent gen-key`).",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)
    return config.encryption_key


@app.command()
def version() -> None:
    """Print the version and exit."""
    typer.echo(__version__)


@app.command("gen-key")
def gen_key() -> None:
    """Print a fresh Fernet key for the encrypted deferred-upload cache."""
    typer.echo(generate_key())


@app.command()
def scan(
    server_url: Annotated[
        str | None,
        typer.Option("--server-url", help="Ingest endpoint URL (required unless --no-upload)."),
    ] = None,
    role: Annotated[
        EndpointRole, typer.Option("--role", help="Endpoint role for rule scoping.")
    ] = EndpointRole.UNKNOWN,
    output_json: Annotated[
        Path | None, typer.Option("--output-json", help="Also write raw report JSON here.")
    ] = None,
    cache_dir: Annotated[
        Path, typer.Option("--cache-dir", help="Where to defer bundles on failure.")
    ] = _DEFAULT_CACHE,
    no_upload: Annotated[
        bool, typer.Option("--no-upload", help="Collect only; do not upload.")
    ] = False,
    defer_on_failure: Annotated[
        bool,
        typer.Option("--defer/--no-defer", help="Encrypt to cache if upload fails."),
    ] = True,
    insecure: Annotated[
        bool, typer.Option("--insecure", help="Disable TLS verification (testing only).")
    ] = False,
    cmdline: Annotated[
        bool,
        typer.Option("--cmdline", help="Collect command lines and store them encrypted."),
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", help="Verbose logging.")] = False,
) -> None:
    """Collect telemetry and upload it, deferring to an encrypted cache on failure."""
    _configure_logging(verbose)
    _exit_if_disabled()
    if not no_upload:
        server_url = _require_upload_url(server_url)
    config = _build_config(
        role,
        server_url,
        cache_dir,
        verify_tls=not insecure,
        collect_cmdline=_want_cmdline(cmdline),
    )
    if config.collect_cmdline:
        _require_key(config)

    report = collect_report(config)
    typer.echo(
        f"Collected: {len(report.processes)} procs, "
        f"{len(report.listening_connections)} listeners, "
        f"{len(report.services)} services, "
        f"{len(report.observations)} local observations."
    )

    if output_json:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        typer.echo(f"Wrote {output_json}")

    if no_upload:
        typer.echo("--no-upload set; skipping upload.")
        return

    if server_url is None:
        raise typer.Exit(code=2)

    if not config.token:
        typer.secho(f"Missing token env var {TOKEN_ENV}.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    # Key first, so a failed upload can still be deferred. Missing key exits
    # before any HTTP call and writes no bundle.
    defer_key = _require_key(config) if defer_on_failure else None

    try:
        result = upload_report(
            report,
            server_url,
            config.token,
            timeout_s=config.upload_timeout_s,
            verify_tls=config.verify_tls,
        )
        typer.secho(f"Upload OK: {result}", fg=typer.colors.GREEN)
    except UploadError as exc:
        typer.secho(f"Upload failed: {exc}", fg=typer.colors.YELLOW, err=True)
        if defer_key is not None:
            path = BundleCache(cache_dir, defer_key).save(report)
            typer.echo(f"Deferred to encrypted bundle: {path}")
            raise typer.Exit(code=3) from exc
        raise typer.Exit(code=1) from exc


@app.command()
def bundle(
    role: Annotated[
        EndpointRole, typer.Option("--role", help="Endpoint role for rule scoping.")
    ] = EndpointRole.UNKNOWN,
    cache_dir: Annotated[
        Path, typer.Option("--cache-dir", help="Where to write the encrypted bundle.")
    ] = _DEFAULT_CACHE,
    verbose: Annotated[bool, typer.Option("--verbose", help="Verbose logging.")] = False,
) -> None:
    """Collect telemetry to an encrypted bundle only (isolated-machine mode)."""
    _configure_logging(verbose)
    _exit_if_disabled()
    config = _build_config(role, None, cache_dir)
    key = _require_key(config)
    report = collect_report(config)
    path = BundleCache(cache_dir, key).save(report)
    typer.secho(f"Wrote encrypted bundle: {path}", fg=typer.colors.GREEN)
    typer.echo(
        "Transfer it to a machine with internet access and run "
        "`WynDoze-InfoScanOverload-agent replay`."
    )


@app.command()
def replay(
    server_url: Annotated[str, typer.Option(..., "--server-url", help="Ingest endpoint URL.")],
    cache_dir: Annotated[
        Path, typer.Option("--cache-dir", help="Cache directory to replay.")
    ] = _DEFAULT_CACHE,
    delete_on_success: Annotated[
        bool, typer.Option("--delete/--keep", help="Delete bundles after upload.")
    ] = True,
    insecure: Annotated[bool, typer.Option("--insecure", help="Disable TLS verify.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", help="Verbose logging.")] = False,
) -> None:
    """Re-send cached bundles (jumpbox / post-outage)."""
    _configure_logging(verbose)
    _exit_if_disabled()
    _require_upload_url(server_url)
    config = _build_config(EndpointRole.UNKNOWN, server_url, cache_dir, verify_tls=not insecure)
    if not config.token:
        typer.secho(f"Missing token env var {TOKEN_ENV}.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    key = _require_key(config)
    cache = BundleCache(cache_dir, key)

    bundles = list(cache.iter_bundles())
    if not bundles:
        typer.echo("No cached bundles to replay.")
        return

    ok = 0
    failed = 0
    cleanup_failed = 0
    for path in bundles:
        try:
            report = cache.load(path)
            upload_report(
                report,
                server_url,
                config.token,
                timeout_s=config.upload_timeout_s,
                verify_tls=config.verify_tls,
            )
        except (UploadError, CryptoError, OSError, ValueError) as exc:
            failed += 1
            typer.secho(f"  {path.name}: FAILED ({exc})", fg=typer.colors.YELLOW, err=True)
            continue
        ok += 1
        typer.secho(f"  {path.name}: uploaded", fg=typer.colors.GREEN)
        if delete_on_success:
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:
                cleanup_failed += 1
                typer.secho(
                    f"  {path.name}: uploaded but could not delete ({exc}); "
                    "the retained bundle may upload again on the next replay.",
                    fg=typer.colors.YELLOW,
                    err=True,
                )

    typer.echo(f"Replay complete: {ok} uploaded, {failed} failed.")
    if cleanup_failed:
        typer.echo(f"{cleanup_failed} uploaded bundle(s) could not be deleted.", err=True)
    if failed or cleanup_failed:
        raise typer.Exit(code=1)


@app.command()
def evaluate_local(
    source: Annotated[
        Path,
        typer.Argument(help="Path to a report .json or an encrypted bundle."),
    ],
    rules: Annotated[
        Path | None, typer.Option("--rules", help="Rule pack YAML (defaults to bundled).")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", help="Verbose logging.")] = False,
) -> None:
    """Run the rules engine locally against a report and print findings as JSON."""
    _configure_logging(verbose)
    report = _load_report_source(source)
    pack = load_rule_pack(rules) if rules else default_rule_pack()
    findings = evaluate(report, pack)
    typer.echo(json.dumps([f.model_dump() for f in findings], indent=2))
    typer.secho(
        f"{len(findings)} finding(s) using pack {pack.name} v{pack.version}.",
        fg=typer.colors.CYAN,
        err=True,
    )


def _load_report_source(source: Path) -> ScanReport:
    if source.name.endswith(BUNDLE_SUFFIX):
        key = os.environ.get(KEY_ENV)
        if not key:
            typer.secho(f"Set {KEY_ENV} to decrypt a bundle.", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)
        return BundleCache(source.parent, key).load(source)
    try:
        return ScanReport.model_validate_json(source.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        typer.secho(f"Could not load report: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc


def main() -> None:
    """Entry point wrapper."""
    try:
        app()
    except KeyboardInterrupt:  # pragma: no cover
        typer.echo("Interrupted.", err=True)
        sys.exit(130)


if __name__ == "__main__":
    main()
