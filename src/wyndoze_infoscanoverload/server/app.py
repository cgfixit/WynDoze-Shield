"""FastAPI application factory.

Two auth domains, both fail closed:

* **Ingest** (``POST /api/scans``) requires ``Authorization: Bearer`` matching
  ``RECON_INGEST_TOKEN``. A missing or empty token rejects every ingest.
* **Dashboard** (HTML + exports) requires HTTP Basic auth. A missing or empty
  ``RECON_DASHBOARD_PASSWORD`` rejects every dashboard route.

``GET /api/health`` stays open and returns ``{"status": "ok"}`` only.
The rules engine runs server-side on every ingest.
"""

from __future__ import annotations

import logging
import os
import secrets
from typing import Annotated
from urllib.parse import parse_qsl, urlparse

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.telemetry import TelemetryConfig
from pydantic import ValidationError

from wyndoze_infoscanoverload._version import __version__
from wyndoze_infoscanoverload.alerts import notify_findings
from wyndoze_infoscanoverload.core.models import Finding, FindingStatus, ScanReport
from wyndoze_infoscanoverload.core.rulepacks import default_rule_pack
from wyndoze_infoscanoverload.core.rules import RulePack, evaluate, load_rule_pack
from wyndoze_infoscanoverload.core.severity import Severity
from wyndoze_infoscanoverload.server import templates
from wyndoze_infoscanoverload.server.config import ServerConfig
from wyndoze_infoscanoverload.server.desk import DeskQuery, safe_next
from wyndoze_infoscanoverload.server.exports import EXPORTERS
from wyndoze_infoscanoverload.server.present import UnreadableScan, public_scan_facts
from wyndoze_infoscanoverload.server.storage import Storage

logger = logging.getLogger("wyndoze_infoscanoverload.server")

_basic = HTTPBasic(auto_error=False)
_MAX_INGEST_BYTES = 8 * 1024 * 1024
_MAX_ACTION_BODY = 2048
_ACTION_STATUS = {
    "flag": "flagged",
    "archive": "archived",
    "suppress": "suppressed",
    "triage": "triage",
}
_FORM_MEDIA = "application/x-www-form-urlencoded"
_HTML_HEADERS: dict[str, str] = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; "
        "img-src 'none'; script-src 'none'; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    ),
    # Form POSTs need their same-origin Origin header for the CSRF check.
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
}


def _html(body: str) -> HTMLResponse:
    """Return an HTML page with the dashboard response headers."""
    return HTMLResponse(body, headers=_HTML_HEADERS)


_TELEMETRY_OFF: TelemetryConfig = {
    "tracing": False,
    "metrics": False,
    "logs": False,
    "operation_spans": False,
    "auto_configure": False,
}


def _const_eq(left: str, right: str) -> bool:
    """Constant-time compare. ``compare_digest`` rejects non-ASCII ``str``."""
    return secrets.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _allowed_flags(pack: RulePack) -> frozenset[str]:
    """Return lowercased names from loaded cmdline_flag rules."""
    return frozenset(
        name for rule in pack.rules if rule.kind == "cmdline_flag" for name in rule.names
    )


def _load_pack(config: ServerConfig) -> RulePack:
    if config.rules_path:
        logger.info("Loading rule pack from %s", config.rules_path)
        return load_rule_pack(config.rules_path)
    return default_rule_pack()


def create_app(config: ServerConfig | None = None) -> FastAPI:
    """Application factory."""
    # FastAPI 0.143 exports OTLP when FASTAPI_OTEL_AUTO_CONFIGURE=true.
    os.environ["OTEL_SDK_DISABLED"] = "true"
    os.environ["FASTAPI_OTEL_AUTO_CONFIGURE"] = "false"
    config = config or ServerConfig()
    storage = Storage(config.db_path)
    storage.init_db()
    rule_pack = _load_pack(config)

    app = FastAPI(
        title="WynDoze-InfoScanOverload",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        telemetry=_TELEMETRY_OFF,
    )
    app.state.config = config
    app.state.storage = storage
    app.state.rule_pack = rule_pack

    if not config.ingest_token:
        logger.warning("RECON_INGEST_TOKEN unset. POST /api/scans will return 401.")
    if not config.dashboard_password:
        logger.warning("RECON_DASHBOARD_PASSWORD unset. Dashboard routes will return 401.")

    _register_routes(app)
    return app


def _require_ingest_token(app: FastAPI, authorization: str | None) -> None:
    config: ServerConfig = app.state.config
    token = config.ingest_token or ""
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid or missing bearer token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token or not authorization:
        raise unauthorized
    if not _const_eq(authorization, f"Bearer {token}"):
        raise unauthorized


def _require_dashboard(app: FastAPI, credentials: HTTPBasicCredentials | None) -> None:
    config: ServerConfig = app.state.config
    password = config.dashboard_password or ""
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="unauthorized",
        headers={"WWW-Authenticate": "Basic"},
    )
    if not password or credentials is None:
        raise unauthorized
    user_ok = _const_eq(credentials.username, config.dashboard_user)
    pass_ok = _const_eq(credentials.password, password)
    if not (user_ok and pass_ok):
        raise unauthorized


def _is_form_body(content_type: str | None) -> bool:
    """Return True when the body should be read as urlencoded form data."""
    if content_type is None:
        return True
    media = content_type.split(";", 1)[0].strip().lower()
    return media == _FORM_MEDIA


async def _posted_next(request: Request) -> str | None:
    """Return the single next field, or None when the body does not carry one.

    A body longer than 2048 bytes is rejected before any status write.
    The body is not logged.
    """
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > _MAX_ACTION_BODY:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="body too large")
        body.extend(chunk)
    if not body:
        return None
    if not _is_form_body(request.headers.get("content-type")):
        return None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    values = [item for key, item in parse_qsl(text, keep_blank_values=True) if key == "next"]
    if len(values) != 1:
        return None
    return values[0]


def _scan_html(app: FastAPI, scan_id: int) -> HTMLResponse:
    """Render one scan, or 404 when it is missing or unreadable."""
    row = app.state.storage.get_scan(scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    try:
        facts = public_scan_facts(
            str(row["raw_json"]),
            str(row["received_at_utc"]),
            _allowed_flags(app.state.rule_pack),
        )
    except UnreadableScan:
        logger.info("scan id=%s unreadable", scan_id)
        raise HTTPException(status_code=404, detail="not found") from None
    findings = app.state.storage.list_findings(scan_id=scan_id)
    names = templates.cmdline_rule_names(app.state.rule_pack.rules)
    return _html(templates.scan_page(facts, findings, f"/scans/{int(scan_id)}", names))


def _reject_foreign_origin(request: Request) -> None:
    """Reject a present Origin whose host is not this server. Missing Origin passes."""
    origin = request.headers.get("origin")
    if origin is None:
        return
    host = request.headers.get("host", "")
    if urlparse(origin).netloc.lower() != host.lower() or not host:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="origin rejected")


def _register_routes(app: FastAPI) -> None:  # noqa: C901, PLR0915 - cohesive route table
    def dashboard_guard(
        credentials: Annotated[HTTPBasicCredentials | None, Depends(_basic)] = None,
    ) -> None:
        _require_dashboard(app, credentials)

    DashAuth = Depends(dashboard_guard)  # noqa: N806

    # -- ingest ------------------------------------------------------------
    @app.post("/api/scans", status_code=status.HTTP_201_CREATED)
    async def ingest_scan(
        request: Request,
        background_tasks: BackgroundTasks,
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, object]:
        _require_ingest_token(app, authorization)
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > _MAX_INGEST_BYTES:
                raise HTTPException(status_code=413, detail="ingest body exceeds 8 MiB")
            body.extend(chunk)
        try:
            report = ScanReport.model_validate_json(body)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail="invalid scan report") from exc
        storage: Storage = app.state.storage
        pack: RulePack = app.state.rule_pack
        findings: list[Finding] = evaluate(report, pack)
        scan_id = storage.record_scan(report, findings)
        background_tasks.add_task(
            notify_findings,
            report.hostname,
            [(item.severity.value, item.rule_id, item.title) for item in findings],
        )
        return {
            "status": "accepted",
            "scan_id": scan_id,
            "hostname": report.hostname,
            "findings": len(findings),
        }

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    # -- dashboard (HTML) --------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def summary_page(_: None = DashAuth) -> HTMLResponse:
        return _html(templates.summary_page(app.state.storage.summary()))

    @app.get("/triage", response_class=HTMLResponse)
    @app.get("/timeline", response_class=HTMLResponse)
    def finding_list(
        request: Request,
        *,
        _: None = DashAuth,
        status_filter: Annotated[str, Query(alias="status", max_length=16)] = "",
        hostname: Annotated[str | None, Query(max_length=255)] = None,
        host: Annotated[str | None, Query(max_length=255)] = None,
        severity: Annotated[str, Query(max_length=16)] = "",
        rule_id: Annotated[str | None, Query(max_length=512)] = None,
        page_number: Annotated[int, Query(alias="page", ge=1, le=1000000)] = 1,
    ) -> HTMLResponse:
        try:
            selected = (
                "active"
                if status_filter == "active"
                else FindingStatus(status_filter).value
                if status_filter
                else None
            )
            selected_severity = Severity(severity).value if severity else None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="invalid finding filter") from exc
        if request.url.path == "/triage" and selected is None:
            selected = "triage"
        hostname = hostname or host
        page_size = 50
        findings = app.state.storage.list_findings(
            status=selected,
            limit=page_size + 1,
            offset=(page_number - 1) * page_size,
            hostname=hostname or None,
            severity=selected_severity,
            rule_id=rule_id or None,
        )
        filters = {
            "status": selected,
            "hostname": hostname or None,
            "severity": selected_severity,
            "rule_id": rule_id or None,
        }
        names = templates.cmdline_rule_names(app.state.rule_pack.rules)
        if request.url.path == "/triage":
            query = DeskQuery(
                status=selected or "triage",
                severity=selected_severity,
                host=hostname,
                rule_id=rule_id,
            )
            return _html(
                templates.triage_page(
                    findings[:page_size],
                    query,
                    app.state.storage.list_endpoints(),
                    names,
                    filters=filters,
                    page_number=page_number,
                    has_next=len(findings) > page_size,
                )
            )
        return _html(
            templates.timeline_page(
                app.state.storage.list_scans_public(),
                findings[:page_size],
                names,
                filters=filters,
                page_number=page_number,
                has_next=len(findings) > page_size,
            )
        )

    @app.get("/findings/{finding_id}", response_class=HTMLResponse)
    def finding_detail(finding_id: int, _: None = DashAuth) -> HTMLResponse:
        finding = app.state.storage.get_finding(finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="finding not found")
        scan = app.state.storage.get_scan(finding["scan_id"])
        return _html(
            templates.finding_detail(
                finding, scan, templates.cmdline_rule_names(app.state.rule_pack.rules)
            )
        )

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    def scan_facts(scan_id: int, _: None = DashAuth) -> HTMLResponse:
        return _scan_html(app, scan_id)

    @app.get("/endpoints", response_class=HTMLResponse)
    def endpoints(_: None = DashAuth) -> HTMLResponse:
        return _html(
            templates.endpoints_table(
                app.state.storage.list_endpoints(app.state.config.stale_after_hours),
                app.state.storage.open_finding_counts(),
            )
        )

    # -- findings lifecycle ------------------------------------------------
    @app.get("/findings/{finding_id}/suppress/confirm", response_class=HTMLResponse)
    def suppress_confirm(finding_id: int, request: Request, _: None = DashAuth) -> HTMLResponse:
        finding = app.state.storage.get_finding(finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="not found")
        target = safe_next(request.query_params.get("next"))
        return _html(templates.suppress_confirm_page(finding, target))

    @app.post("/findings/{finding_id}/{action}")
    async def update_finding(
        finding_id: int, action: str, request: Request, _: None = DashAuth
    ) -> Response:
        _reject_foreign_origin(request)
        new_status = _ACTION_STATUS.get(action)
        if new_status is None:
            raise HTTPException(status_code=404, detail="unknown action")
        posted = await _posted_next(request)
        if not app.state.storage.set_finding_status(finding_id, new_status):
            raise HTTPException(status_code=404, detail="not found")
        return Response(status_code=303, headers={"Location": safe_next(posted)})

    # -- reports -----------------------------------------------------------
    @app.get("/reports/summary", response_class=HTMLResponse)
    def report_summary(_: None = DashAuth) -> HTMLResponse:
        return _html(templates.reports_page())

    # -- exports -----------------------------------------------------------
    @app.get("/export/findings.{fmt}")
    def export_findings(fmt: str, _: None = DashAuth) -> Response:
        alias = {"md": "markdown"}.get(fmt, fmt)
        exporter = EXPORTERS.get(alias)
        if not exporter:
            raise HTTPException(status_code=404, detail="unknown export format")
        render, media_type = exporter
        findings = app.state.storage.list_findings(limit=None)
        content = render(findings)
        filename = f"recon-findings.{fmt}"
        return PlainTextResponse(
            content,
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )


__all__ = ["create_app"]
