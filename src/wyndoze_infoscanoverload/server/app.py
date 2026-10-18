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
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.telemetry import TelemetryConfig
from pydantic import ValidationError

from wyndoze_infoscanoverload.core.models import Finding, ScanReport
from wyndoze_infoscanoverload.core.rulepacks import default_rule_pack
from wyndoze_infoscanoverload.core.rules import RulePack, evaluate, load_rule_pack
from wyndoze_infoscanoverload.server import templates
from wyndoze_infoscanoverload.server.config import ServerConfig
from wyndoze_infoscanoverload.server.exports import EXPORTERS
from wyndoze_infoscanoverload.server.storage import Storage

logger = logging.getLogger("wyndoze_infoscanoverload.server")

_basic = HTTPBasic(auto_error=False)
_MAX_INGEST_BYTES = 8 * 1024 * 1024
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
        version="1.0.0",
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


def _reject_foreign_origin(request: Request) -> None:
    """Reject a present Origin whose host is not this server. Missing Origin passes."""
    origin = request.headers.get("origin")
    if origin is None:
        return
    host = request.headers.get("host", "")
    if urlparse(origin).netloc.lower() != host.lower() or not host:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="origin rejected")


def _register_routes(app: FastAPI) -> None:  # noqa: C901 - cohesive route table
    def dashboard_guard(
        credentials: Annotated[HTTPBasicCredentials | None, Depends(_basic)] = None,
    ) -> None:
        _require_dashboard(app, credentials)

    DashAuth = Depends(dashboard_guard)  # noqa: N806

    # -- ingest ------------------------------------------------------------
    @app.post("/api/scans", status_code=status.HTTP_201_CREATED)
    async def ingest_scan(
        request: Request,
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
    def summary_page(_: None = DashAuth) -> str:
        return templates.summary_page(app.state.storage.summary())

    @app.get("/triage", response_class=HTMLResponse)
    def triage_inbox(_: None = DashAuth) -> str:
        findings = app.state.storage.list_findings(status="triage")
        return templates.findings_table(findings, "Triage Inbox")

    @app.get("/timeline", response_class=HTMLResponse)
    def timeline(_: None = DashAuth) -> str:
        findings = app.state.storage.list_findings()
        return templates.findings_table(findings, "Timeline (all findings)")

    @app.get("/endpoints", response_class=HTMLResponse)
    def endpoints(_: None = DashAuth) -> str:
        return templates.endpoints_table(app.state.storage.list_endpoints())

    # -- findings lifecycle ------------------------------------------------
    @app.post("/findings/{finding_id}/{action}", response_class=HTMLResponse)
    def update_finding(
        finding_id: int, action: str, request: Request, _: None = DashAuth
    ) -> Response:
        _reject_foreign_origin(request)
        mapping = {
            "flag": "flagged",
            "archive": "archived",
            "suppress": "suppressed",
            "triage": "triage",
        }
        new_status = mapping.get(action)
        if not new_status:
            raise HTTPException(status_code=404, detail="unknown action")
        app.state.storage.set_finding_status(finding_id, new_status)
        # PRG: redirect back to the triage inbox.
        return Response(status_code=303, headers={"Location": "/triage"})

    # -- reports -----------------------------------------------------------
    @app.get("/reports/summary", response_class=HTMLResponse)
    def report_summary(_: None = DashAuth) -> str:
        return templates.summary_page(app.state.storage.summary())

    # -- exports -----------------------------------------------------------
    @app.get("/export/findings.{fmt}")
    def export_findings(fmt: str, _: None = DashAuth) -> Response:
        alias = {"md": "markdown"}.get(fmt, fmt)
        exporter = EXPORTERS.get(alias)
        if not exporter:
            raise HTTPException(status_code=404, detail="unknown export format")
        render, media_type = exporter
        findings = app.state.storage.list_findings()
        content = render(findings)
        filename = f"recon-findings.{fmt}"
        return PlainTextResponse(
            content,
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )


__all__ = ["create_app"]
