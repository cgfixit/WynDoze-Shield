"""Opt-in SMTP alerts. This is a client, not a mail server.

The send path follows scrape-n-email: ``smtplib`` plus STARTTLS on the usual
submission port. Port 465 uses ``SMTP_SSL`` instead. Credentials come from the
process environment and are never logged.
"""

from __future__ import annotations

import logging
import os
import smtplib
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage

logger = logging.getLogger("wyndoze_infoscanoverload.alerts")

_ON = frozenset({"1", "true", "yes", "on"})
_SSL_PORT = 465
_MAX_PORT = 65535


@dataclass(frozen=True, slots=True)
class AlertSettings:
    """SMTP submission settings for one alert."""

    host: str
    port: int
    username: str
    recipient: str
    password: str = field(repr=False)


def settings_from_env() -> AlertSettings | None:
    """Return settings when alerts are on and every field is present."""
    raw = os.environ.get("RECON_ALERTS", "")
    if raw.strip().lower() not in _ON:
        return None
    host = os.environ.get("RECON_SMTP_HOST", "").strip()
    username = os.environ.get("RECON_SMTP_USER", "").strip()
    password = os.environ.get("RECON_SMTP_PASSWORD", "")
    recipient = os.environ.get("RECON_ALERT_TO", "").strip()
    port_text = os.environ.get("RECON_SMTP_PORT", "587").strip()
    if not host or not username or not password or not recipient:
        logger.warning("alerts are on but SMTP host, user, password, or recipient is missing")
        return None
    try:
        port = int(port_text)
    except ValueError:
        logger.warning("RECON_SMTP_PORT is not an integer")
        return None
    if port < 1 or port > _MAX_PORT:
        logger.warning("RECON_SMTP_PORT is outside 1..65535")
        return None
    return AlertSettings(
        host=host,
        port=port,
        username=username,
        password=password,
        recipient=recipient,
    )


def send_alert(settings: AlertSettings, subject: str, body: str) -> None:
    """Send one plain-text message. Raise ``smtplib.SMTPException`` on failure."""
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.username
    message["To"] = settings.recipient
    message.set_content(body)
    context = ssl.create_default_context()
    if settings.port == _SSL_PORT:
        with smtplib.SMTP_SSL(settings.host, settings.port, timeout=30, context=context) as server:
            server.login(settings.username, settings.password)
            server.send_message(message)
        return
    with smtplib.SMTP(settings.host, settings.port, timeout=30) as server:
        server.starttls(context=context)
        server.login(settings.username, settings.password)
        server.send_message(message)


def notify_findings(hostname: str, rows: list[tuple[str, str, str]]) -> None:
    """Send titles and severities when alerts are configured. Never raise to ingest."""
    settings = settings_from_env()
    if settings is None:
        return
    lines = [f"{severity} {rule_id} {title}" for severity, rule_id, title in rows[:40]]
    body = f"Host {hostname}\n" + ("\n".join(lines) if lines else "No findings.")
    try:
        send_alert(settings, f"WynDoze-InfoScanOverload {hostname}", body)
    except (smtplib.SMTPException, OSError) as exc:
        logger.warning("alert send failed: %s", type(exc).__name__)


__all__ = ["AlertSettings", "notify_findings", "send_alert", "settings_from_env"]
