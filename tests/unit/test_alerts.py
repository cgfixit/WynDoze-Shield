"""SMTP alert client tests. No network."""

from __future__ import annotations

import smtplib
from unittest.mock import MagicMock, patch

import pytest

from wyndoze_infoscanoverload.alerts import (
    AlertSettings,
    notify_findings,
    send_alert,
    settings_from_env,
)


def test_settings_absent_when_alerts_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RECON_ALERTS", raising=False)
    assert settings_from_env() is None


def test_settings_require_every_field(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECON_ALERTS", "1")
    monkeypatch.setenv("RECON_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("RECON_SMTP_USER", "scan@example.test")
    monkeypatch.delenv("RECON_SMTP_PASSWORD", raising=False)
    monkeypatch.setenv("RECON_ALERT_TO", "ops@example.test")
    assert settings_from_env() is None


def test_send_alert_uses_starttls(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = AlertSettings(
        host="smtp.example.test",
        port=587,
        username="scan@example.test",
        password="secret-value",  # noqa: S106 - fixture, not a real password
        recipient="ops@example.test",
    )
    server = MagicMock()
    monkeypatch.delenv("RECON_SMTP_PASSWORD", raising=False)
    with patch("wyndoze_infoscanoverload.alerts.smtplib.SMTP") as smtp:
        smtp.return_value.__enter__.return_value = server
        send_alert(settings, "WynDoze-InfoScanOverload host", "high rule title")
    server.starttls.assert_called_once()
    server.login.assert_called_once_with("scan@example.test", "secret-value")
    sent = server.send_message.call_args.args[0]
    assert "gAAAA" not in sent.get_content()
    assert sent["To"] == "ops@example.test"


def test_port_465_uses_ssl() -> None:
    settings = AlertSettings(
        host="smtp.example.test",
        port=465,
        username="scan@example.test",
        password="secret-value",  # noqa: S106
        recipient="ops@example.test",
    )
    server = MagicMock()
    with patch("wyndoze_infoscanoverload.alerts.smtplib.SMTP_SSL") as smtp:
        smtp.return_value.__enter__.return_value = server
        send_alert(settings, "subject", "body")
    server.starttls.assert_not_called()
    server.login.assert_called_once()


def test_notify_swallows_smtp_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECON_ALERTS", "on")
    monkeypatch.setenv("RECON_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("RECON_SMTP_PORT", "587")
    monkeypatch.setenv("RECON_SMTP_USER", "scan@example.test")
    monkeypatch.setenv("RECON_SMTP_PASSWORD", "secret-value")
    monkeypatch.setenv("RECON_ALERT_TO", "ops@example.test")
    with patch(
        "wyndoze_infoscanoverload.alerts.send_alert",
        side_effect=smtplib.SMTPException("down"),
    ):
        notify_findings("HOST1", [("high", "rule", "Title")])
