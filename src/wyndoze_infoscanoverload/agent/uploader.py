"""HTTPS uploader with bounded retry.

Uses ``httpx`` with an explicit timeout and TLS verification on by default.
On failure the caller is expected to fall back to the encrypted bundle cache.
"""

from __future__ import annotations

import logging
import time
from urllib.parse import urlparse

import httpx

from wyndoze_infoscanoverload.core.models import ScanReport

logger = logging.getLogger("wyndoze_infoscanoverload.agent.uploader")

_HTTP_CREATED = 201
_HTTP_BAD_REQUEST = 400
_NON_RETRYABLE = frozenset({400, 401, 403, 422})
_LOOPBACK_HTTP = frozenset({"127.0.0.1", "::1"})


def assert_upload_url(server_url: str) -> None:
    """Allow https anywhere, and http only on 127.0.0.1 or ::1."""
    parsed = urlparse(server_url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "https" and host:
        return
    if parsed.scheme == "http" and host in _LOOPBACK_HTTP:
        return
    msg = "server URL must be https, or http on 127.0.0.1 or ::1"
    raise UploadError(msg)


class UploadError(RuntimeError):
    """Raised when an upload ultimately fails."""


def upload_report(
    report: ScanReport,
    server_url: str,
    token: str,
    *,
    timeout_s: int = 60,
    verify_tls: bool = True,
    max_attempts: int = 3,
) -> dict[str, object]:
    """POST ``report`` to the ingest endpoint, retrying transient failures.

    Returns the parsed JSON response on success. Raises :class:`UploadError`
    after exhausting ``max_attempts``. Client errors (4xx other than 429) are
    not retried — they will not succeed on retry.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "WynDoze-InfoScanOverload-agent/1.0",
    }
    assert_upload_url(server_url)
    body = report.model_dump()
    last_exc: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            response = httpx.post(
                server_url,
                headers=headers,
                json=body,
                timeout=timeout_s,
                verify=verify_tls,
                trust_env=False,
            )
        except httpx.HTTPError as exc:
            last_exc = exc
            logger.warning("Upload attempt %d/%d failed: %s", attempt, max_attempts, exc)
        else:
            if response.status_code == _HTTP_CREATED:
                result = _parse_acknowledgement(response, report.hostname)
                logger.info("Upload successful (HTTP %d)", response.status_code)
                return result
            if response.status_code < _HTTP_BAD_REQUEST or response.status_code in _NON_RETRYABLE:
                # Non-retryable: bad token or bad payload.
                msg = f"Upload rejected: HTTP {response.status_code} | {response.text[:500]}"
                raise UploadError(msg)
            last_exc = UploadError(f"HTTP {response.status_code}: {response.text[:200]}")
            logger.warning(
                "Upload attempt %d/%d got HTTP %d", attempt, max_attempts, response.status_code
            )

        if attempt < max_attempts:
            backoff = 2 ** (attempt - 1)
            time.sleep(backoff)

    msg = f"Upload failed after {max_attempts} attempts: {last_exc}"
    raise UploadError(msg)


def _parse_acknowledgement(response: httpx.Response, hostname: str) -> dict[str, object]:
    try:
        data = response.json()
    except ValueError as exc:
        msg = "Upload response is not a valid ingest acknowledgement"
        raise UploadError(msg) from exc
    if (
        not isinstance(data, dict)
        or data.get("status") != "accepted"
        or type(data.get("scan_id")) is not int
        or data["scan_id"] <= 0
        or data.get("hostname") != hostname
    ):
        msg = "Upload response is not a valid ingest acknowledgement"
        raise UploadError(msg)
    return data


__all__ = ["UploadError", "assert_upload_url", "upload_report"]
