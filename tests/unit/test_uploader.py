"""Upload retry policy. No socket is opened; ``httpx.post`` is replaced."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from wyndoze_infoscanoverload._version import __version__
from wyndoze_infoscanoverload.agent import uploader
from wyndoze_infoscanoverload.agent.uploader import UploadError, upload_report
from wyndoze_infoscanoverload.core.models import ScanReport

URL = "http://127.0.0.1:8000/api/scans"


class _Resp:
    def __init__(self, status_code: int, text: str = "{}", payload: Any = None) -> None:
        self.status_code = status_code
        self.text = text
        self._payload = payload

    def json(self) -> Any:
        if self._payload is None:
            msg = "not json"
            raise ValueError(msg)
        return self._payload


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(uploader.time, "sleep", lambda _s: None)


def _install(monkeypatch: pytest.MonkeyPatch, outcomes: list[object]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def fake_post(url: str, **kwargs: Any) -> _Resp:
        calls.append({"url": url, **kwargs})
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        assert isinstance(outcome, _Resp)
        return outcome

    monkeypatch.setattr(uploader.httpx, "post", fake_post)
    return calls


def test_retries_transient_then_succeeds(
    monkeypatch: pytest.MonkeyPatch, clean_report: ScanReport
) -> None:
    calls = _install(
        monkeypatch,
        [
            httpx.ConnectError("refused"),
            _Resp(503, "busy"),
            _Resp(
                201, payload={"status": "accepted", "scan_id": 7, "hostname": clean_report.hostname}
            ),
        ],
    )
    result = upload_report(clean_report, URL, "tok")
    assert result["scan_id"] == 7
    assert len(calls) == 3


def test_sends_bearer_and_versioned_user_agent(
    monkeypatch: pytest.MonkeyPatch, clean_report: ScanReport
) -> None:
    calls = _install(
        monkeypatch,
        [
            _Resp(
                201, payload={"status": "accepted", "scan_id": 1, "hostname": clean_report.hostname}
            )
        ],
    )
    upload_report(clean_report, URL, "tok", timeout_s=7, verify_tls=False)
    headers = calls[0]["headers"]
    assert headers["Authorization"] == "Bearer tok"
    assert headers["User-Agent"] == f"WynDoze-InfoScanOverload-agent/{__version__}"
    assert calls[0]["timeout"] == 7
    assert calls[0]["verify"] is False


@pytest.mark.parametrize("code", [400, 401, 403, 422])
def test_client_errors_are_not_retried(
    monkeypatch: pytest.MonkeyPatch, clean_report: ScanReport, code: int
) -> None:
    calls = _install(monkeypatch, [_Resp(code, "nope"), _Resp(201)])
    with pytest.raises(UploadError, match=str(code)):
        upload_report(clean_report, URL, "tok")
    assert len(calls) == 1


def test_gives_up_after_max_attempts(
    monkeypatch: pytest.MonkeyPatch, clean_report: ScanReport
) -> None:
    calls = _install(monkeypatch, [_Resp(500), _Resp(429), _Resp(502)])
    with pytest.raises(UploadError, match="after 3 attempts"):
        upload_report(clean_report, URL, "tok", max_attempts=3)
    assert len(calls) == 3


def test_rejects_bad_url_before_any_request(
    monkeypatch: pytest.MonkeyPatch, clean_report: ScanReport
) -> None:
    calls = _install(monkeypatch, [_Resp(201)])
    with pytest.raises(UploadError):
        upload_report(clean_report, "http://192.0.2.9/api/scans", "tok")
    assert calls == []


@pytest.mark.parametrize("code", [200, 201])
@pytest.mark.parametrize("payload", [None, [1, 2], {"status": "accepted"}])
def test_malformed_acknowledgements_are_rejected(monkeypatch, clean_report, code, payload):
    calls = _install(monkeypatch, [_Resp(code, text="plain ok", payload=payload)])
    with pytest.raises(UploadError):
        upload_report(clean_report, URL, "tok")
    assert len(calls) == 1
