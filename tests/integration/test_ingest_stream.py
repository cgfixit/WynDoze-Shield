"""Application body limits through chunked ASGI receive events."""

import pytest

from wyndoze_infoscanoverload.core.models import ScanReport
from wyndoze_infoscanoverload.server.app import _MAX_INGEST_BYTES, create_app
from wyndoze_infoscanoverload.server.config import ServerConfig

TOKEN = "synthetic"  # noqa: S105 - disposable fixture


async def request(app, chunks, headers=(), *, authenticated=True, poison=False):
    reads = 0
    statuses = []

    async def receive():
        nonlocal reads
        reads += 1
        if reads > len(chunks):
            msg = "Read after the body cap was crossed"
            raise AssertionError(msg)
        return {
            "type": "http.request",
            "body": chunks[reads - 1],
            "more_body": poison or reads < len(chunks),
        }

    async def send(message):
        if message["type"] == "http.response.start":
            statuses.append(message["status"])

    auth = [(b"authorization", b"Bearer synthetic")] if authenticated else []
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/scans",
        "raw_path": b"/api/scans",
        "query_string": b"",
        "headers": auth + list(headers),
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 1),
        "root_path": "",
    }
    await app(scope, receive, send)
    return statuses[0], reads


@pytest.fixture
def api(tmp_path):
    return create_app(ServerConfig(db_path=tmp_path / "state.sqlite3", ingest_token=TOKEN))


@pytest.mark.parametrize(
    "headers", [(), ((b"content-length", b"1"),), ((b"transfer-encoding", b"chunked"),)]
)
async def test_oversize_stops_receiving_before_end(api, headers):
    status, reads = await request(api, [b" " * _MAX_INGEST_BYTES, b"x"], headers, poison=True)
    assert (status, reads) == (413, 2)
    assert api.state.storage.summary()["scans"] == 0
    assert api.state.storage.list_endpoints() == []
    assert api.state.storage.list_findings() == []


async def test_authentication_precedes_body_receive(api):
    assert await request(api, [], authenticated=False, poison=True) == (401, 0)


async def test_exact_boundary_and_split_json_are_accepted(api):
    body = ScanReport(hostname="H", scan_time_utc="2026-10-18T12:00:00Z").model_dump_json().encode()
    body += b" " * (_MAX_INGEST_BYTES - len(body))
    assert await request(api, [body[:5], body[5:]]) == (201, 2)
    assert api.state.storage.summary()["scans"] == 1


async def test_under_limit_invalid_json_stays_422(api):
    assert await request(api, [b"{"]) == (422, 1)
    assert api.state.storage.summary()["scans"] == 0
