"""Fresh database and supported minimum-dependency startup."""

import os
import subprocess

import pytest
from fastapi.testclient import TestClient

from wyndoze_infoscanoverload.server.app import create_app
from wyndoze_infoscanoverload.server.config import ServerConfig
from wyndoze_infoscanoverload.server.storage import Storage


def test_fresh_directory_startup(tmp_path):
    path = tmp_path / "state with spaces" / "dashboard.sqlite3"
    with TestClient(create_app(ServerConfig(db_path=path))) as client:
        assert client.get("/api/health").status_code == 200
        assert client.get("/").status_code == 401
    assert path.exists()
    if os.name != "nt":
        assert path.parent.stat().st_mode & 0o777 == 0o700


def test_existing_directory_permissions_are_preserved(tmp_path):
    before = tmp_path.stat().st_mode
    Storage(tmp_path / "state.sqlite3").init_db()
    assert tmp_path.stat().st_mode == before


def test_windows_acl_failure_prevents_database(tmp_path, monkeypatch):
    monkeypatch.setattr("wyndoze_infoscanoverload.server.storage._IS_WINDOWS", True)

    def fail(*args, **_kwargs):
        raise subprocess.CalledProcessError(5, args[0])

    monkeypatch.setattr("wyndoze_infoscanoverload.server.storage.subprocess.run", fail)
    path = tmp_path / "new-state" / "state.sqlite3"
    with pytest.raises(subprocess.CalledProcessError):
        Storage(path).init_db()
    assert not path.exists()
    assert not path.parent.exists()
