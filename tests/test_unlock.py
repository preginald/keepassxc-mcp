from __future__ import annotations

import json
from pathlib import Path

import pytest

from keepassxc_mcp import protocol as protocol_module
from keepassxc_mcp.dbus import find_db_path, is_locked_error
from keepassxc_mcp.protocol import KPXCClient, KeePassXCError
from keepassxc_mcp.server import get_logins, set_client
from tests.fakeserver import FakeKeePassXC, start_fake_server


def test_is_locked_error() -> None:
    assert is_locked_error(KeePassXCError("Database not opened"))
    assert is_locked_error(KeePassXCError("database is locked"))
    assert not is_locked_error(KeePassXCError("association failed"))


def test_find_db_path_env_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "x.kdbx"
    db.write_bytes(b"not really encrypted")
    monkeypatch.setenv("KEEPASSXC_DB", str(db))
    assert find_db_path() == str(db)


def test_find_db_path_newest_in_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    monkeypatch.delenv("KEEPASSXC_DB", raising=False)
    folder = tmp_path / "kp"
    folder.mkdir()
    old = folder / "old.kdbx"
    new = folder / "new.kdbx"
    old.write_bytes(b"a")
    new.write_bytes(b"b")
    os.utime(old, (1_000_000, 1_000_000))
    os.utime(new, (2_000_000, 2_000_000))
    monkeypatch.setenv("KEEPASSXC_DB_DIR", str(folder))
    assert find_db_path() == str(new)


def test_locked_database_raises_without_auto_unlock(tmp_path: Path) -> None:
    peer, sock, _ = start_fake_server(FakeKeePassXC())
    client = KPXCClient(sock=sock, timeout=3, identity_file=tmp_path / "id.json")
    client.auto_unlock = False
    client.exchange_keys()
    client.associate()
    peer.locked = True
    with pytest.raises(KeePassXCError) as excinfo:
        client.get_logins("https://example.com")
    assert "not opened" in str(excinfo.value).lower()
    sock.close()


def test_auto_unlock_prompts_then_retries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "live.kdbx"
    db.write_bytes(b"placeholder")
    peer, sock, _ = start_fake_server(FakeKeePassXC())
    client = KPXCClient(sock=sock, timeout=3, identity_file=tmp_path / "id.json")
    client.exchange_keys()
    client.associate()

    prompted: list[str] = []

    def fake_request_open(path: str) -> bool:
        prompted.append(path)
        peer.locked = False  # user accepted the unlock prompt
        return True

    monkeypatch.setattr(protocol_module, "request_open", fake_request_open)
    monkeypatch.setenv("KEEPASSXC_DB", str(db))

    client.auto_unlock = True
    peer.locked = True
    result = client.get_logins("https://example.com")
    assert prompted == [str(db)]
    assert result["entries"][0]["login"] == "alice"
    sock.close()


def test_unlock_fails_without_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KEEPASSXC_DB", raising=False)
    monkeypatch.setenv("KEEPASSXC_DB_DIR", str(tmp_path / "empty"))
    peer, sock, _ = start_fake_server(FakeKeePassXC())
    client = KPXCClient(sock=sock, timeout=3, identity_file=tmp_path / "id.json")
    client.exchange_keys()
    with pytest.raises(KeePassXCError) as excinfo:
        client.unlock()
    assert "database path" in str(excinfo.value).lower()
    sock.close()


def test_mcp_unlock_tool_reports_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "live.kdbx"
    db.write_bytes(b"placeholder")
    peer, sock, _ = start_fake_server(FakeKeePassXC())
    client = KPXCClient(sock=sock, timeout=3, identity_file=tmp_path / "id.json")
    set_client(client)
    try:
        client.exchange_keys()
        client.associate()
        monkeypatch.setenv("KEEPASSXC_DB", str(db))
        monkeypatch.setattr(protocol_module, "request_open", lambda path: True)
        payload = json.loads(get_logins("https://example.com"))
        assert payload["count"] == 1
    finally:
        set_client(None)
        sock.close()
