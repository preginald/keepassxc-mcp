from __future__ import annotations

import json
from pathlib import Path

import pytest

from keepassxc_mcp.protocol import KPXCClient, detect_socket_path, save_identity
from keepassxc_mcp.server import (
    associate,
    create_group,
    generate_password,
    get_database_groups,
    get_logins,
    get_totp,
    lock_database,
    set_client,
    set_login,
    status,
)
from tests.fakeserver import FakeKeePassXC, start_fake_server


@pytest.fixture
def client(tmp_path: Path) -> KPXCClient:
    identity = tmp_path / "identity.json"
    peer, sock, _thread = start_fake_server()
    kpxc = KPXCClient(sock=sock, timeout=5, identity_file=identity)
    kpxc.exchange_keys()
    yield kpxc
    kpxc.disconnect()
    sock.close()
    set_client(None)


def test_detect_socket_prefers_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    socket_file = tmp_path / "kpxc_server"
    socket_file.write_text("")
    monkeypatch.setenv("KEEPASSXC_SOCKET", str(socket_file))
    assert detect_socket_path() == str(socket_file)


def test_associate_and_get_logins(client: KPXCClient) -> None:
    assoc_id = client.associate()
    assert assoc_id == "keepassxc-mcp-test"
    result = client.get_logins("https://example.com")
    assert result["entries"][0]["login"] == "alice"
    assert result["entries"][0]["password"] == "s3cret"


def test_reuse_saved_identity(tmp_path: Path) -> None:
    identity_file = tmp_path / "identity.json"
    peer, sock, _thread = start_fake_server()
    first = KPXCClient(sock=sock, timeout=5, identity_file=identity_file)
    first.exchange_keys()
    first.associate()
    first.disconnect()
    sock.close()

    peer2, sock2, _thread2 = start_fake_server(peer)
    second = KPXCClient(sock=sock2, timeout=5, identity_file=identity_file)
    second.exchange_keys()
    second.ensure_associated()
    assert second.identity is not None
    assert second.identity["id"] == "keepassxc-mcp-test"
    result = second.get_logins("https://example.com")
    assert result["count"] == "1"
    sock2.close()


def test_set_login_and_totp_and_groups(client: KPXCClient) -> None:
    client.associate()
    saved = client.set_login(
        {
            "url": "https://new.example",
            "login": "bob",
            "password": "hunter2",
        }
    )
    assert saved["success"] == "true"
    totp = client.get_totp("entry-1")
    assert totp["totp"] == "123456"
    groups = client.get_database_groups()
    assert groups["groups"][0]["name"] == "Root"
    created = client.create_group("Root/MCP")
    assert created["uuid"] == "group-1"
    hashed = client.get_databasehash()
    assert hashed["hash"] == "abc123hash"
    generated = client.generate_password()
    assert generated["password"] == "Generated-Pass-1"
    locked = client.lock_database()
    assert locked.get("locked") is True or locked.get("error") == "Database not opened"


def test_mcp_tools_round_trip(tmp_path: Path) -> None:
    identity = tmp_path / "identity.json"
    _peer, sock, _thread = start_fake_server()
    kpxc = KPXCClient(sock=sock, timeout=5, identity_file=identity)
    set_client(kpxc)
    try:
        assoc = json.loads(associate())
        assert assoc["associated_as"] == "keepassxc-mcp-test"
        st = json.loads(status())
        assert st["connected"] is True
        logins = json.loads(get_logins("https://example.com"))
        assert logins["count"] == 1
        assert logins["entries"][0]["login"] == "alice"
        totp = json.loads(get_totp("entry-1"))
        assert totp["totp"] == "123456"
        saved = json.loads(
            set_login(url="https://svc.example", login="carol", password="pw")
        )
        assert saved["success"] is True
        groups = json.loads(get_database_groups())
        assert "groups" in groups
        created = json.loads(create_group("Work"))
        assert created["name"] == "Work"
        generated = json.loads(generate_password())
        assert generated["password"] == "Generated-Pass-1"
        locked = json.loads(lock_database())
        assert locked["locked"] is True
    finally:
        set_client(None)
        sock.close()


def test_identity_file_mode(tmp_path: Path) -> None:
    path = tmp_path / "identity.json"
    save_identity({"id": "x", "idKey": "y"}, path)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
