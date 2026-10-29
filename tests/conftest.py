from __future__ import annotations

import pytest

import keepassxc_mcp.dbus as dbus_module
import keepassxc_mcp.protocol as protocol_module


@pytest.fixture(autouse=True)
def _isolate_from_live_vault(tmp_path, monkeypatch):
    """Keep every test away from the real KeePassXC app, GUI and database.

    All three escape hatches — busctl, gdbus and launching the binary — are
    stubbed so a test can never raise the real unlock prompt or open the live
    vault.
    """
    monkeypatch.setenv("KEEPASSXC_MCP_AUTO_UNLOCK", "0")
    fake_db = tmp_path / "do-not-touch.kdbx"
    fake_db.write_bytes(b"placeholder")
    monkeypatch.setenv("KEEPASSXC_DB", str(fake_db))
    monkeypatch.setenv("KEEPASSXC_SOCKET", str(tmp_path / "no-such-socket"))
    monkeypatch.setattr(dbus_module, "_busctl_open", lambda path: False)
    monkeypatch.setattr(dbus_module, "_gdbus_open", lambda path: False)
    monkeypatch.setattr(dbus_module, "launch_gui", lambda path: False)
    monkeypatch.setattr(protocol_module, "launch_gui", lambda path: False)
    yield
