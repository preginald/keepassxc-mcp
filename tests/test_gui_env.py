from __future__ import annotations

import os

from keepassxc_mcp.dbus import _gui_env


def test_gui_env_pins_wayland(monkeypatch) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "wayland;xcb")
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-1")
    env = _gui_env()
    assert env["QT_QPA_PLATFORM"] == "wayland"
    assert env["WAYLAND_DISPLAY"] == "wayland-1"


def test_gui_env_discovers_wayland_socket(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    (tmp_path / "wayland-2").write_text("")
    (tmp_path / "wayland-2.lock").write_text("")
    env = _gui_env()
    assert env["WAYLAND_DISPLAY"] == "wayland-2"


def test_gui_env_keeps_existing_display(monkeypatch) -> None:
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-7")
    assert _gui_env()["WAYLAND_DISPLAY"] == "wayland-7"
