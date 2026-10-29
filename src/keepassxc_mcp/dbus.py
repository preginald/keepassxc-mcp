"""D-Bus bridge to KeePassXC's own unlock prompt.

When the database is locked, the browser-integration socket still accepts a
connection but every credential action fails with "Database not opened".
Rather than hold a master password, ask KeePassXC to open the file — its GUI
then prompts the user, who types the password locally.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

DBUS_DEST = "org.keepassxc.KeePassXC.MainWindow"
DBUS_PATH = "/keepassxc"
DBUS_IFACE = "org.keepassxc.KeePassXC.MainWindow"

LOCK_INDICATORS = (
    "database not opened",
    "database not open",
    "database is locked",
    "locked database",
)


def log(message: str) -> None:
    sys.stderr.write(f"[keepassxc-mcp] {message}\n")
    sys.stderr.flush()


def is_locked_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return any(marker in text for marker in LOCK_INDICATORS)


def find_db_path() -> str | None:
    """Resolve the encrypted database path without reading it.

    Order: KEEPASSXC_DB, then the synced KeePass folder's most recently
    modified .kdbx (KeePassXC saves on every change, so mtime tracks the
    database actually in use).
    """
    override = os.environ.get("KEEPASSXC_DB")
    if override:
        return override

    folder = os.environ.get("KEEPASSXC_DB_DIR")
    if folder:
        # An explicit directory wins outright — never fall back to the live vault.
        base = Path(folder).expanduser()
        if not base.is_dir():
            return None
        found = [p for p in base.glob("*.kdbx") if p.is_file()]
        if not found:
            return None
        return str(max(found, key=lambda p: p.stat().st_mtime))

    default_base = Path.home() / "Sync" / "KeePass"
    if not default_base.is_dir():
        return None
    found = [p for p in default_base.glob("*.kdbx") if p.is_file()]
    if not found:
        return None
    return str(max(found, key=lambda p: p.stat().st_mtime))


def _busctl_open(db_path: str) -> bool:
    if not shutil.which("busctl"):
        return False
    cmd = [
        "busctl",
        "--user",
        "call",
        DBUS_DEST,
        DBUS_PATH,
        DBUS_IFACE,
        "openDatabase",
        "s",
        db_path,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log(f"busctl openDatabase failed: {exc}")
        return False
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        if stderr:
            log(f"busctl openDatabase: {stderr}")
        return False
    return True


def _gdbus_open(db_path: str) -> bool:
    if not shutil.which("gdbus"):
        return False
    cmd = [
        "gdbus",
        "call",
        "--session",
        "--dest",
        DBUS_DEST,
        "--object-path",
        DBUS_PATH,
        "--method",
        f"{DBUS_IFACE}.openDatabase",
        db_path,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log(f"gdbus openDatabase failed: {exc}")
        return False
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        if stderr:
            log(f"gdbus openDatabase: {stderr}")
        return False
    return True


def request_open(db_path: str) -> bool:
    """Ask KeePassXC to open the database, which raises its unlock prompt."""
    if _busctl_open(db_path):
        return True
    return _gdbus_open(db_path)


def launch_gui(db_path: str) -> bool:
    """Start the KeePassXC binary on the database.

    With SingleInstance enabled this forwards to the running tray process,
    which shows its unlock window — the one path proven to raise a usable
    prompt when the app is hidden in the tray. The password is typed by the
    user in that window, never handled here.
    """
    binary = os.environ.get("KEEPASSXC_BIN") or shutil.which("keepassxc")
    if not binary:
        log("keepassxc binary not found; cannot raise the unlock window")
        return False
    try:
        subprocess.Popen(
            [binary, db_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return True
    except OSError as exc:
        log(f"could not launch {binary}: {exc}")
        return False
