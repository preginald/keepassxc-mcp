"""KeePassXC-Browser protocol client.

Talks to a running KeePassXC instance over its browser-integration socket
(NaCl box encryption). Never reads the .kdbx file and never asks for the
master password — KeePassXC must already be unlocked, and the first
association is confirmed in the KeePassXC GUI.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any

from nacl.public import Box, PrivateKey, PublicKey
from nacl.utils import random as nacl_random

from keepassxc_mcp.dbus import find_db_path, is_locked_error, launch_gui, request_open

NONCE_SIZE = 24
CLIENT_ID_SIZE = 24


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value)


def log(message: str) -> None:
    sys.stderr.write(f"[keepassxc-mcp] {message}\n")
    sys.stderr.flush()


def identity_path() -> Path:
    override = os.environ.get("KEEPASSXC_MCP_IDENTITY")
    if override:
        return Path(override)
    data_home = os.environ.get("XDG_DATA_HOME")
    if data_home:
        return Path(data_home) / "keepassxc-mcp" / "identity.json"
    return Path.home() / ".local" / "share" / "keepassxc-mcp" / "identity.json"


def load_identity(path: Path | None = None) -> dict[str, str] | None:
    path = path or identity_path()
    try:
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("id") and data.get("idKey"):
            return data
    except (OSError, json.JSONDecodeError, TypeError):
        log("warning: failed to load identity file")
    return None


def save_identity(identity: dict[str, str], path: Path | None = None) -> None:
    path = path or identity_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(identity, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    os.chmod(path, 0o600)


def detect_socket_path() -> str | None:
    """Locate the KeePassXC browser-integration Unix socket."""
    candidates: list[str] = []
    override = os.environ.get("KEEPASSXC_SOCKET")
    if override:
        candidates.append(override)

    xdg = os.environ.get("XDG_RUNTIME_DIR")
    uid = os.getuid() if hasattr(os, "getuid") else None
    names = (
        "org.keepassxc.KeePassXC.BrowserServer",
        "kpxc_server",
    )
    if xdg:
        for name in names:
            candidates.append(os.path.join(xdg, name))
        candidates.append(
            os.path.join(xdg, "app", "org.keepassxc.KeePassXC", names[0])
        )
    if uid is not None:
        run_user = f"/run/user/{uid}"
        for name in names:
            candidates.append(os.path.join(run_user, name))
        candidates.append(
            os.path.join(run_user, "app", "org.keepassxc.KeePassXC", names[0])
        )

    tmpdir = os.environ.get("TMPDIR", "/tmp").rstrip("/")
    for name in names:
        candidates.append(f"{tmpdir}/{name}")
    candidates.append("/tmp/kpxc_server")

    seen: set[str] = set()
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)
        if os.path.exists(path):
            return path
    return None


class KeePassXCError(RuntimeError):
    """A protocol-level error returned by KeePassXC."""

    def __init__(self, message: str, code: Any = None):
        super().__init__(message)
        self.code = code


class KPXCClient:
    def __init__(
        self,
        *,
        host: str | None = None,
        port: int | None = None,
        socket_path: str | None = None,
        timeout: float = 30,
        identity_file: Path | None = None,
        sock: socket.socket | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.socket_path = socket_path
        self.timeout = timeout
        self.identity_file = identity_file
        self.sock = sock
        self.session_sk: PrivateKey | None = None
        self.session_pk: bytes | None = None
        self.server_pk: bytes | None = None
        self.client_id = ""
        self.identity = load_identity(identity_file)
        self.auto_unlock = os.environ.get("KEEPASSXC_MCP_AUTO_UNLOCK", "1") not in {"0", "false", "no"}
        self._lock = threading.Lock()
        self._new_session()

    @property
    def mode(self) -> str:
        if self.sock is not None and self.host is None and self.socket_path is None:
            return "injected"
        return "tcp" if self.host else "unix"

    def _new_session(self) -> None:
        sk = PrivateKey.generate()
        self.session_sk = sk
        self.session_pk = bytes(sk.public_key)
        self.client_id = b64e(nacl_random(CLIENT_ID_SIZE))
        self.server_pk = None

    def connect(self) -> None:
        if self.sock is not None and self.mode == "injected":
            return
        if self.sock is not None:
            return
        self._new_session()
        if self.mode == "tcp":
            if not self.host:
                raise KeePassXCError("TCP mode requires a host")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(min(self.timeout, 10))
            sock.connect((self.host, int(self.port or 19455)))
            self.sock = sock
            log(f"connected tcp {self.host}:{self.port or 19455}")
            return
        path = self.socket_path or detect_socket_path()
        if not path:
            raise KeePassXCError(
                "KeePassXC browser socket not found. Enable Browser Integration "
                "in KeePassXC (Settings → Browser Integration) and leave the "
                "database unlocked."
            )
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(min(self.timeout, 10))
        sock.connect(path)
        self.sock = sock
        self.socket_path = path
        log(f"connected unix {path}")

    def disconnect(self) -> None:
        if self.sock is not None and self.mode != "injected":
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
        self.server_pk = None

    def _reconnect(self) -> None:
        if self.mode == "injected":
            raise KeePassXCError("injected socket closed")
        self.disconnect()
        self.connect()

    def _send_recv(self, msg: dict[str, Any], timeout: float | None = None) -> dict[str, Any]:
        if self.sock is None:
            self.connect()
        assert self.sock is not None
        timeout = timeout if timeout is not None else self.timeout
        raw = json.dumps(msg, separators=(",", ":")).encode("utf-8") + b"\n"
        self.sock.sendall(raw)
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = max(deadline - time.time(), 0.05)
            self.sock.settimeout(remaining)
            try:
                chunk = self.sock.recv(65536)
            except TimeoutError:
                continue
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError("KeePassXC closed the connection")
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line.decode("utf-8"))
                except json.JSONDecodeError:
                    continue
                action = parsed.get("action")
                if action in {"database-locked", "database-unlocked"}:
                    continue
                return parsed
            # Some KeePassXC builds reply with a single JSON object, no newline.
            if buf:
                try:
                    parsed = json.loads(buf.decode("utf-8"))
                    action = parsed.get("action")
                    if action in {"database-locked", "database-unlocked"}:
                        buf = b""
                        continue
                    return parsed
                except json.JSONDecodeError:
                    pass
        raise TimeoutError(f"no KeePassXC response within {timeout}s")

    def _box(self) -> Box:
        if self.session_sk is None or self.server_pk is None:
            raise KeePassXCError("session keys are not established")
        return Box(self.session_sk, PublicKey(self.server_pk))

    def _encrypt(self, payload: dict[str, Any]) -> tuple[str, str]:
        nonce = nacl_random(NONCE_SIZE)
        plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ciphertext = self._box().encrypt(plaintext, nonce).ciphertext
        return b64e(ciphertext), b64e(nonce)

    def _decrypt(self, message_b64: str, nonce_b64: str) -> dict[str, Any]:
        plaintext = self._box().decrypt(b64d(message_b64), b64d(nonce_b64))
        return json.loads(plaintext.decode("utf-8"))

    def exchange_keys(self) -> None:
        self.connect()
        nonce = b64e(nacl_random(NONCE_SIZE))
        assert self.session_pk is not None
        resp = self._send_recv(
            {
                "action": "change-public-keys",
                "publicKey": b64e(self.session_pk),
                "nonce": nonce,
                "clientID": self.client_id,
            }
        )
        if str(resp.get("success")).lower() != "true" or not resp.get("publicKey"):
            raise KeePassXCError(f"key exchange failed: {resp}")
        self.server_pk = b64d(resp["publicKey"])

    def send_encrypted(
        self,
        action: str,
        payload: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        if self.server_pk is None:
            self.exchange_keys()
        body = {"action": action, **(payload or {})}
        message, nonce = self._encrypt(body)
        resp = self._send_recv(
            {
                "action": action,
                "message": message,
                "nonce": nonce,
                "clientID": self.client_id,
            },
            timeout=timeout,
        )
        if resp.get("error") and not resp.get("message"):
            raise KeePassXCError(
                str(resp.get("error") or "KeePassXC error"),
                resp.get("errorCode"),
            )
        if resp.get("message") and resp.get("nonce"):
            decrypted = self._decrypt(resp["message"], resp["nonce"])
            if decrypted.get("error") and str(decrypted.get("success")).lower() != "true":
                raise KeePassXCError(
                    str(decrypted.get("error") or "KeePassXC error"),
                    decrypted.get("errorCode"),
                )
            return decrypted
        return resp

    def request(
        self,
        action: str,
        payload: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        try:
            return self.send_encrypted(action, payload, timeout)
        except KeePassXCError as exc:
            if (
                action != "lock-database"
                and self.auto_unlock
                and is_locked_error(exc)
            ):
                log("database locked; asking KeePassXC to prompt for unlock")
                self.unlock()
                return self.send_encrypted(action, payload, timeout)
            raise
        except (ConnectionError, BrokenPipeError, ConnectionResetError, OSError) as exc:
            log(f"connection lost ({exc}); reconnecting")
            self._reconnect()
            return self.send_encrypted(action, payload, timeout)

    def _is_available(self) -> bool:
        """True when the database answers; False only while it is locked."""
        try:
            self.send_encrypted("get-databasehash")
            return True
        except KeePassXCError as exc:
            if is_locked_error(exc):
                return False
            raise

    def unlock(self, db_path: str | None = None, timeout: float | None = None) -> dict[str, Any]:
        """Ask KeePassXC to open the database, which raises its unlock prompt.

        Two attempts, because a tray-hidden KeePassXC ignores a bare D-Bus
        open request: first the D-Bus method, then launching the binary, which
        brings up the window with its password box. The master password is
        typed by the user there; this process never receives it.
        """
        path = db_path or find_db_path()
        if not path:
            raise KeePassXCError(
                "cannot determine the database path; set KEEPASSXC_DB or KEEPASSXC_DB_DIR"
            )
        if not Path(path).exists():
            raise KeePassXCError(f"database file not found: {path}")

        total = timeout if timeout is not None else float(
            os.environ.get("KEEPASSXC_UNLOCK_TIMEOUT", "120")
        )
        deadline = time.time() + total

        if self._is_available():
            return {"unlocked": True, "database": path, "already_unlocked": True}

        asked = request_open(path)
        if not asked:
            log("D-Bus open request failed; will launch the KeePassXC window")

        probe_until = time.time() + 5
        while time.time() < probe_until:
            if self._is_available():
                log(f"database unlocked via D-Bus: {path}")
                return {"unlocked": True, "database": path}
            time.sleep(0.5)

        log("no response to the D-Bus request; launching KeePassXC's unlock window")
        if not launch_gui(path):
            raise KeePassXCError(
                "KeePassXC is locked and its window could not be opened; "
                "open KeePassXC and unlock the database manually"
            )

        while time.time() < deadline:
            if self._is_available():
                log(f"database unlocked: {path}")
                return {"unlocked": True, "database": path}
            time.sleep(1)

        raise KeePassXCError(
            "timed out waiting for the database to be unlocked in KeePassXC. "
            "Open KeePassXC (it may be hidden in the tray) and unlock it, then retry."
        )

    def associate(self) -> str:
        if self.server_pk is None:
            self.exchange_keys()
        id_sk = PrivateKey.generate()
        id_pk = bytes(id_sk.public_key)
        result = self.send_encrypted(
            "associate",
            {
                "key": b64e(self.session_pk or b""),
                "idKey": b64e(id_pk),
            },
            timeout=max(self.timeout, 120),
        )
        if str(result.get("success")).lower() != "true":
            raise KeePassXCError(f"association failed: {result}")
        identity = {
            "id": str(result["id"]),
            "idKey": b64e(id_pk),
        }
        save_identity(identity, self.identity_file)
        self.identity = identity
        log(f'associated as "{identity["id"]}"')
        return identity["id"]

    def test_associate(self) -> bool:
        if not self.identity:
            return False
        result = self.send_encrypted(
            "test-associate",
            {"id": self.identity["id"], "key": self.identity["idKey"]},
        )
        return str(result.get("success")).lower() == "true"

    def ensure_associated(self) -> None:
        if self.server_pk is None:
            self.exchange_keys()
        if self.identity and self.test_associate():
            return
        self.associate()

    def ensure_ready(self) -> None:
        try:
            self.ensure_associated()
        except KeePassXCError as exc:
            if self.auto_unlock and is_locked_error(exc):
                log("database locked during readiness check; prompting for unlock")
                self.unlock()
                self.ensure_associated()
                return
            raise
        except (ConnectionError, BrokenPipeError, ConnectionResetError, OSError, TimeoutError) as exc:
            log(f"readiness check failed ({exc}); reconnecting")
            self._reconnect()
            self.ensure_associated()

    def association_keys(self) -> list[dict[str, str]]:
        if not self.identity:
            raise KeePassXCError("not associated with KeePassXC")
        return [{"id": self.identity["id"], "key": self.identity["idKey"]}]

    def get_logins(self, url: str, submit_url: str | None = None) -> dict[str, Any]:
        with self._lock:
            self.ensure_ready()
            payload: dict[str, Any] = {"url": url, "keys": self.association_keys()}
            if submit_url:
                payload["submitUrl"] = submit_url
            return self.request("get-logins", payload)

    def get_totp(self, uuid: str) -> dict[str, Any]:
        with self._lock:
            self.ensure_ready()
            return self.request("get-totp", {"uuid": uuid})

    def set_login(self, params: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.ensure_ready()
            body = {**params, "id": self.identity["id"] if self.identity else ""}
            return self.request("set-login", body)

    def create_group(self, group_name: str) -> dict[str, Any]:
        with self._lock:
            self.ensure_ready()
            return self.request("create-new-group", {"groupName": group_name})

    def generate_password(self) -> dict[str, Any]:
        with self._lock:
            if self.server_pk is None:
                self.exchange_keys()
            nonce = b64e(nacl_random(NONCE_SIZE))
            resp = self._send_recv(
                {
                    "action": "generate-password",
                    "nonce": nonce,
                    "clientID": self.client_id,
                    "requestID": b64e(nacl_random(6))[:8],
                },
                timeout=max(self.timeout, 60),
            )
            if resp.get("message") and resp.get("nonce"):
                return self._decrypt(resp["message"], resp["nonce"])
            if resp.get("error"):
                raise KeePassXCError(str(resp["error"]), resp.get("errorCode"))
            return resp

    def lock_database(self) -> dict[str, Any]:
        with self._lock:
            self.ensure_ready()
            try:
                return self.request("lock-database")
            except KeePassXCError as exc:
                if "Database not opened" in str(exc):
                    return {"success": "true", "locked": True}
                raise

    def get_database_groups(self) -> dict[str, Any]:
        with self._lock:
            self.ensure_ready()
            return self.request("get-database-groups")

    def get_databasehash(self) -> dict[str, Any]:
        with self._lock:
            self.ensure_ready()
            return self.request("get-databasehash")
