"""In-process KeePassXC-Browser protocol peer for tests."""

from __future__ import annotations

import json
import socket
import threading
from typing import Any

from nacl.public import Box, PrivateKey, PublicKey
from nacl.utils import random as nacl_random

from keepassxc_mcp.protocol import b64d, b64e


class FakeKeePassXC:
    """Speaks the KeePassXC-Browser protocol over an injected socket pair."""

    def __init__(self) -> None:
        self.host_sk = PrivateKey.generate()
        self.host_pk = bytes(self.host_sk.public_key)
        self.client_pk: bytes | None = None
        self.associated: dict[str, str] | None = None
        self.entries: list[dict[str, Any]] = [
            {
                "login": "alice",
                "name": "Example",
                "password": "s3cret",
                "uuid": "entry-1",
                "url": "https://example.com",
            }
        ]
        self.groups = {
            "defaultGroup": "KeePassXC-Browser Passwords",
            "defaultGroupAlwaysAllow": False,
            "groups": [
                {
                    "name": "Root",
                    "uuid": "root-uuid",
                    "children": [
                        {
                            "name": "KeePassXC-Browser Passwords",
                            "uuid": "browser-uuid",
                            "children": [],
                        }
                    ],
                }
            ],
        }
        self.created_groups: list[str] = []
        self.locked = False
        self.database_hash = "abc123hash"
        self.version = "2.7.12"
        self.association_name = "keepassxc-mcp-test"
        self.auto_approve_associate = True

    def _box(self) -> Box:
        if self.client_pk is None:
            raise RuntimeError("no client public key")
        return Box(self.host_sk, PublicKey(self.client_pk))

    def decrypt(self, message: str, nonce: str) -> dict[str, Any]:
        plaintext = self._box().decrypt(b64d(message), b64d(nonce))
        return json.loads(plaintext.decode("utf-8"))

    def encrypt(self, payload: dict[str, Any], nonce_b64: str) -> dict[str, str]:
        nonce = b64d(nonce_b64)
        # KeePassXC increments the request nonce for the response.
        nonce_list = list(nonce)
        for i in range(len(nonce_list) - 1, -1, -1):
            nonce_list[i] = (nonce_list[i] + 1) % 256
            if nonce_list[i] != 0:
                break
        resp_nonce = bytes(nonce_list)
        ciphertext = self._box().encrypt(
            json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            resp_nonce,
        ).ciphertext
        return {
            "message": b64e(ciphertext),
            "nonce": b64e(resp_nonce),
        }

    def handle(self, msg: dict[str, Any]) -> dict[str, Any]:
        action = msg.get("action")
        if action == "change-public-keys":
            self.client_pk = b64d(msg["publicKey"])
            return {
                "action": "change-public-keys",
                "version": self.version,
                "publicKey": b64e(self.host_pk),
                "success": "true",
            }
        if action == "generate-password":
            encrypted = self.encrypt(
                {
                    "version": self.version,
                    "password": "Generated-Pass-1",
                    "success": "true",
                },
                msg["nonce"],
            )
            return {"action": action, **encrypted}

        payload = self.decrypt(msg["message"], msg["nonce"])
        inner_action = payload.get("action") or action

        if inner_action == "associate":
            if not self.auto_approve_associate:
                encrypted = self.encrypt(
                    {"success": "false", "error": "Association declined"},
                    msg["nonce"],
                )
                return {"action": inner_action, **encrypted}
            self.associated = {
                "id": self.association_name,
                "idKey": payload["idKey"],
            }
            encrypted = self.encrypt(
                {
                    "hash": self.database_hash,
                    "version": self.version,
                    "success": "true",
                    "id": self.association_name,
                },
                msg["nonce"],
            )
            return {"action": inner_action, **encrypted}

        if inner_action == "test-associate":
            ok = (
                self.associated is not None
                and payload.get("id") == self.associated["id"]
                and payload.get("key") == self.associated["idKey"]
            )
            encrypted = self.encrypt(
                {
                    "version": self.version,
                    "hash": self.database_hash,
                    "id": self.association_name if ok else "",
                    "success": "true" if ok else "false",
                    **({} if ok else {"error": "Not associated"}),
                },
                msg["nonce"],
            )
            return {"action": inner_action, **encrypted}

        if inner_action == "get-logins":
            url = payload.get("url", "")
            matches = [e for e in self.entries if e.get("url", "").startswith(url) or url.startswith(e.get("url", ""))]
            encrypted = self.encrypt(
                {
                    "count": str(len(matches)),
                    "entries": matches,
                    "success": "true",
                    "hash": self.database_hash,
                    "version": self.version,
                },
                msg["nonce"],
            )
            return {"action": inner_action, **encrypted}

        if inner_action == "get-totp":
            encrypted = self.encrypt(
                {"totp": "123456", "version": self.version, "success": "true"},
                msg["nonce"],
            )
            return {"action": inner_action, **encrypted}

        if inner_action == "set-login":
            entry = {
                "login": payload.get("login"),
                "name": payload.get("login"),
                "password": payload.get("password"),
                "uuid": payload.get("uuid") or f"entry-{len(self.entries) + 1}",
                "url": payload.get("url"),
            }
            self.entries.append(entry)
            encrypted = self.encrypt(
                {
                    "count": None,
                    "entries": None,
                    "error": "",
                    "success": "true",
                    "hash": self.database_hash,
                    "version": self.version,
                },
                msg["nonce"],
            )
            return {"action": inner_action, **encrypted}

        if inner_action == "get-database-groups":
            encrypted = self.encrypt(self.groups, msg["nonce"])
            return {"action": inner_action, **encrypted}

        if inner_action == "get-databasehash":
            encrypted = self.encrypt(
                {
                    "action": "hash",
                    "hash": self.database_hash,
                    "version": self.version,
                },
                msg["nonce"],
            )
            return {"action": inner_action, **encrypted}

        if inner_action == "create-new-group":
            name = payload.get("groupName", "New")
            self.created_groups.append(name)
            encrypted = self.encrypt(
                {"name": name, "uuid": f"group-{len(self.created_groups)}"},
                msg["nonce"],
            )
            return {"action": inner_action, **encrypted}

        if inner_action == "lock-database":
            self.locked = True
            encrypted = self.encrypt(
                {
                    "action": "lock-database",
                    "errorCode": 1,
                    "error": "Database not opened",
                },
                msg["nonce"],
            )
            return {"action": inner_action, **encrypted}

        encrypted = self.encrypt(
            {"success": "false", "error": f"unknown action {inner_action}"},
            msg["nonce"],
        )
        return {"action": inner_action, **encrypted}


def serve_pair(peer: FakeKeePassXC, server_sock: socket.socket) -> None:
    buf = b""
    try:
        while True:
            chunk = server_sock.recv(65536)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                msg = json.loads(line.decode("utf-8"))
                reply = peer.handle(msg)
                server_sock.sendall(json.dumps(reply).encode("utf-8") + b"\n")
    except OSError:
        pass
    finally:
        try:
            server_sock.close()
        except OSError:
            pass


def start_fake_server(peer: FakeKeePassXC | None = None) -> tuple[FakeKeePassXC, socket.socket, threading.Thread]:
    peer = peer or FakeKeePassXC()
    client_sock, server_sock = socket.socketpair()
    thread = threading.Thread(target=serve_pair, args=(peer, server_sock), daemon=True)
    thread.start()
    return peer, client_sock, thread
