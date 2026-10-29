"""KeePassXC MCP server (stdio).

Talks to a running, unlocked KeePassXC via the browser-integration protocol.
The MCP process never sees the master password and never opens the .kdbx file.
"""

from __future__ import annotations

import json
import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from keepassxc_mcp.protocol import KPXCClient, KeePassXCError, detect_socket_path, log

mcp = FastMCP(
    "keepassxc",
    instructions=(
        "KeePassXC password manager. Look up credentials by URL, save new "
        "logins, generate passwords, and read TOTP. KeePassXC must be running "
        "with Browser Integration enabled and the database unlocked. First use "
        "pops a confirmation dialog in KeePassXC — the user must approve it. "
        "Lookups are by URL, not title. Never echo retrieved passwords into "
        "chat unless the user asked for the secret itself."
    ),
)

_client: KPXCClient | None = None


def get_client() -> KPXCClient:
    global _client
    if _client is not None:
        return _client
    host = os.environ.get("KEEPASSXC_HOST")
    port = os.environ.get("KEEPASSXC_PORT")
    socket_path = os.environ.get("KEEPASSXC_SOCKET")
    timeout = float(os.environ.get("KEEPASSXC_TIMEOUT", "30"))
    if host:
        _client = KPXCClient(host=host, port=int(port or 19455), timeout=timeout)
    else:
        path = socket_path or detect_socket_path()
        if not path:
            raise KeePassXCError(
                "KeePassXC browser socket not found. Enable Browser Integration "
                "in KeePassXC and leave the database unlocked."
            )
        _client = KPXCClient(socket_path=path, timeout=timeout)
    return _client


def set_client(client: KPXCClient | None) -> None:
    """Test hook."""
    global _client
    _client = client


def _ok(payload: Any) -> str:
    return json.dumps(payload, indent=2, default=str)


def _fail(exc: Exception) -> str:
    log(f"tool error: {exc}")
    return _ok({"error": str(exc)})


@mcp.tool()
def associate() -> str:
    """Associate this MCP server with the unlocked KeePassXC database.

    KeePassXC shows a confirmation dialog; the user must accept it. Usually
    needed only once — the association is stored locally for later sessions.
    """
    try:
        assoc_id = get_client().associate()
        return _ok({"associated_as": assoc_id})
    except Exception as exc:
        return _fail(exc)


@mcp.tool()
def status() -> str:
    """Report whether KeePassXC is reachable and this client is associated."""
    try:
        client = get_client()
        client.ensure_ready()
        info = client.get_databasehash()
        return _ok(
            {
                "connected": True,
                "associated": True,
                "association_id": client.identity["id"] if client.identity else None,
                "database_hash": info.get("hash"),
                "keepassxc_version": info.get("version"),
            }
        )
    except Exception as exc:
        return _fail(exc)


@mcp.tool()
def get_logins(url: str, submit_url: str | None = None) -> str:
    """Look up saved credentials whose URL field matches.

    KeePassXC's browser protocol matches on URL, not title. Pass a full URL
    such as https://github.com or https://console.aws.amazon.com. Returns
    username, password, name, uuid, and TOTP when present.
    """
    try:
        result = get_client().get_logins(url, submit_url)
        entries = result.get("entries") or []
        return _ok(
            {
                "count": len(entries),
                "entries": entries,
            }
        )
    except Exception as exc:
        return _fail(exc)


@mcp.tool()
def get_totp(uuid: str) -> str:
    """Get the current TOTP code for an entry UUID (from get_logins)."""
    try:
        result = get_client().get_totp(uuid)
        return _ok({"uuid": uuid, "totp": result.get("totp")})
    except Exception as exc:
        return _fail(exc)


@mcp.tool()
def set_login(
    url: str,
    login: str,
    password: str,
    submit_url: str | None = None,
    group: str | None = None,
    group_uuid: str | None = None,
    uuid: str | None = None,
) -> str:
    """Save a new login, or update an existing one when uuid is provided.

    KeePassXC may still prompt the user to confirm the write. Prefer generating
    the password with generate_password first rather than inventing one.
    """
    try:
        params: dict[str, Any] = {
            "url": url,
            "login": login,
            "password": password,
        }
        if submit_url:
            params["submitUrl"] = submit_url
        if group:
            params["group"] = group
        if group_uuid:
            params["groupUuid"] = group_uuid
        if uuid:
            params["uuid"] = uuid
        result = get_client().set_login(params)
        return _ok(
            {
                "success": str(result.get("success")).lower() == "true",
                "hash": result.get("hash"),
            }
        )
    except Exception as exc:
        return _fail(exc)


@mcp.tool()
def unlock(timeout: float | None = None) -> str:
    """Ask KeePassXC to open a locked database, raising its unlock prompt.

    The master password is typed by the user in the KeePassXC window; this
    server never sees it. Other tools call this automatically when they hit a
    locked database, unless KEEPASSXC_MCP_AUTO_UNLOCK=0.
    """
    try:
        result = get_client().unlock(timeout=timeout)
        return _ok(result)
    except Exception as exc:
        return _fail(exc)


@mcp.tool()
def generate_password() -> str:
    """Generate a password using KeePassXC's generator settings.

    On some KeePassXC versions this opens the generator dialog and waits for
    the user to accept it.
    """
    try:
        result = get_client().generate_password()
        return _ok({"password": result.get("password")})
    except Exception as exc:
        return _fail(exc)


@mcp.tool()
def get_database_groups() -> str:
    """List the group/folder tree of the unlocked database."""
    try:
        result = get_client().get_database_groups()
        if isinstance(result, str):
            result = json.loads(result)
        return _ok(result)
    except Exception as exc:
        return _fail(exc)


@mcp.tool()
def create_group(group_name: str) -> str:
    """Create a group (path, e.g. 'Root/MCP' or 'Work/API keys')."""
    try:
        result = get_client().create_group(group_name)
        return _ok({"name": result.get("name"), "uuid": result.get("uuid")})
    except Exception as exc:
        return _fail(exc)


@mcp.tool()
def lock_database() -> str:
    """Lock the currently open KeePassXC database."""
    try:
        get_client().lock_database()
        return _ok({"locked": True})
    except Exception as exc:
        return _fail(exc)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
