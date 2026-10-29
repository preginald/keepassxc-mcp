# keepassxc-mcp

MCP server for [KeePassXC](https://keepassxc.org/). It talks to the **running, unlocked** app over the same browser-integration socket the Chrome/Firefox extension uses. Hermes (or any MCP client) can then look up and save credentials without copy-paste.

It never opens your `.kdbx` file and never asks for the master password.

## What you get

| Tool | Does |
|---|---|
| `status` | Reachable? Associated? Database hash + KeePassXC version |
| `associate` | First-time pairing (KeePassXC shows a confirm dialog) |
| `get_logins` | Username/password/TOTP for a **URL** |
| `get_totp` | Current TOTP for an entry UUID |
| `set_login` | Create or update a login |
| `generate_password` | KeePassXC's generator |
| `get_database_groups` | Folder tree |
| `create_group` | New group/path |
| `lock_database` | Lock the open database |

Lookups are by **URL**, not title — that is a KeePassXC protocol limit, not this server's.

## Requirements

- KeePassXC 2.7+ with **Browser Integration** enabled (Settings → Browser Integration)
- Database unlocked
- Python 3.10+

On this laptop the socket is already present when KeePassXC is running:

`/run/user/$UID/org.keepassxc.KeePassXC.BrowserServer`

## Install

```bash
git clone https://github.com/preginald/keepassxc-mcp.git
cd keepassxc-mcp
uv sync --all-extras
```

Or without uv:

```bash
pip install -e '.[dev]'
```

## Hermes

```bash
hermes mcp add keepassxc \
  --command uv \
  --args --directory /ABS/PATH/TO/keepassxc-mcp run keepassxc-mcp
```

Restart Hermes after adding. First real lookup pops a KeePassXC dialog named something like `keepassxc-mcp` — accept it once. The association is stored at `~/.local/share/keepassxc-mcp/identity.json` (mode 0600).

Then: "get my GitHub login" or "save this API key in KeePassXC for https://api.example.com".

## Other MCP clients

stdio command:

```
uv --directory /ABS/PATH/TO/keepassxc-mcp run keepassxc-mcp
```

or `python -m keepassxc_mcp` from an environment that has the package installed.

## Environment

| Variable | Meaning |
|---|---|
| `KEEPASSXC_SOCKET` | Unix socket path (otherwise auto-detected) |
| `KEEPASSXC_HOST` / `KEEPASSXC_PORT` | TCP instead of Unix (for a forwarded socket) |
| `KEEPASSXC_MCP_IDENTITY` | Identity file path |
| `KEEPASSXC_TIMEOUT` | Seconds (default 30; association waits up to 120) |

## Security

- Secrets travel encrypted (NaCl box) between this process and KeePassXC, then as MCP tool results to the agent.
- The agent **will see** passwords it fetches. Do not attach this server to an untrusted chat.
- Writes still go through KeePassXC; it may prompt you.
- Identity file is equivalent to a browser-extension pairing key. Keep it 0600 and local.

## Tests

```bash
uv run pytest
```

Tests use an in-process fake KeePassXC. They never touch a real vault.

## Protocol

[keepassxc-browser protocol](https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md)
