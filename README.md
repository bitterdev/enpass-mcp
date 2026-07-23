# enpass-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that gives
an AI assistant controlled, local access to your [Enpass](https://www.enpass.io)
password vaults: unlock a vault, list vaults, list and read entries, and create new
entries.

Runs locally over stdio. Your Enpass vault never leaves your machine, and your
**master password never passes through the model**: it is stored in your operating
system's keychain and read directly by the server.

## Why this is safe

- **Master passwords live in the OS keychain** (macOS Keychain, Windows Credential
  Manager, Linux Secret Service), not in config files, not in environment variables,
  and never as a tool argument. The `unlock_vault` tool deliberately takes **no
  password parameter**, so the password can never end up in the model's context or in
  logs.
- **The vault stays local.** The server reads the encrypted `vault.enpassdb` file
  directly with SQLCipher. Nothing is uploaded anywhere.
- **Reads are explicit.** Listing entries never returns passwords. Secrets are only
  returned by `get_item` / `get_password`, when you explicitly ask for them.
- **Writes are backed up.** `create_item` copies the vault file before writing.

Entry passwords are, by design, returned to the assistant when you ask for them, so
only connect this to an assistant and vaults you trust.

## Requirements

- Node.js 18 or newer
- An Enpass 6 / 7 / 8 vault (`vault.enpassdb`, SQLCipher format)
- On Linux: a Secret Service provider (GNOME Keyring or KWallet) for password storage

Native dependencies (`better-sqlite3-multiple-ciphers`, `@napi-rs/keyring`) ship
prebuilt binaries for common platforms, so no compiler is required in the normal case.

## Install

```bash
git clone https://github.com/fabianbitter/enpass-mcp.git
cd enpass-mcp
npm install
npm link   # optional: makes the `enpass-mcp` command available globally
```

## Register your vaults (do this once, in a terminal)

This is the secure step that keeps the master password away from the model. You run it
yourself; the password is typed into a hidden prompt and stored in the OS keychain.

```bash
# Find your vault files automatically
enpass-mcp discover

# Register a vault (you will be prompted for the master password)
enpass-mcp add-vault personal --path "/Users/you/Documents/Enpass/Vaults/primary/vault.enpassdb"
enpass-mcp add-vault work     --path "/path/to/work/vault.enpassdb"

# With a keyfile
enpass-mcp add-vault personal --path "/path/vault.enpassdb" --keyfile "/path/vault.keyfile"

# Manage
enpass-mcp list-vaults
enpass-mcp test-unlock personal
enpass-mcp remove-vault work
```

`add-vault` verifies the password can actually unlock the vault before saving it.

The vault file is usually found at:

| OS | Typical location |
| --- | --- |
| macOS | `~/Documents/Enpass/Vaults/<vault>/vault.enpassdb` |
| Windows | `%USERPROFILE%\Documents\Enpass\Vaults\<vault>\vault.enpassdb` |
| Linux | `~/Documents/Enpass/Vaults/<vault>/vault.enpassdb` |

If you sync via Dropbox / OneDrive / WebDAV, point `--path` at the synced copy.

## Connect it to your assistant

The server speaks MCP over stdio. Point your MCP client at `enpass-mcp serve`.

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "enpass": {
      "command": "enpass-mcp",
      "args": ["serve"]
    }
  }
}
```

If you did not run `npm link`, use the absolute path instead:

```json
{
  "mcpServers": {
    "enpass": {
      "command": "node",
      "args": ["/absolute/path/to/enpass-mcp/src/cli.js", "serve"]
    }
  }
}
```

**Claude Code:**

```bash
claude mcp add enpass -- enpass-mcp serve
```

## Tools

| Tool | Description |
| --- | --- |
| `list_vaults` | List registered vaults, whether their file exists, whether a password is stored, and whether they are unlocked. |
| `unlock_vault` | Unlock a vault using the master password from the OS keychain. Takes only a vault name, never a password. |
| `lock_vault` | Lock a vault and clear its derived key from memory. |
| `list_items` | List entries (title, username, URL). Never returns passwords. Supports `query`, `category`, `folder`, `limit`. |
| `get_item` | Return a full entry including all field values (password, TOTP, etc.) and its attachment list. |
| `get_password` | Return just the password (and TOTP) of an entry. |
| `list_attachments` | List an entry's file attachments (name, size, MIME). |
| `export_attachment` | Decrypt an attachment; writes it to disk and returns the path (or base64 inline for small files). |
| `create_item` | Create a new entry. Backs up the vault file first. |

`list_items` / `get_item` work for **every** Enpass entry type (logins, credit
cards, secure notes, identities, etc.), not just logins, and return all fields.

A typical assistant flow: `list_vaults` → `unlock_vault` → `list_items` → `get_password`.

## How it works

Enpass stores each vault as a standard SQLCipher database (`vault.enpassdb`). The raw
encryption key is derived from your master password (optionally combined with a
keyfile) and the 16-byte salt at the start of the file:

- PBKDF2-HMAC-SHA512, 100000 iterations (older vaults) or 320000 (newer vaults), the
  first 32 bytes used as the raw SQLCipher key
- opened with `cipher_compatibility` 4 (Enpass 6.8+) or 3 (older vaults)

The server tries these combinations automatically, so it works across Enpass vault
versions. The derived key is kept in memory only, for the lifetime of the server
process, and is never written to disk or returned to the model.

References: [Enpass Security Whitepaper](https://support.enpass.io/docs/security-whitepaper-enpass/vault.html),
[hazcod/enpass-cli](https://github.com/hazcod/enpass-cli).

## Attachments

Enpass keeps file attachments encrypted. Small files (up to 1 KB) sit inline in the
vault; larger files live in separate `<uuid>.enpassattach` SQLCipher files next to the
vault, each encrypted with its own key stored in the vault. `export_attachment` handles
both: it decrypts the file and, by default, writes it to disk and returns the path, so
it works for files of any size without pushing binary data through the model.

External-attachment handling is implemented from Enpass's documented format. If you hit
a vault whose attachments do not decrypt, please open an issue with the (non-secret)
schema of your `attachment` table.

## Creating entries

`create_item` inserts a new item and its fields into the vault and creates a
`*.backup-<timestamp>` copy of the vault file first. Enpass picks up the new entry on
its next sync. Close the Enpass app (or let it sync) to avoid write conflicts, and keep
the backup until you have confirmed the entry looks right.

## Configuration

Master passwords are in the OS keychain; only non-secret data (vault names and paths)
is stored in a small `vaults.json`:

- macOS: `~/Library/Application Support/enpass-mcp/vaults.json`
- Windows: `%APPDATA%\enpass-mcp\vaults.json`
- Linux: `~/.config/enpass-mcp/vaults.json`

Override the directory with `ENPASS_MCP_CONFIG_DIR`.

## Development

```bash
npm test                    # runs against genuine SQLCipher fixtures in test/fixtures

# Rebuild the fixtures from scratch with real SQLCipher (vault + entries + attachments)
npm install --no-save @journeyapps/sqlcipher
npm run generate-fixtures
```

CI (GitHub Actions) creates a vault from scratch with real SQLCipher, seeds entries and
attachments, then runs the full read/write test suite on Node 18/20/22, and separately
verifies the shipped server reads the fixtures on macOS and Windows.

## Security notes and limitations

- Anyone who can talk to this MCP server can read every password in a vault once it is
  unlocked. Only connect trusted clients.
- The server does not implement Enpass sync, attachments, item history, or trashing.
- `create_item` writes directly to the vault database. It is best-effort across Enpass
  schema versions and always makes a backup, but review new entries in Enpass.
- This is an independent project and is not affiliated with or endorsed by Enpass.

## License

MIT © Fabian Bitter
