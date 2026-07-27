# enpass-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that gives
an AI assistant controlled, local access to your [Enpass](https://www.enpass.io)
password vaults: unlock a vault, list vaults, and list and read entries. Creating and
deleting entries is possible too, but switched off until you enable it.

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
- **Read-only unless you say otherwise.** Out of the box the server cannot change
  anything: the writing tools are not even advertised. Set
  `ENPASS_MCP_ALLOW_WRITES=1` to enable them (see [Writing](#writing-opt-in)).

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
git clone https://github.com/bitterdev/enpass-mcp.git
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
| `get_password` | Return the password and, if present, the current TOTP code of an entry. |
| `get_otp` | Generate the current TOTP / 2FA one-time code for an entry, with seconds until it rotates. |
| `list_attachments` | List an entry's file attachments (name, size, MIME). |
| `export_attachment` | Decrypt an attachment; writes it to disk and returns the path (or base64 inline for small files). |
| `sync_status` | List the vaults that use Enpass folder sync and whether the copy in the sync folder is newer. |

With `ENPASS_MCP_ALLOW_WRITES=1` three more tools appear (see [Writing](#writing-opt-in)):

| Tool | Description |
| --- | --- |
| `create_item` | Create an entry, including custom fields; sensitive values are encrypted the way Enpass does it. |
| `delete_item` | Delete an entry, or move it to the trash, leaving the tombstone Enpass uses so the deletion syncs. |
| `sync_pull` | Take in a newer copy from the sync folder, after backing up the local vault. |

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

## Per-item field encryption

Enpass encrypts every value flagged as "sensitive" a second time, underneath
SQLCipher, with a key that belongs to the entry rather than the vault. Fields
carrying that layer have `itemfield.algo_version = 1`:

| Piece | Where | Layout |
| --- | --- | --- |
| Key and nonce | `item.key` | 44 bytes: 32-byte AES-256 key, then a 12-byte GCM nonce |
| Value | `itemfield.value` | hex of `ciphertext \|\| 16-byte GCM tag` |
| Additional data | the entry's uuid | hyphens stripped, hex-decoded to 16 raw bytes |

Binding the AAD to the entry uuid is what makes a value unusable if it is copied into
another entry. Enpass did **not** re-encrypt existing entries when it introduced this
layer, so one vault mixes ciphertext and plaintext under the same `algo_version`; a
value is treated as encrypted only when it has the shape of a payload (pure hex, whole
bytes, longer than the tag on its own).

A value that looks encrypted but fails authentication is returned as `null` with
`decryptionFailed: true`, never as the raw column content: stored ciphertext is a
plausible-looking string, and handing that back would silently pass off a wrong secret
as a real one.

## Two-factor codes (TOTP)

Entries with a one-time-password secret (stored by Enpass as an `otpauth://` URI)
can produce a live 2FA code: `get_otp` returns the current 6-digit code and the
seconds until it rotates, and `get_password` includes the current code alongside the
password. This lets an assistant fill both the password and the 2FA prompt.

## Attachments

Enpass keeps file attachments encrypted. Small files (up to 1 KB) sit inline in the
vault; larger files live in separate `<uuid>.enpassattach` SQLCipher files next to the
vault, each encrypted with its own key stored in the vault. `export_attachment` handles
both: it decrypts the file and, by default, writes it to disk and returns the path, so
it works for files of any size without pushing binary data through the model.

External-attachment handling is implemented from Enpass's documented format. If you hit
a vault whose attachments do not decrypt, please open an issue with the (non-secret)
schema of your `attachment` table.

## Writing (opt-in)

Writing is switched off by default. A password vault is the last place where a tool
should be able to change data just because a model decided to, so the server starts
read-only and does not even list `create_item`, `delete_item` and `sync_pull` until you
turn them on:

```bash
ENPASS_MCP_ALLOW_WRITES=1
```

Set it in the server's environment (in your MCP client config, or in the `.env` next to
`vaults.json`). Nothing else changes: reading works exactly the same either way.

**Enpass must be closed while writing.** The app keeps the database in memory and would
write its own cached copy back over any change made underneath it. Every writing tool
refuses to run while Enpass is open.

Earlier versions of this README claimed writing was impossible because recent vaults
(schema version 6) crash Enpass when entries are inserted directly. The crash was real,
the diagnosis was wrong. Three concrete rules make it work, all of them derived from
what Enpass itself writes:

1. **Enpass never stores `NULL`.** The crash is `EXC_BAD_ACCESS` in `strlen` on a null
   pointer: a column omitted from the `INSERT` defaults to `NULL`, and the app calls
   `strlen` on it. Every column is written explicitly, empty strings instead of `NULL`.
2. **A template has a fixed field set.** `login.default` always carries the same nine
   fields, in the same order, with the same field uids, even when most are empty.
   Writing only the fields you happen to have a value for produces an entry the app
   cannot render.
3. **The per-item key is reproducible.** `item.key` is a 32-byte AES-256 key plus a
   12-byte GCM nonce, stored as `hex(ciphertext || tag)` with the item UUID as
   additional authenticated data. Nothing in it is tied to Enpass internals, so a fresh
   random key per item is fine.

Verified end to end against a real vault: written, read back, decrypted to the original,
deleted, synced in both directions, and Enpass opens the vault without crashing.

## Configuration

Master passwords are in the OS keychain; only non-secret data (vault names and paths)
is stored in a small `vaults.json`:

- macOS: `~/Library/Application Support/enpass-mcp/vaults.json`
- Windows: `%APPDATA%\enpass-mcp\vaults.json`
- Linux: `~/.config/enpass-mcp/vaults.json`

Override the directory with `ENPASS_MCP_CONFIG_DIR`.

Environment variables:

| Variable | Effect |
| --- | --- |
| `ENPASS_MCP_ALLOW_WRITES` | `1`, `true`, `yes` or `on` enables the writing tools. Anything else, including unset, keeps the server read-only. |
| `ENPASS_MCP_CONFIG_DIR` | Where `vaults.json` and the optional `.env` live. |
| `ENPASS_MASTER_PASSWORD` | Optional fallback master password for vaults without a keychain entry. Prefer the keychain. |
| `ENPASS_MASTER_PASSWORD_<VAULT>` | Same, for one specific vault. |

## Development

```bash
npm test                    # runs against genuine SQLCipher fixtures in test/fixtures

# Rebuild the fixtures from scratch with real SQLCipher (vault + entries + attachments)
npm install --no-save @journeyapps/sqlcipher
npm run generate-fixtures
```

CI (GitHub Actions) creates a vault from scratch with real SQLCipher, seeds entries and
attachments, then runs the full read-only test suite on Node 18/20/22.

## Security notes and limitations

- Anyone who can talk to this MCP server can read every password in a vault once it is
  unlocked. Only connect trusted clients.
- The server does not implement Enpass sync, item history, or trashing.
- The server is read-only and never modifies a vault. Creating or editing entries is
  intentionally not supported, because direct database writes crash recent Enpass
  vaults (see [Why there is no write support](#why-there-is-no-write-support)).
- This is an independent project and is not affiliated with or endorsed by Enpass.

## License

MIT © Fabian Bitter
