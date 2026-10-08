/* Author: Fabian Bitter (fabian@bitter.de) */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  listVaults as listRegisteredVaults,
  getVault,
  getSecret,
  writesEnabled,
} from "./config.js";
import {
  unlockParameters,
  listItems,
  getItem,
  listAttachments,
  readAttachment,
} from "./vault.js";
import { computeOtp, isOtpValue, totpFieldValue } from "./otp.js";
import { entryProblems } from "./hygiene.js";
import { execFileSync } from "node:child_process";
import Database from "better-sqlite3-multiple-ciphers";
import { insertItem, deleteItem, addAttachment, finalizeVault, pushSync, pullSync } from "./write.js";
import { discoverSyncedVaults, syncTargetFor, remoteStatus } from "./foldersync.js";

function findOtpField(item) {
  return item.fields.find((f) => (f.type === "totp" && f.value) || isOtpValue(f.value));
}

// First field of one of the given types that actually holds a value. Entries often
// carry an empty built-in field (an unused "password" slot on a login that keeps its
// real credentials in labelled custom fields), and picking that empty one first would
// report the entry as having no password at all.
function firstValue(item, types) {
  const found = item.fields.find((f) => types.includes(f.type) && f.value);
  return found ? found.value : null;
}

// Unlocked sessions: vault name -> { path, hexKey, compat }. The derived key
// lives in memory only, for the lifetime of this stdio process. It is never
// logged and never returned to the model.
const sessions = new Map();

function requireSession(name) {
  const session = sessions.get(name);
  if (!session) {
    throw new Error(
      `Vault "${name}" is locked. Call unlock_vault first (it reads the master password from the OS keychain).`,
    );
  }
  return session;
}

function json(payload) {
  return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }] };
}

function fail(message) {
  return { isError: true, content: [{ type: "text", text: message }] };
}

export function createServer() {
  const server = new McpServer({ name: "enpass-mcp", version: "0.2.0" });

  server.registerTool(
    "list_vaults",
    {
      title: "List vaults",
      description:
        "Lists the Enpass vaults registered on this machine, whether their file exists, whether a master password is stored in the OS keychain, and whether they are currently unlocked in this session.",
      inputSchema: {},
    },
    async () => {
      const vaults = listRegisteredVaults().map((v) => ({
        name: v.name,
        path: v.path,
        pathExists: v.pathExists,
        passwordStored: v.hasSecret,
        unlocked: sessions.has(v.name),
      }));
      if (vaults.length === 0) {
        return json({
          vaults: [],
          hint: "No vaults registered. Register one from a terminal: `enpass-mcp add-vault <name> --path <vault.enpassdb>`.",
        });
      }
      return json({ vaults });
    },
  );

  server.registerTool(
    "unlock_vault",
    {
      title: "Unlock vault",
      description:
        "Unlocks a registered vault using the master password stored in the OS keychain. The password is never passed as an argument and never reaches the model. Must be called before listing or reading entries.",
      inputSchema: { vault: z.string().describe("Registered vault name") },
    },
    async ({ vault }) => {
      const entry = getVault(vault);
      if (!entry) return fail(`Vault "${vault}" is not registered.`);
      const password = getSecret(vault);
      if (!password) {
        return fail(
          `No master password stored for "${vault}". Register it from a terminal: \`enpass-mcp add-vault ${vault} --path <vault.enpassdb>\`.`,
        );
      }
      try {
        const params = await unlockParameters(entry.path, password, entry.keyfile);
        sessions.set(vault, { path: entry.path, hexKey: params.hexKey, compat: params.compat });
        return json({ unlocked: true, vault });
      } catch (err) {
        return fail(err.message);
      }
    },
  );

  server.registerTool(
    "lock_vault",
    {
      title: "Lock vault",
      description: "Locks a vault and clears its derived key from memory for this session.",
      inputSchema: { vault: z.string().describe("Registered vault name") },
    },
    async ({ vault }) => {
      const existed = sessions.delete(vault);
      return json({ locked: true, vault, wasUnlocked: existed });
    },
  );

  server.registerTool(
    "list_items",
    {
      title: "List entries",
      description:
        "Lists entries in an unlocked vault. Returns titles, usernames and URLs but no passwords or other sensitive values. Supports optional search, category and folder filters.",
      inputSchema: {
        vault: z.string().describe("Registered vault name"),
        query: z.string().optional().describe("Case-insensitive search across title, username and URL"),
        category: z.string().optional().describe("Filter by category, e.g. login, creditcard, note"),
        folder: z.string().optional().describe("Filter by folder title or uuid"),
        limit: z.number().int().positive().max(1000).optional().describe("Max results (default 200)"),
      },
    },
    async ({ vault, query, category, folder, limit }) => {
      try {
        const session = requireSession(vault);
        const items = await listItems(session, { query, category, folder, limit });
        return json({ vault, count: items.length, items });
      } catch (err) {
        return fail(err.message);
      }
    },
  );

  server.registerTool(
    "get_item",
    {
      title: "Get entry",
      description:
        "Returns a full entry from an unlocked vault including sensitive field values (password, TOTP, etc.). Use this when the user explicitly wants the credentials.",
      inputSchema: {
        vault: z.string().describe("Registered vault name"),
        uuid: z.string().describe("Entry uuid (from list_items)"),
      },
    },
    async ({ vault, uuid }) => {
      try {
        const session = requireSession(vault);
        const item = await getItem(session, uuid);
        if (!item) return fail(`Entry "${uuid}" not found in vault "${vault}".`);
        return json(item);
      } catch (err) {
        return fail(err.message);
      }
    },
  );

  server.registerTool(
    "get_password",
    {
      title: "Get password",
      description:
        "Returns just the password (and TOTP if present) of an entry in an unlocked vault.",
      inputSchema: {
        vault: z.string().describe("Registered vault name"),
        uuid: z.string().describe("Entry uuid (from list_items)"),
      },
    },
    async ({ vault, uuid }) => {
      try {
        const session = requireSession(vault);
        const item = await getItem(session, uuid);
        if (!item) return fail(`Entry "${uuid}" not found in vault "${vault}".`);
        const otpField = findOtpField(item);
        const otp = otpField ? computeOtp(otpField.value) : null;
        return json({
          uuid: item.uuid,
          title: item.title,
          username: firstValue(item, ["username", "email"]),
          password: firstValue(item, ["password"]),
          otp: otp ? otp.code : null,
          otp_seconds_remaining: otp ? otp.secondsRemaining : null,
        });
      } catch (err) {
        return fail(err.message);
      }
    },
  );

  server.registerTool(
    "get_otp",
    {
      title: "Get one-time code",
      description:
        "Generates the current TOTP / two-factor one-time code for an entry that stores an OTP secret. Returns the code and how many seconds until it rotates, so it can be entered for 2FA.",
      inputSchema: {
        vault: z.string().describe("Registered vault name"),
        uuid: z.string().describe("Entry uuid (from list_items)"),
      },
    },
    async ({ vault, uuid }) => {
      try {
        const session = requireSession(vault);
        const item = getItem(session, uuid);
        if (!item) return fail(`Entry "${uuid}" not found in vault "${vault}".`);
        const otpField = findOtpField(item);
        if (!otpField) return fail(`Entry "${item.title}" has no OTP / 2FA secret.`);
        const otp = computeOtp(otpField.value);
        if (!otp) return fail("Could not generate a one-time code from the stored secret.");
        return json({
          uuid: item.uuid,
          title: item.title,
          code: otp.code,
          secondsRemaining: otp.secondsRemaining,
          period: otp.period,
        });
      } catch (err) {
        return fail(err.message);
      }
    },
  );

  server.registerTool(
    "list_attachments",
    {
      title: "List attachments",
      description:
        "Lists the file attachments of an entry in an unlocked vault (name, size, MIME). Use export_attachment to get the file itself.",
      inputSchema: {
        vault: z.string().describe("Registered vault name"),
        uuid: z.string().describe("Entry uuid (from list_items)"),
      },
    },
    async ({ vault, uuid }) => {
      try {
        const session = requireSession(vault);
        const attachments = listAttachments(session, uuid);
        return json({ vault, uuid, count: attachments.length, attachments });
      } catch (err) {
        return fail(err.message);
      }
    },
  );

  server.registerTool(
    "export_attachment",
    {
      title: "Export attachment",
      description:
        "Decrypts a file attachment from an unlocked vault. By default it writes the file to disk and returns the path (works for any size). Set inline=true to get small files as base64 instead.",
      inputSchema: {
        vault: z.string().describe("Registered vault name"),
        uuid: z.string().describe("Entry uuid (from list_items)"),
        attachment: z
          .union([z.string(), z.number()])
          .describe("Attachment name or index (from list_attachments)"),
        dest: z.string().optional().describe("Destination directory (default: OS temp dir)"),
        inline: z.boolean().optional().describe("Return small files as base64 instead of writing to disk"),
      },
    },
    async ({ vault, uuid, attachment, dest, inline }) => {
      try {
        const session = requireSession(vault);
        const selector = typeof attachment === "number"
          ? attachment
          : /^\d+$/.test(attachment) ? Number(attachment) : attachment;
        const { name, mime, size, buffer } = readAttachment(session, uuid, selector);

        if (inline) {
          const MAX_INLINE = 256 * 1024;
          if (buffer.length > MAX_INLINE) {
            return fail(`File is ${buffer.length} bytes, too large for inline. Omit inline to export it to disk.`);
          }
          return json({ name, mime, size, encoding: "base64", data: buffer.toString("base64") });
        }

        const dir = dest || path.join(os.tmpdir(), "enpass-mcp-exports");
        fs.mkdirSync(dir, { recursive: true });
        const safeName = (name || "attachment").replace(/[^\w.\-]+/g, "_") || "attachment";
        const outPath = path.join(dir, safeName);
        fs.writeFileSync(outPath, buffer, { mode: 0o600 });
        return json({ name, mime, size, path: outPath });
      } catch (err) {
        return fail(err.message);
      }
    },
  );

  // --- writing -------------------------------------------------------------
  //
  // Writing WAS disabled here with the note that inserting entries corrupts recent
  // vaults. That diagnosis was wrong: the crash came from NULL columns, an incomplete
  // template field set and a stale sync state, not from Enpass rejecting outside writes.
  // See src/write.js. Verified end to end on 2026-07-26: written, deleted, synced both
  // ways, Enpass opens without a crash.
  //
  // Enpass MUST be closed while writing, it caches the database in memory and would
  // overwrite anything written underneath it. Every writing tool refuses otherwise.

  const enpassRunning = () => {
    try {
      return execFileSync("/usr/bin/pgrep", ["-x", "Enpass"], { encoding: "utf8" }).trim().length > 0;
    } catch {
      return false; // pgrep exits non-zero when nothing matches
    }
  };
  const requireClosed = () =>
    enpassRunning()
      ? fail("Enpass is running. Quit it before writing, otherwise it overwrites the change from its cache.")
      : null;

  // Opens the vault read-write using the session key from unlock_vault.
  const openWritable = (vault) => {
    const session = sessions.get(vault);
    if (!session) throw new Error(`Vault "${vault}" is locked. Call unlock_vault first.`);
    const db = new Database(session.path, { fileMustExist: true });
    db.pragma("cipher='sqlcipher'");
    db.pragma(`legacy=${session.compat}`);
    db.pragma(`key="x'${session.hexKey}'"`);
    return { db, dbPath: session.path };
  };

  // After any write: republish through folder sync, but ONLY for vaults that actually
  // use it. Vaults on iCloud/Dropbox/WebDAV or without sync are left alone.
  const publish = (dbPath, vaultUuid) => {
    const target = vaultUuid ? syncTargetFor(vaultUuid) : null;
    if (!target) return { synced: false, reason: "no folder sync for this vault" };
    const res = pushSync(target.vaultDir, target.syncDir, target.remoteDir);
    const meta = new Database(path.join(target.syncDir, "syncmeta.db"), { fileMustExist: true });
    const set = meta.prepare("INSERT INTO main(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");
    set.run("revision", String(res.now));
    set.run("sync_last_done_time", String(res.now));
    set.run("sync_vault_dirty", "0");
    meta.close();
    return { synced: true, targets: res.written, revision: res.now, attachmentsPublished: res.attachments };
  };

  const vaultUuidOf = (dbPath) => path.basename(path.dirname(dbPath));

  // Everything past this point can change the vault, so it is only advertised when the
  // user opted in. Read-only stays the default: an agent that is not supposed to edit
  // the vault should not even see that these tools exist.
  const allowWrites = writesEnabled();

  if (allowWrites) {
  server.registerTool(
    "create_item",
    {
      title: "Create item",
      description:
        "Creates a login entry in an unlocked vault and publishes it through Enpass folder sync when that vault uses it. Supports arbitrary custom fields (e.g. SMTP host, port), sensitive ones are encrypted like Enpass does. Enpass must be closed.",
      inputSchema: {
        vault: z.string().describe("Registered vault name"),
        title: z.string(),
        username: z.string().optional(),
        email: z.string().optional(),
        password: z.string().optional(),
        url: z.string().optional(),
        totp: z
          .string()
          .optional()
          .describe("One-time code secret (base32 or otpauth URI), stored in the built-in TOTP field so Enpass shows the code"),
        note: z.string().optional(),
        subtitle: z.string().optional(),
        custom: z
          .array(z.object({ label: z.string(), value: z.string(), sensitive: z.boolean().optional() }))
          .optional()
          .describe("Extra fields beyond the template, e.g. [{label:'SMTP Port', value:'587'}]"),
      },
    },
    async ({ vault, title, username, email, password, url, totp, note, subtitle, custom }) => {
      const blocked = requireClosed();
      if (blocked) return blocked;
      const problems = entryProblems({ title, subtitle, note, custom });
      if (problems.length) return fail(`entry refused: ${problems.join("; ")}`);
      try {
        const { db, dbPath } = openWritable(vault);
        let uuid;
        db.transaction(() => {
          uuid = insertItem(db, {
            title,
            subtitle: subtitle ?? "",
            note: note ?? "",
            values: { username, email, password, url, totp: totpFieldValue(totp) },
            custom: custom ?? [],
          });
        })();
        const counts = finalizeVault(db, dbPath);
        db.close();
        return json({ created: uuid, title, items: counts.items, sync: publish(dbPath, vaultUuidOf(dbPath)) });
      } catch (err) {
        return fail(err.message);
      }
    },
  );

  server.registerTool(
    "delete_item",
    {
      title: "Delete item",
      description:
        "Deletes an entry the way Enpass does: the row stays as a tombstone with deleted=1 so the other machine learns about the deletion instead of resurrecting the entry. Publishes through folder sync. Enpass must be closed.",
      inputSchema: {
        vault: z.string(),
        uuid: z.string().optional().describe("Item uuid; alternatively pass title"),
        title: z.string().optional().describe("Exact title, used when uuid is omitted"),
        toTrash: z.boolean().optional().describe("Move to trash instead of deleting permanently"),
      },
    },
    async ({ vault, uuid, title, toTrash }) => {
      const blocked = requireClosed();
      if (blocked) return blocked;
      try {
        const { db, dbPath } = openWritable(vault);
        let target = uuid;
        if (!target) {
          if (!title) { db.close(); return fail("Pass either uuid or title."); }
          const row = db.prepare("SELECT uuid FROM item WHERE title=? AND deleted=0").get(title);
          if (!row) { db.close(); return fail(`No active entry titled "${title}".`); }
          target = row.uuid;
        }
        let res;
        db.transaction(() => { res = deleteItem(db, target, { toTrash: !!toTrash }); })();
        const counts = finalizeVault(db, dbPath);
        db.close();
        return json({ deleted: res.uuid, mode: res.mode, items: counts.items, sync: publish(dbPath, vaultUuidOf(dbPath)) });
      } catch (err) {
        return fail(err.message);
      }
    },
  );

  // The file itself is taken from a path, never from base64 in the argument list. Passing
  // a document through the model as text is what produced the data-URI attachments that
  // Enpass then handed out verbatim, so the bytes are read from disk and stored raw.
  server.registerTool(
    "add_attachment",
    {
      title: "Add attachment",
      description:
        "Attaches a file from disk to an existing entry and publishes it through Enpass folder sync. The bytes are stored raw, exactly as the Enpass app stores them, and read back byte for byte. Enpass must be closed.",
      inputSchema: {
        vault: z.string().describe("Registered vault name"),
        uuid: z.string().optional().describe("Entry uuid; alternatively pass title"),
        title: z.string().optional().describe("Exact entry title, used when uuid is omitted"),
        file: z.string().describe("Absolute path of the file to attach"),
        name: z.string().optional().describe("Name inside the vault (default: the file name)"),
      },
    },
    async ({ vault, uuid, title, file, name }) => {
      const blocked = requireClosed();
      if (blocked) return blocked;
      let db;
      try {
        if (!fs.existsSync(file)) return fail(`File not found: ${file}`);
        const content = fs.readFileSync(file);
        const opened = openWritable(vault);
        db = opened.db;
        const dbPath = opened.dbPath;
        let target = uuid;
        if (!target) {
          if (!title) { db.close(); return fail("Pass either uuid or title."); }
          const row = db.prepare("SELECT uuid FROM item WHERE title=? AND deleted=0").get(title);
          if (!row) { db.close(); return fail(`No active entry titled "${title}".`); }
          target = row.uuid;
        }
        const label = name || path.basename(file);
        let res;
        db.transaction(() => { res = addAttachment(db, dbPath, target, label, content); })();
        const counts = finalizeVault(db, dbPath);
        db.close();
        db = null;
        return json({
          attached: res.name, uuid: res.uuid, size: res.size, item: target,
          attachments: counts.atts, sync: publish(dbPath, vaultUuidOf(dbPath)),
        });
      } catch (err) {
        db?.close();
        return fail(err.message);
      }
    },
  );
  }

  server.registerTool(
    "sync_status",
    {
      title: "Sync status",
      description:
        "Lists every vault that uses Enpass folder sync, where its sync folder is, and whether the copy there is newer than the local one. Vaults without folder sync are not listed. Answers include a reason, so 'no baseline yet' is distinguishable from 'up to date'.",
      inputSchema: {},
    },
    async () => {
      try {
        const vaults = discoverSyncedVaults().map((v) => {
          const st = remoteStatus(v, Database);
          return { vault: v.name, uuid: v.uuid, syncFolder: v.remoteDir, remoteIsNewer: st.newer, reason: st.reason };
        });
        return json({ vaults, count: vaults.length });
      } catch (err) {
        return fail(err.message);
      }
    },
  );

  // sync_pull replaces the local vault file with the copy from the sync folder, so it
  // counts as writing even though nothing inside the database is edited.
  if (allowWrites) {
  server.registerTool(
    "sync_pull",
    {
      title: "Pull newer copy",
      description:
        "Takes in the copy from the sync folder when it is genuinely newer, after backing up the local vault (one generation, under .enpass-mcp-previous). Does nothing when there is no baseline or no folder sync. Enpass must be closed.",
      inputSchema: {
        vaultUuid: z.string().describe("Vault uuid as reported by sync_status"),
        force: z.boolean().optional().describe("Pull even when the local copy looks current"),
      },
    },
    async ({ vaultUuid, force }) => {
      const blocked = requireClosed();
      if (blocked) return blocked;
      try {
        const target = syncTargetFor(vaultUuid);
        if (!target) return fail(`No folder sync configured for vault ${vaultUuid}.`);
        const st = remoteStatus(target, Database);
        if (!st.newer && !force) return json({ pulled: false, reason: st.reason });
        const res = pullSync(target.vaultDir, target.syncDir, target.remoteDir, Database);
        return json({
          pulled: true, vault: res.vaultName, items: res.items, revision: res.stamp,
          attachmentsFetched: res.attachments, backup: ".enpass-mcp-previous",
        });
      } catch (err) {
        return fail(err.message);
      }
    },
  );
  }

  return server;
}

export async function serve() {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stdout is reserved for the MCP protocol; log to stderr only.
  process.stderr.write("enpass-mcp server ready (stdio)\n");
}
