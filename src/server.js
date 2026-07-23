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
} from "./config.js";
import {
  unlockParameters,
  listItems,
  getItem,
  createItem,
  listAttachments,
  readAttachment,
} from "./vault.js";
import { computeOtp, isOtpValue } from "./otp.js";

function findOtpField(item) {
  return item.fields.find((f) => f.type === "totp" || isOtpValue(f.value));
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
  const server = new McpServer({ name: "enpass-mcp", version: "0.1.0" });

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
        const password = item.fields.find((f) => f.type === "password");
        const otpField = findOtpField(item);
        const otp = otpField ? computeOtp(otpField.value) : null;
        return json({
          uuid: item.uuid,
          title: item.title,
          username: item.fields.find((f) => f.type === "username" || f.type === "email")?.value || null,
          password: password ? password.value : null,
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

  server.registerTool(
    "create_item",
    {
      title: "Create entry",
      description:
        "Creates a new entry in an unlocked vault. The vault file is backed up automatically before writing. Enpass picks up the new entry on its next sync.",
      inputSchema: {
        vault: z.string().describe("Registered vault name"),
        title: z.string().describe("Entry title"),
        password: z.string().optional().describe("Password value"),
        username: z.string().optional().describe("Username or email"),
        url: z.string().optional().describe("Website URL"),
        note: z.string().optional().describe("Free-text note"),
        category: z.string().optional().describe("Category, defaults to 'login'"),
        fields: z
          .array(
            z.object({
              label: z.string(),
              value: z.string(),
              type: z.string().optional(),
              sensitive: z.boolean().optional(),
            }),
          )
          .optional()
          .describe("Additional custom fields"),
      },
    },
    async ({ vault, title, password, username, url, note, category, fields }) => {
      try {
        const session = requireSession(vault);
        const result = await createItem(session, { title, password, username, url, note, category, fields });
        return json({ created: true, vault, uuid: result.uuid, backup: result.backupPath });
      } catch (err) {
        return fail(err.message);
      }
    },
  );

  return server;
}

export async function serve() {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stdout is reserved for the MCP protocol; log to stderr only.
  process.stderr.write("enpass-mcp server ready (stdio)\n");
}
