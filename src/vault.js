/* Author: Fabian Bitter (fabian@bitter.de) */

import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3-multiple-ciphers";
import {
  readSalt,
  buildMasterSecret,
  deriveHexKey,
  decryptFieldValue,
  looksEncrypted,
  ENCRYPTED_ALGO_VERSION,
  ITERATION_CANDIDATES,
  COMPAT_CANDIDATES,
} from "./crypto.js";

// Opens the SQLCipher database with an already-derived raw key. Enpass databases
// are standard SQLCipher databases; the raw key is passed with the SQLCipher
// raw-key syntax `PRAGMA key = "x'<64 hex chars>'"`.
function openWithKey(vaultPath, hexKey, compat, readonly) {
  const db = new Database(vaultPath, { readonly, fileMustExist: true });
  db.pragma("cipher='sqlcipher'");
  db.pragma(`legacy=${compat}`);
  db.pragma(`key="x'${hexKey}'"`);
  return db;
}

// Tries the known Enpass key-derivation and cipher-compatibility combinations.
// Returns the parameters needed to open the vault, without keeping a handle open.
// The derived key is memory-only and must be treated as a secret.
export function unlockParameters(vaultPath, password, keyfilePath) {
  if (!fs.existsSync(vaultPath)) {
    throw new Error(`Vault file not found: ${vaultPath}`);
  }
  const salt = readSalt(vaultPath);
  const masterSecret = buildMasterSecret(password, keyfilePath);

  let lastError;
  for (const iterations of ITERATION_CANDIDATES) {
    const hexKey = deriveHexKey(masterSecret, salt, iterations);
    for (const compat of COMPAT_CANDIDATES) {
      let db;
      try {
        db = openWithKey(vaultPath, hexKey, compat, true);
        db.prepare("SELECT count(*) AS c FROM sqlite_master").get();
        return { hexKey, compat, iterations };
      } catch (err) {
        lastError = err;
      } finally {
        if (db) {
          try {
            db.close();
          } catch {
            // ignore
          }
        }
      }
    }
  }
  const detail = lastError ? ` (${lastError.message})` : "";
  throw new Error(
    `Unlock failed: wrong master password or unsupported vault format${detail}`,
  );
}

function withConnection(session, readonly, fn) {
  const db = openWithKey(session.path, session.hexKey, session.compat, readonly);
  try {
    return fn(db);
  } finally {
    try {
      db.close();
    } catch {
      // ignore
    }
  }
}

function tableInfo(db, table) {
  return db.prepare(`PRAGMA table_info(${table})`).all();
}

function hasTable(db, name) {
  return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?").get(name);
}

function tableColumns(db, table) {
  return new Set(tableInfo(db, table).map((r) => r.name));
}

function itemFilter(columns) {
  const clauses = [];
  if (columns.has("trashed")) clauses.push("(item.trashed IS NULL OR item.trashed = 0)");
  if (columns.has("deleted")) clauses.push("(item.deleted IS NULL OR item.deleted = 0)");
  return clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
}

function pickValue(fields, types) {
  for (const t of types) {
    const found = fields.find((f) => f.type === t && f.value);
    if (found) return found.value;
  }
  return null;
}

// Maps one raw `itemfield` row to the shape callers see, decrypting the value when
// the vault stores it with the per-item encryption layer (algo_version = 1).
//
// A failed decryption yields a null value, never the raw column content: the stored
// ciphertext is a plausible-looking string, and returning it silently hands the caller
// a wrong secret instead of an error.
function resolveField(row, itemKey, itemUuid) {
  const sensitive = row.sensitive === 1 || row.sensitive === true;
  const field = { label: row.label, type: row.type, value: row.value, sensitive };
  // algo_version 0 (or absent) means the value is already plaintext behind SQLCipher.
  if (!sensitive || !row.value || row.algo_version !== ENCRYPTED_ALGO_VERSION) return field;
  // Entries written before Enpass added the per-item layer still carry plaintext
  // under algo_version 1, so pass anything that is not shaped like a payload through.
  if (!looksEncrypted(row.value)) return field;

  const plaintext = decryptFieldValue(row.value, itemKey, itemUuid, row.algo_version);
  if (plaintext === null) {
    field.value = null;
    field.decryptionFailed = true;
  } else {
    field.value = plaintext;
  }
  return field;
}

// Lists entries in a vault without exposing sensitive field values.
export function listItems(session, { query, category, folder, limit = 200 } = {}) {
  return withConnection(session, true, (db) => {
    const itemCols = tableColumns(db, "item");
    const where = itemFilter(itemCols);
    const selectSub = itemCols.has("subtitle") ? "item.subtitle" : "NULL AS subtitle";
    const selectCat = itemCols.has("category") ? "item.category" : "NULL AS category";

    let sql = `SELECT item.uuid, item.title, ${selectSub}, ${selectCat} FROM item ${where}`;
    const params = [];
    if (folder) {
      sql += `${where ? " AND" : " WHERE"} item.uuid IN (
        SELECT item_uuid FROM folder_item fi
        JOIN folder f ON f.uuid = fi.folder_uuid
        WHERE f.title = ? OR f.uuid = ?)`;
      params.push(folder, folder);
    }
    sql += " ORDER BY item.title COLLATE NOCASE";

    const rows = db.prepare(sql).all(params);
    const nonSecretStmt = db.prepare(
      `SELECT label, type, value FROM itemfield
       WHERE item_uuid = ? AND type IN ('username','email','url') AND (deleted IS NULL OR deleted = 0)`,
    );

    const results = [];
    for (const row of rows) {
      if (category && String(row.category || "").toLowerCase() !== category.toLowerCase()) {
        continue;
      }
      const fields = nonSecretStmt.all(row.uuid);
      const item = {
        uuid: row.uuid,
        title: row.title,
        subtitle: row.subtitle || null,
        category: row.category || null,
        username: pickValue(fields, ["username", "email"]),
        url: pickValue(fields, ["url"]),
      };
      if (query) {
        const haystack = `${item.title} ${item.subtitle || ""} ${item.username || ""} ${item.url || ""}`.toLowerCase();
        if (!haystack.includes(query.toLowerCase())) continue;
      }
      results.push(item);
      if (results.length >= limit) break;
    }
    return results;
  });
}

// Returns a full entry including sensitive field values (passwords, TOTP, etc.).
export function getItem(session, uuid) {
  return withConnection(session, true, (db) => {
    const itemCols = tableColumns(db, "item");
    const selectSub = itemCols.has("subtitle") ? "subtitle" : "NULL AS subtitle";
    const selectCat = itemCols.has("category") ? "category" : "NULL AS category";
    const selectNote = itemCols.has("note") ? "note" : "NULL AS note";

    // `item.key` carries the per-item key that sensitive field values are encrypted
    // with; vaults predating that layer have no such column.
    const selectKey = itemCols.has("key") ? "key" : "NULL AS key";
    const item = db
      .prepare(
        `SELECT uuid, title, ${selectSub}, ${selectCat}, ${selectNote}, ${selectKey} FROM item WHERE uuid = ?`,
      )
      .get(uuid);
    if (!item) return null;
    const itemKey = normalizeBlob(item.key);

    // Field ordering varies across Enpass schema versions; some vaults have no
    // "order" column. Order by it only when present, otherwise by rowid.
    const fieldCols = tableColumns(db, "itemfield");
    const orderBy = fieldCols.has("order") ? `"order"` : "rowid";
    const delFilter = fieldCols.has("deleted") ? "AND (deleted IS NULL OR deleted = 0)" : "";
    const selectAlgo = fieldCols.has("algo_version") ? "algo_version" : "NULL AS algo_version";
    const fields = db
      .prepare(
        `SELECT label, type, value, sensitive, ${selectAlgo} FROM itemfield
         WHERE item_uuid = ? ${delFilter}
         ORDER BY ${orderBy}`,
      )
      .all(uuid);

    return {
      uuid: item.uuid,
      title: item.title,
      subtitle: item.subtitle || null,
      category: item.category || null,
      note: item.note || null,
      fields: fields.map((f) => resolveField(f, itemKey, item.uuid)),
      attachments: attachmentMeta(db, uuid),
    };
  });
}

// --- attachments ---

const EXTERNAL_ATTACHMENT_THRESHOLD = 1024;

// Attachment metadata for an item (no file bytes). Enpass stores small files
// (<= 1 KB) inline in the vault and larger files in separate SQLCipher databases
// named "<attachment uuid>.enpassattach" next to the vault.
function attachmentMeta(db, itemUuid) {
  if (!hasTable(db, "attachment")) return [];
  const cols = tableColumns(db, "attachment");
  if (!cols.has("item_uuid")) return [];
  const idExpr = cols.has("uuid") ? "uuid" : "rowid";
  const select = [
    `${idExpr} AS id`,
    cols.has("name") ? "name" : "NULL AS name",
    cols.has("size") ? "size" : "NULL AS size",
    cols.has("mime") ? "mime" : "NULL AS mime",
  ];
  const delFilter = cols.has("deleted") ? "AND (deleted IS NULL OR deleted = 0)" : "";
  const rows = db
    .prepare(`SELECT ${select.join(", ")} FROM attachment WHERE item_uuid = ? ${delFilter}`)
    .all(itemUuid);
  return rows.map((r, i) => ({
    index: i,
    id: String(r.id),
    name: r.name || null,
    size: r.size ?? null,
    mime: r.mime || null,
  }));
}

export function listAttachments(session, itemUuid) {
  return withConnection(session, true, (db) => attachmentMeta(db, itemUuid));
}

// Returns { name, mime, size, buffer } for one attachment, decrypting an external
// ".enpassattach" file with its per-attachment key when necessary.
export function readAttachment(session, itemUuid, selector) {
  return withConnection(session, true, (db) => {
    if (!hasTable(db, "attachment")) throw new Error("This vault has no attachments.");
    const cols = tableColumns(db, "attachment");
    if (!cols.has("item_uuid")) throw new Error("Attachment table has no item link.");
    const delFilter = cols.has("deleted") ? "AND (deleted IS NULL OR deleted = 0)" : "";
    const rows = db
      .prepare(`SELECT rowid AS _rowid, * FROM attachment WHERE item_uuid = ? ${delFilter}`)
      .all(itemUuid);

    let row;
    if (typeof selector === "number") {
      row = rows[selector];
    } else {
      row = rows.find((r) => r.name === selector);
      if (!row && /^\d+$/.test(String(selector))) row = rows[Number(selector)];
    }
    if (!row) throw new Error(`Attachment "${selector}" not found for item "${itemUuid}".`);

    const name = row.name || `attachment-${row._rowid}`;
    const mime = row.mime || "application/octet-stream";
    const data = normalizeBlob(row.data);
    const password = normalizeBlob(row.password);
    const size = row.size ?? null;

    let buffer;
    const isExternal = password && password.length > 0 && (!data || data.length === 0 || (size != null && size > EXTERNAL_ATTACHMENT_THRESHOLD));
    if (isExternal) {
      const attId = cols.has("uuid") ? row.uuid : String(row._rowid);
      buffer = readExternalAttachment(session.path, attId, password);
    } else if (data && data.length > 0) {
      buffer = data;
    } else {
      throw new Error(`Attachment "${name}" has no readable data.`);
    }
    return { name, mime, size: size ?? buffer.length, buffer };
  });
}

function normalizeBlob(value) {
  if (value == null) return null;
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === "string") return Buffer.from(value);
  return null;
}

function readExternalAttachment(vaultPath, attachmentId, keyBlob) {
  const file = path.join(path.dirname(vaultPath), `${attachmentId}.enpassattach`);
  if (!fs.existsSync(file)) {
    throw new Error(`External attachment file not found: ${file}`);
  }
  const hexKey = keyBlob.toString("hex");
  let lastError;
  for (const compat of COMPAT_CANDIDATES) {
    let db;
    try {
      db = new Database(file, { readonly: true, fileMustExist: true });
      db.pragma("cipher='sqlcipher'");
      db.pragma(`legacy=${compat}`);
      db.pragma(`key="x'${hexKey}'"`);
      const tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .all();
      for (const t of tables) {
        const tcols = tableInfo(db, t.name);
        const blobCol = tcols.find((c) => /BLOB/i.test(c.type)) || tcols[tcols.length - 1];
        if (!blobCol) continue;
        const r = db.prepare(`SELECT "${blobCol.name}" AS data FROM "${t.name}" LIMIT 1`).get();
        const buf = normalizeBlob(r && r.data);
        if (buf && buf.length > 0) return buf;
      }
      throw new Error("No attachment data found inside the .enpassattach file.");
    } catch (err) {
      lastError = err;
    } finally {
      if (db) {
        try {
          db.close();
        } catch {
          // ignore
        }
      }
    }
  }
  throw new Error(`Failed to read external attachment (${lastError ? lastError.message : "unknown error"}).`);
}

// Writing is DISABLED — this MCP is read-only.
//
// Inserting an entry directly into the SQLCipher database corrupts recent Enpass
// vaults: Enpass crashes on load. This was verified end to end against a real
// vault (schema version 6, per-item `item.key`, itemfield.algo_version = 1).
// Sensitive field values are encrypted with an undocumented per-item key we cannot
// reproduce, and even a fully structured, NON-sensitive-only entry (correct
// template / orde / item_field_uid / icon, no sensitive fields, no per-item key)
// still crashes the app, so Enpass rejects externally inserted items at a level
// below the field encryption. Reproducing Enpass's item-acceptance model from
// outside the app is not feasible. To add entries, use the Enpass app itself.
export function createItem() {
  throw new Error(
    "Writing is disabled: inserting entries directly into the Enpass database " +
      "corrupts recent vaults and crashes Enpass. This MCP is read-only, add " +
      "entries in the Enpass app.",
  );
}
