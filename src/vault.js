/* Author: Fabian Bitter (fabian@bitter.de) */

import fs from "node:fs";
import crypto from "node:crypto";
import Database from "better-sqlite3-multiple-ciphers";
import {
  readSalt,
  buildMasterSecret,
  deriveHexKey,
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

function tableColumns(db, table) {
  return new Set(tableInfo(db, table).map((r) => r.name));
}

// A type-appropriate zero value for a NOT NULL column we do not otherwise set,
// so inserts succeed across Enpass schema versions with extra required columns.
function zeroValueForType(type) {
  const t = String(type || "").toUpperCase();
  if (t.includes("INT")) return 0;
  if (t.includes("REAL") || t.includes("FLOA") || t.includes("DOUB")) return 0;
  if (t.includes("BLOB")) return Buffer.alloc(0);
  return "";
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

    const item = db
      .prepare(`SELECT uuid, title, ${selectSub}, ${selectCat}, ${selectNote} FROM item WHERE uuid = ?`)
      .get(uuid);
    if (!item) return null;

    const fields = db
      .prepare(
        `SELECT label, type, value, sensitive FROM itemfield
         WHERE item_uuid = ? AND (deleted IS NULL OR deleted = 0)
         ORDER BY "order"`,
      )
      .all(uuid);

    return {
      uuid: item.uuid,
      title: item.title,
      subtitle: item.subtitle || null,
      category: item.category || null,
      note: item.note || null,
      fields: fields.map((f) => ({
        label: f.label,
        type: f.type,
        value: f.value,
        sensitive: f.sensitive === 1 || f.sensitive === true,
      })),
    };
  });
}

// Backs up the vault file, then inserts a new entry. Enpass picks up the new
// entry on its next sync. The backup protects against schema surprises.
export function createItem(session, data) {
  const backupPath = backupVault(session.path);
  const uuid = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);
  const category = data.category || "login";

  withConnection(session, false, (db) => {
    const itemCols = tableInfo(db, "item");
    const fieldCols = tableInfo(db, "itemfield");

    const insertItemAndFields = db.transaction(() => {
      insertRow(db, "item", {
        uuid,
        title: data.title,
        subtitle: data.username || "",
        category,
        template_type: `${category}.default`,
        note: data.note || "",
        created_at: now,
        updated_at: now,
        meta_updated_at: now,
        favorite: 0,
        archived: 0,
        trashed: 0,
        deleted: 0,
      }, itemCols);

      const fields = [];
      if (data.username) fields.push({ label: "Username", type: "username", value: data.username, sensitive: 0 });
      if (data.password) fields.push({ label: "Password", type: "password", value: data.password, sensitive: 1 });
      if (data.url) fields.push({ label: "Website", type: "url", value: data.url, sensitive: 0 });
      for (const extra of data.fields || []) {
        fields.push({
          label: extra.label,
          type: extra.type || "text",
          value: extra.value,
          sensitive: extra.sensitive ? 1 : 0,
        });
      }

      let order = 1;
      for (const field of fields) {
        insertRow(db, "itemfield", {
          uuid: crypto.randomUUID(),
          item_uuid: uuid,
          label: field.label,
          type: field.type,
          value: field.value,
          sensitive: field.sensitive,
          order: order++,
          deleted: 0,
          updated_at: now,
          value_updated_at: now,
          hash: crypto.createHash("sha1").update(String(field.value)).digest("hex"),
        }, fieldCols);
      }
    });
    insertItemAndFields();
  });

  return { uuid, backupPath };
}

function insertRow(db, table, values, columnInfo) {
  const names = new Set(columnInfo.map((c) => c.name));
  const row = {};
  for (const [key, value] of Object.entries(values)) {
    if (names.has(key)) row[key] = value;
  }
  // Fill any NOT NULL column without a default that we did not set, so the insert
  // does not fail on Enpass schema versions with extra required columns.
  for (const col of columnInfo) {
    if (col.notnull === 1 && col.dflt_value === null && col.pk === 0 && !(col.name in row)) {
      row[col.name] = zeroValueForType(col.type);
    }
  }
  const cols = Object.keys(row);
  if (cols.length === 0) throw new Error(`No matching columns for table ${table}`);
  const placeholders = cols.map(() => "?").join(", ");
  const quoted = cols.map((c) => `"${c}"`).join(", ");
  const params = cols.map((c) => row[c]);
  db.prepare(`INSERT INTO ${table} (${quoted}) VALUES (${placeholders})`).run(params);
}

export function backupVault(vaultPath) {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupPath = `${vaultPath}.backup-${stamp}`;
  fs.copyFileSync(vaultPath, backupPath);
  return backupPath;
}
