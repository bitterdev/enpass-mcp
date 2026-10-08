/* Author: Fabian Bitter (fabian@bitter.de) */
//
// Writing items into an Enpass vault from outside the app.
//
// The previous attempt concluded this was impossible ("Enpass rejects externally
// inserted items"). That conclusion was wrong. Analysis of a real vault (1291 items,
// 13797 fields, schema version 6) plus the crash report produced three concrete rules,
// and every one of them was broken by the old attempt:
//
//   1. ENPASS NEVER STORES NULL. Not once, in any column, in any of those 13797 rows.
//      The crash report is EXC_BAD_ACCESS in _platform_strlen with a null pointer, i.e.
//      Enpass calls strlen() on a column it assumes is a string. A column left out of
//      the INSERT defaults to NULL in SQLite, and that is what kills the app. Every
//      column is therefore written explicitly, empty strings instead of NULL.
//
//   2. A TEMPLATE HAS A FIXED FIELD SET. login.default always carries the same nine
//      fields in the same order with the same field uids, even when most are empty.
//      Writing only the fields one happens to have a value for produces an item the app
//      cannot render. The full set is written, empty ones included.
//
//   3. THE PER-ITEM KEY IS REPRODUCIBLE. item.key is a 32-byte AES-256 key followed by
//      a 12-byte GCM nonce; the value is hex(ciphertext || 16-byte tag) with the item
//      UUID (hyphens stripped, hex-decoded) as additional authenticated data. Nothing
//      in it is tied to Enpass internals, so a fresh random key per item is fine.
//      Verified by a round trip: written, read back, decrypted to the original.
//
// vault.json next to the database carries vault_items_count / vault_att_count /
// last_modified_time and is updated too, so the counters stay consistent with the data.
import crypto from "node:crypto";
import Database from "better-sqlite3-multiple-ciphers";
import fs from "node:fs";
import path from "node:path";

export const KEY_LENGTH = 32;
export const NONCE_LENGTH = 12;
export const TAG_LENGTH = 16;
export const ALGO_VERSION = 1;

// The field sets Enpass itself writes, taken from real items. `uid` and `orde` are what
// the app uses; keeping them identical is what makes an item render correctly.
export const TEMPLATES = {
  "login.default": {
    category: "login",
    icon: '{"fav":"","image":{"file":"misc/login"},"type":1,"uuid":""}',
    fields: [
      { uid: 10, orde: 1, type: "username", sensitive: 0 },
      { uid: 12, orde: 2, type: "email", sensitive: 0 },
      { uid: 11, orde: 3, type: "password", sensitive: 1 },
      { uid: 13, orde: 4, type: "url", sensitive: 0 },
      { uid: 101, orde: 5, type: "section", sensitive: 0 },
      { uid: 14, orde: 6, type: "phone", sensitive: 0 },
      { uid: 102, orde: 7, type: "totp", sensitive: 0 },
      { uid: 15, orde: 8, type: "text", sensitive: 0 },
      { uid: 16, orde: 9, type: "text", sensitive: 1 },
    ],
  },
};

export function encryptFieldValue(plaintext, itemKey, itemUuid) {
  const aad = Buffer.from(String(itemUuid).replace(/-/g, ""), "hex");
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    itemKey.subarray(0, KEY_LENGTH),
    itemKey.subarray(KEY_LENGTH, KEY_LENGTH + NONCE_LENGTH),
    { authTagLength: TAG_LENGTH },
  );
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(String(plaintext), "utf8")),
    cipher.final(),
  ]);
  return Buffer.concat([ciphertext, cipher.getAuthTag()]).toString("hex");
}

// Custom fields get high uids like the app does. Collisions inside one item would break
// the UNIQUE(item_uuid,item_field_uid) constraint, so already-used ids are skipped.
function nextCustomUid(used) {
  let uid;
  do {
    uid = 1000 + crypto.randomInt(9000);
  } while (used.has(uid));
  used.add(uid);
  return uid;
}

/**
 * Inserts one item. `values` maps a template field type to its value
 * (e.g. {username, password, url}); `custom` is a list of {label, value, sensitive, type}
 * for anything the template does not cover, such as an SMTP host and port.
 * The caller owns the transaction and the vault.json update via finalizeVault().
 */
export function insertItem(db, { title, subtitle = "", note = "", template = "login.default", values = {}, custom = [] }) {
  const tpl = TEMPLATES[template];
  if (!tpl) throw new Error(`Unknown template: ${template}`);

  const now = Math.floor(Date.now() / 1000);
  const uuid = crypto.randomUUID();
  const itemKey = crypto.randomBytes(KEY_LENGTH + NONCE_LENGTH);

  db.prepare(`
    INSERT INTO item (uuid,created_at,meta_updated_at,field_updated_at,title,subtitle,note,
      icon,favorite,trashed,archived,deleted,auto_submit,form_data,category,template,
      wearable,usage_count,last_used,key,extra,updated_at)
    VALUES (@uuid,@created_at,@meta_updated_at,@field_updated_at,@title,@subtitle,@note,
      @icon,0,0,0,0,1,'',@category,@template,0,0,0,@key,'',@updated_at)`).run({
    uuid, created_at: now, meta_updated_at: now, field_updated_at: now,
    title, subtitle, note, icon: tpl.icon, category: tpl.category, template,
    key: itemKey, updated_at: now,
  });

  const insertField = db.prepare(`
    INSERT INTO itemfield (item_uuid,item_field_uid,label,value,deleted,sensitive,historical,
      type,form_id,updated_at,value_updated_at,orde,wearable,history,initial,hash,strength,
      algo_version,expiry,excluded,pwned_check_time,extra,non_compliant_check_time,non_compliant)
    VALUES (@item_uuid,@uid,@label,@value,0,@sensitive,1,@type,'',@now,@now,@orde,0,'','','',
      -1,@algo,0,0,0,'',0,0)`);

  const used = new Set();
  // Rule 2: the whole template, empty fields included.
  for (const f of tpl.fields) {
    used.add(f.uid);
    const raw = values[f.type] ?? "";
    insertField.run({
      item_uuid: uuid, uid: f.uid, label: "",
      value: raw === "" ? "" : f.sensitive ? encryptFieldValue(raw, itemKey, uuid) : String(raw),
      sensitive: f.sensitive, type: f.type, now, orde: f.orde, algo: ALGO_VERSION,
    });
  }
  // Custom fields, e.g. SMTP host and port, appended after the template fields.
  custom.forEach((c, i) => {
    const sensitive = c.sensitive ? 1 : 0;
    insertField.run({
      item_uuid: uuid, uid: nextCustomUid(used), label: c.label ?? "",
      value: c.value === undefined || c.value === "" ? ""
        : sensitive ? encryptFieldValue(c.value, itemKey, uuid) : String(c.value),
      sensitive, type: c.type || (sensitive ? "password" : "text"),
      now, orde: tpl.fields.length + i + 1, algo: ALGO_VERSION,
    });
  });

  return uuid;
}

// Keeps vault.json in step with the database. Enpass compares these counters.
export function finalizeVault(db, vaultPath) {
  const items = db.prepare("SELECT count(*) c FROM item WHERE deleted=0 AND trashed=0").get().c;
  const atts = db.prepare("SELECT count(*) c FROM attachment WHERE deleted=0").get().c;
  const jsonPath = path.join(path.dirname(vaultPath), "vault.json");
  const meta = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
  meta.vault_items_count = items;
  meta.vault_att_count = atts;
  meta.last_modified_time = Math.floor(Date.now() / 1000);
  meta.last_modified_by_user = "local";
  fs.writeFileSync(jsonPath, JSON.stringify(meta, null, 4) + "\n");
  return { items, atts };
}

// --- deleting ---------------------------------------------------------------
//
// Enpass does not remove a deleted item's row, it leaves a tombstone so the other
// machine learns about the deletion on the next sync instead of resurrecting the entry.
// Verified against 3 permanently deleted items in a real vault: the item row stays with
// deleted=1, trashed=0, its itemfield rows are REMOVED entirely, and icon and key are
// emptied. Trash is a different state: deleted=1 AND trashed=1.
export function deleteItem(db, uuid, { toTrash = false } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const item = db.prepare("SELECT uuid FROM item WHERE uuid=?").get(uuid);
  if (!item) throw new Error(`No item with uuid ${uuid}`);

  if (toTrash) {
    db.prepare(`UPDATE item SET deleted=1, trashed=1, meta_updated_at=@now, updated_at=@now WHERE uuid=@uuid`)
      .run({ uuid, now });
    return { uuid, mode: "trash" };
  }
  db.prepare("DELETE FROM itemfield WHERE item_uuid=?").run(uuid);
  db.prepare(`
    UPDATE item SET deleted=1, trashed=0, icon='', key=x'',
      meta_updated_at=@now, field_updated_at=@now, updated_at=@now
    WHERE uuid=@uuid`).run({ uuid, now });
  // These carry per-item state that must not outlive the item.
  db.prepare("DELETE FROM identical_passwords WHERE item_uuid=?").run(uuid);
  db.prepare("DELETE FROM folder_items WHERE item_uuid=?").run(uuid);
  return { uuid, mode: "delete" };
}

// --- folder sync ------------------------------------------------------------
//
// Fabian's requirement, and he was right to insist: writing into the database alone is
// not enough. Enpass tracks what it has synced, and a vault whose sync state still says
// "unchanged since yesterday" gets OVERWRITTEN by the remote copy on the next sync,
// silently losing everything written from outside.
//
// He also spotted the flaw in the easy answer: setting a dirty flag only helps if Enpass
// is running, and it is not (writing requires it to be closed) and its GUI cannot be
// driven reliably. So the sync file is written here directly.
//
// The container format, derived from a real sync file:
//   bytes 0..N     the vault.json metadata as JSON
//   bytes N..1024  zero padding
//   bytes 1024..   the vault.enpassdb file, byte for byte unchanged
// The local copy under .sync/<vault>/folder.enpassdbsync and the one in the sync folder
// are identical, so the same bytes are written to both.
import { createHash } from "node:crypto";
import { backupVault } from "./foldersync.js";

export const SYNC_HEADER_SIZE = 1024;

// Attachments do NOT travel inside the container. Enpass keeps every file larger than a
// kilobyte in its own "<attachment uuid>.enpassattach" database and drops those files
// into the sync folder next to the container, verified on the real sync folders: the
// container is always exactly the vault database plus the 1024-byte header, while the
// .enpassattach files sit beside it.
//
// That makes the two sync directions dangerous for attachments if they only move the
// database: a pull would install rows pointing at files that never arrived, and a push
// would publish rows the other machine cannot resolve. Both look exactly like "the
// attachments are broken" while every byte in the vault is fine.
//
// Only MISSING files are copied, in both directions. An .enpassattach file is named
// after the attachment uuid and is never rewritten in place (editing an attachment
// creates a new uuid), so filling gaps is safe and overwriting would not be.
function copyMissingAttachments(fromDir, toDir) {
  if (!fs.existsSync(fromDir) || !fs.existsSync(toDir)) return [];
  const copied = [];
  for (const name of fs.readdirSync(fromDir)) {
    if (!name.endsWith(".enpassattach")) continue;
    const dest = path.join(toDir, name);
    if (fs.existsSync(dest)) continue;
    fs.copyFileSync(path.join(fromDir, name), dest);
    copied.push(name);
  }
  return copied;
}

// --- writing attachments ---------------------------------------------------
//
// Enpass stores an attachment's bytes RAW inside its own encrypted database, one row,
// and keeps the key for that file as a finished SQLCipher key expression in the vault's
// attachment.password column. Two mistakes were made here before and both look like a
// corrupted file to the user, so they are spelled out:
//
//   1. Storing a data-URI ("data:;base64,<payload>") instead of the bytes. Enpass hands
//      such a payload out verbatim, so every export is a text file with a .pdf name.
//      On 2026-07-30 that affected 74 attachments across the vaults and had to be
//      repaired with scripts/repair-data-uri-attachments.mjs.
//   2. Hex-encoding the key expression again. It is already ASCII and must be passed
//      through unchanged, otherwise SQLCipher answers "file is not a database".
//
// The reference shape was taken from a working attachment: inner table
// attachment(ID PRIMARY KEY CHECK (ID=1), uuid TEXT UNIQUE, data blob), cipher
// compatibility 3, and a 48-byte random key rendered as x'<96 hex>'.
const ATTACHMENT_KEY_BYTES = 48; // 32 byte key + 16 byte salt, as Enpass does it

function attachmentKeyExpression() {
  return `x'${crypto.randomBytes(ATTACHMENT_KEY_BYTES).toString("hex")}'`;
}

// Guesses the media type from the file name. Enpass fills this column, and a missing
// value is what made the app fall back to handing out the raw payload.
function mediaTypeFor(name) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  const types = {
    pdf: "application/pdf", jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png",
    gif: "image/gif", txt: "text/plain", json: "application/json", zip: "application/zip",
    p12: "application/x-pkcs12", pfx: "application/x-pkcs12", pem: "application/x-pem-file",
    cer: "application/x-x509-ca-cert", key: "application/octet-stream",
  };
  return types[ext] || "application/octet-stream";
}

// Writes one attachment for an existing item. `content` must be the RAW bytes; a
// data-URI is rejected rather than stored, because storing it is exactly the bug above.
export function addAttachment(db, vaultPath, itemUuid, name, content) {
  if (!Buffer.isBuffer(content)) throw new Error("content must be a Buffer of raw bytes");
  if (content.length === 0) throw new Error("refusing to store an empty attachment");
  if (content.subarray(0, 5).toString("latin1") === "data:") {
    throw new Error(
      "content looks like a data-URI. Decode it first and pass the raw bytes, " +
      "otherwise Enpass hands the text out as the file.");
  }
  const item = db.prepare("SELECT uuid FROM item WHERE uuid=? AND deleted=0").get(itemUuid);
  if (!item) throw new Error(`No item with uuid ${itemUuid}`);

  const uuid = crypto.randomUUID();
  const keyExpression = attachmentKeyExpression();
  const file = path.join(path.dirname(vaultPath), `${uuid}.enpassattach`);
  if (fs.existsSync(file)) throw new Error(`attachment file already exists: ${file}`);

  // The inner database mirrors the structure Enpass itself creates.
  const inner = new Database(file);
  try {
    inner.pragma("cipher='sqlcipher'");
    inner.pragma("legacy=3");
    inner.pragma(`key="${keyExpression}"`);
    inner.exec(
      "CREATE TABLE attachment(ID INTEGER PRIMARY KEY AUTOINCREMENT CHECK (ID=1)," +
      "uuid TEXT UNIQUE NOT NULL,data blob,UNIQUE (uuid) ON CONFLICT REPLACE)");
    inner.prepare("INSERT INTO attachment (ID,uuid,data) VALUES (1,?,?)").run(uuid, content);
  } catch (err) {
    inner.close();
    fs.rmSync(file, { force: true });
    throw err;
  }
  inner.close();

  // The column set of `attachment` differs between vault generations (older ones have
  // no `orde`, `internal` or `extra`, and carry a `kind` instead). So the row is built
  // from the columns this vault really has. Every one of them gets an explicit value:
  // Enpass never stores NULL anywhere and crashes on a NULL it expected to be a string.
  const now = Math.floor(Date.now() / 1000);
  const available = new Set(db.prepare("PRAGMA table_info(attachment)").all().map((c) => c.name));
  const candidates = {
    uuid,
    item_uuid: itemUuid,
    name,
    size: content.length,
    mime: mediaTypeFor(name),
    kind: mediaTypeFor(name),
    updated_at: now,
    created_at: now,
    deleted: 0,
    internal: 0,
    extra: "",
    password: Buffer.from(keyExpression, "latin1"),
    data: Buffer.alloc(0),
  };
  if (available.has("orde")) {
    candidates.orde = (db
      .prepare("SELECT COALESCE(MAX(orde),0) o FROM attachment WHERE item_uuid=?")
      .get(itemUuid).o) + 1;
  }
  const columns = Object.keys(candidates).filter((c) => available.has(c));
  const missing = [...available].filter((c) => !columns.includes(c) && c !== "ID");
  if (missing.length) {
    throw new Error(
      `Unknown columns in this vault's attachment table: ${missing.join(", ")}. ` +
      "Refusing to insert a row with NULLs in them.");
  }
  db.prepare(
    `INSERT INTO attachment (${columns.join(",")}) VALUES (${columns.map((c) => `@${c}`).join(",")})`,
  ).run(Object.fromEntries(columns.map((c) => [c, candidates[c]])));

  return { uuid, name, size: content.length, file };
}

export function buildSyncContainer(vaultJsonPath, vaultDbPath) {
  const meta = fs.readFileSync(vaultJsonPath);
  if (meta.length >= SYNC_HEADER_SIZE) throw new Error("vault.json larger than the sync header");
  const header = Buffer.alloc(SYNC_HEADER_SIZE, 0);
  meta.copy(header, 0);
  return Buffer.concat([header, fs.readFileSync(vaultDbPath)]);
}

/**
 * Publishes a locally written vault so Enpass and the other machine pick it up.
 * `syncDir` is the vault's folder under Documents/.sync/<uuid>, `remoteDir` the folder
 * Enpass syncs against (may be null when the drive is not mounted).
 */
export function pushSync(vaultDir, syncDir, remoteDir) {
  const vaultDb = path.join(vaultDir, "vault.enpassdb");
  const vaultJson = path.join(vaultDir, "vault.json");
  const container = buildSyncContainer(vaultJson, vaultDb);
  const now = Math.floor(Date.now() / 1000);
  const written = [];

  if (fs.existsSync(syncDir)) {
    // folder.enpassdb is the plain database, the other two are the container.
    fs.writeFileSync(path.join(syncDir, "folder.enpassdb"), fs.readFileSync(vaultDb));
    fs.writeFileSync(path.join(syncDir, "folder.enpassdbsync"), container);
    fs.writeFileSync(path.join(syncDir, "folder.enpassdbupload"), container);
    fs.copyFileSync(vaultJson, path.join(syncDir, "folder.json"));
    written.push("lokale Sync-Kopie");
  }
  let attachments = [];
  if (remoteDir && fs.existsSync(remoteDir)) {
    fs.writeFileSync(path.join(remoteDir, "vault.enpassdbsync"), container);
    written.push("Sync-Ordner");
    attachments = copyMissingAttachments(vaultDir, remoteDir);
  }
  return {
    now, written, attachments,
    size: container.length,
    sha256: createHash("sha256").update(container).digest("hex").slice(0, 16),
  };
}

/**
 * Tells Enpass the vault changed. `revision` and `sync_last_done_time` are kept equal to
 * the timestamp actually published, which is the state Enpass leaves behind after its
 * own successful sync (verified across all 8 vaults).
 */
export function markSynced(syncMetaPath, DatabaseCtor, timestamp) {
  const meta = new DatabaseCtor(syncMetaPath, { fileMustExist: true });
  const set = meta.prepare("INSERT INTO main(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");
  set.run("revision", String(timestamp));
  set.run("sync_last_done_time", String(timestamp));
  set.run("sync_vault_dirty", "0");
  meta.close();
}

/** Is the copy in the sync folder newer than what we last took in? */
export function remoteIsNewer(syncMetaPath, DatabaseCtor, remoteDir) {
  const remote = path.join(remoteDir, "vault.enpassdbsync");
  if (!fs.existsSync(remote)) return false;
  const meta = new DatabaseCtor(syncMetaPath, { readonly: true, fileMustExist: true });
  const row = meta.prepare("SELECT value FROM main WHERE key='sync_last_done_time'").get();
  meta.close();
  const done = row ? Number(row.value) : 0;
  return Math.floor(fs.statSync(remote).mtimeMs / 1000) > done + 1;
}

/**
 * Takes in a newer copy from the sync folder, the direction Fabian asked for after he
 * edited a vault on his MacBook: reading locally must notice the remote change first
 * instead of silently serving a stale vault.
 *
 * The container is split back into its two parts: the 1024-byte header holds the
 * vault.json metadata, everything after it is the database verbatim. Both are written,
 * so vault.json's counters keep matching the data.
 *
 * The caller must have quit Enpass and taken a backup; this replaces the local vault.
 */
export function pullSync(vaultDir, syncDir, remoteDir, DatabaseCtor) {
  const remoteFile = path.join(remoteDir, "vault.enpassdbsync");
  if (!fs.existsSync(remoteFile)) throw new Error(`No sync file at ${remoteFile}`);
  // Rule 1 (Fabian): keep one generation back before the local vault is replaced.
  backupVault(vaultDir);
  const container = fs.readFileSync(remoteFile);
  if (container.length <= SYNC_HEADER_SIZE) throw new Error("Sync file too small to hold a vault");

  const header = container.subarray(0, SYNC_HEADER_SIZE);
  const nul = header.indexOf(0);
  const metaText = header.subarray(0, nul === -1 ? header.length : nul).toString("utf8").trim();
  const meta = JSON.parse(metaText); // throws early if the header is not what we expect
  const payload = container.subarray(SYNC_HEADER_SIZE);

  fs.writeFileSync(path.join(vaultDir, "vault.enpassdb"), payload);
  fs.writeFileSync(path.join(vaultDir, "vault.json"), metaText + "\n");
  // The incoming database may reference attachments this machine has never seen.
  const attachments = copyMissingAttachments(remoteDir, vaultDir);

  if (fs.existsSync(syncDir)) {
    fs.writeFileSync(path.join(syncDir, "folder.enpassdb"), payload);
    fs.writeFileSync(path.join(syncDir, "folder.enpassdbsync"), container);
    fs.writeFileSync(path.join(syncDir, "folder.enpassdbupload"), container);
    fs.writeFileSync(path.join(syncDir, "folder.json"), metaText + "\n");
  }

  // Record the remote file's own timestamp, not "now": that is the revision both sides
  // must agree on, otherwise the next comparison thinks we are ahead of the remote.
  const stamp = Math.floor(fs.statSync(remoteFile).mtimeMs / 1000);
  markSynced(path.join(syncDir, "syncmeta.db"), DatabaseCtor, stamp);
  return { stamp, items: meta.vault_items_count, size: payload.length, vaultName: meta.vault_name, attachments };
}
