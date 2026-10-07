/* Author: Fabian Bitter (fabian@bitter.de) */
//
// Changing and moving existing items in place.
//
// Until now an item could only be created or deleted, so renaming meant re-creating it,
// which loses the uuid, the password history and the exact field types (a TOTP field
// written back as text no longer produces codes). These functions keep everything:
//
//   editItem  changes title, subtitle and note on the item row and rewrites or removes
//             url fields. Removing a field is done the way Enpass does it: the row stays
//             with deleted=1 (measured: 1259 such url rows in a real vault).
//   moveItem  copies the item row, every itemfield row, the attachment rows and their
//             external .enpassattach files and the item's passkeys BYTE FOR BYTE into
//             another vault, uuid and item key included, so every encrypted value and the
//             per-field history stay decryptable. Only after the copy was read back and
//             compared is the source turned into a tombstone via deleteItem.
//             (password_history is the generator's log, not per item, and stays put.)
//
// Same rules as write.js: never NULL, Enpass closed, caller owns finalizeVault and sync.
import fs from "node:fs";
import path from "node:path";
import { deleteItem } from "./write.js";

const TEMPLATE_URL_UID = 13;

function columns(db, table) {
  return db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
}

function hasTable(db, name) {
  return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(name);
}

/**
 * `changes`: { title?, subtitle?, note?, appendNote?, urls? }
 * `urls` is the complete list of url values the item should end up with, in order.
 * Existing url rows are reused (the template row first), surplus rows are marked deleted.
 */
export function editItem(db, uuid, changes) {
  const now = Math.floor(Date.now() / 1000);
  const item = db.prepare("SELECT uuid,title,subtitle,note FROM item WHERE uuid=? AND deleted=0").get(uuid);
  if (!item) throw new Error(`No active item with uuid ${uuid}`);

  const itemCols = columns(db, "item");
  const set = {};
  if (changes.title !== undefined) {
    if (!String(changes.title).trim()) throw new Error("title must not be empty");
    set.title = String(changes.title);
  }
  if (changes.subtitle !== undefined) set.subtitle = String(changes.subtitle ?? "");
  if (changes.note !== undefined) set.note = String(changes.note ?? "");
  if (changes.appendNote) {
    const base = set.note ?? item.note ?? "";
    set.note = base ? `${base}\n\n${changes.appendNote}` : String(changes.appendNote);
  }
  if (Object.keys(set).length) {
    const assign = Object.keys(set).map((k) => `${k}=@${k}`).join(",");
    const stamps = ["meta_updated_at", "updated_at"].filter((c) => itemCols.includes(c)).map((c) => `, ${c}=@now`).join("");
    db.prepare(`UPDATE item SET ${assign}${stamps} WHERE uuid=@uuid`).run({ ...set, now, uuid });
  }

  let urlChange = null;
  if (Array.isArray(changes.urls)) {
    const fieldCols = columns(db, "itemfield");
    const uidCol = fieldCols.includes("item_field_uid") ? "item_field_uid" : "NULL AS item_field_uid";
    const ordCol = fieldCols.includes("orde") ? "orde" : fieldCols.includes("order") ? '"order"' : "rowid";
    const rows = db.prepare(
      `SELECT rowid AS rid,${uidCol},value,${ordCol} AS ord FROM itemfield WHERE item_uuid=? AND type='url' AND deleted=0 ORDER BY ord`,
    ).all(uuid);
    rows.sort((a, b) => (b.item_field_uid === TEMPLATE_URL_UID) - (a.item_field_uid === TEMPLATE_URL_UID) || a.ord - b.ord);
    const wanted = changes.urls.map(String);
    if (wanted.length > rows.length) throw new Error("editItem cannot add url fields, only keep, rewrite or remove");
    const stamp = fieldCols.includes("value_updated_at") ? ", value_updated_at=@now" : "";
    const rewrite = db.prepare(`UPDATE itemfield SET value=@value, updated_at=@now${stamp} WHERE rowid=@rid`);
    const remove = db.prepare("UPDATE itemfield SET deleted=1, updated_at=@now WHERE rowid=@rid");
    let rewritten = 0;
    let removed = 0;
    rows.forEach((r, i) => {
      if (i < wanted.length) {
        if (r.value !== wanted[i]) { rewrite.run({ value: wanted[i], now, rid: r.rid }); rewritten++; }
      } else if (r.item_field_uid === TEMPLATE_URL_UID) {
        // The template row must stay present (rule 2 in write.js), so it is emptied.
        rewrite.run({ value: "", now, rid: r.rid }); removed++;
      } else {
        remove.run({ now, rid: r.rid }); removed++;
      }
    });
    const itemStamps = ["field_updated_at", "updated_at"].filter((c) => itemCols.includes(c));
    if ((rewritten || removed) && itemStamps.length) {
      db.prepare(`UPDATE item SET ${itemStamps.map((c) => `${c}=@now`).join(",")} WHERE uuid=@uuid`).run({ now, uuid });
    }
    urlChange = { before: rows.map((r) => r.value), after: wanted, rewritten, removed };
  }
  return { uuid, changed: Object.keys(set), urls: urlChange };
}

// Copies all rows of `table` whose `key` column equals `uuid`, leaving out the
// autoincrement ID. Fails when the target table lacks a column the source has,
// because dropping it would silently lose data.
function copyRows(src, dst, table, key, uuid) {
  if (!hasTable(src, table)) return 0;
  const rows = src.prepare(`SELECT * FROM ${table} WHERE ${key}=? ORDER BY rowid`).all(uuid);
  if (!rows.length) return 0;
  if (!hasTable(dst, table)) throw new Error(`target vault has no table ${table}`);
  const srcCols = columns(src, table).filter((c) => c !== "ID");
  const dstCols = new Set(columns(dst, table));
  const missing = srcCols.filter((c) => !dstCols.has(c));
  if (missing.length) throw new Error(`target ${table} lacks columns ${missing.join(", ")}`);
  const extra = [...dstCols].filter((c) => c !== "ID" && !srcCols.includes(c));
  if (extra.length) throw new Error(`target ${table} has columns the source lacks: ${extra.join(", ")}`);
  const ins = dst.prepare(`INSERT INTO ${table} (${srcCols.map((c) => `"${c}"`).join(",")}) VALUES (${srcCols.map((c) => `@${c}`).join(",")})`);
  for (const r of rows) ins.run(Object.fromEntries(srcCols.map((c) => [c, r[c]])));
  return rows.length;
}

function snapshot(db, uuid) {
  const strip = (r) => { const { ID, ...rest } = r; return rest; };
  const by = (t, k) => (hasTable(db, t) ? db.prepare(`SELECT * FROM ${t} WHERE ${k}=? ORDER BY rowid`).all(uuid).map(strip) : []);
  return {
    item: by("item", "uuid"),
    fields: by("itemfield", "item_uuid"),
    attachments: by("attachment", "item_uuid"),
    passkeys: by("passkeys", "item_uuid"),
  };
}

// Compares as multisets: SQLite returns rows in index order unless told otherwise,
// so the same content may come back in a different order from the other vault.
function sameRows(a, b) {
  const norm = (rows) => rows.map((r) => JSON.stringify(
    Object.fromEntries(Object.entries(r).map(([k, v]) => [k, Buffer.isBuffer(v) ? `hex:${v.toString("hex")}` : v])))).sort();
  return JSON.stringify(norm(a)) === JSON.stringify(norm(b));
}

/**
 * Moves one item from `src` (vault file `srcPath`) to `dst` (vault file `dstPath`).
 * `changes` are applied with editItem in the target after the verified copy.
 * Returns what was copied; throws, and leaves the source untouched, on any mismatch.
 */
export function moveItem(src, srcPath, dst, dstPath, uuid, changes = null) {
  const before = snapshot(src, uuid);
  if (!before.item.length || before.item[0].deleted) throw new Error(`No active item ${uuid} in source`);
  if (dst.prepare("SELECT 1 FROM item WHERE uuid=?").get(uuid)) {
    throw new Error(`uuid ${uuid} already exists in the target vault (also as tombstone)`);
  }

  const srcDir = path.dirname(srcPath);
  const dstDir = path.dirname(dstPath);
  const files = [];
  for (const a of before.attachments) {
    const f = `${a.uuid}.enpassattach`;
    if (fs.existsSync(path.join(srcDir, f))) {
      if (fs.existsSync(path.join(dstDir, f))) throw new Error(`attachment file ${f} already in target`);
      files.push(f);
    }
  }

  // Copy and verification run in one target transaction, so a mismatch rolls the
  // target back and removes the copied attachment files: nothing is left half moved.
  let copied;
  const written = [];
  try {
    dst.transaction(() => {
      copied = {
        item: copyRows(src, dst, "item", "uuid", uuid),
        fields: copyRows(src, dst, "itemfield", "item_uuid", uuid),
        attachments: copyRows(src, dst, "attachment", "item_uuid", uuid),
        passkeys: copyRows(src, dst, "passkeys", "item_uuid", uuid),
      };
      for (const f of files) {
        fs.copyFileSync(path.join(srcDir, f), path.join(dstDir, f));
        written.push(f);
      }
      const after = snapshot(dst, uuid);
      for (const k of Object.keys(before)) {
        if (!sameRows(before[k], after[k])) throw new Error(`verification failed for ${k} of ${uuid}; nothing moved`);
      }
      for (const f of files) {
        if (!fs.readFileSync(path.join(srcDir, f)).equals(fs.readFileSync(path.join(dstDir, f)))) {
          throw new Error(`attachment file ${f} differs after copy; nothing moved`);
        }
      }
    })();
  } catch (err) {
    for (const f of written) fs.rmSync(path.join(dstDir, f), { force: true });
    throw err;
  }

  let edited = null;
  if (changes) dst.transaction(() => { edited = editItem(dst, uuid, changes); })();
  src.transaction(() => { deleteItem(src, uuid); })();
  return { uuid, copied, attachmentFiles: files, edited };
}
