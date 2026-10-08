/* Author: Fabian Bitter (fabian@bitter.de) */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3-multiple-ciphers";
import { unlockParameters, getItem, readAttachment } from "../src/vault.js";
import { editItem, moveItem } from "../src/edit.js";

const MASTER = "Correct-Horse-Battery-Staple-9";
const fixturesDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures");

function tempVault() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "enpass-mcp-edit-"));
  const dest = path.join(dir, "vault.enpassdb");
  fs.copyFileSync(path.join(fixturesDir, "fixture-v4.enpassdb"), dest);
  for (const f of fs.readdirSync(fixturesDir)) {
    if (f.endsWith(".enpassattach")) fs.copyFileSync(path.join(fixturesDir, f), path.join(dir, f));
  }
  return dest;
}

function openVault(vaultPath) {
  const p = unlockParameters(vaultPath, MASTER, null);
  const db = new Database(vaultPath);
  db.pragma("cipher='sqlcipher'");
  db.pragma(`legacy=${p.compat}`);
  db.pragma(`key="x'${p.hexKey}'"`);
  return { db, session: { path: vaultPath, hexKey: p.hexKey, compat: p.compat } };
}

test("editItem renames in place and keeps uuid, field types and secrets", () => {
  const vaultPath = tempVault();
  const { db, session } = openVault(vaultPath);
  const before = getItem(session, "item-1");
  db.transaction(() => editItem(db, "item-1", { title: "GitHub Fabian", appendNote: "Konto octocat" }))();
  db.close();
  const after = getItem(session, "item-1");
  assert.equal(after.uuid, "item-1");
  assert.equal(after.title, "GitHub Fabian");
  assert.ok(after.note.endsWith("Konto octocat"));
  assert.deepEqual(after.fields, before.fields);
  assert.equal(after.attachments.length, before.attachments.length);
});

test("editItem removes surplus url fields as deleted rows", () => {
  const vaultPath = tempVault();
  const { db, session } = openVault(vaultPath);
  const urls = getItem(session, "item-1").fields.filter((f) => f.type === "url").map((f) => f.value);
  // Give the item a duplicate url the way the real vaults have them.
  const tpl = db.prepare("SELECT * FROM itemfield WHERE item_uuid='item-1' AND type='url' LIMIT 1").get();
  const { ID, ...row } = tpl;
  if ("uuid" in row) row.uuid = "dup-url-field";
  if ("item_field_uid" in row) row.item_field_uid = 4711;
  if ("orde" in row) row.orde = 99;
  if ("order" in row) row.order = 99;
  const cols = Object.keys(row);
  db.prepare(`INSERT INTO itemfield (${cols.map((c) => `"${c}"`).join(",")}) VALUES (${cols.map((c) => `@${c}`).join(",")})`).run(row);
  assert.equal(getItem(session, "item-1").fields.filter((f) => f.type === "url").length, urls.length + 1);

  const res = editItem(db, "item-1", { urls });
  db.close();
  assert.equal(res.urls.removed, 1);
  const left = getItem(session, "item-1").fields.filter((f) => f.type === "url").map((f) => f.value);
  assert.deepEqual(left, urls);
});

test("moveItem copies everything byte for byte and tombstones the source", () => {
  const srcPath = tempVault();
  const dstPath = tempVault();
  const a = openVault(srcPath);
  const b = openVault(dstPath);
  // The fixture predates columns and tables deleteItem touches in real vaults.
  for (const v of [a, b]) {
    v.db.exec("ALTER TABLE item ADD COLUMN icon TEXT NOT NULL DEFAULT ''");
    v.db.exec("ALTER TABLE item ADD COLUMN field_updated_at INTEGER NOT NULL DEFAULT 0");
    v.db.exec("CREATE TABLE identical_passwords (item_uuid TEXT)");
    v.db.exec("CREATE TABLE folder_items (item_uuid TEXT)");
  }
  // The target is a copy of the same fixture; drop the item there so the uuid is free.
  for (const [t, k] of [["itemfield", "item_uuid"], ["attachment", "item_uuid"], ["item", "uuid"]]) {
    b.db.prepare(`DELETE FROM ${t} WHERE ${k}='item-1'`).run();
  }
  for (const f of fs.readdirSync(path.dirname(dstPath))) {
    if (f.endsWith(".enpassattach")) fs.rmSync(path.join(path.dirname(dstPath), f));
  }
  const before = getItem(a.session, "item-1");
  const totp = before.fields.find((f) => f.type === "totp").value;
  const photo = readAttachment(a.session, "item-1", "photo.bin").buffer;

  const res = moveItem(a.db, srcPath, b.db, dstPath, "item-1", { title: "GitHub verschoben" });
  a.db.close();
  b.db.close();

  assert.ok(res.copied.fields > 0);
  const moved = getItem(b.session, "item-1");
  assert.equal(moved.title, "GitHub verschoben");
  assert.deepEqual(moved.fields, before.fields);
  assert.equal(moved.fields.find((f) => f.type === "totp").value, totp);
  assert.equal(moved.attachments.length, before.attachments.length);
  assert.ok(readAttachment(b.session, "item-1", "photo.bin").buffer.equals(photo));

  const check = openVault(srcPath);
  const tomb = check.db.prepare("SELECT deleted FROM item WHERE uuid='item-1'").get();
  check.db.close();
  assert.equal(tomb.deleted, 1);
});

test("moveItem refuses when the uuid already exists in the target", () => {
  const a = openVault(tempVault());
  const dstPath = tempVault();
  const b = openVault(dstPath);
  assert.throws(() => moveItem(a.db, a.session.path, b.db, dstPath, "item-1"), /already exists/);
  a.db.close();
  b.db.close();
});

test("editItem clears a field and appends labelled custom fields", () => {
  const vaultPath = tempVault();
  const { db, session } = openVault(vaultPath);
  const before = getItem(session, "item-1");
  const user = before.fields.find((f) => f.type === "username");
  assert.ok(user && user.value);
  const res = editItem(db, "item-1", {
    setFields: [{ type: "username", value: "" }],
    addFields: [{ label: "Region", value: "eu-central-1" }],
  });
  db.close();
  assert.equal(res.fields.length, 2);
  const after = getItem(session, "item-1");
  assert.equal(after.fields.find((f) => f.type === "username").value, "");
  assert.equal(after.fields.find((f) => f.label === "Region").value, "eu-central-1");
  assert.equal(after.fields.length, before.fields.length + 1);
  const pw = (it) => it.fields.find((f) => f.type === "password");
  assert.deepEqual(pw(after), pw(before));
});

test("editItem removes a custom field by label and never a template field", () => {
  const vaultPath = tempVault();
  const { db, session } = openVault(vaultPath);
  const before = getItem(session, "item-1");
  editItem(db, "item-1", { addFields: [{ label: "Ticket", value: "X-1" }] });
  const res = editItem(db, "item-1", { removeFields: ["Ticket"] });
  assert.deepEqual(res.fields, [{ removed: "Ticket", count: 1 }]);
  assert.throws(() => editItem(db, "item-1", { removeFields: ["Ticket"] }), /no active custom field/);
  db.close();
  const after = getItem(session, "item-1");
  assert.ok(!after.fields.some((f) => f.label === "Ticket"));
  assert.equal(after.fields.length, before.fields.length);
});
