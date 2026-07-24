/* Author: Fabian Bitter (fabian@bitter.de) */

// Generates genuine SQLCipher test fixtures in the Enpass vault format, using real
// SQLCipher (@journeyapps/sqlcipher). This is the "create a vault, create entries
// and attachments" step: it builds vaults for cipher_compatibility 4 and 3, seeds
// entries, an inline attachment and an external ".enpassattach" attachment, and
// verifies each vault can be reopened. Run it locally or in CI to (re)build the
// fixtures the read-side tests run against.
//
//   node scripts/generate-fixtures.mjs [outputDir]

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import sqlite3pkg from "@journeyapps/sqlcipher";

const sqlite3 = sqlite3pkg.verbose();
export const MASTER = "Correct-Horse-Battery-Staple-9";
const ITERATIONS = 100000;
const EXTERNAL_ATTACHMENT_ID = "att-ext-1";
const EXTERNAL_PAYLOAD = Buffer.alloc(4096, 0xab); // > 1 KB, deterministic

const run = (db, sql) => new Promise((res, rej) => db.run(sql, (e) => (e ? rej(e) : res())));
const runP = (db, sql, params) => new Promise((res, rej) => db.run(sql, params, (e) => (e ? rej(e) : res())));
const get = (db, sql) => new Promise((res, rej) => db.get(sql, (e, r) => (e ? rej(e) : res(r))));
const close = (db) => new Promise((res, rej) => db.close((e) => (e ? rej(e) : res())));

function deriveHexKey(password, salt, iterations) {
  return crypto.pbkdf2Sync(Buffer.from(password, "utf8"), salt, iterations, 64, "sha512").toString("hex").slice(0, 64);
}

// Item whose sensitive fields carry Enpass's per-item encryption layer
// (`item.key`, `itemfield.algo_version = 1`). Its uuid must be a real hex uuid
// because the item uuid doubles as the AAD.
export const ENCRYPTED_ITEM_UUID = "3f2b7c10-4d5e-4a8b-9c1d-2e3f4a5b6c7d";
// 32-byte AES key || 12-byte GCM nonce, exactly as Enpass stores it in item.key.
export const ENCRYPTED_ITEM_KEY = Buffer.from(
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + "a0a1a2a3a4a5a6a7a8a9aaab",
  "hex",
);
export const ENCRYPTED_PASSWORD = "6sxNl3vgohOqRtgY6L0DMA";
export const LEGACY_PLAINTEXT_LICENCE = "MG-8NZ2W-TQPQT-H5BR1";

// Mirrors what Enpass writes: AES-256-GCM over the value, keyed by item.key, with
// the item uuid (hyphens stripped) as additional authenticated data, stored as
// hex(ciphertext || tag).
function encryptFieldValue(plaintext, itemKey, itemUuid) {
  const cipher = crypto.createCipheriv("aes-256-gcm", itemKey.subarray(0, 32), itemKey.subarray(32, 44), {
    authTagLength: 16,
  });
  cipher.setAAD(Buffer.from(itemUuid.replace(/-/g, ""), "hex"));
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([ct, cipher.getAuthTag()]).toString("hex");
}

async function seed(db, externalKeyHex) {
  await run(db, `CREATE TABLE item(uuid TEXT PRIMARY KEY,title TEXT,subtitle TEXT,category TEXT,note TEXT,template_type TEXT,created_at INTEGER,updated_at INTEGER,meta_updated_at INTEGER,favorite INTEGER,archived INTEGER,trashed INTEGER,deleted INTEGER,key BLOB)`);
  await run(db, `CREATE TABLE itemfield(uuid TEXT,item_uuid TEXT,label TEXT,type TEXT,value TEXT,sensitive INTEGER,"order" INTEGER,deleted INTEGER,updated_at INTEGER,value_updated_at INTEGER,hash TEXT,algo_version INTEGER)`);
  await run(db, `CREATE TABLE folder(uuid TEXT PRIMARY KEY,title TEXT,updated_at INTEGER,parent_uuid TEXT)`);
  await run(db, `CREATE TABLE folder_item(folder_uuid TEXT,item_uuid TEXT)`);
  await run(db, `CREATE TABLE attachment(uuid TEXT PRIMARY KEY,item_uuid TEXT,name TEXT,size INTEGER,mime TEXT,kind TEXT,password BLOB,data BLOB,updated_at INTEGER,deleted INTEGER)`);

  await run(db, `INSERT INTO item(uuid,title,subtitle,category,note,template_type,trashed,deleted,favorite) VALUES('item-1','GitHub','octocat','login','my main account','login.default',0,0,1)`);
  await run(db, `INSERT INTO itemfield(uuid,item_uuid,label,type,value,sensitive,"order",deleted) VALUES('f1','item-1','Username','username','octocat',0,1,0)`);
  await run(db, `INSERT INTO itemfield(uuid,item_uuid,label,type,value,sensitive,"order",deleted) VALUES('f2','item-1','Password','password','s3cr3t-token',1,2,0)`);
  await run(db, `INSERT INTO itemfield(uuid,item_uuid,label,type,value,sensitive,"order",deleted) VALUES('f3','item-1','Website','url','https://github.com',0,3,0)`);
  await run(db, `INSERT INTO itemfield(uuid,item_uuid,label,type,value,sensitive,"order",deleted) VALUES('f4','item-1','TOTP','totp','otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=30&digits=6',1,4,0)`);
  await run(db, `INSERT INTO item(uuid,title,subtitle,category,note,template_type,trashed,deleted,favorite) VALUES('item-2','Bank','12345','finance','','finance.default',0,0,0)`);
  await run(db, `INSERT INTO itemfield(uuid,item_uuid,label,type,value,sensitive,"order",deleted) VALUES('f5','item-2','PIN','password','9999',1,1,0)`);

  // Credit card entry (non-login type with sensitive fields)
  await run(db, `INSERT INTO item(uuid,title,subtitle,category,note,template_type,trashed,deleted,favorite) VALUES('item-3','Visa Card','John Doe','creditcard','','creditcard.default',0,0,0)`);
  await run(db, `INSERT INTO itemfield(uuid,item_uuid,label,type,value,sensitive,"order",deleted) VALUES('f6','item-3','Cardholder','text','John Doe',0,1,0)`);
  await run(db, `INSERT INTO itemfield(uuid,item_uuid,label,type,value,sensitive,"order",deleted) VALUES('f7','item-3','Card Number','ccNumber','4111111111111111',1,2,0)`);
  await run(db, `INSERT INTO itemfield(uuid,item_uuid,label,type,value,sensitive,"order",deleted) VALUES('f8','item-3','CVC','ccCvc','123',1,3,0)`);
  await run(db, `INSERT INTO itemfield(uuid,item_uuid,label,type,value,sensitive,"order",deleted) VALUES('f9','item-3','Expiry','ccExpiry','12/28',0,4,0)`);

  // Secure note entry (note plus a hidden custom field)
  await run(db, `INSERT INTO item(uuid,title,subtitle,category,note,template_type,trashed,deleted,favorite) VALUES('item-4','Server Notes','','note','root password rotation schedule','note.default',0,0,0)`);
  await run(db, `INSERT INTO itemfield(uuid,item_uuid,label,type,value,sensitive,"order",deleted) VALUES('f10','item-4','Recovery Key','password','REC-KEY-XYZ',1,1,0)`);

  // Entry using the per-item encryption layer. It also carries an empty built-in
  // password field ahead of the real, labelled ones (the shape Enpass produces for a
  // login whose credentials live in custom fields) and one legacy value that Enpass
  // left in plaintext when it introduced the layer.
  const enc = (v) => encryptFieldValue(v, ENCRYPTED_ITEM_KEY, ENCRYPTED_ITEM_UUID);
  await runP(
    db,
    `INSERT INTO item(uuid,title,subtitle,category,note,template_type,trashed,deleted,favorite,key) VALUES(?,?,?,?,?,?,0,0,0,?)`,
    [ENCRYPTED_ITEM_UUID, "Mail Bridge", "127.0.0.1", "login", "", "login.default", ENCRYPTED_ITEM_KEY],
  );
  await run(db, `INSERT INTO itemfield(uuid,item_uuid,label,type,value,sensitive,"order",deleted,algo_version) VALUES('f11','${ENCRYPTED_ITEM_UUID}','','password','',1,1,0,1)`);
  await run(db, `INSERT INTO itemfield(uuid,item_uuid,label,type,value,sensitive,"order",deleted,algo_version) VALUES('f12','${ENCRYPTED_ITEM_UUID}','Username (IMAP)','username','fabian@example.com',0,2,0,1)`);
  await run(db, `INSERT INTO itemfield(uuid,item_uuid,label,type,value,sensitive,"order",deleted,algo_version) VALUES('f13','${ENCRYPTED_ITEM_UUID}','Password (IMAP)','password','${enc(ENCRYPTED_PASSWORD)}',1,3,0,1)`);
  await run(db, `INSERT INTO itemfield(uuid,item_uuid,label,type,value,sensitive,"order",deleted,algo_version) VALUES('f14','${ENCRYPTED_ITEM_UUID}','TOTP','totp','${enc("otpauth://totp/Bridge:fabian?secret=JBSWY3DPEHPK3PXP&issuer=Bridge&period=30&digits=6")}',1,4,0,1)`);
  await run(db, `INSERT INTO itemfield(uuid,item_uuid,label,type,value,sensitive,"order",deleted,algo_version) VALUES('f15','${ENCRYPTED_ITEM_UUID}','Licence','text','${LEGACY_PLAINTEXT_LICENCE}',1,5,0,1)`);

  await run(db, `INSERT INTO folder(uuid,title) VALUES('fold-1','Work')`);
  await run(db, `INSERT INTO folder_item(folder_uuid,item_uuid) VALUES('fold-1','item-1')`);

  // Inline attachment (<= 1 KB): data stored directly in the vault
  const inlineData = Buffer.from("hello inline attachment", "utf8");
  await runP(db, `INSERT INTO attachment(uuid,item_uuid,name,size,mime,kind,password,data,deleted) VALUES(?,?,?,?,?,?,?,?,0)`,
    ["att-inline-1", "item-1", "note.txt", inlineData.length, "text/plain", "inline", null, inlineData]);

  // External attachment (> 1 KB): only the per-file key is stored here; bytes live
  // in <uuid>.enpassattach encrypted with that key.
  await runP(db, `INSERT INTO attachment(uuid,item_uuid,name,size,mime,kind,password,data,deleted) VALUES(?,?,?,?,?,?,?,?,0)`,
    [EXTERNAL_ATTACHMENT_ID, "item-1", "photo.bin", EXTERNAL_PAYLOAD.length, "application/octet-stream", "external", Buffer.from(externalKeyHex, "hex"), null]);
}

async function buildV4(vaultPath, externalKeyHex) {
  fs.rmSync(vaultPath, { force: true });
  const db = new sqlite3.Database(vaultPath);
  await new Promise((r) => db.serialize(r));
  await run(db, `PRAGMA key='${MASTER}'`);
  await run(db, `PRAGMA cipher_compatibility=4`);
  await run(db, `PRAGMA kdf_iter=${ITERATIONS}`);
  await seed(db, externalKeyHex);
  await close(db);
}

// Enpass compat-3 vaults use SQLCipher-3 cipher settings but a SHA512-derived raw
// key. Create with a temp raw key, then rekey to the Enpass-style key (real
// SQLCipher preserves the header salt on rekey).
async function buildV3(vaultPath, externalKeyHex) {
  fs.rmSync(vaultPath, { force: true });
  const temp = crypto.randomBytes(32).toString("hex");
  let db = new sqlite3.Database(vaultPath);
  await new Promise((r) => db.serialize(r));
  await run(db, `PRAGMA key="x'${temp}'"`);
  await run(db, `PRAGMA cipher_compatibility=3`);
  await seed(db, externalKeyHex);
  await close(db);

  const salt = fs.readFileSync(vaultPath).slice(0, 16);
  const target = deriveHexKey(MASTER, salt, ITERATIONS);
  db = new sqlite3.Database(vaultPath);
  await new Promise((r) => db.serialize(r));
  await run(db, `PRAGMA key="x'${temp}'"`);
  await run(db, `PRAGMA cipher_compatibility=3`);
  await run(db, `PRAGMA rekey="x'${target}'"`);
  await close(db);
}

async function buildExternalAttachment(filePath, keyHex, payload) {
  fs.rmSync(filePath, { force: true });
  const db = new sqlite3.Database(filePath);
  await new Promise((r) => db.serialize(r));
  await run(db, `PRAGMA key="x'${keyHex}'"`);
  await run(db, `PRAGMA cipher_compatibility=4`);
  await run(db, `CREATE TABLE attachment_data(data BLOB)`);
  await runP(db, `INSERT INTO attachment_data(data) VALUES(?)`, [payload]);
  await close(db);
}

async function verify(vaultPath, compat) {
  const salt = fs.readFileSync(vaultPath).slice(0, 16);
  const hexKey = deriveHexKey(MASTER, salt, ITERATIONS);
  const db = new sqlite3.Database(vaultPath, sqlite3.OPEN_READONLY);
  await new Promise((r) => db.serialize(r));
  await run(db, `PRAGMA key="x'${hexKey}'"`);
  await run(db, `PRAGMA cipher_compatibility=${compat}`);
  const row = await get(db, `SELECT count(*) AS c FROM item`);
  await close(db);
  if (!row || row.c < 2) throw new Error(`Verification failed for ${vaultPath}`);
}

async function main() {
  const outDir = process.argv[2]
    ? path.resolve(process.argv[2])
    : path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "test", "fixtures");
  fs.mkdirSync(outDir, { recursive: true });

  const externalKeyHex = crypto.randomBytes(32).toString("hex");
  const v4 = path.join(outDir, "fixture-v4.enpassdb");
  const v3 = path.join(outDir, "fixture-v3.enpassdb");
  const ext = path.join(outDir, `${EXTERNAL_ATTACHMENT_ID}.enpassattach`);

  await buildV4(v4, externalKeyHex);
  await buildV3(v3, externalKeyHex);
  await buildExternalAttachment(ext, externalKeyHex, EXTERNAL_PAYLOAD);

  await verify(v4, 4);
  await verify(v3, 3);

  process.stdout.write(`Fixtures written to ${outDir}:\n  ${path.basename(v4)}\n  ${path.basename(v3)}\n  ${path.basename(ext)}\n`);
}

main().catch((err) => {
  process.stderr.write(`${err.stack || err.message}\n`);
  process.exit(1);
});
