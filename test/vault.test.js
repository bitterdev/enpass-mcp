/* Author: Fabian Bitter (fabian@bitter.de) */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import Database from "better-sqlite3-multiple-ciphers";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  unlockParameters,
  listItems,
  getItem,
  listAttachments,
  readAttachment,
} from "../src/vault.js";
import { createServer } from "../src/server.js";
import { computeOtp } from "../src/otp.js";

// The fixtures are genuine SQLCipher databases in the Enpass vault format
// (cipher_compatibility 4 and 3, PBKDF2-HMAC-SHA512, 100000 iterations),
// generated with real SQLCipher. See test/fixtures/README.md.
const MASTER = "Correct-Horse-Battery-Staple-9";
const fixturesDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures");

// Copies a fixture (and any external .enpassattach files) to a temp dir so write
// tests never mutate the committed vault.
function tempVault(fixture) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "enpass-mcp-test-"));
  const dest = path.join(dir, "vault.enpassdb");
  fs.copyFileSync(path.join(fixturesDir, fixture), dest);
  for (const f of fs.readdirSync(fixturesDir)) {
    if (f.endsWith(".enpassattach")) {
      fs.copyFileSync(path.join(fixturesDir, f), path.join(dir, f));
    }
  }
  return dest;
}

function unlock(vaultPath) {
  const params = unlockParameters(vaultPath, MASTER, null);
  return { session: { path: vaultPath, hexKey: params.hexKey, compat: params.compat }, params };
}

test("unlock derives the correct raw key and rejects wrong passwords", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { params } = unlock(vaultPath);
  assert.equal(params.compat, 4);
  assert.equal(params.iterations, 100000);
  assert.equal(params.hexKey.length, 64);

  assert.throws(() => unlockParameters(vaultPath, "wrong-password", null), /Unlock failed/);
});

test("unlock auto-detects older cipher_compatibility 3 vaults", () => {
  const vaultPath = tempVault("fixture-v3.enpassdb");
  const { params } = unlock(vaultPath);
  assert.equal(params.compat, 3);
});

test("list_items returns every entry type without exposing secrets", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);

  const items = listItems(session, {});
  assert.equal(items.length, 5);
  const titles = items.map((i) => i.title).sort();
  assert.deepEqual(titles, ["Bank", "GitHub", "Mail Bridge", "Server Notes", "Visa Card"]);

  const github = items.find((i) => i.title === "GitHub");
  assert.equal(github.username, "octocat");
  assert.equal(github.url, "https://github.com");

  const dump = JSON.stringify(items);
  for (const secret of ["s3cr3t-token", "9999", "4111111111111111", "REC-KEY-XYZ"]) {
    assert.equal(dump.includes(secret), false, `list_items must not leak ${secret}`);
  }

  assert.equal(listItems(session, { query: "hub" }).length, 1);
  assert.equal(listItems(session, { query: "nonexistent" }).length, 0);
  assert.equal(listItems(session, { category: "finance" }).length, 1);
  assert.equal(listItems(session, { category: "creditcard" }).length, 1);
  assert.equal(listItems(session, { category: "note" }).length, 1);
  assert.equal(listItems(session, { folder: "Work" }).length, 1);
});

test("get_item reads all field types across entry categories", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);

  const card = getItem(session, "item-3");
  assert.equal(card.category, "creditcard");
  const number = card.fields.find((f) => f.type === "ccNumber");
  assert.equal(number.value, "4111111111111111");
  assert.equal(number.sensitive, true);
  assert.equal(card.fields.find((f) => f.label === "Expiry").value, "12/28");

  const note = getItem(session, "item-4");
  assert.equal(note.category, "note");
  assert.equal(note.note, "root password rotation schedule");
  assert.equal(note.fields.find((f) => f.type === "password").value, "REC-KEY-XYZ");
});

test("get_item returns the password and TOTP values", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);

  const item = getItem(session, "item-1");
  const password = item.fields.find((f) => f.type === "password");
  assert.equal(password.value, "s3cr3t-token");
  assert.equal(password.sensitive, true);
  assert.ok(item.fields.find((f) => f.type === "totp").value.startsWith("otpauth://"));
});

test("computes TOTP one-time codes from a stored secret", () => {
  // Deterministic at a fixed timestamp; matches any standard authenticator app.
  const fromUri = computeOtp(
    "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
    0,
  );
  assert.equal(fromUri.code, "282760");
  assert.equal(fromUri.period, 30);
  assert.equal(fromUri.secondsRemaining, 30);

  const fromBareSecret = computeOtp("JBSWY3DPEHPK3PXP", 0);
  assert.equal(fromBareSecret.code, "282760");

  assert.equal(computeOtp("!!!not-base32!!!", 0), null);
  assert.equal(computeOtp(null), null);
});

test("get_otp end via vault fields on the fixture entry", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);
  const item = getItem(session, "item-1");
  const otpField = item.fields.find((f) => f.type === "totp");
  const otp = computeOtp(otpField.value, 0);
  assert.equal(otp.code, "282760");
});

test("get_item surfaces attachment metadata", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);
  const item = getItem(session, "item-1");
  assert.equal(item.attachments.length, 2);
  assert.ok(item.attachments.some((a) => a.name === "note.txt"));
  assert.ok(item.attachments.some((a) => a.name === "photo.bin"));
});

test("list_attachments and read inline attachment", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);

  const attachments = listAttachments(session, "item-1");
  assert.equal(attachments.length, 2);

  const inline = readAttachment(session, "item-1", "note.txt");
  assert.equal(inline.mime, "text/plain");
  assert.equal(inline.buffer.toString("utf8"), "hello inline attachment");
});

test("read external .enpassattach attachment with per-file key", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);

  const external = readAttachment(session, "item-1", "photo.bin");
  assert.equal(external.size, 4096);
  assert.equal(external.buffer.length, 4096);
  assert.equal(external.buffer[0], 0xab);
  assert.equal(external.buffer[4095], 0xab);
});

test("external attachments also work on compat-3 vaults", () => {
  const vaultPath = tempVault("fixture-v3.enpassdb");
  const { session } = unlock(vaultPath);
  const external = readAttachment(session, "item-1", "photo.bin");
  assert.equal(external.buffer.length, 4096);
});

// --- the write switch ---

const WRITING_TOOLS = ["create_item", "delete_item", "sync_pull"];

function toolNames() {
  return Object.keys(createServer()._registeredTools ?? {});
}

function withAllowWrites(value, fn) {
  const previous = process.env.ENPASS_MCP_ALLOW_WRITES;
  if (value === undefined) delete process.env.ENPASS_MCP_ALLOW_WRITES;
  else process.env.ENPASS_MCP_ALLOW_WRITES = value;
  try {
    return fn();
  } finally {
    if (previous === undefined) delete process.env.ENPASS_MCP_ALLOW_WRITES;
    else process.env.ENPASS_MCP_ALLOW_WRITES = previous;
  }
}

test("without the switch the writing tools are not advertised at all", () => {
  const names = withAllowWrites(undefined, toolNames);
  for (const tool of WRITING_TOOLS) assert.ok(!names.includes(tool), `${tool} must stay hidden`);
  assert.ok(names.includes("get_password"), "reading stays available");
});

test("ENPASS_MCP_ALLOW_WRITES turns the writing tools on", () => {
  const names = withAllowWrites("1", toolNames);
  for (const tool of WRITING_TOOLS) assert.ok(names.includes(tool), `${tool} must be offered`);
});

test("only an explicit yes counts as enabled", () => {
  for (const value of ["", "0", "false", "no", "maybe"]) {
    const names = withAllowWrites(value, toolNames);
    assert.ok(!names.includes("create_item"), `"${value}" must not enable writing`);
  }
  for (const value of ["1", "true", "yes", "on", "TRUE", " Yes "]) {
    const names = withAllowWrites(value, toolNames);
    assert.ok(names.includes("create_item"), `"${value}" must enable writing`);
  }
});

// --- per-item field encryption (itemfield.algo_version = 1) ---

const ENCRYPTED_ITEM = "3f2b7c10-4d5e-4a8b-9c1d-2e3f4a5b6c7d";

function fieldByLabel(item, label) {
  return item.fields.find((f) => f.label === label);
}

test("sensitive fields encrypted with the per-item key are decrypted", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);

  const item = getItem(session, ENCRYPTED_ITEM);
  const password = fieldByLabel(item, "Password (IMAP)");
  assert.equal(password.value, "6sxNl3vgohOqRtgY6L0DMA");
  assert.equal(password.sensitive, true);
  assert.equal(password.decryptionFailed, undefined);
});

test("encrypted values are never returned as raw ciphertext", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);

  for (const f of getItem(session, ENCRYPTED_ITEM).fields) {
    if (!f.value) continue;
    assert.ok(
      !/^(?:[0-9a-f]{2}){17,}$/i.test(f.value),
      `field "${f.label}" still looks like hex ciphertext: ${f.value}`,
    );
  }
});

test("plaintext values left unmigrated under algo_version 1 are passed through", () => {
  // Enpass did not re-encrypt older entries when it introduced the per-item layer,
  // so a vault mixes ciphertext and plaintext under the same algo_version.
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);

  const licence = fieldByLabel(getItem(session, ENCRYPTED_ITEM), "Licence");
  assert.equal(licence.value, "MG-8NZ2W-TQPQT-H5BR1");
  assert.equal(licence.decryptionFailed, undefined);
});

test("an encrypted TOTP secret still yields a one-time code", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);

  const totp = fieldByLabel(getItem(session, ENCRYPTED_ITEM), "TOTP");
  const otp = computeOtp(totp.value, 1700000000000);
  assert.ok(otp, "expected a code from the decrypted otpauth:// secret");
  assert.match(otp.code, /^\d{6}$/);
});

test("per-item encryption also works on compat-3 vaults", () => {
  const vaultPath = tempVault("fixture-v3.enpassdb");
  const { session } = unlock(vaultPath);
  const password = fieldByLabel(getItem(session, ENCRYPTED_ITEM), "Password (IMAP)");
  assert.equal(password.value, "6sxNl3vgohOqRtgY6L0DMA");
});

test("entries without the encryption layer keep working", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);
  const password = getItem(session, "item-1").fields.find((f) => f.type === "password");
  assert.equal(password.value, "s3cr3t-token");
});

test("a value that cannot be decrypted is reported, not returned raw", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);

  // Corrupt the stored ciphertext so authentication fails.
  const params = unlockParameters(vaultPath, MASTER, null);
  const db = new Database(vaultPath, { fileMustExist: true });
  db.pragma("cipher='sqlcipher'");
  db.pragma(`legacy=${params.compat}`);
  db.pragma(`key="x'${params.hexKey}'"`);
  const row = db.prepare("SELECT value FROM itemfield WHERE uuid = 'f13'").get();
  const flipped = `${row.value.slice(0, -2)}${row.value.slice(-2) === "00" ? "01" : "00"}`;
  db.prepare("UPDATE itemfield SET value = ? WHERE uuid = 'f13'").run(flipped);
  db.close();

  const password = fieldByLabel(getItem(session, ENCRYPTED_ITEM), "Password (IMAP)");
  assert.equal(password.value, null);
  assert.equal(password.decryptionFailed, true);
});
