/* Author: Fabian Bitter (fabian@bitter.de) */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  unlockParameters,
  listItems,
  getItem,
  createItem,
  listAttachments,
  readAttachment,
} from "../src/vault.js";
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
  assert.equal(items.length, 4);
  const titles = items.map((i) => i.title).sort();
  assert.deepEqual(titles, ["Bank", "GitHub", "Server Notes", "Visa Card"]);

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

test("create_item writes a new entry and backs up the vault", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);
  const before = listItems(session, {}).length;

  const result = createItem(session, {
    title: "GitLab",
    username: "octo",
    password: "new-pass-123",
    url: "https://gitlab.com",
    category: "login",
  });
  assert.ok(result.uuid);
  assert.ok(fs.existsSync(result.backupPath));

  const created = getItem(session, result.uuid);
  assert.equal(created.title, "GitLab");
  assert.equal(created.fields.find((f) => f.type === "password").value, "new-pass-123");
  assert.equal(listItems(session, {}).length, before + 1);
});

test("create_item saves non-login types with sensitive custom fields", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);

  const card = createItem(session, {
    title: "Amex",
    category: "creditcard",
    note: "backup card",
    fields: [
      { label: "Cardholder", value: "Jane Doe", type: "text", sensitive: false },
      { label: "Card Number", value: "378282246310005", type: "ccNumber", sensitive: true },
      { label: "CVC", value: "1234", type: "ccCvc", sensitive: true },
    ],
  });

  const readBack = getItem(session, card.uuid);
  assert.equal(readBack.category, "creditcard");
  assert.equal(readBack.note, "backup card");
  const number = readBack.fields.find((f) => f.label === "Card Number");
  assert.equal(number.value, "378282246310005");
  assert.equal(number.type, "ccNumber");
  assert.equal(number.sensitive, true);
  const holder = readBack.fields.find((f) => f.label === "Cardholder");
  assert.equal(holder.sensitive, false);

  // persisted to disk: a fresh unlock still sees it
  const reopened = unlock(vaultPath);
  assert.ok(getItem(reopened.session, card.uuid));
});
