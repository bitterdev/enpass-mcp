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
} from "../src/vault.js";

// The fixtures are genuine SQLCipher databases in the Enpass vault format
// (cipher_compatibility 4 and 3, PBKDF2-HMAC-SHA512, 100000 iterations),
// generated with real SQLCipher. See test/fixtures/README.md.
const MASTER = "Correct-Horse-Battery-Staple-9";
const fixturesDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures");

// Copies a fixture to a temp file so write tests never mutate the committed vault.
function tempVault(fixture) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "enpass-mcp-test-"));
  const dest = path.join(dir, "vault.enpassdb");
  fs.copyFileSync(path.join(fixturesDir, fixture), dest);
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

test("list_items returns entries without exposing secrets", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);

  const items = listItems(session, {});
  assert.equal(items.length, 2);
  const github = items.find((i) => i.title === "GitHub");
  assert.equal(github.username, "octocat");
  assert.equal(github.url, "https://github.com");
  assert.equal(JSON.stringify(items).includes("s3cr3t-token"), false);
  assert.equal(JSON.stringify(items).includes("9999"), false);

  assert.equal(listItems(session, { query: "hub" }).length, 1);
  assert.equal(listItems(session, { query: "nonexistent" }).length, 0);
  assert.equal(listItems(session, { category: "finance" }).length, 1);
  assert.equal(listItems(session, { folder: "Work" }).length, 1);
});

test("get_item returns the password and TOTP values", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);

  const item = getItem(session, "item-1");
  const password = item.fields.find((f) => f.type === "password");
  assert.equal(password.value, "s3cr3t-token");
  assert.equal(password.sensitive, true);
  assert.equal(item.fields.find((f) => f.type === "totp").value, "otpauth://totp/demo");
});

test("create_item writes a new entry and backs up the vault", () => {
  const vaultPath = tempVault("fixture-v4.enpassdb");
  const { session } = unlock(vaultPath);

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
  assert.equal(listItems(session, {}).length, 3);
});
