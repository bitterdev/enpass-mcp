/* Author: Fabian Bitter (fabian@bitter.de) */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3-multiple-ciphers";
import { totpFieldValue, computeOtp } from "../src/otp.js";
import { unlockParameters, getItem } from "../src/vault.js";
import { editItem } from "../src/edit.js";

const MASTER = "Correct-Horse-Battery-Staple-9";
const fixturesDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures");

function openTempVault() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "enpass-mcp-totp-"));
  const vaultPath = path.join(dir, "vault.enpassdb");
  fs.copyFileSync(path.join(fixturesDir, "fixture-v4.enpassdb"), vaultPath);
  const p = unlockParameters(vaultPath, MASTER, null);
  const db = new Database(vaultPath);
  db.pragma("cipher='sqlcipher'");
  db.pragma(`legacy=${p.compat}`);
  db.pragma(`key="x'${p.hexKey}'"`);
  return { db, session: { path: vaultPath, hexKey: p.hexKey, compat: p.compat } };
}

test("totpFieldValue stores the bare base32 secret like the Enpass app", () => {
  assert.equal(totpFieldValue("jbsw y3dp ehpk 3pxp"), "JBSWY3DPEHPK3PXP");
  assert.equal(totpFieldValue("otpauth://totp/Upwork:a@b.c?secret=JBSWY3DPEHPK3PXP&issuer=Upwork&algorithm=SHA1&digits=6&period=30"), "JBSWY3DPEHPK3PXP");
  const custom = "otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP&digits=8";
  assert.equal(totpFieldValue(custom), custom);
  assert.equal(totpFieldValue(""), "");
  assert.throws(() => totpFieldValue("not a secret!"));
});

test("editItem writes the secret into the built-in totp field so a code renders", () => {
  const { db, session } = openTempVault();
  // Real vaults keep the built-in totp field unencrypted (sensitive=0), the fixture does not.
  db.prepare("UPDATE itemfield SET sensitive=0 WHERE item_uuid='item-1' AND type='totp'").run();
  db.transaction(() => {
    editItem(db, "item-1", {
      addFields: [{ label: "TOTP", value: "otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP" }],
    });
    editItem(db, "item-1", {
      setFields: [{ type: "totp", value: "otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP&issuer=A" }],
      removeFields: ["TOTP"],
    });
  })();
  db.close();
  const fields = getItem(session, "item-1").fields;
  assert.equal(fields.filter((f) => f.label === "TOTP" && f.type !== "totp").length, 0);
  const totp = fields.filter((f) => f.type === "totp");
  assert.equal(totp.length, 1);
  assert.equal(totp[0].value, "JBSWY3DPEHPK3PXP");
  assert.match(computeOtp(totp[0].value, 1700000000000).code, /^\d{6}$/);
});
