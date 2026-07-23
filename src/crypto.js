/* Author: Fabian Bitter (fabian@bitter.de) */

import crypto from "node:crypto";
import fs from "node:fs";

// Enpass derives the SQLCipher raw key with PBKDF2-HMAC-SHA512 from the master
// password (optionally combined with a keyfile) and the 16-byte salt stored at
// the start of the vault file. Enpass 6.x used 100000 iterations; newer vaults
// use 320000. The database itself is a standard SQLCipher database, opened with
// cipher_compatibility 4 (Enpass 6.8+) or 3 (older vaults).
export const SALT_LENGTH = 16;
export const ITERATION_CANDIDATES = [100000, 320000];
export const COMPAT_CANDIDATES = [4, 3];

export function readSalt(vaultPath) {
  const fd = fs.openSync(vaultPath, "r");
  try {
    const salt = Buffer.alloc(SALT_LENGTH);
    fs.readSync(fd, salt, 0, SALT_LENGTH, 0);
    return salt;
  } finally {
    fs.closeSync(fd);
  }
}

// Combines the master password with an optional keyfile the same way Enpass does:
// the keyfile payload (base64 inside <Data>...</Data>, or raw bytes) is
// hex-encoded and appended to the password bytes.
export function buildMasterSecret(password, keyfilePath) {
  const passwordBuffer = Buffer.isBuffer(password)
    ? password
    : Buffer.from(password, "utf8");
  if (!keyfilePath) return passwordBuffer;

  const raw = fs.readFileSync(keyfilePath);
  const text = raw.toString("utf8");
  const match = text.match(/<Data[^>]*>([\s\S]*?)<\/Data>/i);
  const keyBytes = match
    ? Buffer.from(match[1].trim(), "base64")
    : raw;
  return Buffer.concat([passwordBuffer, Buffer.from(keyBytes.toString("hex"), "utf8")]);
}

// Returns the 64-hex-character (256-bit) raw key SQLCipher expects.
export function deriveHexKey(masterSecret, salt, iterations) {
  const secret = Buffer.isBuffer(masterSecret)
    ? masterSecret
    : Buffer.from(masterSecret, "utf8");
  const derived = crypto.pbkdf2Sync(secret, salt, iterations, 64, "sha512");
  return derived.toString("hex").slice(0, 64);
}
