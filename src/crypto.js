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

// --- per-item field encryption ---
//
// On top of SQLCipher, Enpass encrypts every value flagged as "sensitive" a second
// time with a per-item key stored in `item.key`. Fields carrying this second layer
// have `itemfield.algo_version = 1`; older vaults store such values in the clear.
//
// The layout, verified against a live schema-version-6 vault:
//   item.key           44 bytes: 32-byte AES-256 key || 12-byte GCM nonce
//   itemfield.value    hex string: ciphertext || 16-byte GCM auth tag
//   additional data    the item's UUID as raw bytes (hyphens stripped, hex-decoded)
//
// Binding the AAD to the item UUID is what makes a field value unusable if it is
// copied into another item, so the UUID must be passed exactly as stored.
export const FIELD_KEY_LENGTH = 32;
export const FIELD_NONCE_LENGTH = 12;
export const FIELD_TAG_LENGTH = 16;
export const ENCRYPTED_ALGO_VERSION = 1;

// True when a stored value has the shape of a GCM payload (pure hex, whole bytes,
// longer than the auth tag alone). Enpass did not re-encrypt older entries when it
// introduced this layer, so a vault mixes ciphertext and plaintext under the same
// `algo_version = 1`, and the format is the only thing that tells them apart.
export function looksEncrypted(value) {
  if (typeof value !== "string" || value.length === 0) return false;
  if (!/^(?:[0-9a-f]{2})+$/i.test(value)) return false;
  return value.length / 2 > FIELD_TAG_LENGTH;
}

function itemUuidToAad(itemUuid) {
  const compact = String(itemUuid).replace(/-/g, "");
  if (!/^[0-9a-f]{32}$/i.test(compact)) return null;
  return Buffer.from(compact, "hex");
}

// Decrypts one sensitive field value. Returns the plaintext, or null when the value
// cannot be decrypted (unknown algo version, missing/short item key, malformed hex,
// failed authentication). Callers decide how to surface that; never fall back to
// returning the raw ciphertext, which would look like a valid secret.
export function decryptFieldValue(value, itemKey, itemUuid, algoVersion) {
  if (typeof value !== "string" || value.length === 0) return null;
  if (algoVersion !== undefined && algoVersion !== ENCRYPTED_ALGO_VERSION) return null;
  if (!itemKey || itemKey.length < FIELD_KEY_LENGTH + FIELD_NONCE_LENGTH) return null;
  if (!/^(?:[0-9a-f]{2})+$/i.test(value)) return null;

  const aad = itemUuidToAad(itemUuid);
  if (!aad) return null;

  const payload = Buffer.from(value, "hex");
  if (payload.length <= FIELD_TAG_LENGTH) return null;

  try {
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      itemKey.subarray(0, FIELD_KEY_LENGTH),
      itemKey.subarray(FIELD_KEY_LENGTH, FIELD_KEY_LENGTH + FIELD_NONCE_LENGTH),
      { authTagLength: FIELD_TAG_LENGTH },
    );
    decipher.setAAD(aad);
    decipher.setAuthTag(payload.subarray(payload.length - FIELD_TAG_LENGTH));
    const plaintext = Buffer.concat([
      decipher.update(payload.subarray(0, payload.length - FIELD_TAG_LENGTH)),
      decipher.final(),
    ]);
    return plaintext.toString("utf8");
  } catch {
    return null;
  }
}
