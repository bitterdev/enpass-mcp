/* Author: Fabian Bitter (fabian@bitter.de) */
//
// Enpass folder sync, discovered and driven from outside the app.
//
// This is deliberately GENERIC: no hardcoded vault uuids, no hardcoded sync folders, no
// assumption that a vault is synced at all. Fabian's requirement: "das ist eine
// generische Loesung, ein generischer MCP fuer Enpass, der soll nicht nur bei mir
// laufen, sondern ueberall."
//
// Four rules he asked for, each of them a real failure mode:
//   1. Back up the local vault before replacing it on pull. One level is enough and it
//      may be overwritten every time; the point is a way back if a pull goes wrong.
//   2. Only report "remote is newer" once there IS a baseline. A vault that has never
//      synced has sync_last_done_time = 0, and a naive comparison then claims a newer
//      remote on EVERY call and downloads in a loop.
//   3. Do nothing at all for vaults without folder sync. Touching them would break
//      setups that use iCloud, Dropbox, WebDAV or no sync.
//   4. Find the sync folder automatically. Every sync file carries its own vault_uuid in
//      its header, so folders are matched by content, not by name: Fabian's "Primary"
//      vault lives in a folder called "Fabian", so matching on names would fail.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

export const SYNC_HEADER_SIZE = 1024;
const CONTAINER = "vault.enpassdbsync";

const ENPASS_CONTAINER = path.join(
  process.env.HOME || "",
  "Library/Containers/in.sinew.Enpass-Desktop/Data",
);
export const VAULTS_DIR = path.join(ENPASS_CONTAINER, "Documents/Vaults");
export const SYNC_STATE_DIR = path.join(ENPASS_CONTAINER, "Documents/.sync");
const PREFS = path.join(ENPASS_CONTAINER, "Library/Preferences/in.sinew.Enpass-Desktop.plist");

/** Reads the metadata header of a sync container without decrypting anything. */
export function readContainerHeader(file) {
  const fd = fs.openSync(file, "r");
  try {
    const buf = Buffer.alloc(SYNC_HEADER_SIZE);
    fs.readSync(fd, buf, 0, SYNC_HEADER_SIZE, 0);
    const nul = buf.indexOf(0);
    return JSON.parse(buf.subarray(0, nul === -1 ? buf.length : nul).toString("utf8").trim());
  } catch {
    return null;
  } finally {
    fs.closeSync(fd);
  }
}

// Enpass stores every folder the user granted access to as a security-scoped bookmark,
// keyed by its path. Those keys are the only place the sync locations are readable from;
// the settings database itself is encrypted.
function bookmarkedPaths() {
  try {
    const out = execFileSync("/usr/bin/plutil", ["-p", PREFS], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
    const found = new Set();
    for (const m of out.matchAll(/"(\/[^"]+)"\s*=>/g)) found.add(m[1]);
    return [...found];
  } catch {
    return [];
  }
}

/**
 * All vaults with folder sync, matched to their sync folder by the vault_uuid inside the
 * container header. Vaults without folder sync are simply absent from the result, which
 * is what makes rule 3 hold everywhere.
 */
export function discoverSyncedVaults() {
  const candidates = [];
  for (const base of bookmarkedPaths()) {
    for (const dir of [base, path.join(base, "Enpass")]) {
      const file = path.join(dir, CONTAINER);
      if (fs.existsSync(file)) candidates.push({ dir, file });
    }
  }
  const result = [];
  for (const c of candidates) {
    const meta = readContainerHeader(c.file);
    if (!meta || !meta.vault_uuid) continue;
    const vaultDir = path.join(VAULTS_DIR, meta.vault_uuid);
    const syncDir = path.join(SYNC_STATE_DIR, meta.vault_uuid);
    if (!fs.existsSync(vaultDir)) continue; // synced folder for a vault not on this Mac
    result.push({
      uuid: meta.vault_uuid,
      name: meta.vault_name,
      vaultDir,
      syncDir,
      remoteDir: c.dir,
      remoteFile: c.file,
      hasSyncState: fs.existsSync(path.join(syncDir, "syncmeta.db")),
    });
  }
  return result;
}

/** The sync folder of one vault, or null when that vault is not folder-synced. */
export function syncTargetFor(vaultUuid) {
  return discoverSyncedVaults().find((v) => v.uuid === vaultUuid) || null;
}

function lastDone(syncMetaPath, DatabaseCtor) {
  if (!fs.existsSync(syncMetaPath)) return null;
  try {
    const meta = new DatabaseCtor(syncMetaPath, { readonly: true, fileMustExist: true });
    const row = meta.prepare("SELECT value FROM main WHERE key='sync_last_done_time'").get();
    meta.close();
    const n = row ? Number(row.value) : 0;
    return Number.isFinite(n) && n > 0 ? n : null;
  } catch {
    return null;
  }
}

/**
 * Rule 2. Returns {newer, reason} instead of a bare boolean, so a caller can tell "there
 * is genuinely something newer" apart from "there is no baseline to compare against".
 * Without a baseline the answer is NO: pulling then would be guessing, and it would
 * repeat on every single call.
 */
export function remoteStatus(target, DatabaseCtor) {
  if (!target) return { newer: false, reason: "kein Ordner-Abgleich fuer diesen Tresor" };
  if (!fs.existsSync(target.remoteFile)) return { newer: false, reason: "keine Datei im Sync-Ordner" };
  const done = lastDone(path.join(target.syncDir, "syncmeta.db"), DatabaseCtor);
  if (done === null) {
    return { newer: false, reason: "noch nie abgeglichen, kein Vergleichswert, deshalb kein automatisches Holen" };
  }
  const remoteTime = Math.floor(fs.statSync(target.remoteFile).mtimeMs / 1000);
  // One second of slack: the file is written just after the timestamp is recorded.
  if (remoteTime > done + 1) {
    return { newer: true, reason: `entfernte Datei ist ${remoteTime - done}s neuer`, remoteTime, done };
  }
  return { newer: false, reason: "lokaler Stand ist aktuell", remoteTime, done };
}

/**
 * Rule 1. Keeps exactly one previous generation of the vault next to it, overwritten on
 * every call. Cheap, and enough to undo a bad pull.
 */
export function backupVault(vaultDir) {
  const dest = path.join(vaultDir, ".enpass-mcp-previous");
  fs.mkdirSync(dest, { recursive: true });
  for (const name of ["vault.enpassdb", "vault.json"]) {
    const src = path.join(vaultDir, name);
    if (fs.existsSync(src)) fs.copyFileSync(src, path.join(dest, name));
  }
  fs.writeFileSync(path.join(dest, "stamp.txt"), `${new Date().toISOString()}\n`);
  return dest;
}

export function restoreVault(vaultDir) {
  const src = path.join(vaultDir, ".enpass-mcp-previous");
  if (!fs.existsSync(path.join(src, "vault.enpassdb"))) throw new Error("Keine Sicherung vorhanden");
  for (const name of ["vault.enpassdb", "vault.json"]) {
    const f = path.join(src, name);
    if (fs.existsSync(f)) fs.copyFileSync(f, path.join(vaultDir, name));
  }
  return true;
}
