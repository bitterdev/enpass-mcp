/* Author: Fabian Bitter (fabian@bitter.de) */

// Repairs attachments that were stored as a data-URI text blob instead of raw bytes.
//
// Background, measured on 2026-07-30: most attachments in these vaults hold
// "data:;base64,<payload>" as their stored data. That form carries NO media type, and
// the Enpass app hands it out verbatim, so every export is a text file with a .pdf or
// .jpeg name that no viewer opens. Two files exported from the app by hand confirmed
// it: a .jpeg and a .pdf attachment were both plain text whose base64
// body decoded to a perfectly valid JPEG and PDF.
//
// The reference for the correct form is a .pdf attachment in the primary vault: it is
// stored RAW, and it is the one attachment that exports correctly. So this script
// rewrites the others into that same shape.
//
// What it changes, and nothing else:
//   - inner ".enpassattach" database: attachment.data gets the decoded raw bytes
//   - outer vault: attachment.size gets the new byte length, to match the reference
// Timestamps are deliberately left alone so the sync state is not disturbed.
//
// Safety: --dry-run by default, refuses to run while Enpass is open, verifies the
// decoded payload against the file signature its name implies, and re-reads every
// patched attachment afterwards to prove it comes back as a real file.
//
// --- why the local repair alone is not enough (measured 2026-07-30) -----------
//
// The attachment bytes do NOT live in the sync container. Every external attachment is
// its own ".enpassattach" file, and folder sync keeps a second copy of each of those
// files in the shared sync folder. Repairing the vault under the Enpass container
// therefore fixes THIS machine only: the shared folder keeps the data-URI copies, and
// every other device keeps reading those. Proven on 2026-07-30: the container in the
// shared folder had been rewritten by the second Mac at 10:40 and still declared
// size=1795049 for that .pdf attachment, the data-URI length, while this machine's
// repaired vault declares the raw 1346276.
//
// So `--sync-folders` repairs the copies in the shared folder as well. It never trusts
// its own decoding there: a remote payload is only rewritten when the decoded bytes are
// byte for byte the payload this machine already holds, so the shared folder can only
// ever converge on the verified local state.

import Database from "better-sqlite3-multiple-ciphers";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { unlockParameters } from "../src/vault.js";
import { getVault, getSecret, listVaults } from "../src/config.js";
import { discoverSyncedVaults } from "../src/foldersync.js";

const sha256 = (buffer) => crypto.createHash("sha256").update(buffer).digest("hex");

const SIGNATURES = {
  pdf: [0x25, 0x50, 0x44, 0x46],
  jpg: [0xff, 0xd8, 0xff],
  jpeg: [0xff, 0xd8, 0xff],
  png: [0x89, 0x50, 0x4e, 0x47],
  gif: [0x47, 0x49, 0x46, 0x38],
  zip: [0x50, 0x4b, 0x03, 0x04],
  docx: [0x50, 0x4b, 0x03, 0x04],
  xlsx: [0x50, 0x4b, 0x03, 0x04],
  // JKS starts feedfeed, PKCS#12 starts with an ASN.1 SEQUENCE. Both are valid
  // keystores, so this entry lists alternatives rather than one fixed signature.
  keystore: [[0xfe, 0xed, 0xfe, 0xed], [0x30, 0x82]],
  p12: [[0x30, 0x82]],
  pfx: [[0x30, 0x82]],
};

function enpassRunning() {
  try {
    execFileSync("pgrep", ["-x", "Enpass"], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

function openVaultDb(file, hexKey, compat, readonly) {
  const db = new Database(file, { readonly, fileMustExist: true });
  db.pragma("cipher='sqlcipher'");
  db.pragma(`legacy=${compat}`);
  db.pragma(`key="x'${hexKey}'"`);
  return db;
}

// The per-attachment key is stored as the finished SQLCipher key expression in ASCII,
// e.g. x'<64 hex key><32 hex salt>'. It must be passed through unchanged.
function openAttachmentDb(file, password, readonly) {
  const expression = Buffer.isBuffer(password) ? password.toString("latin1") : String(password ?? "");
  const db = new Database(file, { readonly, fileMustExist: true });
  db.pragma("cipher='sqlcipher'");
  db.pragma("legacy=3");
  db.pragma(`key="${expression}"`);
  return db;
}

function decodeDataUri(buffer) {
  const text = buffer.toString("latin1");
  if (!text.startsWith("data:")) return null;
  const comma = text.indexOf(",");
  if (comma < 0) return null;
  const header = text.slice(5, comma);
  if (!/base64/i.test(header)) return null;
  const decoded = Buffer.from(text.slice(comma + 1), "base64");
  return decoded.length > 0 ? { decoded, mediaType: header.split(";")[0] } : null;
}

function signatureMatches(name, buffer) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  const expected = SIGNATURES[ext];
  if (!expected) return null; // unknown type, cannot judge either way
  const alternatives = Array.isArray(expected[0]) ? expected : [expected];
  return alternatives.some((sig) => sig.every((byte, i) => buffer[i] === byte));
}

function collect(vaultName) {
  const entry = getVault(vaultName);
  const params = unlockParameters(entry.path, getSecret(vaultName), entry.keyfile);
  return { entry, params };
}

async function processVault(vaultName, apply, report) {
  let entry, params;
  try {
    ({ entry, params } = collect(vaultName));
    params = await params;
  } catch (err) {
    report.skipped.push(`${vaultName}: ${err.message}`);
    return;
  }
  const dir = path.dirname(entry.path);
  const db = openVaultDb(entry.path, params.hexKey, params.compat, !apply);
  const hasTable = db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='attachment'").get();
  if (!hasTable) {
    db.close();
    return;
  }

  for (const row of db.prepare("SELECT uuid,name,size,data,password FROM attachment WHERE deleted=0").all()) {
    const external = !row.data || row.data.length === 0;
    const file = path.join(dir, `${row.uuid}.enpassattach`);
    if (external && !fs.existsSync(file)) {
      report.problems.push(`${vaultName} / ${row.name}: Datei fehlt`);
      continue;
    }

    let stored, innerDb = null;
    if (external) {
      try {
        innerDb = openAttachmentDb(file, row.password, !apply);
        const rows = innerDb.prepare("SELECT ID,data FROM attachment ORDER BY ID").all();
        if (rows.length !== 1) {
          report.problems.push(`${vaultName} / ${row.name}: ${rows.length} innere Zeilen, uebersprungen`);
          innerDb.close();
          continue;
        }
        stored = rows[0].data;
      } catch (err) {
        report.problems.push(`${vaultName} / ${row.name}: nicht oeffenbar (${err.message.slice(0, 40)})`);
        continue;
      }
    } else {
      stored = row.data;
    }

    const decodedInfo = decodeDataUri(stored);
    if (!decodedInfo) {
      report.alreadyRaw++;
      innerDb?.close();
      continue;
    }
    const { decoded } = decodedInfo;
    const sigOk = signatureMatches(row.name, decoded);
    if (sigOk === false) {
      report.problems.push(`${vaultName} / ${row.name}: entpackt passt nicht zum Typ, uebersprungen`);
      innerDb?.close();
      continue;
    }

    report.toFix.push({
      vault: vaultName, name: row.name, uuid: row.uuid, external,
      storedSize: stored.length, realSize: decoded.length, signature: sigOk,
    });

    if (apply) {
      if (external) {
        innerDb.prepare("UPDATE attachment SET data=? WHERE ID=(SELECT MIN(ID) FROM attachment)").run(decoded);
      } else {
        db.prepare("UPDATE attachment SET data=? WHERE uuid=?").run(decoded, row.uuid);
      }
      db.prepare("UPDATE attachment SET size=? WHERE uuid=?").run(decoded.length, row.uuid);
      report.fixed++;
    }
    innerDb?.close();
  }
  db.close();
}

// Repairs the second copy of every external attachment, the one in the shared folder.
// The vault database is only READ here, for the per-attachment key expression and the
// name; nothing in the container is touched. A remote payload is rewritten only when it
// decodes to exactly the bytes this machine already stores, so the shared folder can
// never receive anything that was not verified locally first.
async function processSyncFolder(vaultName, apply, report) {
  let entry, params;
  try {
    ({ entry, params } = collect(vaultName));
    params = await params;
  } catch (err) {
    report.skipped.push(`${vaultName}: ${err.message}`);
    return;
  }
  const uuid = path.basename(path.dirname(entry.path));
  const synced = discoverSyncedVaults().find((v) => v.uuid === uuid);
  if (!synced) return; // no folder sync for this vault, nothing shared to repair

  const db = openVaultDb(entry.path, params.hexKey, params.compat, true);
  const hasTable = db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='attachment'").get();
  if (!hasTable) {
    db.close();
    return;
  }

  const rows = db
    .prepare("SELECT uuid,name,password FROM attachment WHERE deleted=0 AND (data IS NULL OR length(data)=0)")
    .all();
  for (const row of rows) {
    const localFile = path.join(path.dirname(entry.path), `${row.uuid}.enpassattach`);
    const remoteFile = path.join(synced.remoteDir, `${row.uuid}.enpassattach`);
    if (!fs.existsSync(remoteFile)) continue; // not published yet, Enpass will upload it
    if (!fs.existsSync(localFile)) {
      report.problems.push(`${vaultName} / ${row.name}: lokale Datei fehlt, kein Vergleich moeglich`);
      continue;
    }

    let localPayload, remotePayload, remoteDb;
    try {
      const l = openAttachmentDb(localFile, row.password, true);
      localPayload = l.prepare("SELECT data FROM attachment ORDER BY ID LIMIT 1").get().data;
      l.close();
      remoteDb = openAttachmentDb(remoteFile, row.password, !apply);
      const remoteRows = remoteDb.prepare("SELECT ID,data FROM attachment ORDER BY ID").all();
      if (remoteRows.length !== 1) {
        report.problems.push(`${vaultName} / ${row.name}: ${remoteRows.length} innere Zeilen im Sync-Ordner, uebersprungen`);
        remoteDb.close();
        continue;
      }
      remotePayload = remoteRows[0].data;
    } catch (err) {
      report.problems.push(`${vaultName} / ${row.name}: Sync-Kopie nicht oeffenbar (${err.message.slice(0, 40)})`);
      remoteDb?.close();
      continue;
    }

    const decodedInfo = decodeDataUri(remotePayload);
    if (!decodedInfo) {
      report.alreadyRaw++;
      remoteDb.close();
      continue;
    }
    const { decoded } = decodedInfo;

    // The decisive guard: the shared copy may only be replaced by the bytes this
    // machine already holds. Anything else means the two copies are not the same file.
    if (sha256(decoded) !== sha256(localPayload)) {
      report.problems.push(
        `${vaultName} / ${row.name}: entpackte Sync-Kopie weicht von der lokalen ab, uebersprungen`);
      remoteDb.close();
      continue;
    }
    if (signatureMatches(row.name, decoded) === false) {
      report.problems.push(`${vaultName} / ${row.name}: entpackt passt nicht zum Typ, uebersprungen`);
      remoteDb.close();
      continue;
    }

    report.toFix.push({
      vault: vaultName, name: row.name, uuid: row.uuid, external: true,
      storedSize: remotePayload.length, realSize: decoded.length, signature: true,
    });
    if (apply) {
      remoteDb.prepare("UPDATE attachment SET data=? WHERE ID=(SELECT MIN(ID) FROM attachment)").run(decoded);
      report.fixed++;
    }
    remoteDb.close();
  }
  db.close();
}

async function main() {
  const apply = process.argv.includes("--apply");
  const syncFolders = process.argv.includes("--sync-folders");
  const only = process.argv.find((a) => a.startsWith("--vault="))?.split("=")[1];
  if (apply && enpassRunning()) {
    console.error("Enpass laeuft. Bitte schliessen, sonst wird die Datenbank beschaedigt.");
    process.exit(1);
  }

  const report = { toFix: [], problems: [], skipped: [], alreadyRaw: 0, fixed: 0 };
  for (const v of listVaults()) {
    if (only && v.name !== only) continue;
    if (syncFolders) await processSyncFolder(v.name, apply, report);
    else await processVault(v.name, apply, report);
  }

  console.log(`${apply ? "REPARIERT" : "GEFUNDEN"}: ${report.toFix.length} Anhaenge als Datenblock gespeichert`);
  console.log(`bereits roh gespeichert: ${report.alreadyRaw}`);
  for (const f of report.toFix) {
    console.log(`  ${f.vault.slice(0, 20).padEnd(21)} ${f.name.slice(0, 34).padEnd(35)} ${String(f.storedSize).padStart(8)} -> ${String(f.realSize).padStart(8)} B  Signatur=${f.signature === null ? "unbekannt" : f.signature}`);
  }
  if (report.problems.length) {
    console.log(`\nProbleme (${report.problems.length}):`);
    report.problems.forEach((p) => console.log(`  ${p}`));
  }
  if (report.skipped.length) {
    console.log(`\nUebersprungene Tresore (${report.skipped.length}):`);
    report.skipped.forEach((s) => console.log(`  ${s}`));
  }
}

await main();
