#!/usr/bin/env node
/* Author: Fabian Bitter (fabian@bitter.de) */
//
// Applies a list of in-place edits and cross-vault moves from a JSON file:
//   [{ "op": "edit", "vault": "primary", "uuid": "...", "changes": { "title": "...", "urls": [...] } },
//    { "op": "move", "from": "primary", "to": "b-a-media-group-fze-llc", "uuid": "...", "changes": {...} }]
//
// Refuses to run while Enpass is open or when any touched vault has a newer copy in its
// sync folder. Each vault is finalized and published through folder sync once at the end.
// `--dry-run` opens everything, applies inside a transaction and rolls back.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3-multiple-ciphers";
import { listVaults, getSecret } from "../src/config.js";
import { unlockParameters } from "../src/vault.js";
import { finalizeVault, pushSync, markSynced } from "../src/write.js";
import { syncTargetFor, remoteStatus } from "../src/foldersync.js";
import { editItem, moveItem } from "../src/edit.js";

const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const planFile = args.find((a) => !a.startsWith("--"));
if (!planFile) {
  console.error("usage: apply-changes.mjs <plan.json> [--dry-run]");
  process.exit(2);
}

function enpassRunning() {
  try {
    return execFileSync("/usr/bin/pgrep", ["-x", "Enpass"], { encoding: "utf8" }).trim().length > 0;
  } catch {
    return false;
  }
}

if (enpassRunning()) {
  console.error("Enpass is running. Quit it first.");
  process.exit(3);
}

const plan = JSON.parse(fs.readFileSync(planFile, "utf8"));
const registry = Object.fromEntries(listVaults().map((v) => [v.name, v]));
const touched = new Set(plan.flatMap((p) => (p.op === "move" ? [p.from, p.to] : [p.vault])));

const open = {};
for (const name of touched) {
  const v = registry[name];
  if (!v) throw new Error(`unknown vault ${name}`);
  const vaultUuid = path.basename(path.dirname(v.path));
  const target = syncTargetFor(vaultUuid);
  const st = remoteStatus(target, Database);
  if (st.newer) {
    console.error(`vault ${name}: sync folder is newer (${st.reason}), stopping`);
    process.exit(4);
  }
  const params = unlockParameters(v.path, getSecret(name), v.keyfile);
  const db = new Database(v.path, { fileMustExist: true });
  db.pragma("cipher='sqlcipher'");
  db.pragma(`legacy=${params.compat}`);
  db.pragma(`key="x'${params.hexKey}'"`);
  open[name] = { db, path: v.path, target };
}

const results = [];
let failed = 0;
for (const step of plan) {
  try {
    if (dryRun) {
      const dbs = step.op === "move" ? [open[step.from].db, open[step.to].db] : [open[step.vault].db];
      dbs.forEach((d) => d.exec("SAVEPOINT dry"));
      try {
        results.push({ ...step, ok: true, result: runStep(step, true) });
      } finally {
        dbs.forEach((d) => { d.exec("ROLLBACK TO dry"); d.exec("RELEASE dry"); });
      }
    } else {
      results.push({ ...step, ok: true, result: runStep(step, false) });
    }
  } catch (err) {
    failed++;
    results.push({ ...step, ok: false, error: err.message });
  }
}

function runStep(step, dry) {
  if (step.op === "edit") {
    const { db } = open[step.vault];
    let r;
    if (dry) r = editItem(db, step.uuid, step.changes);
    else db.transaction(() => { r = editItem(db, step.uuid, step.changes); })();
    return r;
  }
  if (step.op === "move") {
    if (dry) {
      // The file copy of a move cannot be rolled back, so a dry run only checks preconditions.
      const s = open[step.from].db.prepare("SELECT 1 FROM item WHERE uuid=? AND deleted=0").get(step.uuid);
      const t = open[step.to].db.prepare("SELECT 1 FROM item WHERE uuid=?").get(step.uuid);
      if (!s) throw new Error("not active in source");
      if (t) throw new Error("uuid exists in target");
      return { checked: true };
    }
    const a = open[step.from];
    const b = open[step.to];
    return moveItem(a.db, a.path, b.db, b.path, step.uuid, step.changes || null);
  }
  throw new Error(`unknown op ${step.op}`);
}

const published = {};
for (const [name, o] of Object.entries(open)) {
  if (!dryRun) {
    finalizeVault(o.db, o.path);
    o.db.close();
    if (o.target) {
      const res = pushSync(o.target.vaultDir, o.target.syncDir, o.target.remoteDir);
      markSynced(path.join(o.target.syncDir, "syncmeta.db"), Database, res.now);
      published[name] = { written: res.written, attachments: res.attachments, sha256: res.sha256 };
    }
  } else {
    o.db.close();
  }
}

console.log(JSON.stringify({ dryRun, steps: results.length, failed, published, results }, null, 1));
process.exit(failed ? 1 : 0);
