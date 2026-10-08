#!/usr/bin/env node
/* Author: Fabian Bitter (fabian@bitter.de) */
//
// Applies a list of in-place edits and cross-vault moves from a JSON file:
//   [{ "op": "edit", "vault": "primary", "uuid": "...", "changes": { "title": "...", "urls": [...] } },
//    { "op": "move", "from": "primary", "to": "b-a-media-group-fze-llc", "uuid": "...", "changes": {...} },
//    { "op": "attach", "vault": "primary", "uuid": "...", "file": "/abs/path/key.pem", "name": "key.pem" },
//    { "op": "attach", "vault": "...", "uuid": "...", "name": "key.pem", "from_note": [a, b], "sha": "...", "pem": "PRIVATE KEY" },
//    { "op": "replace_note", "vault": "...", "uuid": "...", "title": "...", "username": {...}, "password": {...},
//      "url": { "value": "..." }, "custom": [...], "attach": [...] }]
// Values may be note slices ({ from_note, sha }) so a plan holds no secret in clear text.
//
// Refuses to run while Enpass is open or when any touched vault has a newer copy in its
// sync folder. Each vault is finalized and published through folder sync once at the end.
// `--dry-run` opens everything, applies inside a transaction and rolls back.
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3-multiple-ciphers";
import { listVaults, getSecret } from "../src/config.js";
import { unlockParameters, readAttachment, getItem } from "../src/vault.js";
import { finalizeVault, pushSync, markSynced, addAttachment, insertItem, deleteItem } from "../src/write.js";
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
  open[name] = { db, path: v.path, target, session: { path: v.path, hexKey: params.hexKey, compat: params.compat } };
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

function sha12(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex").slice(0, 12);
}

// A plan never carries secrets in clear text: a field or attachment may name a slice of the
// current note ({ from_note: [start, end], sha }, code point offsets) instead of a value.
// `noteSha` pins the note the plan was built from, so a note edited since then stops the step.
function currentNote(db, uuid, noteSha) {
  const row = db.prepare("SELECT note FROM item WHERE uuid=? AND deleted=0").get(uuid);
  if (!row) throw new Error("not active");
  const note = row.note || "";
  if (noteSha && sha12(note) !== noteSha) throw new Error("note changed since the plan was built");
  return note;
}

function fromNote(note, spec, what) {
  const value = Array.from(note).slice(spec.from_note[0], spec.from_note[1]).join("");
  if (sha12(value) !== spec.sha) throw new Error(`note slice for "${what}" does not match its hash`);
  return value;
}

function resolveList(note, list, key) {
  return (list || []).map((f) => {
    if (!f.from_note) return f;
    const { from_note, sha, ...rest } = f;
    return { ...rest, value: fromNote(note, f, f[key]) };
  });
}

// A key kept on one line in a note becomes a proper PEM file: header, 64 column body, footer.
function pemFile(body, label) {
  const clean = body.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
  return `-----BEGIN ${label}-----\n${clean.match(/.{1,64}/g).join("\n")}\n-----END ${label}-----\n`;
}

function attachmentContent(db, step) {
  if (step.file) return fs.readFileSync(step.file);
  const value = fromNote(currentNote(db, step.uuid_note || step.uuid, step.noteSha), step, step.name);
  const text = step.pem ? pemFile(value, step.pem) : value.endsWith("\n") ? value : `${value}\n`;
  return Buffer.from(text, "utf8");
}

// A field value may also be taken from another field of the same entry ({ from_field: label }),
// e.g. a one-time code secret that sits in a custom field and belongs in the built-in one.
function fromField(step, spec, what) {
  const item = getItem(open[step.vault].session, step.uuid);
  const src = item && item.fields.find((x) => x.label === spec.from_field && x.value
    && (!spec.from_type || x.type === spec.from_type));
  if (!src) throw new Error(`no field "${spec.from_field}" with a value for "${what}"`);
  if (spec.sha && sha12(src.value) !== spec.sha) throw new Error(`field "${spec.from_field}" changed since the plan was built`);
  const { from_field, from_type, sha, ...rest } = spec;
  return { ...rest, value: src.value };
}

function resolveChanges(db, step) {
  const changes = { ...step.changes };
  for (const key of ["setFields", "addFields"]) {
    // An empty label ("") names a template field, so test for presence, not truthiness:
    // on 08.10.2026 a truthiness test skipped five such specs and wrote empty key fields.
    if (changes[key]) changes[key] = changes[key].map((f) => ("from_field" in f ? fromField(step, f, f.type || f.label) : f));
  }
  const needsNote = step.noteSha
    || [...(changes.addFields || []), ...(changes.setFields || [])].some((f) => f.from_note);
  if (!needsNote) return changes;
  const note = currentNote(db, step.uuid, step.noteSha);
  if (changes.addFields) changes.addFields = resolveList(note, changes.addFields, "label");
  if (changes.setFields) changes.setFields = resolveList(note, changes.setFields, "type");
  return changes;
}

function runStep(step, dry) {
  if (step.op === "edit") {
    const { db } = open[step.vault];
    let r;
    const apply = () => { r = editItem(db, step.uuid, resolveChanges(db, step)); };
    if (dry) apply();
    else db.transaction(apply)();
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
  if (step.op === "attach") {
    const o = open[step.vault];
    const content = attachmentContent(o.db, step);
    if (dry) {
      if (!o.db.prepare("SELECT 1 FROM item WHERE uuid=? AND deleted=0").get(step.uuid)) throw new Error("not active");
      return { checked: true, size: content.length };
    }
    let r;
    o.db.transaction(() => { r = addAttachment(o.db, o.path, step.uuid, step.name || path.basename(step.file), content); })();
    return { ...r, size: content.length };
  }
  if (step.op === "replace_note") {
    // A secure note rebuilt as a login entry: the new entry is written and read back field by
    // field and attachment by attachment before the note entry is retired.
    const o = open[step.vault];
    const note = currentNote(o.db, step.uuid, step.noteSha);
    const pick = (spec) => (spec && spec.from_note ? fromNote(note, spec, "value") : spec?.value ?? "");
    const custom = resolveList(note, step.custom, "label");
    const values = { username: pick(step.username), email: "", password: pick(step.password), url: pick(step.url), totp: "" };
    const files = (step.attach || []).map((a) => ({ name: a.name, content: attachmentContent(o.db, { ...a, uuid: step.uuid, noteSha: step.noteSha }) }));
    if (dry) return { checked: true, fields: custom.length, attachments: files.length };
    let created;
    o.db.transaction(() => {
      created = insertItem(o.db, { title: step.title, subtitle: "", note: step.note ?? "", values, custom });
    })();
    for (const f of files) o.db.transaction(() => addAttachment(o.db, o.path, created, f.name, f.content))();
    const back = getItem(o.session, created);
    const val = (t) => (back.fields.find((x) => x.type === t) || {}).value ?? "";
    const problems = [];
    for (const t of ["username", "password", "url"]) if (val(t) !== values[t]) problems.push(t);
    for (const c of custom) if (!back.fields.some((x) => x.label === c.label && x.value === c.value)) problems.push(c.label);
    for (const f of files) {
      let ok = false;
      try { ok = readAttachment(o.session, created, f.name).buffer.equals(f.content); } catch { ok = false; }
      if (!ok) problems.push(f.name);
    }
    if (problems.length) throw new Error(`new entry ${created} does not read back (${problems.join(", ")}), note entry kept`);
    o.db.transaction(() => deleteItem(o.db, step.uuid))();
    return { created, retired: step.uuid, fields: custom.length, attachments: files.length };
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
