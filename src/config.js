/* Author: Fabian Bitter (fabian@bitter.de) */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Entry } from "@napi-rs/keyring";

const KEYRING_SERVICE = "enpass-mcp";
const REGISTRY_FILE = "vaults.json";

// Cross-platform config directory (macOS, Windows, Linux). The registry only
// stores non-secret data (vault names and file paths); master passwords live in
// the OS keychain.
export function configDir() {
  if (process.env.ENPASS_MCP_CONFIG_DIR) return process.env.ENPASS_MCP_CONFIG_DIR;
  const home = os.homedir();
  if (process.platform === "win32") {
    return path.join(process.env.APPDATA || path.join(home, "AppData", "Roaming"), "enpass-mcp");
  }
  if (process.platform === "darwin") {
    return path.join(home, "Library", "Application Support", "enpass-mcp");
  }
  return path.join(process.env.XDG_CONFIG_HOME || path.join(home, ".config"), "enpass-mcp");
}

function registryPath() {
  return path.join(configDir(), REGISTRY_FILE);
}

export function loadRegistry() {
  try {
    const raw = fs.readFileSync(registryPath(), "utf8");
    const data = JSON.parse(raw);
    return data && typeof data === "object" && data.vaults ? data : { vaults: {} };
  } catch (err) {
    if (err.code === "ENOENT") return { vaults: {} };
    throw err;
  }
}

function saveRegistry(registry) {
  const dir = configDir();
  fs.mkdirSync(dir, { recursive: true });
  const file = registryPath();
  fs.writeFileSync(file, JSON.stringify(registry, null, 2), { mode: 0o600 });
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    // best effort on platforms without POSIX permissions
  }
}

export function listVaults() {
  const registry = loadRegistry();
  return Object.entries(registry.vaults).map(([name, entry]) => ({
    name,
    path: entry.path,
    keyfile: entry.keyfile || null,
    pathExists: fs.existsSync(entry.path),
    hasSecret: hasSecret(name),
  }));
}

export function getVault(name) {
  const registry = loadRegistry();
  return registry.vaults[name] || null;
}

export function upsertVault(name, vaultPath, keyfile = null) {
  const registry = loadRegistry();
  registry.vaults[name] = { path: vaultPath, keyfile: keyfile || null };
  saveRegistry(registry);
}

export function removeVault(name) {
  const registry = loadRegistry();
  if (!registry.vaults[name]) return false;
  delete registry.vaults[name];
  saveRegistry(registry);
  deleteSecret(name);
  return true;
}

// Scans the common Enpass folder-sync locations for vault databases so users can
// register them without hunting for the file path manually.
export function discoverVaults() {
  const home = os.homedir();
  const bases = [
    path.join(home, "Documents", "Enpass"),
    path.join(home, "Enpass"),
    path.join(home, "Library", "Application Support", "Enpass"),
    path.join(home, "OneDrive", "Enpass"),
    path.join(home, "Dropbox", "Enpass"),
  ];
  const found = new Set();
  for (const base of bases) {
    walkForVaults(base, 0, 5, found);
  }
  return [...found];
}

function walkForVaults(dir, depth, maxDepth, found) {
  if (depth > maxDepth) return;
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isFile() && entry.name.endsWith(".enpassdb")) {
      found.add(full);
    } else if (entry.isDirectory() && !entry.name.startsWith(".")) {
      walkForVaults(full, depth + 1, maxDepth, found);
    }
  }
}

// --- OS keychain (master passwords) ---

function entryFor(name) {
  return new Entry(KEYRING_SERVICE, name);
}

export function setSecret(name, password) {
  entryFor(name).setPassword(password);
}

export function getSecret(name) {
  try {
    return entryFor(name).getPassword();
  } catch {
    return null;
  }
}

export function hasSecret(name) {
  return getSecret(name) !== null;
}

export function deleteSecret(name) {
  try {
    entryFor(name).deletePassword();
  } catch {
    // no stored secret
  }
}
