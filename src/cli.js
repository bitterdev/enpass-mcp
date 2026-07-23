#!/usr/bin/env node
/* Author: Fabian Bitter (fabian@bitter.de) */

import fs from "node:fs";
import path from "node:path";
import {
  listVaults,
  getVault,
  upsertVault,
  removeVault,
  setSecret,
  getSecret,
  discoverVaults,
} from "./config.js";
import { unlockParameters, listItems } from "./vault.js";
import { serve } from "./server.js";

function parseFlags(args) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const next = args[i + 1];
      if (next && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(arg);
    }
  }
  return { flags, positional };
}

// Reads a secret from the terminal without echoing it.
function promptHidden(question) {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    process.stdout.write(question);
    const wasRaw = stdin.isRaw;
    if (stdin.isTTY) stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    let input = "";
    const onData = (chunk) => {
      for (const ch of chunk) {
        const code = ch.charCodeAt(0);
        if (ch === "\n" || ch === "\r" || code === 4) {
          // Enter or Ctrl-D: finish
          if (stdin.isTTY) stdin.setRawMode(wasRaw);
          stdin.pause();
          stdin.removeListener("data", onData);
          process.stdout.write("\n");
          resolve(input);
          return;
        } else if (code === 3) {
          // Ctrl-C: abort
          process.stdout.write("\n");
          process.exit(130);
        } else if (code === 127 || code === 8) {
          // Backspace
          input = input.slice(0, -1);
        } else if (code >= 32) {
          input += ch;
        }
      }
    };
    stdin.on("data", onData);
  });
}

async function cmdAddVault(positional, flags) {
  const name = positional[0];
  const vaultPath = flags.path ? path.resolve(String(flags.path)) : null;
  if (!name || !vaultPath) {
    fail("Usage: enpass-mcp add-vault <name> --path <vault.enpassdb> [--keyfile <file>]");
  }
  if (!fs.existsSync(vaultPath)) {
    fail(`Vault file not found: ${vaultPath}`);
  }
  const keyfile = flags.keyfile ? path.resolve(String(flags.keyfile)) : null;
  if (keyfile && !fs.existsSync(keyfile)) {
    fail(`Keyfile not found: ${keyfile}`);
  }

  const password = await promptHidden(`Master password for "${name}": `);
  if (!password) fail("Empty password, aborted.");

  process.stdout.write("Verifying master password...\n");
  try {
    await unlockParameters(vaultPath, password, keyfile);
  } catch (err) {
    fail(err.message);
  }

  setSecret(name, password);
  upsertVault(name, vaultPath, keyfile);
  process.stdout.write(`Vault "${name}" registered. Master password stored in the OS keychain.\n`);
}

function cmdListVaults() {
  const vaults = listVaults();
  if (vaults.length === 0) {
    process.stdout.write("No vaults registered.\n");
    return;
  }
  for (const v of vaults) {
    process.stdout.write(
      `- ${v.name}\n    path:     ${v.path}${v.pathExists ? "" : "  (MISSING)"}\n    password: ${v.hasSecret ? "stored in keychain" : "NOT stored"}\n`,
    );
  }
}

function cmdDiscover() {
  const vaults = discoverVaults();
  if (vaults.length === 0) {
    process.stdout.write(
      "No Enpass vaults found in the common locations. Register one manually with --path.\n",
    );
    return;
  }
  process.stdout.write("Found Enpass vaults:\n");
  for (const v of vaults) process.stdout.write(`  ${v}\n`);
  process.stdout.write("\nRegister one with: enpass-mcp add-vault <name> --path <file>\n");
}

function cmdRemoveVault(positional) {
  const name = positional[0];
  if (!name) fail("Usage: enpass-mcp remove-vault <name>");
  const removed = removeVault(name);
  process.stdout.write(removed ? `Vault "${name}" removed.\n` : `Vault "${name}" was not registered.\n`);
}

async function cmdTestUnlock(positional) {
  const name = positional[0];
  if (!name) fail("Usage: enpass-mcp test-unlock <name>");
  const entry = getVault(name);
  if (!entry) fail(`Vault "${name}" is not registered.`);
  const password = getSecret(name);
  if (!password) fail(`No master password stored for "${name}".`);

  const params = await unlockParameters(entry.path, password, entry.keyfile);
  const session = { path: entry.path, hexKey: params.hexKey, compat: params.compat };
  const items = await listItems(session, { limit: 1000 });
  process.stdout.write(
    `Unlock OK (cipher_compatibility=${params.compat}, iterations=${params.iterations}). ${items.length} entries readable.\n`,
  );
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function usage() {
  process.stdout.write(
    `enpass-mcp - MCP server for Enpass vaults\n\n` +
      `Usage:\n` +
      `  enpass-mcp serve                                 Start the MCP stdio server\n` +
      `  enpass-mcp add-vault <name> --path <file> [--keyfile <file>]\n` +
      `                                                   Register a vault, store password in OS keychain\n` +
      `  enpass-mcp discover                              Find Enpass vault files in common locations\n` +
      `  enpass-mcp list-vaults                           List registered vaults\n` +
      `  enpass-mcp remove-vault <name>                   Remove a vault and its stored password\n` +
      `  enpass-mcp test-unlock <name>                    Verify a vault can be unlocked\n`,
  );
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const { flags, positional } = parseFlags(rest);

  switch (command) {
    case "serve":
      await serve();
      break;
    case "add-vault":
      await cmdAddVault(positional, flags);
      break;
    case "list-vaults":
      cmdListVaults();
      break;
    case "discover":
      cmdDiscover();
      break;
    case "remove-vault":
      cmdRemoveVault(positional);
      break;
    case "test-unlock":
      await cmdTestUnlock(positional);
      break;
    case undefined:
    case "help":
    case "--help":
    case "-h":
      usage();
      break;
    default:
      process.stderr.write(`Unknown command: ${command}\n\n`);
      usage();
      process.exit(1);
  }
}

main().catch((err) => {
  process.stderr.write(`${err.stack || err.message}\n`);
  process.exit(1);
});
