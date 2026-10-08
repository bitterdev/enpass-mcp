/* Author: Fabian Bitter (fabian@bitter.de) */

import test from "node:test";
import assert from "node:assert/strict";
import { entryProblems } from "../src/hygiene.js";

test("a clean entry passes", () => {
  assert.deepEqual(entryProblems({ title: "Auth0 (fonella)", note: "", custom: [{ label: "Region", value: "eu-central-1" }] }), []);
});

test("middle dot and ticket numbers are refused", () => {
  const p = entryProblems({ title: "AWS SES · fonella", subtitle: "angelegt in JUNO-2261", note: "siehe juno-12" });
  assert.equal(p.length, 3);
});

test("key material belongs in an attachment", () => {
  const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n";
  assert.equal(entryProblems({ title: "Deploy Key", note: pem }).length, 1);
  assert.equal(entryProblems({ title: "Deploy Key", custom: [{ label: "Key", value: pem }] }).length, 1);
});
