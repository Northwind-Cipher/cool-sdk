/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/** The platform CLI commands and their stable exit codes (docs/cli-exit-codes.md). */
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EXIT, bundleCommand, decideCommand, gateDemoCommand } from "../src/cli/platform";

const quiet = async <T>(fn: () => T | Promise<T>): Promise<T> => {
  const write = process.stdout.write.bind(process.stdout);
  process.stdout.write = (() => true) as typeof process.stdout.write;
  try { return await fn(); } finally { process.stdout.write = write; }
};

test("cli: gate-demo runs the milestone end to end and leaves verifiable files", async () => {
  const dir = mkdtempSync(join(tmpdir(), "cool-cli-"));
  assert.equal(await quiet(() => gateDemoCommand([join(dir, "demo")])), EXIT.ok);
  for (const f of ["bundle.json", "trust.json", "policy.json", join("prod", "service.tar")]) assert.ok(existsSync(join(dir, "demo", f)), f);
  const bundle = join(dir, "demo", "bundle.json");
  assert.equal(await quiet(() => bundleCommand(["verify", bundle, "--trust", join(dir, "demo", "trust.json")])), EXIT.ok);
  assert.equal(await quiet(() => bundleCommand(["verify", bundle])), EXIT.unknown, "self-asserted trust is not a pass");

  const tampered = JSON.parse(readFileSync(bundle, "utf8"));
  tampered.envelopes.pop();
  writeFileSync(bundle, JSON.stringify(tampered));
  assert.equal(await quiet(() => bundleCommand(["verify", bundle, "--trust", join(dir, "demo", "trust.json")])), EXIT.fail);
});

test("cli: decide maps decisions to exit codes; bad input has its own codes", async () => {
  const dir = mkdtempSync(join(tmpdir(), "cool-cli-"));
  const policy = join(dir, "p.json");
  writeFileSync(policy, JSON.stringify({ schema: "cool.policy.v1", id: "p", version: "1", mode: "enforce", default: "allow", rules: [
    { id: "a", when: { fact: "x", op: "eq", value: 1 }, decision: "deny", reason: "x_is_1" },
    { id: "b", when: { fact: "y", op: "eq", value: 1 }, decision: "require_approval", reason: "y_is_1", on_unknown: "allow" },
  ] }));
  const facts = (o: object) => { const f = join(dir, `${Math.random()}.json`); writeFileSync(f, JSON.stringify(o)); return f; };
  assert.equal(await quiet(() => decideCommand([policy, facts({ x: 0, y: 0 })])), EXIT.ok);
  assert.equal(await quiet(() => decideCommand([policy, facts({ x: 1, y: 0 })])), EXIT.fail);
  assert.equal(await quiet(() => decideCommand([policy, facts({ x: 0, y: 1 })])), EXIT.unknown);
  assert.equal(await quiet(() => decideCommand([policy])), EXIT.usage);
  assert.equal(await quiet(() => decideCommand([join(dir, "missing.json"), policy])), EXIT.noInput);
  const notJson = join(dir, "bad.json");
  writeFileSync(notJson, "{");
  assert.equal(await quiet(() => decideCommand([notJson, policy])), EXIT.dataErr);
  writeFileSync(notJson, JSON.stringify({ schema: "cool.policy.v1", id: "p", version: "1", mode: "x", default: "allow", rules: [] }));
  assert.equal(await quiet(() => decideCommand([notJson, facts({})])), EXIT.dataErr);
});
