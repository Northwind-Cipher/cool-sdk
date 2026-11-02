/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/** `cool bundle verify` and its stable exit codes (docs/cli-exit-codes.md). */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EXIT, bundleCommand } from "../src/cli/platform";
import { createEnvelope, exportBundle, signEnvelope } from "../src/platform/index";
import { KEYS, commitInput, registry, trust } from "./support/platform";

const quiet = async <T>(fn: () => T | Promise<T>): Promise<T> => {
  const write = process.stdout.write.bind(process.stdout);
  process.stdout.write = (() => true) as typeof process.stdout.write;
  try { return await fn(); } finally { process.stdout.write = write; }
};

function files() {
  const dir = mkdtempSync(join(tmpdir(), "cool-cli-"));
  const envs = [0, 1].map((i) => signEnvelope(createEnvelope(commitInput({ event_id: `e${i}`, occurred_at: new Date(Date.now() - 60_000).toISOString(), observed_at: new Date(Date.now() - 30_000).toISOString() }), registry), KEYS.source));
  const bundle = exportBundle({ title: "cli test", envelopes: envs, trust: trust(), exporter: KEYS.exporter });
  const b = join(dir, "bundle.json");
  const t = join(dir, "trust.json");
  writeFileSync(b, JSON.stringify(bundle));
  writeFileSync(t, JSON.stringify({ ...trust().snapshot(), as_of: new Date().toISOString() }));
  return { dir, b, t, bundle };
}

test("cli: bundle verify passes with your trust, is unknown with only the exporter's, fails when tampered", async () => {
  const f = files();
  assert.equal(await quiet(() => bundleCommand(["verify", f.b, "--trust", f.t])), EXIT.ok);
  assert.equal(await quiet(() => bundleCommand(["verify", f.b])), EXIT.unknown, "self-asserted trust is not a pass");
  writeFileSync(f.b, JSON.stringify({ ...f.bundle, envelopes: f.bundle.envelopes.slice(1) }));
  assert.equal(await quiet(() => bundleCommand(["verify", f.b, "--trust", f.t])), EXIT.fail);
});

test("cli: usage, unreadable and invalid input have their own exit codes", async () => {
  const f = files();
  assert.equal(await quiet(() => bundleCommand(["verify"])), EXIT.usage);
  assert.equal(await quiet(() => bundleCommand(["verify", join(f.dir, "missing.json")])), EXIT.noInput);
  const bad = join(f.dir, "bad.json");
  writeFileSync(bad, "{");
  assert.equal(await quiet(() => bundleCommand(["verify", bad])), EXIT.dataErr);
  writeFileSync(bad, JSON.stringify({ schema: "not-a-bundle" }));
  assert.equal(await quiet(() => bundleCommand(["verify", bad])), EXIT.dataErr);
});
