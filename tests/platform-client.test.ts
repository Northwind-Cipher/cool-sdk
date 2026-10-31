/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/** CoolClient lifecycle and configuration, and the connector framework. */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CooLError } from "../src/errors";
import { hybridSign } from "../src/sign";
import {
  CoolClient,
  FileConfigConnector,
  GitConnector,
  TransparencyLog,
  fileDigest,
  redact,
  runConnector,
  type Connector,
  type EnvelopeInput,
} from "../src/platform/index";
import { KEYS, T0, commitInput, trust } from "./support/platform";

test("client: configuration is validated with actionable errors", () => {
  assert.throws(() => new CoolClient({ project: "", signer: KEYS.source, trust: trust() }), (e: unknown) => e instanceof CooLError && e.code === "COOL_CONFIGURATION_INVALID");
  assert.throws(() => new CoolClient({ project: "p", signer: undefined as never, trust: trust() }), (e: unknown) => e instanceof CooLError && !!e.action);
});

test("client: inspectConfig explains effective settings and leaks no key material", () => {
  const c = new CoolClient({ project: "acme", signer: KEYS.source, trust: trust() });
  const view = c.inspectConfig();
  assert.equal(view["policy_mode"], "audit");
  assert.deepEqual(view["enforcement"], { enabled: false, default: "dry run" });
  assert.equal(view["environment_variables_read"], "none");
  const text = JSON.stringify(view);
  for (const secret of [KEYS.source.ed25519Secret, KEYS.source.mlDsaSecret]) {
    assert.equal(text.includes(Buffer.from(secret).toString("base64").slice(0, 24)), false);
    assert.equal(text.includes(Buffer.from(secret).toString("hex").slice(0, 24)), false);
  }
  assert.deepEqual(redact({ api_token: "x", nested: { password: "y", ok: 1 }, blob: new Uint8Array(3) }), { api_token: "[redacted]", nested: { password: "[redacted]", ok: 1 }, blob: "[3 bytes]" });
});

test("client: record → publish → verify; publish without a log is a clear error", () => {
  const log = new TransparencyLog("l", KEYS.log, () => new Date(T0));
  const c = new CoolClient({ project: "acme", signer: KEYS.source, trust: trust(), log, clock: () => new Date(T0) });
  const env = c.evidence.publish(c.evidence.record(commitInput()));
  assert.equal(c.evidence.verify(env, { now: T0 }).overall_status, "pass");
  const noLog = new CoolClient({ project: "acme", signer: KEYS.source, trust: trust() });
  assert.throws(() => noLog.evidence.publish(env), (e: unknown) => e instanceof CooLError && e.code === "COOL_TRANSPARENCY_FAILED");
});

test("client: policy modes — disabled returns null, audit is advisory, enforce follows the policy", () => {
  const p = { schema: "cool.policy.v1" as const, id: "p", version: "1", mode: "enforce" as const, default: "deny" as const, rules: [] };
  const mk = (policyMode: "disabled" | "audit" | "enforce") => new CoolClient({ project: "a", signer: KEYS.source, trust: trust(), policyMode });
  assert.equal(mk("disabled").policy.evaluate(p, {}), null);
  assert.equal(mk("audit").policy.evaluate(p, {})?.enforced, false);
  assert.equal(mk("enforce").policy.evaluate(p, {})?.enforced, true);
});

test("client: close is deterministic — later calls fail with COOL_CLOSED", () => {
  const c = new CoolClient({ project: "acme", signer: KEYS.source, trust: trust() });
  c.close();
  c.close();
  assert.throws(() => c.evidence.record(commitInput()), (e: unknown) => e instanceof CooLError && e.code === "COOL_CLOSED");
});

test("client: a provider-backed signer works without the client ever holding the private key", () => {
  // Stands in for a KMS/HSM: the client only sees keyId, public keys and sign().
  let calls = 0;
  const provider = {
    keyId: KEYS.source.keyId,
    directoryEntry: KEYS.source.directoryEntry,
    sign: (message: Uint8Array) => (calls++, hybridSign(message, KEYS.source)),
  };
  const c = new CoolClient({ project: "acme", signer: provider, trust: trust(), clock: () => new Date(T0) });
  const env = c.evidence.record(commitInput());
  assert.equal(calls, 1);
  assert.equal(c.evidence.verify(env, { now: T0 }).checks.signature_valid.status, "pass");
  assert.equal((c.inspectConfig()["signer"] as { kind: string }).kind, "provider");
});

/* ── connectors ───────────────────────────────────────────────────────── */

const fake = (behaviour: Array<"ok" | "fail-after-one" | "fail">): Connector & { runs: number } => {
  const c = {
    id: "fake", kind: "test", permissions: [], network: "none" as const, runs: 0,
    async *collect(): AsyncIterable<EnvelopeInput> {
      const b = behaviour[Math.min(c.runs++, behaviour.length - 1)];
      if (b === "fail") throw new Error("503 from upstream");
      yield commitInput();
      if (b === "fail-after-one") throw new Error("connection dropped");
    },
  };
  return c;
};

test("connectors: retries recover; persistent failure is partial or unavailable, never an empty success", async () => {
  const recovers = await runConnector(fake(["fail", "ok"]), { backoffMs: 1 });
  assert.equal(recovers.status, "complete");
  assert.equal(recovers.attempts, 2);
  const partial = await runConnector(fake(["fail-after-one"]), { retries: 1, backoffMs: 1 });
  assert.equal(partial.status, "partial");
  assert.equal(partial.collected.length, 1);
  const down = await runConnector(fake(["fail"]), { retries: 1, backoffMs: 1 });
  assert.equal(down.status, "unavailable");
  assert.equal(down.errors.length, 2);
  const ac = new AbortController();
  ac.abort();
  assert.equal((await runConnector(fake(["ok"]), { signal: ac.signal })).status, "cancelled");
});

test("connectors: local git history becomes scm.commit evidence (this repository)", async () => {
  const run = await runConnector(new GitConnector(process.cwd(), { repository: "cool-sdk", limit: 3 }));
  assert.equal(run.status, "complete", run.errors.join("; "));
  assert.ok(run.collected.length >= 1);
  const c = new CoolClient({ project: "acme", signer: KEYS.source, trust: trust() });
  for (const input of run.collected) {
    const core = c.evidence.create(input);
    assert.match(String(core.payload["commit"]), /^[0-9a-f]{40}$/);
    assert.equal(JSON.stringify(core).includes("@"), false, "no e-mail addresses in evidence");
  }
});

test("connectors: config drift against an approved baseline", async () => {
  const dir = mkdtempSync(join(tmpdir(), "cool-cfg-"));
  const path = join(dir, "app.yaml");
  writeFileSync(path, "replicas: 3\n");
  const baseline = { [path]: fileDigest(path) };
  assert.equal((await runConnector(new FileConfigConnector(baseline))).collected.length, 0);
  writeFileSync(path, "replicas: 30\n");
  const run = await runConnector(new FileConfigConnector(baseline));
  assert.equal(run.collected[0]?.event_type, "configuration.drift_detected");
  assert.equal(JSON.stringify(run.collected).includes("replicas"), false, "contents never enter evidence");
});
