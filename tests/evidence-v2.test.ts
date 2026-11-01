/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/** Verifier outcomes, legacy wrapping, TEE adapters, sequence gaps, attachments, the agent demo. */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CoolTee, SimulatedDstackClient } from "../src/phala/index";
import {
  ADAPTERS,
  check,
  classifyOutcome,
  createEnvelope,
  exportBundle,
  signEnvelope,
  verifyBundle,
  verifyEnvelope,
  verifyWrappedLegacy,
  wrapLegacyReceipt,
} from "../src/platform/index";
import { KEYS, commitInput, registry, trust } from "./support/platform";
import { runAgentDemo } from "../scripts/demo-agent";

test("outcome: precedence invalid > unsupported > stale > incomplete > indeterminate > verified", () => {
  const p = check("pass", "ok", "");
  const c = (reason: string, status: "fail" | "unknown" | "not_checked" = "fail") => check(status, reason, "");
  assert.equal(classifyOutcome({ a: p, b: p }, ["a", "b"]).outcome, "verified");
  assert.equal(classifyOutcome({ a: c("signature_invalid"), b: c("attestation_stale") }, ["a", "b"]).outcome, "invalid");
  assert.equal(classifyOutcome({ a: c("unsupported_algorithm"), b: c("attestation_stale") }, ["a", "b"]).outcome, "unsupported");
  assert.equal(classifyOutcome({ a: c("attestation_stale"), b: c("sequence_gap") }, ["a", "b"]).outcome, "stale");
  assert.equal(classifyOutcome({ a: c("missing_evidence"), b: c("x", "unknown") }, ["a", "b"]).outcome, "incomplete");
  assert.equal(classifyOutcome({ a: c("no_policy", "not_checked") }, ["a"]).outcome, "indeterminate");
});

test("envelope reports carry the outcome", () => {
  const env = signEnvelope(createEnvelope(commitInput(), registry), KEYS.source);
  assert.equal(verifyEnvelope(env, { registry, trust: trust() }).outcome, "verified");
  assert.equal(verifyEnvelope(signEnvelope(createEnvelope(commitInput(), registry), KEYS.rogue), { registry, trust: trust() }).outcome, "invalid");
  assert.equal(verifyEnvelope({ ...env, format: "x" as never }, { registry, trust: trust() }).outcome, "unsupported", "an unknown format is unsupported, not merely invalid");
});

test("legacy: a cool.receipt.v2 is wrapped without changing its meaning, and still verifies as v2", async () => {
  const tee = await CoolTee.connect({ dstack: new SimulatedDstackClient({ appName: "legacy", imageDigest: "sha256:legacy" }), capture: { flushMs: 1 } });
  const receipt = await tee.record({ type: "model.execution", metadata: { model: "m" } });
  await tee.close();
  const env = signEnvelope(createEnvelope(wrapLegacyReceipt(receipt, { source: "cool-sdk-3.x", actor: "service:migrator" }), registry), KEYS.source);
  const v = await verifyWrappedLegacy(env, receipt);
  assert.equal(v.binding.status, "pass");
  assert.equal(v.legacy.checks.signature.status, "pass");
  assert.equal(verifyEnvelope(env, { registry, trust: trust() }).overall_status, "pass");
  const other = { ...receipt, binding_hash: `mh:sha256:${"0".repeat(64)}` } as typeof receipt;
  assert.equal((await verifyWrappedLegacy(env, other)).binding.reason, "legacy_mismatch");
});

test("TEE adapters: one contract; unsupported platforms say so and are never verified", async () => {
  for (const p of ["amd-sev-snp", "nvidia-cc"] as const) {
    const r = await ADAPTERS[p].verify(undefined as never);
    assert.equal(r.outcome, "unsupported");
    assert.equal(r.support, "unsupported");
    assert.ok(r.limitations[0]);
  }
  assert.equal(ADAPTERS["aws-nitro"].support, "implemented");
  assert.equal(ADAPTERS["phala-dstack"].support, "partial");
});

test("bundles: a sequence gap is incomplete; an altered attachment is invalid", () => {
  const seq = [0, 1, 3].map((n) => signEnvelope(createEnvelope(commitInput({ event_id: `s${n}`, sequence: { epoch: 2, number: n } }), registry), KEYS.source));
  const gap = verifyBundle(JSON.parse(JSON.stringify(exportBundle({ title: "gap", envelopes: seq, trust: trust(), exporter: KEYS.exporter }))), { registry, trust: trust() });
  assert.equal(gap.outcome, "incomplete");
  assert.equal(gap.checks.sequence_complete.reason, "sequence_gap");

  const withAtt = JSON.parse(JSON.stringify(exportBundle({ title: "att", envelopes: [seq[0]!], attachments: [{ kind: "note", body: { a: 1 } }], trust: trust(), exporter: KEYS.exporter })));
  assert.equal(verifyBundle(withAtt, { registry, trust: trust() }).checks.attachments_bound.status, "pass");
  withAtt.attachments[0].body.a = 2;
  assert.equal(verifyBundle(withAtt, { registry, trust: trust() }).checks.attachments_bound.reason, "attachment_mismatch");
});

test("agent demo: scenarios A–H all hold, and the artifacts are written", async () => {
  const out = await runAgentDemo({ dir: join(mkdtempSync(join(tmpdir(), "cool-demo-test-")), "out"), quiet: true });
  assert.deepEqual(out.results.filter((r) => !r.ok).map((r) => `${r.scenario}: ${r.claim}`), []);
  assert.equal(new Set(out.results.map((r) => r.scenario[0])).size, 9);
});

test("bench: every hot path runs and reports timings", async () => {
  const { runBench } = await import("../scripts/bench");
  const rows = await runBench(2);
  assert.equal(rows.length, 6);
  assert.ok(rows.every((r) => r.iterations === 2 && r.median_ms >= 0 && r.p95_ms >= r.median_ms));
});
