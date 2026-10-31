/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * The first milestone (spec page 49), end to end: build a benign artifact,
 * record signed provenance, verify it, pass policy and deploy; tamper the
 * artifact, retry, and have the target refuse it; export a bundle and verify
 * it independently. The deployment target is a real local directory.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CoolClient,
  LocalDirectoryTarget,
  TransparencyLog,
  buildProvenance,
  exportBundle,
  verifyBundle,
  type SignedEnvelope,
} from "../src/platform/index";
import { KEYS, T0, iso, registry, trust } from "./support/platform";

function setup(content = "benign release\n") {
  const dir = mkdtempSync(join(tmpdir(), "cool-sc-"));
  const artifactPath = join(dir, "service.tar");
  writeFileSync(artifactPath, content);
  const log = new TransparencyLog("cool-log", KEYS.log, () => new Date(T0));
  const builder = new CoolClient({ project: "acme", signer: KEYS.builder, trust: trust(), log, clock: () => new Date(T0) });
  const operator = new CoolClient({ project: "acme", signer: KEYS.source, trust: trust(), log, policyMode: "enforce", enforcement: { enabled: true }, clock: () => new Date(T0) });
  const prov = buildProvenance({ buildId: "b-42", builderId: "builder-1", repository: "acme/service", commit: "abc123", artifactPath, finishedAt: iso(-60_000) });
  const build = builder.evidence.publish(builder.evidence.record({ ...prov.build, observed_at: iso(-55_000) }));
  const artifact = builder.evidence.publish(builder.evidence.record({ ...prov.artifact, observed_at: iso(-55_000), provenance: { collection_method: "emitted", refs: [build.digest] } }));
  const target = new LocalDirectoryTarget(join(dir, "prod"));
  const evidence = () => ({
    artifactPath, build, artifact,
    buildReport: operator.evidence.verify(build, { purpose: "builder" }),
    artifactReport: operator.evidence.verify(artifact, { purpose: "builder" }),
    trustedBuilders: ["builder-1"], allowedRepositories: ["acme/service"],
  });
  return { dir, artifactPath, log, builder, operator, build, artifact, target, evidence };
}

test("milestone: verified provenance passes policy and the target deploys and confirms", async () => {
  const s = setup();
  const e = s.evidence();
  assert.equal(e.buildReport.overall_status, "pass", e.buildReport.reasons.join("; "));
  assert.equal(e.buildReport.checks.inclusion_proof_valid.status, "pass");
  const g = await s.operator.supply_chain.gate({ evidence: e, target: s.target, deploymentId: "d-1", environment: "prod", requestedBy: "user:asha", dryRun: false });
  assert.equal(g.decision.decision, "audit_only"); // no SBOM: admitted, flagged
  assert.ok(g.decision.reason_codes.includes("sbom:sbom_missing"));
  assert.equal(g.enforcement.state, "completed");
  assert.equal(g.enforcement.confirmed, true);
  assert.equal(readFileSync(join(s.dir, "prod", "service.tar"), "utf8"), "benign release\n");
  assert.equal(g.records[1]!.payload["outcome"], "succeeded");
});

test("milestone: a tampered artifact is denied by policy AND would be refused by the target", async () => {
  const s = setup();
  writeFileSync(s.artifactPath, "benign release\n# injected\n");
  const g = await s.operator.supply_chain.gate({ evidence: s.evidence(), target: s.target, deploymentId: "d-2", environment: "prod", requestedBy: "user:asha", dryRun: false });
  assert.equal(g.decision.decision, "deny");
  assert.ok(g.decision.reason_codes.includes("bytes-match:artifact_digest_mismatch"));
  assert.equal(g.enforcement.state, "not_executed");
  assert.equal(existsSync(join(s.dir, "prod", "service.tar")), false);
  assert.equal(g.records[1]!.payload["outcome"], "rejected");
});

test("milestone: untrusted builder, disallowed source and unverifiable provenance are denied", async () => {
  const s = setup();
  const base = s.evidence();
  const untrusted = await s.operator.supply_chain.gate({ evidence: { ...base, trustedBuilders: ["builder-9"] }, target: s.target, deploymentId: "d-3", environment: "prod", requestedBy: "u", dryRun: false });
  assert.ok(untrusted.decision.reason_codes.includes("trusted-builder:untrusted_builder"));
  const source = await s.operator.supply_chain.gate({ evidence: { ...base, allowedRepositories: ["acme/other"] }, target: s.target, deploymentId: "d-4", environment: "prod", requestedBy: "u", dryRun: false });
  assert.ok(source.decision.reason_codes.includes("allowed-source:source_not_allowed"));

  // Provenance signed by a key the operator does not trust: unknown facts → deny.
  const rogue = new CoolClient({ project: "acme", signer: KEYS.rogue, trust: trust(), clock: () => new Date(T0) });
  const fakeBuild = rogue.evidence.record({ ...buildProvenance({ buildId: "b-x", builderId: "builder-1", repository: "acme/service", commit: "abc", artifactPath: s.artifactPath, finishedAt: iso(-60_000) }).build, observed_at: iso(-50_000) });
  const r = await s.operator.supply_chain.gate({ evidence: { ...base, build: fakeBuild, buildReport: s.operator.evidence.verify(fakeBuild, { purpose: "builder" }) }, target: s.target, deploymentId: "d-5", environment: "prod", requestedBy: "u", dryRun: false });
  assert.equal(r.decision.decision, "deny");
  assert.ok(r.decision.reason_codes.includes("provenance-verified:provenance_unverified"));
});

test("milestone: provenance for a different artifact (wrong subject / replayed provenance) is denied", async () => {
  const s = setup();
  const other = setup("a different release\n");
  const e = { ...s.evidence(), build: other.build, buildReport: s.operator.evidence.verify(other.build, { purpose: "builder" }) };
  const g = await s.operator.supply_chain.gate({ evidence: e, target: s.target, deploymentId: "d-6", environment: "prod", requestedBy: "u", dryRun: false });
  assert.ok(g.decision.reason_codes.includes("subject-match:wrong_provenance_subject"));
});

test("milestone: in audit mode the same gate only advises — nothing is deployed", async () => {
  const s = setup();
  const audit = new CoolClient({ project: "acme", signer: KEYS.source, trust: trust(), policyMode: "audit", enforcement: { enabled: true }, clock: () => new Date(T0) });
  const g = await audit.supply_chain.gate({ evidence: s.evidence(), target: s.target, deploymentId: "d-7", environment: "prod", requestedBy: "u", dryRun: false });
  assert.equal(g.decision.enforced, false);
  assert.equal(g.enforcement.state, "not_executed");
  assert.equal(existsSync(join(s.dir, "prod", "service.tar")), false);
});

test("milestone: the exported bundle verifies independently; tampering with it is caught", async () => {
  const s = setup();
  const g = await s.operator.supply_chain.gate({ evidence: s.evidence(), target: s.target, deploymentId: "d-8", environment: "prod", requestedBy: "u", dryRun: false });
  const records: SignedEnvelope[] = g.records.map((input) => s.operator.evidence.publish(s.operator.evidence.record({ ...input, observed_at: iso(), policy: undefined })));
  const bundle = exportBundle({ title: "release d-8", envelopes: [s.build, s.artifact, ...records], decisions: [g.decision], trust: trust(), exporter: KEYS.exporter, now: new Date(T0) });

  const json = JSON.parse(JSON.stringify(bundle));
  const report = verifyBundle(json, { registry, trust: trust(), now: T0, purpose: (t) => (t.startsWith("build") || t.startsWith("artifact") ? "builder" : "evidence") });
  assert.equal(report.overall_status, "pass", report.reasons.join("; "));
  assert.equal(report.timeline.entries.length, 4);
  assert.ok(report.timeline.links.some((l) => l.kind === "deterministic" && l.fields.includes("artifact_digest")));

  const dropped = { ...json, envelopes: json.envelopes.slice(1) };
  assert.equal(verifyBundle(dropped, { registry, trust: trust(), now: T0 }).checks.manifest_valid.reason, "manifest_mismatch");
  const selfTrust = verifyBundle(json, { registry, now: T0, purpose: (t) => (t.startsWith("build") || t.startsWith("artifact") ? "builder" : "evidence") });
  assert.equal(selfTrust.checks.trust_source.reason, "self_asserted_trust");
  assert.equal(selfTrust.overall_status, "unknown");
});
