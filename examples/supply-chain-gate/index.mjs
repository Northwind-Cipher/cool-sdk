/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * A deployment gate in ~60 lines: signed provenance in, a verified decision
 * and a confirmed (or refused) deployment out, and a bundle anyone can check.
 *
 *   npm install
 *   node index.mjs
 *
 * Writes only to a fresh temporary directory. Makes no network calls.
 */
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair } from "cool-nwc";
import {
  CoolClient, LocalDirectoryTarget, PayloadRegistry, TransparencyLog, TrustStore,
  buildProvenance, exportBundle, verifyBundle,
} from "cool-nwc/platform";

const dir = mkdtempSync(join(tmpdir(), "cool-gate-"));
const builderKey = generateKeypair("ci-builder");
const opsKey = generateKeypair("ops");
const logKey = generateKeypair("log");
const key = (k, purposes) => ({ key_id: k.keyId, entry: k.directoryEntry, purposes, owner: "example", valid_from: "2026-01-01T00:00:00Z", status: "active" });
const trust = new TrustStore({ schema: "cool.trust-snapshot.v1", id: "example", as_of: new Date().toISOString(), keys: [key(builderKey, ["builder"]), key(opsKey, ["evidence"]), key(logKey, ["log"])] });
const log = new TransparencyLog("example-log", logKey);

// 1. CI builds an artifact and records signed provenance.
const ci = new CoolClient({ project: "example", signer: builderKey, trust, log });
const artifactPath = join(dir, "service.tar");
writeFileSync(artifactPath, "service v1\n");
const prov = buildProvenance({ buildId: "b-1", builderId: builderKey.keyId, repository: "acme/service", commit: "0".repeat(40), artifactPath, finishedAt: new Date().toISOString() });
const build = ci.evidence.publish(ci.evidence.record(prov.build));
const artifact = ci.evidence.publish(ci.evidence.record({ ...prov.artifact, provenance: { collection_method: "emitted", refs: [build.digest] } }));

// 2. Ops gates the deployment. Enforcement is explicitly enabled here.
const ops = new CoolClient({ project: "example", signer: opsKey, trust, log, policyMode: "enforce", enforcement: { enabled: true } });
const target = new LocalDirectoryTarget(join(dir, "prod"));
const evidence = () => ({
  artifactPath, build, artifact, trustedBuilders: [builderKey.keyId], allowedRepositories: ["acme/service"],
  buildReport: ops.evidence.verify(build, { purpose: "builder" }),
  artifactReport: ops.evidence.verify(artifact, { purpose: "builder" }),
});
const good = await ops.supply_chain.gate({ evidence: evidence(), target, deploymentId: "d-1", environment: "prod", requestedBy: "user:ops", dryRun: false });
console.log("benign   ", good.decision.decision, good.enforcement.state, "confirmed:", good.enforcement.confirmed);

writeFileSync(artifactPath, "service v1\n# tampered\n");
const bad = await ops.supply_chain.gate({ evidence: evidence(), target, deploymentId: "d-2", environment: "prod", requestedBy: "user:ops", dryRun: false });
console.log("tampered ", bad.decision.decision, bad.decision.reason_codes.join(", "));

// 3. Export everything and verify it the way an auditor would.
const records = [...good.records, ...bad.records].map((r) => ops.evidence.publish(ops.evidence.record(r)));
const bundle = exportBundle({ title: "example", envelopes: [build, artifact, ...records], decisions: [good.decision, bad.decision], trust, exporter: opsKey });
const report = verifyBundle(JSON.parse(JSON.stringify(bundle)), { registry: PayloadRegistry.standard(), trust, purpose: (t) => (/^(build|artifact)\./.test(t) ? "builder" : "evidence") });
console.log("bundle   ", report.overall_status, `${report.envelopes.length} envelopes`);

const ok = good.enforcement.confirmed && bad.decision.decision === "deny" && report.overall_status === "pass";
process.exit(ok ? 0 : 1);
