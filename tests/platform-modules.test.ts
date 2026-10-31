/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/** Identity & Authority, Change Control, Runtime Guard and Incident Evidence. */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AuthorizationMatrix,
  CHANGE_POLICY,
  CoolClient,
  CredentialLifecycle,
  EnforcementCoordinator,
  IncidentCase,
  LocalDenylistTarget,
  ReplayGuard,
  RolloutController,
  RuntimeGuard,
  buildTimeline,
  changeFacts,
  detectDrift,
  evaluatePolicy,
  verifyEnvelope,
} from "../src/platform/index";
import { KEYS, T0, iso, registry, trust } from "./support/platform";

const D = (c: string) => `mh:sha256:${c.repeat(64)}` as const;
const client = (signer = KEYS.sensor) => new CoolClient({ project: "acme", signer, trust: trust(), clock: () => new Date(T0) });

/* ── identity ─────────────────────────────────────────────────────────── */

test("identity: rotation is only final when the provider confirms; a timeout is unknown", () => {
  const c = new CredentialLifecycle("cred:db-prod", "vault", "svc-api");
  c.requestRotation("user:asha", iso());
  assert.equal(c.state, "rotation_requested");
  assert.equal(c.providerResult({ confirmed: false, timedOut: true, at: iso(1000) }), "unknown");
  assert.equal(c.providerResult({ confirmed: true, at: iso(2000) }), "rotated");
  const recs = c.records();
  assert.deepEqual(recs.map((r) => r.payload["to_state"]), ["rotation_requested", "unknown", "rotated"]);
  assert.deepEqual(recs.map((r) => r.payload["confirmed"]), [false, false, true]);
  for (const r of recs) client().evidence.create(r);

  const never = new CredentialLifecycle("cred:x", "vault", "s");
  never.requestRevocation("user:asha", iso());
  assert.equal(never.providerResult({ confirmed: false, at: iso(1) }), "revocation_requested");
  assert.throws(() => new CredentialLifecycle("c", "v", "s").providerResult({ confirmed: true, at: iso() }), /no pending request/);
});

test("identity: default deny, explicit grants, unknown identities and cross-tenant access", () => {
  const m = new AuthorizationMatrix([
    { actor: "user:asha", resource: "tenant-a/db", action: "read", environment: "prod" },
    { actor: "svc:ci", resource: "*", action: "deploy", environment: "staging" },
  ]);
  assert.equal(m.evaluate({ actor: "user:asha", resource: "tenant-a/db", action: "read", environment: "prod", actorKnown: true }).decision, "allow");
  assert.equal(m.evaluate({ actor: "user:asha", resource: "tenant-b/db", action: "read", environment: "prod", actorKnown: true }).reason, "no_matching_grant");
  assert.equal(m.evaluate({ actor: "svc:ci", resource: "anything", action: "deploy", environment: "prod", actorKnown: true }).decision, "deny");
  const unknown = m.evaluate({ actor: "user:asha", resource: "tenant-a/db", action: "read", environment: "prod", actorKnown: false });
  assert.equal(unknown.reason, "unknown_identity");
  assert.equal(unknown.record.event_type, "authorization.denied");
  client().evidence.create(unknown.record);
});

test("identity: a replayed token is detected within its lifetime", () => {
  const g = new ReplayGuard(60_000);
  assert.equal(g.check("jti-1", T0), "fresh");
  assert.equal(g.check("jti-1", T0 + 1_000), "replayed");
  assert.equal(g.check("jti-1", T0 + 120_000), "fresh");
});

/* ── change control ───────────────────────────────────────────────────── */

test("change control: altered after approval, stale, self-approved and missing approvals", () => {
  const now = T0;
  const ok = changeFacts({ author: "dev", appliedDigest: D("a"), approval: { approver: "lead", approved_digest: D("a"), approved_at: iso(-60_000) }, maxApprovalAgeMs: 86_400_000, now });
  assert.equal(evaluatePolicy(CHANGE_POLICY, ok, { now: new Date(now) }).decision, "allow");
  const altered = changeFacts({ author: "dev", appliedDigest: D("b"), approval: { approver: "lead", approved_digest: D("a"), approved_at: iso(-60_000) }, maxApprovalAgeMs: 86_400_000, now });
  assert.equal(evaluatePolicy(CHANGE_POLICY, altered).decision, "deny");
  const stale = changeFacts({ author: "dev", appliedDigest: D("a"), approval: { approver: "lead", approved_digest: D("a"), approved_at: iso(-10 * 86_400_000) }, maxApprovalAgeMs: 86_400_000, now });
  assert.equal(evaluatePolicy(CHANGE_POLICY, stale).decision, "require_approval");
  const self = changeFacts({ author: "dev", appliedDigest: D("a"), approval: { approver: "dev", approved_digest: D("a"), approved_at: iso(-60_000) }, maxApprovalAgeMs: 86_400_000, now });
  assert.equal(evaluatePolicy(CHANGE_POLICY, self).decision, "deny");
  assert.equal(evaluatePolicy(CHANGE_POLICY, changeFacts({ author: "dev", appliedDigest: D("a"), maxApprovalAgeMs: 1, now })).decision, "require_approval");
});

test("change control: drift is recorded only when the observed config differs", () => {
  assert.equal(detectDrift("nginx.conf", D("a"), D("a"), iso()), null);
  const d = detectDrift("nginx.conf", D("a"), D("b"), iso())!;
  assert.equal(client().evidence.create(d).event_type, "configuration.drift_detected");
});

test("change control: unknown health holds, failed health rolls back only with approval", () => {
  const r = new RolloutController("ro-1", D("a"), [{ name: "canary", percent: 5 }, { name: "half", percent: 50 }, { name: "all", percent: 100 }]);
  assert.equal(r.report("unknown", iso()), "hold");
  assert.equal(r.stage, "canary");
  assert.equal(r.report("pass", iso()), "promote");
  assert.equal(r.report("fail", iso()), "rollback");
  assert.throws(() => r.report("pass", iso()), /rollback_pending/);
  assert.equal(r.rollback(undefined), "rejected");
  assert.equal(r.rollback({ approver: "lead" }), "rolled_back");
  assert.deepEqual(r.records().map((x) => x.payload["action"]), ["hold", "promote", "rollback"]);

  const full = new RolloutController("ro-2", D("a"), [{ name: "all", percent: 100 }]);
  assert.equal(full.report("pass", iso()), "done");
});

/* ── runtime guard ────────────────────────────────────────────────────── */

const runtimeEvent = (signer = KEYS.sensor, payload: Record<string, unknown> = { workload: "api-7f9", from: "app", to: "root" }, type = "runtime.privilege_change", id = "ev-1") =>
  client(signer).evidence.record({ event_type: type, occurred_at: iso(-1_000), observed_at: iso(-500), source: { system: "falco", instance: "node-3", event_id: id }, actor: { id: "workload:api-7f9", type: "workload" }, action: "observe", resource: { type: "workload", ref: "api-7f9" }, payload });

test("runtime: spoofed (untrusted) events are never acted on; duplicates are dropped", () => {
  const g = new RuntimeGuard();
  const spoof = runtimeEvent(KEYS.rogue);
  assert.equal(g.ingest(spoof, verifyEnvelope(spoof, { registry, trust: trust(), now: T0 })), "untrusted_source");
  const real = runtimeEvent();
  const rep = verifyEnvelope(real, { registry, trust: trust(), now: T0 });
  assert.equal(g.ingest(real, rep), "accepted");
  assert.equal(g.ingest(real, rep), "duplicate");
});

test("runtime: privilege escalation → quarantine; the response is a dry run unless enabled, then confirmed", async () => {
  const g = new RuntimeGuard();
  const e = runtimeEvent();
  const decision = g.decide(e, new Date(T0));
  assert.equal(decision.decision, "quarantine");
  const dir = mkdtempSync(join(tmpdir(), "cool-rt-"));
  const target = new LocalDenylistTarget(join(dir, "deny.txt"));
  const dry = await g.respond(e, decision, new EnforcementCoordinator({ enabled: true }), target);
  assert.equal(dry?.state, "not_executed");
  const enforce = evaluatePolicy({ ...(await import("../src/platform/index")).RUNTIME_POLICY, mode: "enforce" }, { "event.type": "runtime.privilege_change", "privilege.to": "root" });
  const live = await g.respond(e, enforce, new EnforcementCoordinator({ enabled: true }), target, false);
  assert.equal(live?.confirmed, true);
  assert.match(readFileSync(join(dir, "deny.txt"), "utf8"), /api-7f9/);
});

test("runtime: unknown egress is not 'safe'; suppressed telemetry shows as silence and sequence gaps", () => {
  const g = new RuntimeGuard({ allowedDestinations: ["10.0.0.5"] });
  const egress = runtimeEvent(KEYS.sensor, { workload: "api", destination: "203.0.113.9", port: 443, protocol: "tcp" }, "runtime.network", "net-1");
  assert.equal(g.decide(egress).decision, "require_approval");
  const noList = new RuntimeGuard();
  assert.equal(noList.decide(egress).decision, "audit_only"); // allowlist unknown → audit, not allow

  for (const seq of [1, 2, 5]) {
    const hb = runtimeEvent(KEYS.sensor, { source: "node-3", sequence: seq }, "runtime.heartbeat", `hb-${seq}`);
    g.ingest(hb, verifyEnvelope(hb, { registry, trust: trust(), now: T0 }));
  }
  const gaps = g.telemetryGaps(T0 + 600_000, 60_000);
  assert.deepEqual(gaps.silent, ["node-3"]);
  assert.deepEqual(gaps.sequenceGaps, [{ source: "node-3", missing: [3, 4] }]);
});

/* ── incidents and correlation ────────────────────────────────────────── */

test("incident: timeline labels, heuristic vs deterministic links, contradictions and gaps", () => {
  const c = client();
  const req = c.evidence.record({ event_type: "deployment.requested", occurred_at: iso(-1_000), observed_at: iso(-900), source: { system: "cd" }, actor: { id: "user:asha", type: "human" }, action: "request_deploy", resource: { type: "environment", ref: "prod" }, payload: { deployment_id: "d-9", artifact_digest: D("c"), environment: "prod", target: "k8s" } });
  const done = c.evidence.record({ event_type: "deployment.completed", occurred_at: iso(-5_000), observed_at: iso(-800), source: { system: "cd" }, actor: { id: "svc:cd", type: "service" }, action: "deploy", resource: { type: "environment", ref: "prod" }, payload: { deployment_id: "d-9", artifact_digest: D("c"), environment: "prod", target: "k8s", outcome: "succeeded", confirmed: true } });
  const other = c.evidence.record({ event_type: "secret.accessed", occurred_at: iso(-700), observed_at: iso(-600), source: { system: "vault" }, actor: { id: "user:asha", type: "human" }, action: "read", resource: { type: "secret", ref: "db" }, provenance: { collection_method: "imported", refs: [D("f")] }, payload: { secret_ref: "kv/db", accessor: "user:asha", vault: "vault-1" } });
  const spoof = client(KEYS.rogue).evidence.record({ event_type: "secret.accessed", occurred_at: iso(-650), observed_at: iso(-640), source: { system: "vault" }, actor: { id: "user:mallory", type: "human" }, action: "read", resource: { type: "secret", ref: "db" }, payload: { secret_ref: "kv/db", accessor: "user:mallory", vault: "vault-1" } });

  const envs = [req, done, other, spoof];
  const reports = envs.map((e) => verifyEnvelope(e, { registry, trust: trust(), now: T0 }));
  const t = buildTimeline(envs, reports);
  assert.ok(t.contradictions.some((x) => /precedes deployment.requested/.test(x)));
  assert.equal(t.entries.find((e) => e.event_id === done.core.event_id)?.label, "contradicted");
  assert.equal(t.entries.find((e) => e.event_id === spoof.core.event_id)?.label, "source-asserted");
  assert.deepEqual(t.gaps.map((g) => g.ref), [D("f")]);
  assert.ok(t.entries.some((e) => e.label === "missing"));
  const det = t.links.find((l) => l.fields.includes("deployment_id"));
  assert.equal(det?.kind, "deterministic");
  const heur = t.links.find((l) => l.kind === "heuristic");
  assert.equal(heur?.label, "inferred");
  assert.match(heur!.rule, /same-actor-window/);
});

test("incident: a case references evidence by digest and exports a verifiable bundle", async () => {
  const c = client();
  const inc = new IncidentCase("INC-7", "suspicious secret read", "high");
  const opened = c.evidence.record(inc.opened(iso(-100), "user:asha"));
  const evt = runtimeEvent();
  const added = c.evidence.record(inc.add(evt, verifyEnvelope(evt, { registry, trust: trust(), now: T0 }), iso(-50), "user:asha"));
  assert.equal(added.core.payload["label"], "verified");
  assert.deepEqual(added.core.relations.map((r) => r.ref), [evt.digest]);
  const closed = c.evidence.record(inc.close("credential rotated", iso(-10), "user:asha"));
  assert.throws(() => inc.add(evt, undefined, iso(), "x"), /closed/);
  const bundle = inc.export([opened, added, closed], trust(), KEYS.exporter, new Date(T0));
  const { verifyBundle } = await import("../src/platform/index");
  const rep = verifyBundle(JSON.parse(JSON.stringify(bundle)), { registry, trust: trust(), now: T0 });
  assert.equal(rep.overall_status, "pass", rep.reasons.join("; "));
  assert.equal(rep.checks.evidence_complete.status, "pass");
});
