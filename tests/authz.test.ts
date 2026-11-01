/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Principals, delegation, requests, decisions, replay and execution binding —
 * every attack named in the spec, asserted by status AND reason code.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  FileNonceStore,
  MemoryNonceStore,
  compareExecution,
  commitValue,
  createAuthorizationRequest,
  decide,
  enrollPrincipal,
  grantDelegation,
  normalize,
  paramsMatch,
  principalEvent,
  requestDigest,
  verifyDecision,
  verifyDelegationChain,
  type AuthorizationRequest,
} from "../src/authz/index";
import { CooLError } from "../src/errors";
import { KEYS, REFUND_POLICY, ROOT_DELEGATION, T0, at, world } from "./support/authz";

const D = (c: string) => `mh:sha256:${c.repeat(64)}` as const;
const refund = (amount: number, extra: Partial<Parameters<typeof createAuthorizationRequest>[0]> = {}) =>
  createAuthorizationRequest({ principal: "agent:refund-bot", action: "refund", resource: "order:4471", audience: "acme-payments", policy_selector: "refunds", params: { order: "4471", amount, recipient: "cust-981" }, now: T0, ...extra });

/* ── principals ───────────────────────────────────────────────────────── */

test("principal: enrolled, rotated without changing identity, and judged at event time", () => {
  const { directory } = world();
  assert.equal(directory.check("agent:refund-bot", T0, KEYS.agent.keyId).status, "pass");
  assert.equal(directory.apply(principalEvent({ event_id: "e1", principal_id: "agent:refund-bot", kind: "key_bound", at: at(1_000), key_id: KEYS.agentRotated.keyId, entry: KEYS.agentRotated.directoryEntry }, KEYS.issuer)).status, "pass");
  directory.apply(principalEvent({ event_id: "e2", principal_id: "agent:refund-bot", kind: "key_retired", at: at(2_000), key_id: KEYS.agent.keyId }, KEYS.issuer));
  assert.equal(directory.check("agent:refund-bot", T0 + 3_000, KEYS.agentRotated.keyId).status, "pass");
  assert.equal(directory.check("agent:refund-bot", T0 + 3_000, KEYS.agent.keyId).reason, "key_not_bound");
  assert.equal(directory.check("agent:refund-bot", T0, KEYS.agent.keyId).status, "pass", "before rotation the old key was valid");
});

test("principal: revoked and unknown identities are never accepted; forged lifecycle changes are refused", () => {
  const { directory } = world();
  directory.apply(principalEvent({ event_id: "r1", principal_id: "agent:refund-bot", kind: "revoked", at: at(10_000), reason: "compromised" }, KEYS.issuer));
  assert.equal(directory.check("agent:refund-bot", T0 + 20_000).reason, "principal_revoked");
  assert.equal(directory.check("agent:refund-bot", T0).status, "pass", "revocation is not retroactive");
  assert.equal(directory.check("agent:ghost", T0).reason, "unknown_principal");
  const forged = principalEvent({ event_id: "x", principal_id: "agent:refund-helper", kind: "revoked", at: at() }, KEYS.rogue);
  assert.equal(directory.apply(forged).reason, "key_substitution");
  const untrustedIssuer = enrollPrincipal({ principal_id: "agent:evil", kind: "agent", issuer: KEYS.rogue.keyId, owner: "x", basis: "self_asserted", created_at: at(-1000), keys: [] }, KEYS.rogue);
  assert.equal(directory.enroll(untrustedIssuer).reason, "untrusted_key");
});

/* ── delegation ───────────────────────────────────────────────────────── */

const ask = { requester: "agent:refund-bot", action: "refund", resource: "order:4471", audience: "acme-payments", amount: 200 };

test("delegation: a valid human→agent chain authorises the concrete request", () => {
  const { directory } = world();
  const c = verifyDelegationChain([ROOT_DELEGATION()], ask, { directory, roots: ["user:asha"], at: T0 });
  assert.equal(c.status, "pass", c.detail);
});

test("delegation: privilege amplification, altered scope, expiry, revocation, cycles and depth all fail closed", () => {
  const { directory } = world();
  const o = { directory, roots: ["user:asha"], at: T0 };
  const root = ROOT_DELEGATION();
  const child = (scope: { actions: string[]; resources: string[]; max_amount?: number }, extra = {}) => grantDelegation({ delegation_id: "del-child", delegator: "agent:refund-bot", delegate: "agent:refund-helper", scope, audience: "acme-payments", not_before: at(-1000), expires_at: at(3_600_000), nonce: "n-c", parent: "del-root", issued_at: at(-1000), ...extra }, KEYS.agent);
  const helperAsk = { ...ask, requester: "agent:refund-helper" };

  assert.equal(verifyDelegationChain([root, child({ actions: ["refund"], resources: ["order:4471"], max_amount: 100 })], helperAsk, o).reason, "scope_exceeded", "amount 200 > child ceiling 100");
  assert.equal(verifyDelegationChain([root, child({ actions: ["refund"], resources: ["order:4471"], max_amount: 300 })], helperAsk, o).status, "pass", "agent→agent narrowing is fine");
  assert.equal(verifyDelegationChain([root, child({ actions: ["refund", "payout"], resources: ["order:*"], max_amount: 100 })], helperAsk, o).reason, "privilege_amplification");
  assert.equal(verifyDelegationChain([root, child({ actions: ["refund"], resources: ["order:*"], max_amount: 5000 })], helperAsk, o).reason, "privilege_amplification");
  assert.equal(verifyDelegationChain([root, child({ actions: ["refund"], resources: ["*"], max_amount: 100 })], helperAsk, o).reason, "privilege_amplification");

  const altered = { ...root, body: { ...root.body, scope: { ...root.body.scope, max_amount: 50_000 } } };
  assert.equal(verifyDelegationChain([altered], ask, o).reason, "digest_mismatch");
  assert.equal(verifyDelegationChain([ROOT_DELEGATION({ expires_at: at(-1) })], ask, o).reason, "delegation_expired");
  assert.equal(verifyDelegationChain([root, child({ actions: ["refund"], resources: ["order:4471"], max_amount: 300 })], helperAsk, { ...o, revoked: new Set(["del-root"]) }).reason, "delegation_revoked", "revoked parent");
  const loop = grantDelegation({ delegation_id: "del-loop", delegator: "agent:refund-bot", delegate: "user:asha", scope: { actions: ["refund"], resources: ["order:4471"], max_amount: 100 }, audience: "acme-payments", not_before: at(-1000), expires_at: at(1000), nonce: "n-l", parent: "del-root", issued_at: at(-1000) }, KEYS.agent);
  assert.equal(verifyDelegationChain([root, loop], { ...ask, requester: "user:asha" }, o).reason, "delegation_cycle");
  assert.equal(verifyDelegationChain([root, root, root, root, root], ask, o).reason, "delegation_too_deep");
  assert.equal(verifyDelegationChain([root], ask, { ...o, roots: ["user:someone-else"] }).reason, "untrusted_root");
  assert.equal(verifyDelegationChain([ROOT_DELEGATION()], { ...ask, amount: 900 }, o).reason, "scope_exceeded");
});

test("delegation: a key not bound to the delegator at issue time, and revocation of the delegator, are refused", () => {
  const { directory } = world();
  const byRogue = grantDelegation({ ...ROOT_DELEGATION().body }, KEYS.rogue);
  assert.equal(verifyDelegationChain([byRogue], ask, { directory, roots: ["user:asha"], at: T0 }).reason, "key_not_bound");
  directory.apply(principalEvent({ event_id: "s1", principal_id: "user:asha", kind: "suspended", at: at(-10) }, KEYS.issuer));
  assert.equal(verifyDelegationChain([ROOT_DELEGATION()], ask, { directory, roots: ["user:asha"], at: T0 }).reason, "principal_suspended", "a concurrent lifecycle change takes effect");
});

/* ── requests ─────────────────────────────────────────────────────────── */

test("request: parameter, recipient, amount, resource and audience substitution break the binding", () => {
  const { request, secrets } = refund(200);
  assert.equal(paramsMatch(request, secrets.params, secrets.params_salt), true);
  assert.equal(paramsMatch(request, { ...secrets.params, amount: 2000 }, secrets.params_salt), false, "amount change");
  assert.equal(paramsMatch(request, { ...secrets.params, recipient: "attacker" }, secrets.params_salt), false, "recipient substitution");
  const base = requestDigest(request);
  for (const change of [{ resource: "order:9999" }, { audience: "other-service" }, { action: "payout" }, { principal: "agent:refund-helper" }, { nonce: "0".repeat(32) }]) {
    assert.notEqual(requestDigest({ ...request, ...change } as AuthorizationRequest), base, JSON.stringify(change));
  }
});

test("request: normalization — NFC, absent vs undefined vs null, integers only; keyed commitments resist guessing", () => {
  const salt = "00".repeat(16);
  assert.equal(commitValue("params", { name: "Amélie" }, salt), commitValue("params", { name: "Amélie" }, salt), "NFC-equivalent strings commit identically");
  assert.equal(commitValue("params", { a: 1, b: undefined }, salt), commitValue("params", { a: 1 }, salt), "undefined is absent");
  assert.notEqual(commitValue("params", { a: 1, b: null }, salt), commitValue("params", { a: 1 }, salt), "null is a value");
  assert.equal(commitValue("params", { b: 2, a: 1 }, salt), commitValue("params", { a: 1, b: 2 }, salt), "map order is canonical");
  assert.throws(() => normalize({ amount: 12.5 }), (e: unknown) => e instanceof CooLError && /send decimals as strings/.test(e.message));
  assert.throws(() => normalize({ when: new Date() }), CooLError);
  const key = new Uint8Array(32).fill(9);
  assert.notEqual(commitValue("params", { approve: "yes" }, salt, key), commitValue("params", { approve: "yes" }, salt), "keyed differs from salted");
  const { request } = refund(200, { commitmentKey: key });
  assert.equal(request.commitment_scheme, "hmac-sha-256");
});

test("request: published cross-language test vectors still hold", () => {
  const vectors = JSON.parse(readFileSync(join(import.meta.dirname, "..", "spec", "test-vectors", "authz-commitments.v1.json"), "utf8"));
  for (const v of vectors.commitments) {
    assert.equal(commitValue(v.kind, v.value, v.salt, v.key ? Uint8Array.from(Buffer.from(v.key, "hex")) : undefined), v.commitment, v.name);
  }
});

/* ── decisions ────────────────────────────────────────────────────────── */

test("decision: permit / deny / indeterminate / error, each signed and bound", () => {
  const { request } = refund(200);
  assert.equal(decide({ request, policy: REFUND_POLICY, facts: { "refund.amount": 200 }, evaluatorKey: KEYS.evaluator, now: T0 }).body.decision, "permit");
  assert.equal(decide({ request, policy: REFUND_POLICY, facts: { "refund.amount": 900 }, evaluatorKey: KEYS.evaluator, now: T0 }).body.decision, "deny");
  const approval = { ...REFUND_POLICY, rules: [{ id: "review", when: { fact: "refund.amount", op: "gt" as const, value: 0 }, decision: "require_approval" as const, reason: "manual_review" }] };
  assert.equal(decide({ request, policy: approval, facts: { "refund.amount": 10 }, evaluatorKey: KEYS.evaluator, now: T0 }).body.decision, "indeterminate");
  const broken = { ...REFUND_POLICY, default: "maybe" } as never;
  assert.equal(decide({ request, policy: broken, facts: {}, evaluatorKey: KEYS.evaluator, now: T0 }).body.decision, "error");
  assert.equal(decide({ request, policy: REFUND_POLICY, facts: { "refund.amount": 200 }, evaluatorKey: KEYS.evaluator, now: T0 + 3_600_000 }).body.reasons[0], "request_expired");
});

test("decision: replays identically; policy, request, facts and evaluator substitution are detected", () => {
  const { trust } = world();
  const { request } = refund(200);
  const facts = { "refund.amount": 200 };
  const d = decide({ request, policy: REFUND_POLICY, facts, evaluatorKey: KEYS.evaluator, now: T0 });
  const ok = verifyDecision(d, { request, trust, mode: "historical", policy: REFUND_POLICY, facts, now: T0 });
  assert.equal(ok.outcome, "indeterminate", "no directory: principal state not checked");
  assert.equal(ok.checks.reproduced.reason, "replayed_identically");
  assert.equal(ok.assurance, "reproducible");

  const v2 = { ...REFUND_POLICY, version: "2", rules: [{ ...REFUND_POLICY.rules[0]!, when: { fact: "refund.amount", op: "lte" as const, value: 50 } }] };
  assert.equal(verifyDecision(d, { request, trust, mode: "historical", policy: v2, facts, now: T0 }).checks.policy_binding.reason, "policy_mismatch", "policy substitution");
  assert.equal(verifyDecision(d, { request, trust, mode: "historical", policy: REFUND_POLICY, facts: { "refund.amount": 499 }, now: T0 }).checks.reproduced.reason, "input_mismatch");
  assert.equal(verifyDecision(d, { request: refund(200).request, trust, mode: "historical", now: T0 }).checks.request_binding.reason, "request_mismatch");
  const forgedEvaluator = decide({ request, policy: REFUND_POLICY, facts, evaluatorKey: KEYS.rogue, now: T0 });
  assert.equal(verifyDecision(forgedEvaluator, { request, trust, mode: "historical", now: T0 }).checks.evaluator_trusted.reason, "untrusted_key");
  const tampered = { ...d, body: { ...d.body, decision: "permit" as const, evaluator: { id: "cool-nwc/policy-engine", version: "2" } } };
  assert.equal(verifyDecision(tampered, { request, trust, mode: "historical", now: T0 }).checks.integrity.reason, "digest_mismatch");
});

test("decision: at the enforcement boundary an expired decision is stale", () => {
  const { trust, directory } = world();
  const { request } = refund(200);
  const d = decide({ request, policy: REFUND_POLICY, facts: { "refund.amount": 200 }, evaluatorKey: KEYS.evaluator, now: T0 });
  const r = verifyDecision(d, { request, trust, directory, mode: "enforcement", now: T0 + 3_600_000 });
  assert.equal(r.checks.freshness.reason, "decision_expired");
  assert.equal(r.outcome, "stale");
});

/* ── replay and execution binding ─────────────────────────────────────── */

test("replay: simultaneous attempts consume a nonce at most once — in memory and across processes", async () => {
  const mem = new MemoryNonceStore();
  const results = await Promise.all(Array.from({ length: 25 }, (_, i) => mem.consume("acme-payments", "nonce-1", `r${i}`)));
  assert.equal(results.filter((r) => r === "consumed").length, 1);
  const dir = mkdtempSync(join(tmpdir(), "cool-nonce-"));
  const a = new FileNonceStore(dir);
  const b = new FileNonceStore(dir);
  const both = await Promise.all([a.consume("aud", "n", "r1"), b.consume("aud", "n", "r2"), a.consume("aud", "n", "r3")]);
  assert.equal(both.filter((r) => r === "consumed").length, 1);
  const blocked = join(dir, "not-a-dir");
  writeFileSync(blocked, "x");
  const broken = Object.create(FileNonceStore.prototype) as FileNonceStore;
  Object.assign(broken, { dir: join(blocked, "inside") });
  assert.equal(await broken.consume("aud", "n2", "r"), "unavailable", "a broken store is unavailable, never a permit");
});

test("execution: a substituted artifact, workload or configuration is a mismatch", () => {
  const planned = { workload_id: "refund-bot", artifact_digest: D("a"), config_digest: D("c"), platform: "linux/amd64" };
  assert.equal(compareExecution(planned, planned).status, "pass");
  assert.equal(compareExecution(planned, { ...planned, artifact_digest: D("b") }).reason, "execution_mismatch");
  assert.equal(compareExecution(planned, { ...planned, workload_id: "other" }).reason, "execution_mismatch");
  assert.equal(compareExecution(planned, undefined).reason, "no_observed_execution");
  assert.equal(compareExecution(undefined, planned).status, "not_applicable");
});
