/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/** The shared policy engine: tri-valued logic, precedence, lifecycle, overrides. */
import test from "node:test";
import assert from "node:assert/strict";
import {
  PolicyRegistry,
  evaluatePolicy,
  overrideDecision,
  simulatePolicy,
  validatePolicy,
  type PolicyDocument,
} from "../src/platform/index";

const P: PolicyDocument = {
  schema: "cool.policy.v1",
  id: "prod-deploy",
  version: "1",
  mode: "enforce",
  default: "allow",
  on_unknown: "deny",
  rules: [
    { id: "signed", when: { fact: "artifact.signed", op: "eq", value: false }, decision: "deny", reason: "unsigned" },
    { id: "big-change", when: { fact: "change.lines", op: "gt", value: 500 }, decision: "require_approval", reason: "large_change" },
    { id: "env", when: { all: [{ fact: "env", op: "eq", value: "prod" }, { fact: "hour", op: "gte", value: 22 }] }, decision: "defer", reason: "after_hours", on_unknown: "audit_only" },
  ],
};
const NOW = new Date("2026-10-31T12:00:00Z");

test("policy: no rule matched → the policy default, recorded as such", () => {
  const r = evaluatePolicy(P, { "artifact.signed": true, "change.lines": 10, env: "dev", hour: 1 }, { now: NOW });
  assert.equal(r.decision, "allow");
  assert.deepEqual(r.reason_codes, ["no_rule_matched:default"]);
  assert.equal(r.enforced, true);
});

test("policy: a missing fact is UNKNOWN, resolved by on_unknown — never treated as safe", () => {
  const r = evaluatePolicy(P, { "change.lines": 10, env: "dev", hour: 1 }, { now: NOW });
  assert.equal(r.decision, "deny");
  const m = r.matched_rules.find((x) => x.id === "signed")!;
  assert.equal(m.result, "unknown");
  assert.deepEqual(m.unknown_facts, ["artifact.signed"]);
});

test("policy: the most restrictive contribution wins", () => {
  const r = evaluatePolicy(P, { "artifact.signed": true, "change.lines": 900, env: "prod", hour: 23 }, { now: NOW });
  assert.equal(r.decision, "require_approval");
  assert.deepEqual(r.matched_rules.map((m) => m.id), ["big-change", "env"]);
  const d = evaluatePolicy(P, { "artifact.signed": false, "change.lines": 900, env: "prod", hour: 23 }, { now: NOW });
  assert.equal(d.decision, "deny");
});

test("policy: a per-rule on_unknown overrides the policy's", () => {
  const r = evaluatePolicy(P, { "artifact.signed": true, "change.lines": 1, env: "prod" }, { now: NOW });
  assert.equal(r.decision, "audit_only");
  assert.equal(r.matched_rules[0]!.reason, "after_hours:unknown_input");
});

test("policy: deterministic — same policy, facts and time give the same record", () => {
  const facts = { "artifact.signed": true, "change.lines": 1, env: "dev", hour: 2 };
  assert.deepEqual(evaluatePolicy(P, facts, { now: NOW }), evaluatePolicy(P, { ...facts }, { now: NOW }));
  const reordered = Object.fromEntries(Object.entries(facts).reverse());
  assert.equal(evaluatePolicy(P, reordered, { now: NOW }).input_digest, evaluatePolicy(P, facts, { now: NOW }).input_digest);
});

test("policy: observe mode decides but does not mark for enforcement", () => {
  const r = evaluatePolicy({ ...P, mode: "observe" }, { "artifact.signed": false }, { now: NOW });
  assert.equal(r.decision, "deny");
  assert.equal(r.enforced, false);
});

test("policy: validation rejects malformed policies, and evaluation refuses them", () => {
  const bad = { ...P, default: "maybe", rules: [{ id: "a", when: { fact: "x", op: "like" }, decision: "allow", reason: "" }, { id: "a", when: { fact: "x", op: "matches", value: "(" }, decision: "nah", reason: "r" }] } as unknown as PolicyDocument;
  const problems = validatePolicy(bad);
  assert.ok(problems.some((p) => p.includes("default")));
  assert.ok(problems.some((p) => p.includes("known op")));
  assert.ok(problems.some((p) => p.includes("duplicated")));
  assert.ok(problems.some((p) => p.includes("invalid regex")));
  assert.ok(problems.some((p) => p.includes("reason code")));
  assert.throws(() => evaluatePolicy(bad, {}), /invalid policy/);
});

test("policy: simulation has no side effects and covers many inputs", () => {
  const out = simulatePolicy(P, [
    { name: "clean", facts: { "artifact.signed": true, "change.lines": 1, env: "dev", hour: 3 } },
    { name: "unsigned", facts: { "artifact.signed": false } },
  ]);
  assert.deepEqual(out.map((o) => o.decision), ["allow", "deny"]);
});

test("policy: an emergency override is attributable and keeps the original decision", () => {
  const r = evaluatePolicy(P, { "artifact.signed": false }, { now: NOW });
  assert.throws(() => overrideDecision(r, { actor: "", reason: "", decision: "allow" }), /actor and a reason/);
  const o = overrideDecision(r, { actor: "oncall:asha", reason: "sev1-hotfix", approver: "cto", decision: "allow", now: NOW });
  assert.equal(o.decision, "allow");
  assert.equal(o.override?.original_decision, "deny");
  assert.ok(o.reason_codes.includes("override:sev1-hotfix"));
});

test("policy lifecycle: draft → validated → approved → active; activation suspends the prior version; rollback leaves a trail", () => {
  const events: string[] = [];
  const reg = new PolicyRegistry({ onEvent: (e) => events.push(`${e.version}:${e.from_state}->${e.to_state}`), clock: () => NOW });
  const v2 = { ...P, version: "2" };
  for (const doc of [P, v2]) {
    reg.draft(doc, "author");
    reg.transition(doc.id, doc.version, "validated", "ci");
    reg.transition(doc.id, doc.version, "approved", "reviewer");
  }
  reg.transition(P.id, "1", "active", "ops");
  reg.transition(P.id, "2", "active", "ops");
  assert.equal(reg.active(P.id)?.version, "2");
  assert.equal(reg.state(P.id, "1"), "suspended");
  reg.transition(P.id, "1", "active", "ops"); // rollback
  assert.equal(reg.active(P.id)?.version, "1");
  assert.equal(reg.state(P.id, "2"), "suspended");
  assert.ok(events.includes("2:active->suspended"));
  assert.throws(() => reg.transition(P.id, "1", "draft", "x"), /cannot move/);
  assert.throws(() => reg.draft(P, "x"), /immutable/);
  const bad = { ...P, version: "3", default: "nope" } as unknown as PolicyDocument;
  reg.draft(bad, "author");
  assert.throws(() => reg.transition(P.id, "3", "validated", "ci"), /validation failed/);
});
