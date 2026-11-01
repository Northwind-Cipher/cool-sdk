/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/** The tool gateway as an enforcement boundary: every refusal path, and confirmations. */
import test from "node:test";
import assert from "node:assert/strict";
import { MemoryNonceStore, ToolGateway, createAuthorizationRequest, decide, verifyConfirmation, type NonceStore } from "../src/authz/index";
import { KEYS, REFUND_POLICY, ROOT_DELEGATION, T0, world } from "./support/authz";

function setup(nonces: NonceStore = new MemoryNonceStore(), fail = false) {
  const { trust, directory } = world();
  const calls: unknown[] = [];
  const gw = new ToolGateway({ id: "gw", audience: "acme-payments", key: KEYS.gateway, trust, nonces, directory, roots: ["user:asha"], now: () => T0 });
  gw.register("issue_refund", { action: "refund", resource: "order:*", async execute(p) { if (fail) throw new Error("upstream 503"); calls.push(p); return { response: { ok: true }, external_ref: `txn-${calls.length}` }; } });
  const make = (amount = 200, extra: Record<string, unknown> = {}) => {
    const { request, secrets } = createAuthorizationRequest({ principal: "agent:refund-bot", action: "refund", resource: "order:1", audience: "acme-payments", policy_selector: "refunds", params: { order: "1", amount }, delegation: "del-root", now: T0, ...extra });
    const decision = decide({ request, policy: REFUND_POLICY, facts: { "refund.amount": amount }, evaluatorKey: KEYS.evaluator, now: T0 });
    return { request, secrets, decision, inv: { tool: "issue_refund", request, params: secrets.params, params_salt: secrets.params_salt, decision, delegation: [ROOT_DELEGATION()] } };
  };
  return { gw, calls, trust, make };
}

test("gateway: a permitted, bound, fresh request completes and is confirmed", async () => {
  const s = setup();
  const { inv, request } = s.make();
  const r = await s.gw.invoke(inv);
  assert.equal(r.confirmation.body.outcome, "completed");
  assert.equal(s.calls.length, 1);
  assert.equal(verifyConfirmation(r.confirmation, { request, trust: s.trust }).outcome, "completed");
});

test("gateway: substituted parameters, wrong audience, unknown tool and wrong action are rejected before anything runs", async () => {
  const s = setup();
  const m = s.make();
  assert.equal((await s.gw.invoke({ ...m.inv, params: { ...m.secrets.params, amount: 150 } })).confirmation.body.reason, "parameter_mismatch");
  const other = s.make(200, { audience: "other" });
  assert.equal((await s.gw.invoke(other.inv)).confirmation.body.reason, "wrong_audience");
  assert.equal((await s.gw.invoke({ ...m.inv, tool: "delete_db" })).confirmation.body.reason, "unknown_tool");
  const wrongAction = s.make(200, { action: "payout" });
  assert.equal((await s.gw.invoke(wrongAction.inv)).confirmation.body.reason, "tool_action_mismatch");
  assert.equal(s.calls.length, 0);
});

test("gateway: a revoked delegation, a forged decision and an unavailable replay store are refused", async () => {
  const s = setup();
  const m = s.make();
  const forged = decide({ request: m.request, policy: REFUND_POLICY, facts: { "refund.amount": 200 }, evaluatorKey: KEYS.rogue, now: T0 });
  assert.match((await s.gw.invoke({ ...m.inv, decision: forged })).confirmation.body.reason, /evaluator_trusted:untrusted_key/);

  const down: NonceStore = { consume: async () => "unavailable" };
  const s2 = setup(down);
  assert.equal((await s2.gw.invoke(s2.make().inv)).confirmation.body.reason, "replay_store_unavailable", "partition → explicit refusal, never a silent permit");

  const { trust, directory } = world();
  const gw = new ToolGateway({ id: "gw", audience: "acme-payments", key: KEYS.gateway, trust, nonces: new MemoryNonceStore(), directory, roots: ["user:asha"], revokedDelegations: () => new Set(["del-root"]), now: () => T0 });
  gw.register("issue_refund", { action: "refund", resource: "order:*", async execute() { return { response: 1 }; } });
  assert.match((await gw.invoke(s.make().inv)).confirmation.body.reason, /delegation_revoked/);
  assert.equal(s.calls.length + s2.calls.length, 0);
});

test("gateway: a tool failure is confirmed as failed, not completed; a tampered confirmation does not verify", async () => {
  const s = setup(new MemoryNonceStore(), true);
  const m = s.make();
  const r = await s.gw.invoke(m.inv);
  assert.equal(r.confirmation.body.outcome, "failed");
  assert.match(r.confirmation.body.reason, /upstream 503/);
  const tampered = { ...r.confirmation, body: { ...r.confirmation.body, outcome: "completed" as const } };
  assert.equal(verifyConfirmation(tampered, { request: m.request, trust: s.trust }).outcome, "unverified");
  const other = s.make();
  assert.equal(verifyConfirmation(r.confirmation, { request: other.request, trust: s.trust }).checks["request_binding"]!.reason, "request_mismatch");
});
