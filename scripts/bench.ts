/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Microbenchmarks for the hot paths: envelope sign/verify, authorization
 * request, decision, decision verification (with replay) and a full gateway
 * invocation. Single-threaded, in-process, no network.
 *
 *   npm run bench               # default iterations
 *   npm run bench -- 200        # iterations per operation
 *
 * Numbers are machine-dependent; they are a baseline for spotting
 * regressions, not a published performance claim.
 */
import { generateKeypair } from "../src/keys";
import {
  MemoryNonceStore,
  ToolGateway,
  createAuthorizationRequest,
  decide,
  verifyDecision,
} from "../src/authz/index";
import { PayloadRegistry, TrustStore, createEnvelope, signEnvelope, verifyEnvelope, type EnvelopeInput } from "../src/platform/index";
import { KEYS, REFUND_POLICY, ROOT_DELEGATION, world } from "../tests/support/authz";

export interface BenchRow { readonly op: string; readonly iterations: number; readonly median_ms: number; readonly p95_ms: number; readonly ops_per_s: number }

async function measure(op: string, iterations: number, fn: (i: number) => unknown): Promise<BenchRow> {
  for (let i = 0; i < Math.min(5, iterations); i++) await fn(-1 - i);
  const samples: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const t = performance.now();
    await fn(i);
    samples.push(performance.now() - t);
  }
  samples.sort((a, b) => a - b);
  const median = samples[Math.floor(samples.length / 2)]!;
  const p95 = samples[Math.min(samples.length - 1, Math.floor(samples.length * 0.95))]!;
  return { op, iterations, median_ms: +median.toFixed(3), p95_ms: +p95.toFixed(3), ops_per_s: Math.round(1000 / median) };
}

export async function runBench(iterations = 50): Promise<BenchRow[]> {
  const now = Date.now();
  const { trust: authzTrust, directory } = world(now);
  const recorder = generateKeypair("bench-recorder");
  const trust = new TrustStore({ ...authzTrust.snapshot(), keys: [...authzTrust.snapshot().keys, { key_id: recorder.keyId, entry: recorder.directoryEntry, purposes: ["evidence"], owner: "bench", valid_from: "2026-01-01T00:00:00Z", status: "active" }] });
  const registry = PayloadRegistry.standard();
  const input: EnvelopeInput = { event_type: "tool.invoked", occurred_at: new Date(now).toISOString(), source: { system: "bench" }, actor: { id: "agent:refund-bot", type: "workload" }, action: "invoke", resource: { type: "tool", ref: "issue_refund" }, payload: { tool: "issue_refund", request_id: "req_bench" } };
  const env = signEnvelope(createEnvelope(input, registry), recorder);

  const delegation = ROOT_DELEGATION({ issued_at: new Date(now - 3_600_000).toISOString(), not_before: new Date(now - 3_600_000).toISOString(), expires_at: new Date(now + 86_400_000).toISOString() });
  const mkRequest = (i: number) => createAuthorizationRequest({ principal: "agent:refund-bot", action: "refund", resource: "order:4471", audience: "acme-payments", policy_selector: "refunds", params: { order: "4471", amount: 200, recipient: `cust-${i}` }, delegation: delegation.body.delegation_id });
  const facts = { "refund.amount": 200 };
  const { request } = mkRequest(0);
  const decision = decide({ request, policy: REFUND_POLICY, facts, evaluatorKey: KEYS.evaluator });

  const gateway = new ToolGateway({ id: "bench-gateway", audience: "acme-payments", key: KEYS.gateway, trust: authzTrust, nonces: new MemoryNonceStore(), directory, roots: ["user:asha"] });
  gateway.register("issue_refund", { action: "refund", resource: "order:*", async execute() { return { response: { ok: true } }; } });

  return [
    await measure("envelope create + hybrid sign", iterations, () => signEnvelope(createEnvelope(input, registry), recorder)),
    await measure("envelope verify", iterations, () => verifyEnvelope(env, { registry, trust })),
    await measure("authorization request (commitments)", iterations, (i) => mkRequest(i)),
    await measure("decide (evaluate + sign)", iterations, () => decide({ request, policy: REFUND_POLICY, facts, evaluatorKey: KEYS.evaluator })),
    await measure("verify decision (enforcement, replayed)", iterations, () => verifyDecision(decision, { request, trust: authzTrust, mode: "enforcement", policy: REFUND_POLICY, facts, directory, delegation: { chain: [delegation], roots: ["user:asha"] } })),
    await measure("gateway invoke (end to end)", iterations, async (i) => {
      const { request: r, secrets } = mkRequest(1_000_000 + i);
      const d = decide({ request: r, policy: REFUND_POLICY, facts, evaluatorKey: KEYS.evaluator });
      const out = await gateway.invoke({ tool: "issue_refund", request: r, params: secrets.params, params_salt: secrets.params_salt, decision: d, delegation: [delegation], policy: REFUND_POLICY, facts });
      if (out.confirmation.body.outcome !== "completed") throw new Error(`bench gateway rejected: ${out.confirmation.body.reason}`);
    }),
  ];
}

if (process.argv[1] && /bench\.(ts|js|mjs)$/.test(process.argv[1])) {
  const n = Number(process.argv[2] ?? 50);
  runBench(Number.isFinite(n) && n > 0 ? n : 50).then((rows) => {
    console.log(`CooL microbenchmarks · node ${process.version} · ${process.platform}/${process.arch} · ${rows[0]?.iterations} iterations each`);
    console.table(rows);
  }).catch((e) => { console.error(e); process.exitCode = 1; });
}
