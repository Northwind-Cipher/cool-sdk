/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The agent-action demo: one consequential action, followed from principal
 * identity through delegation, a concrete authorization request, deterministic
 * policy evaluation, a real enforcement boundary, external confirmation,
 * cryptographic evidence, transparency and offline verification.
 *
 *   npm run demo:agent              # writes to a fresh temp directory
 *   npm run demo:agent -- ./out     # keep the artifacts
 *
 * Scenarios (spec chapter 47):
 *   A  a legitimate agent action under policy completes and is confirmed
 *   B  a request beyond authority is rejected BY THE ENFORCEMENT BOUNDARY
 *   C  the policy changes later; the historical decision keeps its version
 *   D  a consumed authorization replayed is rejected — even under a race
 *   E  a substituted workload breaks the execution binding
 *   F  receipt tampering is detected
 *   G  a dropped event makes the history incomplete, not clean
 *   H  a stale attestation is reported stale, not verified
 *
 * What is real: every signature, digest, policy evaluation, nonce, the
 * gateway's checks, and the refund ledger file it writes to — the gateway owns
 * that ledger, so "rejected" means the ledger did not change. What stands in:
 * the ledger represents a payment system; scenario H's attestation is signed
 * on a SYNTHETIC test PKI. No network is used.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { generateKeypair } from "../src/keys";
import { mhSha256 } from "../src/multihash";
import { canonicalCbor } from "../src/canonical";
import {
  FileNonceStore,
  ToolGateway,
  createAuthorizationRequest,
  decide,
  verifyConfirmation,
  verifyDecision,
  type AuthorizationRequest,
  type ExecutionContext,
} from "../src/authz/index";
import {
  CoolClient,
  PayloadRegistry,
  TransparencyLog,
  TrustStore,
  createEnvelope,
  exportBundle,
  nitroAdapter,
  signEnvelope,
  verifyBundle,
  verifyEnvelope,
  type EnvelopeInput,
  type PolicyDocument,
  type SignedEnvelope,
} from "../src/platform/index";
import { trustBundleFromDer } from "../src/nitro/index";
import { KEYS, REFUND_POLICY, ROOT_DELEGATION, world } from "../tests/support/authz";
import { pcrHex, syntheticAttestation, syntheticNitroPki } from "../tests/support/synthetic-pki";

const COLOR = !process.env["NO_COLOR"] && process.stdout.isTTY;
const paint = (c: string) => (s: string) => (COLOR ? `\x1b[${c}m${s}\x1b[0m` : s);
const [bold, dim, green, red, cyan, yellow] = ["1", "2", "32", "31", "36", "33"].map(paint) as [(s: string) => string, (s: string) => string, (s: string) => string, (s: string) => string, (s: string) => string, (s: string) => string];

export interface DemoResult { readonly scenario: string; readonly claim: string; readonly ok: boolean; readonly detail: string }

export async function runAgentDemo(options: { readonly dir?: string; readonly quiet?: boolean } = {}): Promise<{ dir: string; results: DemoResult[]; passed: number; failed: number }> {
  const dir = resolve(options.dir ?? mkdtempSync(join(tmpdir(), "cool-agent-demo-")));
  mkdirSync(dir, { recursive: true });
  const log = (l = "") => { if (!options.quiet) console.log(l); };
  const results: DemoResult[] = [];
  let scenario = "";
  const section = (id: string, title: string) => { scenario = `${id} ${title}`; log(); log(`${bold(cyan(id))}  ${bold(title)}`); };
  const expect = (ok: boolean, claim: string, detail = "") => { results.push({ scenario, claim, ok, detail }); log(`    ${ok ? green("✓") : red("✕")} ${claim}${detail ? dim(`  — ${detail}`) : ""}`); };

  log(bold("CooL agent-action demo — from principal to verified evidence"));
  log(dim("every ✓ is checked as it runs · the refund ledger stands in for a payment system · scenario H uses a synthetic PKI · no network"));

  /* world: identities, keys, trust, delegation, evidence plumbing */
  const now = Date.now();
  const { trust: authzTrust, directory } = world(now);
  const recorder = generateKeypair("evidence-recorder");
  const logKey = generateKeypair("transparency-log");
  const base = authzTrust.snapshot();
  const trust = new TrustStore({ ...base, as_of: new Date(now - 60_000).toISOString(), keys: [...base.keys, { key_id: recorder.keyId, entry: recorder.directoryEntry, purposes: ["evidence"], owner: "demo", valid_from: "2026-01-01T00:00:00Z", status: "active" }, { key_id: logKey.keyId, entry: logKey.directoryEntry, purposes: ["log"], owner: "demo", valid_from: "2026-01-01T00:00:00Z", status: "active" }] });
  const registry = PayloadRegistry.standard();
  const tlog = new TransparencyLog("agent-demo-log", logKey);
  const cool = new CoolClient({ project: "agent-demo", signer: recorder, trust, log: tlog });
  const evidence: SignedEnvelope[] = [];
  const attachments: Array<{ kind: string; body: unknown }> = [];
  const record = (input: EnvelopeInput) => { const e = cool.evidence.publish(cool.evidence.record(input)); evidence.push(e); return e; };
  const delegation = ROOT_DELEGATION({ issued_at: new Date(now - 3_600_000).toISOString(), not_before: new Date(now - 3_600_000).toISOString(), expires_at: new Date(now + 86_400_000).toISOString() });
  attachments.push({ kind: "delegation", body: delegation });
  record({ event_type: "delegation.granted", occurred_at: delegation.body.issued_at, source: { system: "acme-idp" }, actor: { id: "user:asha", type: "human" }, action: "delegate", resource: { type: "principal", ref: "agent:refund-bot" }, payload: { delegation_id: delegation.body.delegation_id, delegator: delegation.body.delegator, delegate: delegation.body.delegate, audience: delegation.body.audience, expires_at: delegation.body.expires_at, delegation_digest: delegation.digest } });

  const planned: ExecutionContext = { workload_id: "refund-bot", artifact_digest: mhSha256(new TextEncoder().encode("refund-bot:v3.2.0")), config_digest: mhSha256(new TextEncoder().encode("refund-bot.yaml")), platform: "linux/amd64" };
  let observed: ExecutionContext = planned;
  const ledgerPath = join(dir, "refund-ledger.jsonl");
  writeFileSync(ledgerPath, "");
  const ledger = () => readFileSync(ledgerPath, "utf8").split("\n").filter(Boolean);
  const gateway = new ToolGateway({ id: "acme-payments-gateway", audience: "acme-payments", key: KEYS.gateway, trust: authzTrust, nonces: new FileNonceStore(join(dir, "nonces")), directory, roots: ["user:asha"], observedExecution: () => observed });
  gateway.register("issue_refund", {
    action: "refund",
    resource: "order:*",
    async execute(params) {
      const entry = { txn: `rf_${ledger().length + 1}`, order: params["order"], amount: params["amount"], recipient: params["recipient"] };
      writeFileSync(ledgerPath, `${JSON.stringify(entry)}\n`, { flag: "a" });
      return { response: entry, external_ref: entry.txn };
    },
  });

  const flow = async (amount: number, o: { policy?: PolicyDocument; execution?: ExecutionContext; order?: string } = {}) => {
    const order = o.order ?? "4471";
    const { request, secrets } = createAuthorizationRequest({ principal: "agent:refund-bot", action: "refund", resource: `order:${order}`, audience: "acme-payments", policy_selector: "refunds", params: { order, amount, recipient: "cust-981" }, delegation: delegation.body.delegation_id, execution: o.execution ?? planned });
    const policy = o.policy ?? REFUND_POLICY;
    const facts = { "refund.amount": amount };
    const decision = decide({ request, policy, facts, evaluatorKey: KEYS.evaluator });
    const invoke = () => gateway.invoke({ tool: "issue_refund", request, params: secrets.params, params_salt: secrets.params_salt, decision, delegation: [delegation], policy, facts });
    return { request, secrets, decision, policy, facts, invoke };
  };
  const recordFlow = (f: { request: AuthorizationRequest; decision: ReturnType<typeof decide> }, confirmation: Awaited<ReturnType<ToolGateway["invoke"]>>["confirmation"]) => {
    attachments.push({ kind: "authz-request", body: f.request }, { kind: "authz-decision", body: f.decision }, { kind: "external-confirmation", body: confirmation });
    const req = record({ event_type: "authorization.requested", occurred_at: f.request.issued_at, source: { system: "refund-bot", event_id: f.request.request_id }, actor: { id: "agent:refund-bot", type: "workload" }, action: "request", resource: { type: "order", ref: f.request.resource }, payload: { request_id: f.request.request_id, request_digest: f.decision.body.request_digest, principal: f.request.principal, action: f.request.action, resource: f.request.resource, audience: f.request.audience, policy_selector: f.request.policy_selector, params_commitment: f.request.params_commitment, expires_at: f.request.expires_at, delegation: f.request.delegation } });
    const dec = record({ event_type: "authorization.decided", occurred_at: f.decision.body.decided_at, source: { system: "acme-pdp", event_id: f.decision.body.decision_id }, actor: { id: "service:acme-pdp", type: "service" }, action: "decide", resource: { type: "request", ref: f.request.request_id }, provenance: { collection_method: "emitted", refs: [req.digest] }, payload: { decision_id: f.decision.body.decision_id, decision: f.decision.body.decision, request_id: f.request.request_id, request_digest: f.decision.body.request_digest, policy_digest: f.decision.body.policy.digest, evaluator: `${f.decision.body.evaluator.id}@${f.decision.body.evaluator.version}`, assurance: f.decision.body.assurance, decision_digest: f.decision.digest } });
    return record({ event_type: "external.confirmed", occurred_at: confirmation.body.confirmed_at, source: { system: confirmation.body.target, event_id: confirmation.body.confirmation_id }, actor: { id: "service:acme-payments-gateway", type: "service" }, action: "confirm", resource: { type: "request", ref: f.request.request_id }, provenance: { collection_method: "emitted", refs: [dec.digest] }, payload: { confirmation_id: confirmation.body.confirmation_id, target: confirmation.body.target, request_id: f.request.request_id, decision_id: confirmation.body.decision_id, outcome: confirmation.body.outcome, reason: confirmation.body.reason, response_digest: confirmation.body.response_digest, confirmation_digest: confirmation.digest } });
  };

  /* A */
  section("A", "A legitimate agent action under policy");
  const a = await flow(200);
  const ra = await a.invoke();
  expect(a.decision.body.decision === "permit", "refund of 200 within delegated authority → policy decision permit", a.decision.body.reasons.join(", "));
  expect(ra.confirmation.body.outcome === "completed" && ledger().length === 1, "the gateway executed it and the ledger shows the refund", ra.confirmation.body.external_ref);
  const vcA = verifyConfirmation(ra.confirmation, { request: a.request, trust: authzTrust });
  expect(vcA.outcome === "completed", "the external confirmation verifies: signed by the trusted gateway, bound to this request");
  const confA = recordFlow(a, ra.confirmation);
  const hist = verifyDecision(a.decision, { request: a.request, trust: authzTrust, directory, mode: "historical", policy: REFUND_POLICY, facts: a.facts, delegation: { chain: [delegation], roots: ["user:asha"], amount: 200 } });
  expect(hist.outcome === "verified" && hist.assurance === "reproducible", "the decision verifies offline and replays identically (assurance: reproducible)", hist.reasons.join("; ") || "all checks pass");

  /* B */
  section("B", "A request beyond authority is rejected by the enforcement boundary");
  const before = ledger().length;
  const b1 = await flow(900);
  const rb1 = await b1.invoke();
  expect(b1.decision.body.decision === "deny" && rb1.confirmation.body.outcome === "rejected" && ledger().length === before, "refund of 900 → policy denies, the gateway rejects, the ledger is unchanged", rb1.confirmation.body.reason);
  recordFlow(b1, rb1.confirmation);
  const lenient: PolicyDocument = { ...REFUND_POLICY, id: "refunds-misconfigured", version: "1", rules: [{ id: "anything", when: { fact: "request.action", op: "eq", value: "refund" }, decision: "allow", reason: "misconfigured" }] };
  const b2 = await flow(900, { policy: lenient });
  const rb2 = await b2.invoke();
  expect(b2.decision.body.decision === "permit" && rb2.confirmation.body.outcome === "rejected" && ledger().length === before, "even if a misconfigured policy permits 900, the boundary refuses: the delegation ceiling is 500", rb2.confirmation.body.reason);
  recordFlow(b2, rb2.confirmation);

  /* C */
  section("C", "The policy changes later; history keeps the original version");
  const v2: PolicyDocument = { ...REFUND_POLICY, version: "2", rules: [{ ...REFUND_POLICY.rules[0]!, when: { all: [{ fact: "request.action", op: "eq", value: "refund" }, { fact: "refund.amount", op: "lte", value: 100 }] } }, REFUND_POLICY.rules[1]!] };
  record({ event_type: "policy.updated", occurred_at: new Date().toISOString(), source: { system: "acme-pdp" }, actor: { id: "user:asha", type: "human" }, action: "update_policy", resource: { type: "policy", ref: "refunds" }, payload: { policy_id: "refunds", version: "2", policy_digest: mhSha256(canonicalCbor(v2)), previous_digest: a.decision.body.policy.digest } });
  const histAfter = verifyDecision(a.decision, { request: a.request, trust: authzTrust, directory, mode: "historical", policy: REFUND_POLICY, facts: a.facts, delegation: { chain: [delegation], roots: ["user:asha"], amount: 200 } });
  expect(histAfter.outcome === "verified", "after the change to v2, refund A still verifies against v1 — the version it was decided under");
  const sub = verifyDecision(a.decision, { request: a.request, trust: authzTrust, mode: "historical", policy: v2, facts: a.facts });
  expect(sub.checks.policy_binding.reason === "policy_mismatch", "presenting v2 as the policy for A is detected as policy substitution");

  /* D */
  section("D", "Replay of a consumed authorization is rejected");
  const rd = await a.invoke();
  expect(rd.confirmation.body.outcome === "rejected" && rd.confirmation.body.reason === "replayed" && ledger().length === 1, "re-submitting A's request and decision is rejected; no second refund", rd.confirmation.body.reason);
  const race = await flow(150, { order: "5520" });
  const both = await Promise.all([race.invoke(), race.invoke(), race.invoke()]);
  const completed = both.filter((x) => x.confirmation.body.outcome === "completed").length;
  expect(completed === 1 && ledger().length === 2, "three simultaneous submissions of one authorization → exactly one refund", `${completed} completed, ${both.length - completed} rejected (replayed)`);
  recordFlow(race, both.find((x) => x.confirmation.body.outcome === "completed")!.confirmation);

  /* E */
  section("E", "Workload substitution breaks the execution binding");
  observed = { ...planned, artifact_digest: mhSha256(new TextEncoder().encode("refund-bot:v3.2.0-patched-by-attacker")) };
  const e = await flow(120, { order: "6001" });
  const re = await e.invoke();
  expect(re.confirmation.body.outcome === "rejected" && re.confirmation.body.reason === "execution_mismatch" && ledger().length === 2, "a different artifact presents the same authorization → rejected, no refund", re.confirmation.body.reason);
  observed = planned;
  recordFlow(e, re.confirmation);

  /* F */
  section("F", "Receipt tampering is detected");
  const forgedEnv: SignedEnvelope = { ...confA, core: { ...confA.core, payload: { ...confA.core.payload, outcome: "rejected" } } };
  const fr = verifyEnvelope(forgedEnv, { registry, trust });
  expect(fr.outcome === "invalid", "changing A's confirmation envelope from completed to rejected is invalid", fr.reasons[0]);
  const forgedConf = { ...ra.confirmation, body: { ...ra.confirmation.body, outcome: "rejected" as const } };
  expect(verifyConfirmation(forgedConf, { request: a.request, trust: authzTrust }).outcome === "unverified", "the signed confirmation itself cannot be altered either");

  /* G */
  section("G", "A dropped event makes the history incomplete");
  const seq = [0, 1, 2, 3].map((n) => signEnvelope(createEnvelope({ event_type: "tool.invoked", occurred_at: new Date(now + n).toISOString(), source: { system: "refund-bot", event_id: `tool-${n}` }, actor: { id: "agent:refund-bot", type: "workload" }, action: "invoke", resource: { type: "tool", ref: "issue_refund" }, sequence: { epoch: 7, number: n }, payload: { tool: "issue_refund", request_id: `req-${n}` } }, registry), recorder));
  const gappy = verifyBundle(JSON.parse(JSON.stringify(exportBundle({ title: "agent tool calls (one dropped)", envelopes: [seq[0]!, seq[1]!, seq[3]!], trust, exporter: recorder }))), { registry, trust });
  expect(gappy.outcome === "incomplete" && gappy.checks.sequence_complete.reason === "sequence_gap", "receipt 7.2 never arrived → the verifier says incomplete, not verified", gappy.checks.sequence_complete.detail);

  /* H */
  section("H", "A stale attestation is reported stale (SYNTHETIC test PKI)");
  const pki = syntheticNitroPki();
  const nitroBundle = trustBundleFromDer("synthetic-test-pki", "per-run", "tests/support/synthetic-pki.ts", [{ name: "synthetic.nitro-root", der: pki.root }]);
  const doc = syntheticAttestation(pki, { timestamp: Date.now() - 3_600_000 });
  const ar = await nitroAdapter.verify(doc, { trustBundle: nitroBundle, policy: { id: "agent", version: "1", source: "demo", pcrs: { 0: pcrHex("10"), 1: pcrHex("11"), 2: pcrHex("12") }, pcr8: "not_applicable", publicKey: "unused" }, freshness: { mode: "timestamp-window", maxAgeMs: 300_000 } });
  expect(ar.outcome === "stale" || ar.outcome === "indeterminate", "an hour-old attestation under a 5-minute window is not accepted as verified", `outcome ${ar.outcome}`);
  expect(ar.outcome === "stale", "…and it is labelled stale specifically");

  /* export and independent verification */
  section("✓", "Export and independent verification");
  const bundle = exportBundle({ title: "agent action evidence", envelopes: evidence, attachments, trust, exporter: recorder });
  writeFileSync(join(dir, "agent-evidence-bundle.json"), JSON.stringify(bundle, null, 2));
  writeFileSync(join(dir, "trust.json"), JSON.stringify(trust.snapshot(), null, 2));
  writeFileSync(join(dir, "policy-v1.json"), JSON.stringify(REFUND_POLICY, null, 2));
  const vb = verifyBundle(JSON.parse(readFileSync(join(dir, "agent-evidence-bundle.json"), "utf8")), { registry, trust });
  expect(vb.outcome === "verified", "the exported bundle verifies offline: envelopes, inclusion, attachments, references", `${vb.envelopes.length} envelopes, ${bundle.attachments?.length ?? 0} signed protocol objects`);
  expect(existsSync(ledgerPath) && ledger().length === 2, "the ledger shows exactly the two refunds that were permitted and confirmed", ledger().map((l) => JSON.parse(l).txn).join(", "));

  const passed = results.filter((r) => r.ok).length;
  const failed = results.length - passed;
  writeFileSync(join(dir, "demo-report.json"), JSON.stringify({ schema: "cool.demo-report.v1", demo: "agent-action", ran_at: new Date().toISOString(), passed, failed, results }, null, 2));
  log();
  log(bold(failed === 0 ? green(`all ${passed} claims held`) : red(`${failed} of ${results.length} claims did NOT hold`)));
  log(dim(`artifacts: ${dir}`));
  log(dim(`re-check:  node dist/cli/index.js bundle verify ${join(dir, "agent-evidence-bundle.json")} --trust ${join(dir, "trust.json")}`));
  log(yellow("what this proves: each action's authorization, decision and outcome are signed, bound and independently checkable."));
  log(yellow("what it does not: that the agent's reasoning was right, or that actions outside the gateway were captured."));
  return { dir, results, passed, failed };
}

if (process.argv[1] && /demo-agent\.ts$/.test(process.argv[1])) {
  runAgentDemo({ ...(process.argv[2] ? { dir: process.argv[2] } : {}) }).then((o) => process.exit(o.failed === 0 ? 0 : 1), (err) => { console.error(err); process.exit(1); });
}
