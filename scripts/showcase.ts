/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * The CooL showcase: every capability, end to end, in one run.
 *
 *   npm run showcase              # writes to a fresh temp directory
 *   npm run showcase -- ./out     # keep the artifacts
 *
 * The showcase checks itself. Every claim it prints is an assertion; if one
 * does not hold, it says so in red and the process exits 1. It is a demo you
 * cannot accidentally overstate with.
 *
 * Honesty, up front:
 *   • the TDX chapter runs on CooL's attestation SIMULATOR (labelled
 *     "simulated" throughout) — the hardware results are in artifacts/;
 *   • the Nitro chapter verifies a GENUINE AWS document, then runs the full
 *     receipt path on a SYNTHETIC test PKI — no real enclave is involved;
 *   • enforcement targets are a real local directory and a real deny-list
 *     file, standing in for a cluster and a network policy;
 *   • nothing here touches the network.
 */
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { PassThrough, Transform } from "node:stream";
import { generateKeypair } from "../src/keys";
import { mhSha256 } from "../src/multihash";
import {
  CoolTee,
  SimulatedDstackClient,
  attachWitness,
  cosign,
  disclose,
  verifyDisclosure,
  verifyReceiptV2,
  type ReceiptV2,
} from "../src/phala/index";
import {
  AuthorizationMatrix,
  CHANGE_POLICY,
  CoolClient,
  CredentialLifecycle,
  EnforcementCoordinator,
  IncidentCase,
  LocalDenylistTarget,
  LocalDirectoryTarget,
  PayloadRegistry,
  RUNTIME_POLICY,
  ReplayGuard,
  RolloutController,
  RuntimeGuard,
  TransparencyLog,
  TrustStore,
  buildProvenance,
  changeFacts,
  detectDrift,
  evaluatePolicy,
  exportBundle,
  verifyBundle,
  type EnvelopeInput,
  type KeyRecord,
  type PolicyDocument,
  type SignedEnvelope,
  type TrustSnapshot,
} from "../src/platform/index";
import {
  FrameDecoder,
  FrameType,
  NitroLogServer,
  NitroReceiptSealer,
  encodeFrame,
  forwardFrames,
  normalizeNitro,
  trustBundleFromDer,
  verifyNitroAttestation,
  type NsmSource,
} from "../src/nitro/index";
import { pcrHex, syntheticAttestation, syntheticNitroPki } from "../tests/support/synthetic-pki";

/* ── presentation ─────────────────────────────────────────────────────── */

const COLOR = !process.env["NO_COLOR"] && process.stdout.isTTY;
const paint = (code: string) => (s: string) => (COLOR ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = paint("1");
const dim = paint("2");
const green = paint("32");
const red = paint("31");
const cyan = paint("36");
const yellow = paint("33");

export interface ShowcaseResult {
  readonly chapter: string;
  readonly claim: string;
  readonly ok: boolean;
  readonly detail: string;
}

export interface ShowcaseOutcome {
  readonly dir: string;
  readonly results: readonly ShowcaseResult[];
  readonly passed: number;
  readonly failed: number;
}

/* ── the run ──────────────────────────────────────────────────────────── */

export async function runShowcase(options: { readonly dir?: string; readonly quiet?: boolean } = {}): Promise<ShowcaseOutcome> {
  const dir = resolve(options.dir ?? mkdtempSync(join(tmpdir(), "cool-showcase-")));
  mkdirSync(dir, { recursive: true });
  const log = (line = "") => { if (!options.quiet) console.log(line); };
  const results: ShowcaseResult[] = [];
  let current = "";
  let n = 0;
  const chapter = (title: string, why: string) => {
    current = title;
    log();
    log(`${bold(cyan(String(++n).padStart(2, "0")))}  ${bold(title)}`);
    log(`    ${dim(why)}`);
  };
  const note = (text: string) => log(`    ${dim("·")} ${text}`);
  const expect = (ok: boolean, claim: string, detail = "") => {
    results.push({ chapter: current, claim, ok, detail });
    log(`    ${ok ? green("✓") : red("✕")} ${claim}${detail ? dim(`  — ${detail}`) : ""}`);
  };

  log(bold("CooL showcase — cryptographic evidence, policy and enforcement, end to end"));
  log(dim("every line marked ✓ is checked as it runs · simulated and synthetic parts are labelled · no network"));

  /* shared actors and trust */
  const keys = {
    builder: generateKeypair("ci-builder"),
    ops: generateKeypair("ops"),
    log: generateKeypair("transparency-log"),
    witness: generateKeypair("auditor-witness"),
    sensor: generateKeypair("runtime-sensor"),
    exporter: generateKeypair("evidence-exporter"),
    rogue: generateKeypair("unknown-key"),
    retired: generateKeypair("retired-signer"),
  };
  const rec = (k: typeof keys.ops, purposes: KeyRecord["purposes"], extra: Partial<KeyRecord> = {}): KeyRecord =>
    ({ key_id: k.keyId, entry: k.directoryEntry, purposes, owner: "showcase", valid_from: "2026-01-01T00:00:00Z", status: "active", ...extra });
  const snapshot: TrustSnapshot = {
    schema: "cool.trust-snapshot.v1",
    id: "showcase-trust",
    as_of: new Date().toISOString(),
    max_age_ms: 24 * 3_600_000,
    keys: [
      rec(keys.builder, ["builder"]), rec(keys.ops, ["evidence"]), rec(keys.log, ["log"]), rec(keys.witness, ["witness"]),
      rec(keys.sensor, ["evidence"]), rec(keys.exporter, ["evidence"]),
      rec(keys.retired, ["evidence"], { status: "revoked", revoked_at: new Date(Date.now() - 60_000).toISOString() }),
    ],
  };
  const trust = new TrustStore(snapshot);
  const registry = PayloadRegistry.standard();
  const tlog = new TransparencyLog("showcase-log", keys.log);
  const purpose = (t: string) => (/^(build|artifact)\./.test(t) ? "builder" as const : "evidence" as const);
  const collected: SignedEnvelope[] = [];
  const ops = new CoolClient({ project: "showcase", signer: keys.ops, trust, log: tlog, policyMode: "enforce", enforcement: { enabled: true } });
  const sensor = new CoolClient({ project: "showcase", signer: keys.sensor, trust, log: tlog });

  /* 1 ── AI evidence on the TDX path ───────────────────────────────────── */
  chapter("AI change receipts (Intel TDX path, simulator)", "a prompt change becomes a signed, logged, offline-verifiable receipt with no plaintext in it");
  const dstack = new SimulatedDstackClient({ appName: "showcase", imageDigest: "sha256:showcase" });
  const tee = await CoolTee.connect({ dstack, capture: { flushMs: 1 } });
  const promptAfter = "Approve refunds up to $500. Escalate anything larger.";
  const receipt = await tee.change({ kind: "prompt", ref: "billing/refund-agent#system", environment: "prod", before: "Approve refunds up to $50.", after: promptAfter, actor: { id: "user:asha", method: "session" } });
  const verdict = await verifyReceiptV2(receipt);
  expect(verdict.checks.binding.status === "pass" && verdict.checks.signature.status === "pass" && verdict.checks.inclusion.status === "pass", "binding, ML-DSA-65 + Ed25519 signature and RFC 6962 inclusion verify offline");
  expect(verdict.checks.attestation.status === "simulated", "attestation is reported as simulated, never as a pass", verdict.checks.attestation.status);
  expect(!JSON.stringify(receipt).includes(promptAfter), "the prompt text is not in the receipt — only a salted commitment");
  const forged = JSON.parse(JSON.stringify(receipt)) as ReceiptV2;
  (forged.record as unknown as { change: { ref: string } }).change.ref = "billing/refund-agent#system-v2";
  const forgedVerdict = await verifyReceiptV2(forged);
  expect(forgedVerdict.checks.binding.status === "fail" && forgedVerdict.checks.signature.status === "fail", "editing one field breaks the binding and the signature");

  /* 2 ── disclosure and witnesses ──────────────────────────────────────── */
  chapter("Selective disclosure and independent witnesses", "reveal one sealed field to an auditor, and let a second party co-sign the log head");
  const disclosure = disclose(receipt, "change.after", promptAfter);
  expect(verifyDisclosure(receipt, disclosure).ok, "the true prompt text opens its commitment");
  expect(!verifyDisclosure(receipt, { ...disclosure, value: "Approve refunds up to $5,000." }).ok, "a doctored disclosure is refused");
  const witnessed = attachWitness(receipt, cosign(receipt.sth!, keys.witness));
  const wv = await verifyReceiptV2(witnessed);
  expect(wv.checks.witnesses.status === "pass", "an external witness co-signature is counted; the operator's own is not", wv.checks.witnesses.detail);
  await tee.close();

  /* 3 ── the platform envelope ─────────────────────────────────────────── */
  chapter("One evidence envelope for everything", "cool.envelope.v1: typed payloads, canonical bytes, hybrid signatures, transparency, and a report with eleven separate checks");
  const commit = ops.evidence.publish(ops.evidence.record({ event_type: "scm.commit", occurred_at: new Date(Date.now() - 5_000).toISOString(), source: { system: "git", instance: "acme/service", event_id: "a1b2c3" }, actor: { id: "user:asha", type: "human" }, action: "commit", resource: { type: "repository", ref: "acme/service" }, payload: { repository: "acme/service", commit: "a1b2c3", author: "asha", signed: true } }));
  const commitReport = ops.evidence.verify(commit);
  expect(commitReport.overall_status === "pass", "a published envelope passes every applicable check", Object.entries(commitReport.checks).filter(([, c]) => c.status === "pass").map(([k]) => k).join(", "));
  const outsider = new CoolClient({ project: "x", signer: keys.rogue, trust }).evidence.record({ ...commit.core, event_id: undefined } as unknown as EnvelopeInput);
  const or = ops.evidence.verify(outsider);
  expect(or.checks.signature_valid.status === "pass" && or.checks.signer_trusted.reason === "untrusted_key", "a valid signature from an unknown key is NOT trusted — two different questions");
  const retired = new CoolClient({ project: "x", signer: keys.retired, trust }).evidence.record({ ...commit.core, event_id: undefined } as unknown as EnvelopeInput);
  expect(ops.evidence.verify(retired).checks.signer_trusted.reason === "key_revoked", "a revoked key is rejected without independent proof the signature predates revocation");
  let refused = "";
  try { ops.evidence.create({ ...commit.core, event_id: undefined, payload: { ...commit.core.payload, password: "hunter2" } } as unknown as EnvelopeInput); } catch (err) { refused = (err as Error).message; }
  expect(/unexpected field password/.test(refused), "payloads are strict: an unexpected (here, secret) field is refused at creation");
  collected.push(commit);

  /* 4 ── policy ────────────────────────────────────────────────────────── */
  chapter("A policy engine that does not guess", "missing facts are UNKNOWN, resolved by the policy's own on_unknown; the most restrictive rule wins");
  const deployPolicy: PolicyDocument = { schema: "cool.policy.v1", id: "prod-deploy", version: "1", mode: "enforce", default: "allow", on_unknown: "deny", rules: [
    { id: "signed", when: { fact: "commit.signed", op: "eq", value: false }, decision: "deny", reason: "unsigned_commit" },
    { id: "large", when: { fact: "change.lines", op: "gt", value: 500 }, decision: "require_approval", reason: "large_change" },
  ] };
  expect(evaluatePolicy(deployPolicy, { "commit.signed": true, "change.lines": 20 }).decision === "allow", "complete, clean facts → allow");
  const unknown = evaluatePolicy(deployPolicy, { "change.lines": 20 });
  expect(unknown.decision === "deny", "a missing fact is not treated as safe → deny", unknown.reason_codes.join(", "));
  expect(evaluatePolicy(deployPolicy, { "commit.signed": true, "change.lines": 900 }).decision === "require_approval", "a large change needs a human");

  /* 5 ── supply chain ──────────────────────────────────────────────────── */
  chapter("Supply Chain: a real deployment gate", "signed provenance in; the target itself recomputes the artifact digest before it admits anything");
  const ci = new CoolClient({ project: "showcase", signer: keys.builder, trust, log: tlog });
  const artifactPath = join(dir, "service.tar");
  writeFileSync(artifactPath, "acme service v2.4.1\n");
  const prov = buildProvenance({ buildId: "build-311", builderId: keys.builder.keyId, repository: "acme/service", commit: "a1b2c3".padEnd(40, "0"), artifactPath, finishedAt: new Date().toISOString() });
  const build = ci.evidence.publish(ci.evidence.record({ ...prov.build, provenance: { collection_method: "emitted", refs: [commit.digest] } }));
  const artifact = ci.evidence.publish(ci.evidence.record({ ...prov.artifact, provenance: { collection_method: "emitted", refs: [build.digest] } }));
  const target = new LocalDirectoryTarget(join(dir, "prod"));
  const evidence = () => ({ artifactPath, build, artifact, trustedBuilders: [keys.builder.keyId], allowedRepositories: ["acme/service"], buildReport: ops.evidence.verify(build, { purpose: "builder" }), artifactReport: ops.evidence.verify(artifact, { purpose: "builder" }) });
  const good = await ops.supply_chain.gate({ evidence: evidence(), target, deploymentId: "deploy-1", environment: "prod", requestedBy: "user:asha", dryRun: false });
  expect(good.enforcement.state === "completed" && good.enforcement.confirmed, "verified provenance → admitted, and the target confirms the deployed bytes", `${good.decision.decision}: ${good.decision.reason_codes.join(", ")}`);
  writeFileSync(artifactPath, "acme service v2.4.1\n# injected\n");
  const bad = await ops.supply_chain.gate({ evidence: evidence(), target, deploymentId: "deploy-2", environment: "prod", requestedBy: "user:asha", dryRun: false });
  expect(bad.decision.decision === "deny" && readFileSync(join(dir, "prod", "service.tar"), "utf8") === "acme service v2.4.1\n", "a tampered artifact is denied and production keeps the approved bytes", bad.decision.reason_codes[0]);
  const deployRecords = [...good.records, ...bad.records].map((r) => ops.evidence.publish(ops.evidence.record(r)));
  collected.push(build, artifact, ...deployRecords);

  /* 6 ── identity ──────────────────────────────────────────────────────── */
  chapter("Identity & Authority", "CooL records what identity systems assert; rotation is final only when the provider confirms");
  const cred = new CredentialLifecycle("cred:payments-db", "vault-prod", "svc:payments");
  cred.requestRotation("user:asha", new Date().toISOString());
  cred.providerResult({ confirmed: false, timedOut: true, at: new Date().toISOString() });
  expect(cred.state === "unknown", "a provider timeout leaves the credential UNKNOWN, not 'rotated'");
  cred.providerResult({ confirmed: true, at: new Date().toISOString() });
  expect(cred.state === "rotated", "only the provider's confirmation makes it rotated");
  const matrix = new AuthorizationMatrix([{ actor: "user:asha", resource: "tenant-a/*", action: "read", environment: "prod" }, { actor: "user:asha", resource: "tenant-a/db", action: "read", environment: "prod" }]);
  const cross = matrix.evaluate({ actor: "user:asha", resource: "tenant-b/db", action: "read", environment: "prod", actorKnown: true });
  expect(cross.decision === "deny", "cross-tenant access is denied by default", cross.reason);
  const replay = new ReplayGuard(300_000);
  replay.check("jti-77", Date.now());
  expect(replay.check("jti-77", Date.now() + 1_000) === "replayed", "a replayed token is detected");
  collected.push(...cred.records().map((r) => ops.evidence.publish(ops.evidence.record(r))));

  /* 7 ── change control ────────────────────────────────────────────────── */
  chapter("Change Control", "approvals bind to exact bytes; health gates every rollout stage; rollback needs approval too");
  const approved = mhSha256(new TextEncoder().encode("replicas: 3"));
  const applied = mhSha256(new TextEncoder().encode("replicas: 30"));
  const cf = changeFacts({ author: "user:dev", appliedDigest: applied, approval: { approver: "user:lead", approved_digest: approved, approved_at: new Date().toISOString() }, maxApprovalAgeMs: 86_400_000, now: Date.now() });
  expect(evaluatePolicy(CHANGE_POLICY, cf).decision === "deny", "a config edited after approval is denied", "changed_after_approval");
  const drift = detectDrift("k8s/payments.yaml", approved, applied, new Date().toISOString())!;
  collected.push(ops.evidence.publish(ops.evidence.record(drift)));
  expect(drift.event_type === "configuration.drift_detected", "drift from the approved baseline is recorded as evidence");
  const rollout = new RolloutController("ro-9", prov.digest, [{ name: "canary", percent: 5 }, { name: "all", percent: 100 }]);
  expect(rollout.report("unknown", new Date().toISOString()) === "hold", "unknown health holds the rollout — it never promotes");
  rollout.report("fail", new Date().toISOString());
  expect(rollout.rollback(undefined) === "rejected" && rollout.rollback({ approver: "user:lead" }) === "rolled_back", "an unapproved rollback is refused; an approved one proceeds");

  /* 8 ── runtime guard ─────────────────────────────────────────────────── */
  chapter("Runtime Guard", "act only on attributable signals; respond through the same enforcement contract; notice silence");
  const guard = new RuntimeGuard();
  const escalation = (signer: CoolClient, id: string) => signer.evidence.record({ event_type: "runtime.privilege_change", occurred_at: new Date().toISOString(), source: { system: "falco", instance: "node-3", event_id: id }, actor: { id: "workload:payments-7f9", type: "workload" }, action: "observe", resource: { type: "workload", ref: "payments-7f9" }, payload: { workload: "payments-7f9", from: "app", to: "root" } });
  const spoof = escalation(new CoolClient({ project: "x", signer: keys.rogue, trust }), "spoof-1");
  expect(guard.ingest(spoof, ops.evidence.verify(spoof)) === "untrusted_source", "a spoofed sensor event is recorded but never acted on");
  const real = sensor.evidence.publish(escalation(sensor, "esc-1"));
  guard.ingest(real, ops.evidence.verify(real));
  const decision = guard.decide(real);
  expect(decision.decision === "quarantine" && decision.enforced === false, "privilege escalation → quarantine, advisory by default (observe mode)");
  const denylist = new LocalDenylistTarget(join(dir, "denylist.txt"));
  const dry = await guard.respond(real, decision, new EnforcementCoordinator({ enabled: true }), denylist);
  expect(dry?.state === "not_executed", "the response is a dry run unless explicitly enforced", dry?.detail);
  const live = await guard.respond(real, evaluatePolicy({ ...RUNTIME_POLICY, mode: "enforce" }, { "event.type": "runtime.privilege_change", "privilege.to": "root" }), new EnforcementCoordinator({ enabled: true }), denylist, false);
  expect(live?.confirmed === true, "enforced: the workload is on the deny-list, confirmed by re-reading it");
  for (const seq of [1, 2, 6]) {
    const hb = sensor.evidence.record({ event_type: "runtime.heartbeat", occurred_at: new Date(Date.now() - 3_600_000).toISOString(), observed_at: new Date(Date.now() - 3_600_000).toISOString(), source: { system: "falco", instance: "node-3", event_id: `hb-${seq}` }, actor: { id: "sensor:node-3", type: "service" }, action: "heartbeat", resource: { type: "sensor", ref: "node-3" }, payload: { source: "node-3", sequence: seq } });
    guard.ingest(hb, ops.evidence.verify(hb));
  }
  const gaps = guard.telemetryGaps(Date.now(), 300_000);
  expect(gaps.silent.includes("node-3") && gaps.sequenceGaps[0]?.missing.join(",") === "3,4,5", "suppressed telemetry shows up as silence and missing sequences", `missing ${gaps.sequenceGaps[0]?.missing.join(", ")}`);
  collected.push(real, spoof);

  /* 9 ── AWS Nitro: genuine document ───────────────────────────────────── */
  chapter("AWS Nitro: a GENUINE AWS attestation document", "verified offline against the pinned AWS root; a debug enclave is caught");
  const genuine = new Uint8Array(Buffer.from(readFileSync(join(import.meta.dirname, "..", "tests", "fixtures", "nitro", "genuine-debug-us-east-1-2024-09-09.cbor.b64"), "utf8").trim(), "base64"));
  const gr = verifyNitroAttestation(genuine, { now: Date.parse("2024-09-09T19:49:13Z"), certificateTime: "attestation-timestamp" });
  expect(gr.checks.trust_root.status === "pass" && gr.checks.certificate_chain.status === "pass" && gr.checks.cose_signature.status === "pass", "COSE signature and 4-certificate chain verify to AWS_NitroEnclaves_Root-G1", gr.checks.trust_root.detail);
  expect(gr.checks.debug_mode.reason === "debug_enclave" && gr.overall_status === "fail", "this enclave ran in debug mode (PCR0–2 zero), so it fails — whatever else passed");
  const flipped = new Uint8Array(genuine);
  flipped[flipped.length - 1] = flipped[flipped.length - 1]! ^ 1;
  expect(verifyNitroAttestation(flipped, { certificateTime: "attestation-timestamp", now: Date.parse("2024-09-09T19:49:13Z") }).checks.cose_signature.reason === "signature_invalid", "one flipped bit and the signature fails; claims are never consumed");

  /* 10 ── AWS Nitro: receipt path (synthetic PKI) ──────────────────────── */
  chapter("AWS Nitro: enclave → untrusted host → log (SYNTHETIC test PKI)", "fresh in-enclave key, attested; receipts sealed with [epoch].[sequence]; the host can drop or mangle, never forge");
  const pki = syntheticNitroPki();
  const bundle = trustBundleFromDer("synthetic-test-pki", "per-run", "tests/support/synthetic-pki.ts", [{ name: "synthetic.nitro-root", der: pki.root }]);
  const policy = { id: "agent-enclave", version: "1", source: "showcase", pcrs: { 0: pcrHex("10"), 1: pcrHex("11"), 2: pcrHex("12") }, pcr8: "not_applicable" as const };
  const nonce = new Uint8Array(32).fill(7);
  const nsm: NsmSource = { attest: async (req) => syntheticAttestation(pki, { ...req, timestamp: Date.now() - 1_000 }) };
  const sealer = await NitroReceiptSealer.start({ nsm, registry, nonce });
  const server = new NitroLogServer({ logKey: keys.log, logId: "nitro-log", registry, attestation: { trustBundle: bundle, policy, freshness: { mode: "nonce", expected: nonce } } });
  sealer.acceptEpoch(server.register(sealer.attestation, sealer.keyId, sealer.publicEntry, "refund-agent"));
  expect(normalizeNitro(verifyNitroAttestation(sealer.attestation, { trustBundle: bundle, policy, freshness: { mode: "nonce", expected: nonce }, receiptKey: { keyId: sealer.keyId, entry: sealer.publicEntry } })).overall_status === "pass", "the enclave's attestation binds its fresh receipt key (normalized: platform, measurement, key, freshness)");
  const inference = (i: number) => sealer.seal({ event_id: `inf-${i}`, event_type: "ai.inference", occurred_at: new Date().toISOString(), source: { system: "agent" }, actor: { id: "workload:refund-agent", type: "workload" }, action: "infer", resource: { type: "model", ref: "acme/refunds@3" }, payload: { model: "acme/refunds", model_version: "3", input_commitment: mhSha256(new Uint8Array([i])), output_commitment: mhSha256(new Uint8Array([i, 9])) } });
  const receipts = [0, 1, 2, 3].map(inference);
  const viaProxy = async (items: SignedEnvelope[], mutate: boolean) => {
    const from = new PassThrough();
    const to = new PassThrough();
    const chunks: Uint8Array[] = [];
    to.on("data", (d: Buffer) => chunks.push(new Uint8Array(d)));
    const host = new Transform({ transform(c: Buffer, _e, cb) { cb(null, mutate ? Buffer.from(c.toString("latin1").replace("refunds@3", "refunds@4"), "latin1") : c); } });
    const done = forwardFrames(from.pipe(host), to);
    for (const r of items) from.write(encodeFrame(FrameType.receipt, new TextEncoder().encode(JSON.stringify(r))));
    from.end();
    await done;
    const dec = new FrameDecoder();
    return chunks.flatMap((c) => dec.push(c)).map((f) => JSON.parse(new TextDecoder().decode(f.payload)) as SignedEnvelope);
  };
  const delivered = await viaProxy([receipts[0]!, receipts[1]!, receipts[3]!], false); // receipt 2 dropped by the host
  const acks = delivered.map((r) => server.ingest(r).ack.outcome);
  expect(acks.every((a) => a === "accepted"), "receipts cross the host proxy unchanged and are acknowledged (signed acks)");
  expect(server.epochs.gaps(1).map((g) => `${g.sequence}:${g.status}`).join() === "2:unresolved", "the receipt the host dropped becomes a recorded gap");
  expect(server.ingest(receipts[2]!).ack.outcome === "late_fill" && server.epochs.gaps(1)[0]!.status === "filled_late", "a late copy fills the gap — and the gap stays on record");
  const mangled = await viaProxy([inference(4)], true);
  const mack = server.ingest(mangled[0]!);
  expect(mack.ack.outcome === "rejected", "a receipt the host altered is rejected and nothing is stored", mack.ack.detail);
  const staleSealer = await NitroReceiptSealer.start({ nsm: { attest: async (req) => syntheticAttestation(pki, { ...req, timestamp: Date.now() - 3_600_000 }) }, registry, nonce });
  const strict = new NitroLogServer({ logKey: keys.log, logId: "nitro-log-2", registry, attestation: { trustBundle: bundle, policy, freshness: { mode: "timestamp-window", maxAgeMs: 300_000 } } });
  let staleMsg = "";
  try { strict.register(staleSealer.attestation, staleSealer.keyId, staleSealer.publicEntry, "agent"); } catch (err) { staleMsg = (err as Error).message; }
  expect(/attestation_stale/.test(staleMsg), "a stale attestation gets no epoch");
  const cp = server.checkpoint(receipts[0]!.digest, [keys.witness])!;
  expect(cp.sth.witnesses.some((w) => w.id === keys.witness.keyId), "the log checkpoint is co-signed by the witness");

  /* 11 ── incident evidence ────────────────────────────────────────────── */
  chapter("Incident Evidence", "reconstruct from evidence references; label every entry; keep contradictions and gaps visible");
  const inc = new IncidentCase("INC-2041", "unexpected root on payments", "high");
  const opened = ops.evidence.publish(ops.evidence.record(inc.opened(new Date().toISOString(), "user:oncall")));
  for (const env of [real, spoof, ...deployRecords]) collected.push(ops.evidence.publish(ops.evidence.record(inc.add(env, ops.evidence.verify(env), new Date().toISOString(), "user:oncall"))));
  const vaultLog = ops.evidence.publish(ops.evidence.record({ event_type: "secret.accessed", occurred_at: new Date().toISOString(), source: { system: "vault" }, actor: { id: "workload:payments-7f9", type: "workload" }, action: "read", resource: { type: "secret", ref: "payments-db" }, provenance: { collection_method: "imported", refs: [mhSha256(new TextEncoder().encode("vault audit line 88412 — not exported"))] }, payload: { secret_ref: "kv/payments-db", accessor: "workload:payments-7f9", vault: "vault-prod" } }));
  const skewed = ops.evidence.publish(ops.evidence.record({ event_type: "deployment.completed", occurred_at: new Date(Date.now() - 86_400_000).toISOString(), source: { system: "legacy-cd" }, actor: { id: "svc:legacy-cd", type: "service" }, action: "deploy", resource: { type: "environment", ref: "prod" }, payload: { deployment_id: "deploy-1", artifact_digest: prov.digest, environment: "prod", target: "legacy", outcome: "succeeded", confirmed: false } }));
  collected.push(opened, vaultLog, skewed);
  const caseBundle = exportBundle({ title: "INC-2041", envelopes: collected, decisions: [good.decision, bad.decision], trust, exporter: keys.exporter });
  writeFileSync(join(dir, "incident-bundle.json"), JSON.stringify(caseBundle, null, 2));
  const cr = verifyBundle(JSON.parse(readFileSync(join(dir, "incident-bundle.json"), "utf8")), { registry, trust, purpose });
  const labels = (l: string) => cr.timeline.entries.filter((e) => e.label === l).length;
  note(`timeline: ${cr.timeline.entries.length} entries · ${cr.timeline.links.length} links (${cr.timeline.links.filter((x) => x.kind === "heuristic").length} heuristic) · labels: verified ${labels("verified")}, source-asserted ${labels("source-asserted")}, contradicted ${labels("contradicted")}, missing ${labels("missing")}`);
  expect(labels("source-asserted") >= 1, "the spoofed sensor event is labelled source-asserted, not verified");
  expect(cr.timeline.contradictions.length >= 1, "a completion that predates its request is flagged as a contradiction", cr.timeline.contradictions[0]);
  expect(cr.timeline.gaps.length === 1 && labels("missing") === 1, "the vault audit line that was referenced but never exported is a visible gap");
  expect(cr.overall_status === "fail" && cr.checks.evidence_complete.status === "fail", "so the case bundle does not pass — the verifier refuses to paper over gaps", cr.reasons.join("; "));
  expect(cr.timeline.links.some((l) => l.kind === "heuristic" && l.label === "inferred"), "heuristic links are labelled inferred, with their rule version");

  /* 12 ── portable proof ───────────────────────────────────────────────── */
  chapter("Portable proof for an auditor", "export the release evidence; anyone re-verifies it offline with their own trust snapshot");
  const release = exportBundle({ title: "release deploy-1", envelopes: [commit, build, artifact, ...deployRecords], decisions: [good.decision, bad.decision], trust, exporter: keys.exporter });
  writeFileSync(join(dir, "release-bundle.json"), JSON.stringify(release, null, 2));
  writeFileSync(join(dir, "trust.json"), JSON.stringify(snapshot, null, 2));
  const rr = verifyBundle(JSON.parse(readFileSync(join(dir, "release-bundle.json"), "utf8")), { registry, trust, purpose });
  expect(rr.overall_status === "pass", "the release bundle verifies end to end", `${rr.envelopes.length} envelopes, manifest ${release.manifest.digest.slice(0, 22)}…`);
  const selfOnly = verifyBundle(JSON.parse(readFileSync(join(dir, "release-bundle.json"), "utf8")), { registry, purpose });
  expect(selfOnly.overall_status === "unknown", "without your own trust snapshot the result is 'unknown' — the exporter cannot vouch for itself");
  const cut = JSON.parse(readFileSync(join(dir, "release-bundle.json"), "utf8"));
  cut.envelopes.splice(3, 1);
  expect(verifyBundle(cut, { registry, trust, purpose }).checks.manifest_valid.reason === "manifest_mismatch", "removing one record from the bundle is detected");

  /* summary ─────────────────────────────────────────────────────────── */
  const passed = results.filter((r) => r.ok).length;
  const failed = results.length - passed;
  writeFileSync(join(dir, "showcase-report.json"), JSON.stringify({ schema: "cool.showcase-report.v1", ran_at: new Date().toISOString(), passed, failed, results }, null, 2));
  log();
  log(bold(failed === 0 ? green(`all ${passed} claims held`) : red(`${failed} of ${results.length} claims did NOT hold`)));
  log(dim(`artifacts: ${dir}`));
  log(dim(`re-check:  node dist/cli/index.js bundle verify ${join(dir, "release-bundle.json")} --trust ${join(dir, "trust.json")}`));
  log(yellow("limits: TDX ran on the simulator; Nitro receipts ran on a synthetic PKI; enforcement targets are local; no network was used."));
  return { dir, results, passed, failed };
}

if (process.argv[1] && /showcase\.ts$/.test(process.argv[1])) {
  runShowcase({ ...(process.argv[2] ? { dir: process.argv[2] } : {}) }).then(
    (o) => process.exit(o.failed === 0 ? 0 : 1),
    (err) => { console.error(err); process.exit(1); },
  );
}
