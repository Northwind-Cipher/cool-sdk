/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The open CooL showcase: every capability of the open evidence core, end to
 * end, in one run.
 *
 *   npm run showcase              # writes to a fresh temp directory
 *   npm run showcase -- ./out     # keep the artifacts
 *
 * The showcase checks itself. Every claim it prints is an assertion; if one
 * does not hold, it says so in red and the process exits 1.
 *
 * Honesty, up front:
 *   • the TDX chapter runs on CooL's attestation SIMULATOR (labelled
 *     "simulated" throughout) — the hardware results are in artifacts/;
 *   • the Nitro chapters verify a GENUINE AWS document, then seal receipts on
 *     a SYNTHETIC test PKI — no real enclave is involved;
 *   • nothing here touches the network.
 *
 * Policy, enforcement, the deployment gate, incident reconstruction and the
 * Nitro log server are part of the commercial CooL platform and not shown here.
 */
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { PassThrough, Transform } from "node:stream";
import { generateKeypair } from "../src/keys";
import { mhSha256 } from "../src/multihash";
import { CoolTee, SimulatedDstackClient, attachWitness, cosign, disclose, verifyDisclosure, verifyReceiptV2, type ReceiptV2 } from "../src/phala/index";
import {
  CoolClient,
  GitConnector,
  PayloadRegistry,
  TransparencyLog,
  TrustStore,
  exportBundle,
  verifyBundle,
  verifyEnvelope,
  type EnvelopeInput,
  type KeyRecord,
  type SignedEnvelope,
  type TrustSnapshot,
} from "../src/platform/index";
import {
  FrameDecoder,
  FrameType,
  NitroReceiptSealer,
  encodeFrame,
  forwardFrames,
  normalizeNitro,
  trustBundleFromDer,
  verifyNitroAttestation,
  type NsmSource,
} from "../src/nitro/index";
import { pcrHex, syntheticAttestation, syntheticNitroPki } from "../tests/support/synthetic-pki";

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
  const expect = (ok: boolean, claim: string, detail = "") => {
    results.push({ chapter: current, claim, ok, detail });
    log(`    ${ok ? green("✓") : red("✕")} ${claim}${detail ? dim(`  — ${detail}`) : ""}`);
  };

  log(bold("CooL open showcase — independently verifiable evidence, end to end"));
  log(dim("every line marked ✓ is checked as it runs · simulated and synthetic parts are labelled · no network"));

  const keys = {
    app: generateKeypair("app-evidence"),
    log: generateKeypair("transparency-log"),
    witness: generateKeypair("auditor-witness"),
    exporter: generateKeypair("evidence-exporter"),
    rogue: generateKeypair("unknown-key"),
    retired: generateKeypair("retired-signer"),
  };
  const rec = (k: typeof keys.app, purposes: KeyRecord["purposes"], extra: Partial<KeyRecord> = {}): KeyRecord =>
    ({ key_id: k.keyId, entry: k.directoryEntry, purposes, owner: "showcase", valid_from: "2026-01-01T00:00:00Z", status: "active", ...extra });
  const snapshot: TrustSnapshot = {
    schema: "cool.trust-snapshot.v1", id: "showcase-trust", as_of: new Date().toISOString(), max_age_ms: 24 * 3_600_000,
    keys: [rec(keys.app, ["evidence"]), rec(keys.log, ["log"]), rec(keys.witness, ["witness"]), rec(keys.exporter, ["evidence"]),
      rec(keys.retired, ["evidence"], { status: "revoked", revoked_at: new Date(Date.now() - 60_000).toISOString() })],
  };
  const trust = new TrustStore(snapshot);
  const registry = PayloadRegistry.standard();
  const tlog = new TransparencyLog("showcase-log", keys.log);
  const app = new CoolClient({ project: "showcase", signer: keys.app, trust, log: tlog });
  const recorded: SignedEnvelope[] = [];

  /* 1 */
  chapter("AI change receipts (Intel TDX path, simulator)", "a prompt change becomes a signed, logged, offline-verifiable receipt with no plaintext in it");
  const tee = await CoolTee.connect({ dstack: new SimulatedDstackClient({ appName: "showcase", imageDigest: "sha256:showcase" }), capture: { flushMs: 1 } });
  const promptAfter = "Approve refunds up to $500. Escalate anything larger.";
  const receipt = await tee.change({ kind: "prompt", ref: "billing/refund-agent#system", environment: "prod", before: "Approve refunds up to $50.", after: promptAfter, actor: { id: "user:asha", method: "session" } });
  const verdict = await verifyReceiptV2(receipt);
  expect(verdict.checks.binding.status === "pass" && verdict.checks.signature.status === "pass" && verdict.checks.inclusion.status === "pass", "binding, ML-DSA-65 + Ed25519 signature and RFC 6962 inclusion verify offline");
  expect(verdict.checks.attestation.status === "simulated", "attestation is reported as simulated, never as a pass", verdict.checks.attestation.status);
  expect(!JSON.stringify(receipt).includes(promptAfter), "the prompt text is not in the receipt — only a salted commitment");
  const forged = JSON.parse(JSON.stringify(receipt)) as ReceiptV2;
  (forged.record as unknown as { change: { ref: string } }).change.ref = "billing/refund-agent#system-v2";
  const fv = await verifyReceiptV2(forged);
  expect(fv.checks.binding.status === "fail" && fv.checks.signature.status === "fail", "editing one field breaks the binding and the signature");

  /* 2 */
  chapter("Selective disclosure and witness signatures", "reveal one sealed field to an auditor; count only independent co-signatures");
  const disclosure = disclose(receipt, "change.after", promptAfter);
  expect(verifyDisclosure(receipt, disclosure).ok, "the true prompt text opens its commitment");
  expect(!verifyDisclosure(receipt, { ...disclosure, value: "Approve refunds up to $5,000." }).ok, "a doctored disclosure is refused");
  const wv = await verifyReceiptV2(attachWitness(receipt, cosign(receipt.sth!, keys.witness)));
  expect(wv.checks.witnesses.status === "pass", "an external witness co-signature is counted; the operator's own is not", wv.checks.witnesses.detail);
  await tee.close();

  /* 3 */
  chapter("One evidence envelope", "cool.envelope.v1: typed payloads, canonical bytes, hybrid signatures, and eleven separate checks");
  const commitInput: EnvelopeInput = { event_type: "scm.commit", occurred_at: new Date(Date.now() - 5_000).toISOString(), source: { system: "git", instance: "acme/service", event_id: "a1b2c3" }, actor: { id: "user:asha", type: "human" }, action: "commit", resource: { type: "repository", ref: "acme/service" }, payload: { repository: "acme/service", commit: "a1b2c3", author: "asha", signed: true } };
  const commit = app.evidence.publish(app.evidence.record(commitInput));
  const cr = app.evidence.verify(commit);
  expect(cr.overall_status === "pass", "a published envelope passes every applicable check", Object.entries(cr.checks).filter(([, c]) => c.status === "pass").map(([k]) => k).join(", "));
  const outsider = new CoolClient({ project: "x", signer: keys.rogue, trust }).evidence.record({ ...commitInput, event_id: "o1" });
  const or = app.evidence.verify(outsider);
  expect(or.checks.signature_valid.status === "pass" && or.checks.signer_trusted.reason === "untrusted_key", "a valid signature from an unknown key is NOT trusted — two different questions");
  const retired = new CoolClient({ project: "x", signer: keys.retired, trust }).evidence.record({ ...commitInput, event_id: "r1" });
  expect(app.evidence.verify(retired).checks.signer_trusted.reason === "key_revoked", "a revoked key is rejected without independent proof the signature predates revocation");
  let refused = "";
  try { app.evidence.create({ ...commitInput, payload: { ...commitInput.payload, password: "hunter2" } }); } catch (err) { refused = (err as Error).message; }
  expect(/unexpected field password/.test(refused), "payloads are strict: an unexpected (here, secret) field is refused at creation");
  recorded.push(commit);

  /* 4 */
  chapter("Transparency log and witnessed checkpoints", "an append-only RFC 6962 log; a second party co-signs the head; forged heads fail");
  const witnessed = { ...commit, checkpoint: tlog.checkpoint(commit.digest, [keys.witness])! };
  const wr = verifyEnvelope(witnessed, { registry, trust, witnessThreshold: 1 });
  expect(wr.checks.inclusion_proof_valid.status === "pass" && wr.checks.checkpoint_trusted.status === "pass", "inclusion proof and witnessed checkpoint verify", wr.checks.checkpoint_trusted.detail);
  const forgedHead = { ...witnessed, checkpoint: { ...witnessed.checkpoint, sth: { ...witnessed.checkpoint.sth, tree_size: 99 } } };
  expect(verifyEnvelope(forgedHead, { registry, trust }).checks.checkpoint_trusted.reason === "checkpoint_signature_invalid", "a forged tree head is rejected");

  /* 5 */
  chapter("Reference capture: local git history", "a read-only connector turns real commits into evidence — no e-mail addresses, no network");
  const run = await app.connectors.run(new GitConnector(process.cwd(), { repository: "cool-sdk", limit: 3 }));
  const gitEnvs = run.collected.map((input) => app.evidence.publish(app.evidence.record(input)));
  expect(run.status === "complete" && gitEnvs.length > 0, `${gitEnvs.length} real commits recorded as scm.commit evidence`, run.errors.join("; "));
  expect(!JSON.stringify(gitEnvs).includes("@"), "no e-mail addresses entered the evidence");
  recorded.push(...gitEnvs);

  /* 6 */
  chapter("AWS Nitro: a GENUINE AWS attestation document", "verified offline against the pinned AWS root; a debug enclave is caught");
  const genuine = new Uint8Array(Buffer.from(readFileSync(join(import.meta.dirname, "..", "tests", "fixtures", "nitro", "genuine-debug-us-east-1-2024-09-09.cbor.b64"), "utf8").trim(), "base64"));
  const at = { now: Date.parse("2024-09-09T19:49:13Z"), certificateTime: "attestation-timestamp" as const };
  const gr = verifyNitroAttestation(genuine, at);
  expect(gr.checks.trust_root.status === "pass" && gr.checks.certificate_chain.status === "pass" && gr.checks.cose_signature.status === "pass", "COSE signature and 4-certificate chain verify to AWS_NitroEnclaves_Root-G1");
  expect(gr.checks.debug_mode.reason === "debug_enclave" && gr.overall_status === "fail", "this enclave ran in debug mode (PCR0–2 zero), so it fails — whatever else passed");
  const flipped = new Uint8Array(genuine);
  flipped[flipped.length - 1] = flipped[flipped.length - 1]! ^ 1;
  expect(verifyNitroAttestation(flipped, at).checks.cose_signature.reason === "signature_invalid", "one flipped bit and the signature fails; claims are never consumed");

  /* 7 */
  chapter("AWS Nitro: sealing receipts in an enclave (SYNTHETIC test PKI)", "a fresh in-enclave key, bound by attestation; the untrusted host can drop or mangle, never forge");
  const pki = syntheticNitroPki();
  const bundle = trustBundleFromDer("synthetic-test-pki", "per-run", "tests/support/synthetic-pki.ts", [{ name: "synthetic.nitro-root", der: pki.root }]);
  const policy = { id: "agent-enclave", version: "1", source: "showcase", pcrs: { 0: pcrHex("10"), 1: pcrHex("11"), 2: pcrHex("12") }, pcr8: "not_applicable" as const };
  const nonce = new Uint8Array(32).fill(7);
  const nsm: NsmSource = { attest: async (req) => syntheticAttestation(pki, { ...req, timestamp: Date.now() - 1_000 }) };
  const sealer = await NitroReceiptSealer.start({ nsm, registry, nonce });
  sealer.acceptEpoch({ registration: { epoch: 1, key_id: sealer.keyId } });
  expect(normalizeNitro(verifyNitroAttestation(sealer.attestation, { trustBundle: bundle, policy, freshness: { mode: "nonce", expected: nonce }, receiptKey: { keyId: sealer.keyId, entry: sealer.publicEntry } })).overall_status === "pass", "the attestation binds the enclave's fresh receipt key");
  const enclaveTrust = new TrustStore({ ...snapshot, keys: [...snapshot.keys, { key_id: sealer.keyId, entry: sealer.publicEntry, purposes: ["evidence"], owner: "enclave", valid_from: "2026-01-01T00:00:00Z", status: "active" }] });
  const nitroOpts = { registry, trust: enclaveTrust, nitro: { trustBundle: bundle, policy, freshness: { mode: "nonce" as const, expected: nonce } } };
  const sealed = [0, 1].map((i) => sealer.seal({ event_id: `inf-${i}`, event_type: "ai.inference", occurred_at: new Date().toISOString(), source: { system: "agent" }, actor: { id: "workload:refund-agent", type: "workload" }, action: "infer", resource: { type: "model", ref: "acme/refunds@3" }, payload: { model: "acme/refunds", model_version: "3", input_commitment: mhSha256(new Uint8Array([i])), output_commitment: mhSha256(new Uint8Array([i, 9])) } }));
  const viaHost = async (mutate: boolean) => {
    const from = new PassThrough();
    const to = new PassThrough();
    const chunks: Uint8Array[] = [];
    to.on("data", (d: Buffer) => chunks.push(new Uint8Array(d)));
    const host = new Transform({ transform(c: Buffer, _e, cb) { cb(null, mutate ? Buffer.from(c.toString("latin1").replace("refunds@3", "refunds@4"), "latin1") : c); } });
    const done = forwardFrames(from.pipe(host), to);
    for (const r of sealed) from.write(encodeFrame(FrameType.receipt, new TextEncoder().encode(JSON.stringify(r))));
    from.end();
    await done;
    const dec = new FrameDecoder();
    return chunks.flatMap((c) => dec.push(c)).map((f) => JSON.parse(new TextDecoder().decode(f.payload)) as SignedEnvelope);
  };
  const delivered = await viaHost(false);
  expect(delivered.every((r) => verifyEnvelope(r, nitroOpts).overall_status === "pass"), "sealed receipts cross the host unchanged and verify, attestation included");
  const mangled = (await viaHost(true))[0]!;
  expect(verifyEnvelope(mangled, nitroOpts).overall_status === "fail", "a receipt the host altered fails verification", verifyEnvelope(mangled, nitroOpts).reasons[0]);

  /* 8 */
  chapter("Portable proof for an auditor", "export the evidence; anyone re-verifies it offline with their own trust snapshot");
  const proof = exportBundle({ title: "showcase evidence", envelopes: recorded, trust, exporter: keys.exporter });
  writeFileSync(join(dir, "evidence-bundle.json"), JSON.stringify(proof, null, 2));
  writeFileSync(join(dir, "trust.json"), JSON.stringify(snapshot, null, 2));
  const pr = verifyBundle(JSON.parse(readFileSync(join(dir, "evidence-bundle.json"), "utf8")), { registry, trust });
  expect(pr.overall_status === "pass", "the bundle verifies end to end", `${pr.entries.length} envelopes, ordered by time`);
  expect(verifyBundle(JSON.parse(readFileSync(join(dir, "evidence-bundle.json"), "utf8")), { registry }).overall_status === "unknown", "without your own trust snapshot the result is 'unknown' — the exporter cannot vouch for itself");
  const cut = JSON.parse(readFileSync(join(dir, "evidence-bundle.json"), "utf8"));
  cut.envelopes.splice(0, 1);
  expect(verifyBundle(cut, { registry, trust }).checks.manifest_valid.reason === "manifest_mismatch", "removing one record from the bundle is detected");

  const passed = results.filter((r) => r.ok).length;
  const failed = results.length - passed;
  writeFileSync(join(dir, "showcase-report.json"), JSON.stringify({ schema: "cool.showcase-report.v1", edition: "open", ran_at: new Date().toISOString(), passed, failed, results }, null, 2));
  log();
  log(bold(failed === 0 ? green(`all ${passed} claims held`) : red(`${failed} of ${results.length} claims did NOT hold`)));
  log(dim(`artifacts: ${dir}`));
  log(dim(`re-check:  node dist/cli/index.js bundle verify ${join(dir, "evidence-bundle.json")} --trust ${join(dir, "trust.json")}`));
  log(yellow("limits: TDX ran on the simulator; Nitro receipts were sealed on a synthetic PKI; no network was used."));
  log(dim("policy, enforcement, the deployment gate and incident reconstruction are part of the commercial CooL platform."));
  return { dir, results, passed, failed };
}

if (process.argv[1] && /showcase\.ts$/.test(process.argv[1])) {
  runShowcase({ ...(process.argv[2] ? { dir: process.argv[2] } : {}) }).then(
    (o) => process.exit(o.failed === 0 ? 0 : 1),
    (err) => { console.error(err); process.exit(1); },
  );
}
