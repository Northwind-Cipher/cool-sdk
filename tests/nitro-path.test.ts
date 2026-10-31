/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * The Nitro reference path, end to end — on the SYNTHETIC test PKI, never a
 * real enclave. The NSM here signs Nitro-shaped documents with a test leaf
 * key; everything downstream (sealer, framing, proxy, log server, verifier)
 * is the production code.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { PassThrough, Transform } from "node:stream";
import { canonicalCbor } from "../src/canonical";
import { hybridVerify } from "../src/sign";
import { mhSha256 } from "../src/multihash";
import {
  CommandNsmSource,
  FrameDecoder,
  FrameError,
  FrameType,
  MAX_FRAME_BYTES,
  NitroLogServer,
  NitroReceiptSealer,
  encodeFrame,
  forwardFrames,
  normalizeNitro,
  normalizeTdx,
  trustBundleFromDer,
  verifyNitroAttestation,
  type NsmSource,
} from "../src/nitro/index";
import { verifyEnvelope, type SignedEnvelope } from "../src/platform/index";
import { syntheticAttestation, syntheticNitroPki, pcrHex } from "./support/synthetic-pki";
import { KEYS, T0, iso, record, registry, trust } from "./support/platform";

const PKI = syntheticNitroPki();
const BUNDLE = trustBundleFromDer("synthetic-test-pki", "per-run", "tests/support/synthetic-pki.ts", [{ name: "synthetic.nitro-root", der: PKI.root }]);
const POLICY = { id: "agent-enclave", version: "1", source: "test", pcrs: { 0: pcrHex("10"), 1: pcrHex("11"), 2: pcrHex("12") }, pcr8: "not_applicable" as const };

/** A test NSM that answers with a synthetic document dated `at`. */
const nsm = (at: number): NsmSource => ({ attest: async (req) => syntheticAttestation(PKI, { ...req, timestamp: at }) });

const NONCE = new Uint8Array(32).fill(0x42);
const server = (clock = () => new Date(T0)) => new NitroLogServer({
  logKey: KEYS.log,
  logId: "nitro-log",
  registry,
  attestation: { trustBundle: BUNDLE, policy: POLICY, freshness: { mode: "nonce", expected: NONCE } },
  clock,
});

async function enclave(at = T0 - 1_000) {
  const sealer = await NitroReceiptSealer.start({ nsm: nsm(at), registry, nonce: NONCE });
  return sealer;
}

const inference = (i: number) => ({
  event_id: `inf-${i}`,
  event_type: "ai.inference",
  occurred_at: iso(i),
  observed_at: iso(i),
  source: { system: "agent", instance: "enclave" },
  actor: { id: "workload:refund-agent", type: "workload" as const },
  action: "infer",
  resource: { type: "model", ref: "acme/refunds@3" },
  payload: { model: "acme/refunds", model_version: "3", input_commitment: mhSha256(new Uint8Array([i])), output_commitment: mhSha256(new Uint8Array([i, 1])) },
});

test("nitro path: the enclave key is attested, registered, and every receipt is acknowledged and signed", async () => {
  const sealer = await enclave();
  const s = server();
  const reg = s.register(sealer.attestation, sealer.keyId, sealer.publicEntry, "refund-agent");
  sealer.acceptEpoch(reg);
  const ack = s.ingest(sealer.seal(inference(0)));
  assert.equal(ack.ack.outcome, "accepted");
  assert.equal(ack.ack.leaf_index, 0);
  assert.ok(hybridVerify(canonicalCbor(ack.ack), ack.signature, KEYS.log.directoryEntry).ok);
});

test("nitro path: receipts carry no plaintext and are plain envelopes the shared verifier accepts", async () => {
  const sealer = await enclave();
  const s = server();
  sealer.acceptEpoch(s.register(sealer.attestation, sealer.keyId, sealer.publicEntry, "refund-agent"));
  const env = sealer.seal(inference(1));
  assert.equal(JSON.stringify(env).includes("refund this order"), false);
  assert.deepEqual(env.core.sequence, { epoch: 1, number: 0 });
  const t = trust([record({ keyId: sealer.keyId, directoryEntry: sealer.publicEntry } as never, ["evidence"])]);
  const r = verifyEnvelope(env, { registry, trust: t, now: T0, nitro: { trustBundle: BUNDLE, policy: POLICY, freshness: { mode: "nonce", expected: NONCE } } });
  assert.equal(r.checks.attestation_valid.status, "pass", r.checks.attestation_valid.detail);
  assert.equal(r.overall_status, "pass", r.reasons.join("; "));
});

test("nitro path: retries reuse the same sequence; a dropped middle receipt becomes a gap", async () => {
  const sealer = await enclave();
  const s = server();
  sealer.acceptEpoch(s.register(sealer.attestation, sealer.keyId, sealer.publicEntry, "refund-agent"));
  const r0 = sealer.seal(inference(0));
  assert.equal(sealer.seal(inference(0)), r0, "retry returns the identical receipt");
  const r1 = sealer.seal(inference(1));
  const r2 = sealer.seal(inference(2));
  s.ingest(r0);
  s.ingest(r2); // r1 dropped in transit
  assert.deepEqual(s.epochs.gaps(1).map((g) => [g.sequence, g.status]), [[1, "unresolved"]]);
  assert.equal(s.ingest(r1).ack.outcome, "late_fill");
  assert.equal(s.ingest(r1).ack.outcome, "duplicate");
  assert.deepEqual(s.epochs.gaps(1).map((g) => g.status), ["filled_late"]);
});

test("nitro path: frames cross the host proxy unchanged; a mutating proxy produces a rejected receipt", async () => {
  const sealer = await enclave();
  const s = server();
  sealer.acceptEpoch(s.register(sealer.attestation, sealer.keyId, sealer.publicEntry, "refund-agent"));
  const frames = [0, 1, 2].map((i) => encodeFrame(FrameType.receipt, new TextEncoder().encode(JSON.stringify(sealer.seal(inference(i))))));

  const run = async (mutate: boolean) => {
    const from = new PassThrough();
    const to = new PassThrough();
    const received: Uint8Array[] = [];
    to.on("data", (d: Buffer) => received.push(new Uint8Array(d)));
    const hostile = new Transform({ transform(chunk: Buffer, _e, cb) { if (mutate) { const s2 = chunk.toString("latin1").replace("refunds@3", "refunds@4"); cb(null, Buffer.from(s2, "latin1")); } else cb(null, chunk); } });
    const done = forwardFrames(from.pipe(hostile), to);
    for (const f of frames) { from.write(f.subarray(0, 5)); from.write(f.subarray(5)); } // split writes
    from.end();
    const stats = await done;
    const decoder = new FrameDecoder();
    const out = received.flatMap((chunk) => decoder.push(chunk));
    return { stats, receipts: out.map((f) => JSON.parse(new TextDecoder().decode(f.payload)) as SignedEnvelope) };
  };

  const clean = await run(false);
  assert.equal(clean.stats.frames, 3);
  assert.deepEqual(clean.receipts.map((r) => s.ingest(r).ack.outcome), ["accepted", "accepted", "accepted"]);

  const s2 = server();
  s2.register(sealer.attestation, sealer.keyId, sealer.publicEntry, "refund-agent");
  const tampered = await run(true);
  const ack = s2.ingest(tampered.receipts[0]!);
  assert.equal(ack.ack.outcome, "rejected");
  assert.match(ack.ack.detail, /canonical_encoding_valid|digest_valid|schema_valid/);
  assert.equal(s2.epochs.highest(1), -1, "nothing stored from a mutated receipt");
});

test("nitro path: a stale attestation at registration gets no epoch; a debug enclave gets no epoch", async () => {
  const stale = await NitroReceiptSealer.start({ nsm: nsm(T0 - 3_600_000), registry, nonce: NONCE });
  const timed = new NitroLogServer({ logKey: KEYS.log, logId: "l", registry, attestation: { trustBundle: BUNDLE, policy: POLICY, freshness: { mode: "timestamp-window", maxAgeMs: 300_000 } }, clock: () => new Date(T0) });
  assert.throws(() => timed.register(stale.attestation, stale.keyId, stale.publicEntry, "agent"), /freshness: attestation_stale/);

  const debugNsm: NsmSource = { attest: async (req) => syntheticAttestation(PKI, { ...req, timestamp: T0 - 1_000, pcrFill: { 0: "00", 1: "00", 2: "00" } }) };
  const dbg = await NitroReceiptSealer.start({ nsm: debugNsm, registry, nonce: NONCE });
  assert.throws(() => server().register(dbg.attestation, dbg.keyId, dbg.publicEntry, "agent"), /debug_enclave/);
});

test("nitro path: a receipt from an unregistered key, or claiming another key's epoch, is rejected", async () => {
  const a = await enclave();
  const b = await enclave();
  const s = server();
  a.acceptEpoch(s.register(a.attestation, a.keyId, a.publicEntry, "agent"));
  assert.throws(() => b.seal(inference(0)), /no epoch/);
  b.acceptEpoch({ ...s.register(a.attestation, a.keyId, a.publicEntry, "agent"), registration: { ...s.register(a.attestation, a.keyId, a.publicEntry, "agent").registration, key_id: b.keyId } });
  const ack = s.ingest(b.seal(inference(0)));
  assert.equal(ack.ack.outcome, "rejected");
  assert.match(ack.ack.detail, /signer_trusted|attestation_valid/);
});

test("nitro path: the checkpoint is witnessed, and the witness signature is verified", async () => {
  const sealer = await enclave();
  const s = server();
  sealer.acceptEpoch(s.register(sealer.attestation, sealer.keyId, sealer.publicEntry, "agent"));
  const env = sealer.seal(inference(0));
  s.ingest(env);
  const cp = s.checkpoint(env.digest, [KEYS.witness])!;
  const t = trust([record({ keyId: sealer.keyId, directoryEntry: sealer.publicEntry } as never, ["evidence"])]);
  const r = verifyEnvelope({ ...env, checkpoint: cp }, { registry, trust: t, now: T0, witnessThreshold: 1, nitro: { trustBundle: BUNDLE, policy: POLICY, freshness: { mode: "nonce", expected: NONCE } } });
  assert.equal(r.checks.checkpoint_trusted.status, "pass", r.checks.checkpoint_trusted.detail);
  assert.equal(r.checks.inclusion_proof_valid.status, "pass");
});

test("normalization: Nitro and TDX results share one shape; simulated never becomes pass", async () => {
  const sealer = await enclave();
  const rep = verifyNitroAttestation(sealer.attestation, { trustBundle: BUNDLE, policy: POLICY, freshness: { mode: "nonce", expected: NONCE }, receiptKey: { keyId: sealer.keyId, entry: sealer.publicEntry }, now: T0 });
  const n = normalizeNitro(rep);
  assert.equal(n.overall_status, "pass", n.reasons.join("; "));
  assert.deepEqual(Object.keys(n.claims), ["platform_attestation", "workload_measurement", "key_binding", "freshness"]);

  const sim = { status: "simulated" as const, detail: "simulated quote" };
  const tdx = normalizeTdx({ ok: true, schema: "cool.receipt.v2", subject: null, reasons: [], checks: { binding: sim, signature: sim, inclusion: sim, witnesses: sim, attestation: sim, enclave: sim, anchor: sim } } as never);
  assert.equal(tdx.claims.platform_attestation.reason, "simulated_not_hardware");
  assert.equal(tdx.claims.freshness.status, "not_checked");
  assert.notEqual(tdx.overall_status, "pass");
});

test("framing: bad magic, wrong version, oversize and unknown types are refused", () => {
  const d = () => new FrameDecoder();
  assert.throws(() => d().push(Uint8Array.from([0, 0, 1, 2, 0, 0, 0, 0])), (e: unknown) => e instanceof FrameError && e.reason === "bad_magic");
  assert.throws(() => d().push(Uint8Array.from([0xc0, 0x01, 9, 2, 0, 0, 0, 0])), (e: unknown) => e instanceof FrameError && e.reason === "unsupported_version");
  assert.throws(() => d().push(Uint8Array.from([0xc0, 0x01, 1, 99, 0, 0, 0, 0])), (e: unknown) => e instanceof FrameError && e.reason === "unknown_type");
  const huge = Uint8Array.from([0xc0, 0x01, 1, 2, 0xff, 0xff, 0xff, 0xff]);
  assert.throws(() => d().push(huge), (e: unknown) => e instanceof FrameError && e.reason === "frame_too_large");
  assert.throws(() => encodeFrame(FrameType.receipt, new Uint8Array(MAX_FRAME_BYTES + 1)), FrameError);
  const partial = d();
  assert.deepEqual(partial.push(encodeFrame(2, Uint8Array.from([1, 2, 3])).subarray(0, 9)), []);
  assert.equal(partial.pending, 9);
});

test("nsm: a missing helper binary fails loudly instead of returning an empty document", async () => {
  await assert.rejects(new CommandNsmSource("cool-nsm-helper-that-does-not-exist").attest({ user_data: new Uint8Array(32) }), /failed to start|exited/);
});
