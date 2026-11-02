/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The open half of the Nitro path, on the SYNTHETIC test PKI — never a real
 * enclave: the in-enclave sealer, the enclave↔host framing, and verification
 * of sealed receipts by the shared envelope verifier. (Epoch/gap accounting in
 * the log server is part of the commercial platform and tested there.)
 */
import test from "node:test";
import assert from "node:assert/strict";
import { PassThrough, Transform } from "node:stream";
import { mhSha256 } from "../src/multihash";
import {
  CommandNsmSource,
  FrameDecoder,
  FrameError,
  FrameType,
  MAX_FRAME_BYTES,
  NitroReceiptSealer,
  encodeFrame,
  forwardFrames,
  normalizeNitro,
  normalizeTdx,
  trustBundleFromDer,
  verifyNitroAttestation,
  type NsmSource,
} from "../src/nitro/index";
import { verifyEnvelope, type SignedEnvelope, type VerifyEnvelopeOptions } from "../src/platform/index";
import { syntheticAttestation, syntheticNitroPki, pcrHex } from "./support/synthetic-pki";
import { T0, iso, record, registry, trust } from "./support/platform";

const PKI = syntheticNitroPki();
const BUNDLE = trustBundleFromDer("synthetic-test-pki", "per-run", "tests/support/synthetic-pki.ts", [{ name: "synthetic.nitro-root", der: PKI.root }]);
const POLICY = { id: "agent-enclave", version: "1", source: "test", pcrs: { 0: pcrHex("10"), 1: pcrHex("11"), 2: pcrHex("12") }, pcr8: "not_applicable" as const };
const NONCE = new Uint8Array(32).fill(0x42);
const nsm = (at: number, pcrFill?: Record<number, string>): NsmSource => ({ attest: async (req) => syntheticAttestation(PKI, { ...req, timestamp: at, ...(pcrFill ? { pcrFill } : {}) }) });

async function enclave(at = T0 - 1_000) {
  const sealer = await NitroReceiptSealer.start({ nsm: nsm(at), registry, nonce: NONCE });
  sealer.acceptEpoch({ registration: { epoch: 1, key_id: sealer.keyId } });
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

const verifyOpts = (sealer: NitroReceiptSealer): VerifyEnvelopeOptions => ({
  registry,
  trust: trust([record({ keyId: sealer.keyId, directoryEntry: sealer.publicEntry } as never, ["evidence"])]),
  now: T0,
  nitro: { trustBundle: BUNDLE, policy: POLICY, freshness: { mode: "nonce", expected: NONCE } },
});

test("nitro sealer: receipts carry no plaintext and are plain envelopes the shared verifier accepts", async () => {
  const sealer = await enclave();
  const env = sealer.seal(inference(1));
  assert.equal(JSON.stringify(env).includes("refund this order"), false);
  assert.deepEqual(env.core.sequence, { epoch: 1, number: 0 });
  const r = verifyEnvelope(env, verifyOpts(sealer));
  assert.equal(r.checks.attestation_valid.status, "pass", r.checks.attestation_valid.detail);
  assert.equal(r.overall_status, "pass", r.reasons.join("; "));
});

test("nitro sealer: no epoch means no receipts; retries reuse the same sequence", async () => {
  const fresh = await NitroReceiptSealer.start({ nsm: nsm(T0 - 1_000), registry, nonce: NONCE });
  assert.throws(() => fresh.seal(inference(0)), /no epoch/);
  assert.throws(() => fresh.acceptEpoch({ registration: { epoch: 1, key_id: "someone-else" } }), /different key/);
  const sealer = await enclave();
  const r0 = sealer.seal(inference(0));
  assert.equal(sealer.seal(inference(0)), r0, "retry returns the identical receipt");
  assert.deepEqual(sealer.seal(inference(1)).core.sequence, { epoch: 1, number: 1 });
});

test("nitro framing: frames cross the host proxy unchanged; a mutating proxy produces a receipt that fails verification", async () => {
  const sealer = await enclave();
  const frames = [0, 1, 2].map((i) => encodeFrame(FrameType.receipt, new TextEncoder().encode(JSON.stringify(sealer.seal(inference(i))))));
  const run = async (mutate: boolean) => {
    const from = new PassThrough();
    const to = new PassThrough();
    const received: Uint8Array[] = [];
    to.on("data", (d: Buffer) => received.push(new Uint8Array(d)));
    const host = new Transform({ transform(chunk: Buffer, _e, cb) { cb(null, mutate ? Buffer.from(chunk.toString("latin1").replace("refunds@3", "refunds@4"), "latin1") : chunk); } });
    const done = forwardFrames(from.pipe(host), to);
    for (const f of frames) { from.write(f.subarray(0, 5)); from.write(f.subarray(5)); }
    from.end();
    const stats = await done;
    const decoder = new FrameDecoder();
    return { stats, receipts: received.flatMap((c) => decoder.push(c)).map((f) => JSON.parse(new TextDecoder().decode(f.payload)) as SignedEnvelope) };
  };
  const clean = await run(false);
  assert.equal(clean.stats.frames, 3);
  for (const r of clean.receipts) assert.equal(verifyEnvelope(r, verifyOpts(sealer)).overall_status, "pass");
  const tampered = await run(true);
  const report = verifyEnvelope(tampered.receipts[0]!, verifyOpts(sealer));
  assert.equal(report.overall_status, "fail");
  assert.equal(report.checks.canonical_encoding_valid.reason, "core_mismatch");
});

test("nitro attestation: a debug enclave and a stale document are refused", async () => {
  const dbg = await NitroReceiptSealer.start({ nsm: nsm(T0 - 1_000, { 0: "00", 1: "00", 2: "00" }), registry, nonce: NONCE });
  const d = verifyNitroAttestation(dbg.attestation, { trustBundle: BUNDLE, policy: POLICY, freshness: { mode: "nonce", expected: NONCE }, receiptKey: { keyId: dbg.keyId, entry: dbg.publicEntry }, now: T0 });
  assert.equal(d.checks.debug_mode.reason, "debug_enclave");
  const old = await NitroReceiptSealer.start({ nsm: nsm(T0 - 3_600_000), registry, nonce: NONCE });
  const s = verifyNitroAttestation(old.attestation, { trustBundle: BUNDLE, policy: POLICY, freshness: { mode: "timestamp-window", maxAgeMs: 300_000 }, receiptKey: { keyId: old.keyId, entry: old.publicEntry }, now: T0 });
  assert.equal(s.checks.freshness.reason, "attestation_stale");
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
  assert.notEqual(tdx.overall_status, "pass");
});

test("framing: bad magic, wrong version, oversize and unknown types are refused", () => {
  const d = () => new FrameDecoder();
  assert.throws(() => d().push(Uint8Array.from([0, 0, 1, 2, 0, 0, 0, 0])), (e: unknown) => e instanceof FrameError && e.reason === "bad_magic");
  assert.throws(() => d().push(Uint8Array.from([0xc0, 0x01, 9, 2, 0, 0, 0, 0])), (e: unknown) => e instanceof FrameError && e.reason === "unsupported_version");
  assert.throws(() => d().push(Uint8Array.from([0xc0, 0x01, 1, 99, 0, 0, 0, 0])), (e: unknown) => e instanceof FrameError && e.reason === "unknown_type");
  assert.throws(() => d().push(Uint8Array.from([0xc0, 0x01, 1, 2, 0xff, 0xff, 0xff, 0xff])), (e: unknown) => e instanceof FrameError && e.reason === "frame_too_large");
  assert.throws(() => encodeFrame(FrameType.receipt, new Uint8Array(MAX_FRAME_BYTES + 1)), FrameError);
  const partial = d();
  assert.deepEqual(partial.push(encodeFrame(2, Uint8Array.from([1, 2, 3])).subarray(0, 9)), []);
  assert.equal(partial.pending, 9);
});

test("nsm: a missing helper binary fails loudly instead of returning an empty document", async () => {
  await assert.rejects(new CommandNsmSource("cool-nsm-helper-that-does-not-exist").attest({ user_data: new Uint8Array(32) }), /failed to start|exited/);
});
