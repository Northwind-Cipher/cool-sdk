/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Nitro attestation verification.
 *
 * "genuine" tests run against a real AWS document (see fixtures/nitro/
 * PROVENANCE.md) and the pinned AWS root. "synthetic" tests build documents on
 * a test PKI the verifier only trusts when told to, so the positive path —
 * key binding, PCR policy, nonce — can be exercised with values we control.
 * Every assertion checks the status AND the reason code, not just that
 * something failed.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { sign as cryptoSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Tag, decode, encode } from "cbor2";
import { generateKeypair } from "../src/keys";
import { fromBase64Field } from "../src/codec";
import {
  AWS_NITRO_TRUST_BUNDLE,
  ed25519Spki,
  keyBindingUserData,
  memoryNonceLedger,
  trustBundleFromDer,
  verifyNitroAttestation,
} from "../src/nitro/index";
import type { NitroPcrPolicy, VerifyNitroOptions } from "../src/nitro/index";
import { syntheticNitroPki } from "./support/synthetic-pki";

const DIR = join(import.meta.dirname, "fixtures", "nitro");
const GENUINE = new Uint8Array(
  Buffer.from(readFileSync(join(DIR, "genuine-debug-us-east-1-2024-09-09.cbor.b64"), "utf8").trim(), "base64"),
);
const GENUINE_TIME = Date.parse("2024-09-09T19:49:12.400Z");
const GENUINE_NONCE = Uint8Array.from([...new Array(19).fill(0), 1]);

const PKI = syntheticNitroPki();
const SYN_ROOT = PKI.root;
const SYN_INTER = PKI.intermediate;
const SYN_LEAF = PKI.leaf;
const SYN_LEAF_KEY = PKI.leafKey;
const SYN_BUNDLE = trustBundleFromDer("synthetic-test-pki", "per-run", "tests/support/synthetic-pki.ts", [
  { name: "synthetic.nitro-root", der: SYN_ROOT },
]);
const NOW = Date.parse("2027-01-01T00:00:00Z");

const pcr = (fill: number) => new Uint8Array(48).fill(fill);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const RECEIPT_KEY = generateKeypair("cool-nitro-test", { seed: new Uint8Array(32).fill(7) });
const OTHER_KEY = generateKeypair("cool-nitro-other", { seed: new Uint8Array(32).fill(9) });
const NONCE = new Uint8Array(32).fill(0xab);

const POLICY: NitroPcrPolicy = {
  id: "synthetic-enclave",
  version: "1",
  source: "test constants",
  pcrs: { 0: hex(pcr(0x10)), 1: hex(pcr(0x11)), 2: hex(pcr(0x12)) },
  pcr8: "not_applicable",
};

interface DocParts {
  pcrs?: Map<number, Uint8Array>;
  user_data?: Uint8Array | null;
  public_key?: Uint8Array | null;
  nonce?: Uint8Array | null;
  timestamp?: number;
  cabundle?: Uint8Array[];
  extra?: [string, unknown];
  protectedHeader?: Map<number, unknown>;
  tagged?: boolean;
}

/** Build and sign a synthetic Nitro-shaped document. */
function synthetic(parts: DocParts = {}): Uint8Array {
  const payload = new Map<string, unknown>([
    ["module_id", "i-synthetic-enc0000000000000000"],
    ["digest", "SHA384"],
    ["timestamp", parts.timestamp ?? NOW - 1_000],
    ["pcrs", parts.pcrs ?? new Map([[0, pcr(0x10)], [1, pcr(0x11)], [2, pcr(0x12)], [3, pcr(0)], [8, pcr(0)]])],
    ["certificate", SYN_LEAF],
    ["cabundle", parts.cabundle ?? [SYN_ROOT, SYN_INTER]],
    ["public_key", parts.public_key === undefined ? ed25519Spki(RECEIPT_KEY.ed25519Public) : parts.public_key],
    ["user_data", parts.user_data === undefined ? keyBindingUserData(RECEIPT_KEY.keyId, RECEIPT_KEY.directoryEntry) : parts.user_data],
    ["nonce", parts.nonce === undefined ? NONCE : parts.nonce],
  ]);
  if (parts.extra) payload.set(parts.extra[0], parts.extra[1]);
  const protectedBytes = encode(parts.protectedHeader ?? new Map([[1, -35]]));
  const payloadBytes = encode(payload);
  const tbs = encode(["Signature1", protectedBytes, new Uint8Array(0), payloadBytes]);
  const signature = cryptoSign("sha384", tbs, { key: SYN_LEAF_KEY, dsaEncoding: "ieee-p1363" });
  const cose = [protectedBytes, new Map(), payloadBytes, new Uint8Array(signature)];
  return encode(parts.tagged ? new Tag(18, cose) : cose);
}

const synOptions = (extra: Partial<VerifyNitroOptions> = {}): VerifyNitroOptions => ({
  trustBundle: SYN_BUNDLE,
  policy: POLICY,
  receiptKey: { keyId: RECEIPT_KEY.keyId, entry: RECEIPT_KEY.directoryEntry },
  freshness: { mode: "nonce", expected: NONCE },
  now: NOW,
  ...extra,
});

/** Re-encode the genuine document with its payload changed and the ORIGINAL signature kept. */
function mutateGenuinePayload(change: (payload: Map<unknown, unknown>) => void): Uint8Array {
  const cose = decode(GENUINE, { preferMap: true }) as unknown[];
  const payload = decode(cose[2] as Uint8Array, { preferMap: true }) as Map<unknown, unknown>;
  change(payload);
  return encode([cose[0], cose[1], encode(payload), cose[3]]);
}

/* ── genuine AWS document ─────────────────────────────────────────────── */

test("genuine: signature and chain verify to the pinned AWS root, at the attestation time", () => {
  const r = verifyNitroAttestation(GENUINE, { now: GENUINE_TIME + 1_000, certificateTime: "attestation-timestamp" });
  assert.equal(r.checks.structure.status, "pass");
  assert.equal(r.checks.trust_root.status, "pass");
  assert.equal(r.trust_bundle.root, "AWS_NitroEnclaves_Root-G1");
  assert.equal(r.checks.certificate_chain.status, "pass");
  assert.equal(r.checks.cose_signature.status, "pass");
  assert.equal(r.claims?.verified, true);
  assert.equal(r.claims?.module_id, "i-0bbf1bfe232b8c2ce-enc0191ba35c9d1b77a");
  assert.equal(r.document_sha256, "8056eefb696e0e5d178f9d6cb81f7ef0d4bb084cbac9507663b1a31d89e00385");
});

test("genuine: a debug enclave (PCR0–2 zero) fails, whatever else passes", () => {
  const r = verifyNitroAttestation(GENUINE, { now: GENUINE_TIME, certificateTime: "attestation-timestamp" });
  assert.equal(r.checks.debug_mode.status, "fail");
  assert.equal(r.checks.debug_mode.reason, "debug_enclave");
  assert.equal(r.overall_status, "fail");
});

test("genuine: verified today, the three-hour leaf certificate has expired", () => {
  const r = verifyNitroAttestation(GENUINE, { now: NOW });
  assert.equal(r.checks.certificate_chain.status, "fail");
  assert.equal(r.checks.certificate_chain.reason, "certificate_expired");
  assert.equal(r.claims?.verified, false);
  assert.equal(r.checks.pcr_policy.reason, "claims_unverified");
});

test("genuine: stale under a timestamp window; nonce match, mismatch and replay", () => {
  const archived = { certificateTime: "attestation-timestamp" as const };
  const stale = verifyNitroAttestation(GENUINE, { ...archived, now: NOW, freshness: { mode: "timestamp-window", maxAgeMs: 300_000 } });
  assert.equal(stale.checks.freshness.status, "fail");
  assert.equal(stale.checks.freshness.reason, "attestation_stale");

  const ledger = memoryNonceLedger();
  const opts = { ...archived, now: GENUINE_TIME, freshness: { mode: "nonce" as const, expected: GENUINE_NONCE, ledger } };
  assert.equal(verifyNitroAttestation(GENUINE, opts).checks.freshness.reason, "nonce_fresh");
  const replay = verifyNitroAttestation(GENUINE, opts);
  assert.equal(replay.checks.freshness.status, "fail");
  assert.equal(replay.checks.freshness.reason, "nonce_replayed");

  const wrong = verifyNitroAttestation(GENUINE, { ...archived, now: GENUINE_TIME, freshness: { mode: "nonce", expected: NONCE } });
  assert.equal(wrong.checks.freshness.reason, "nonce_mismatch");
});

test("genuine: a changed PCR breaks the signature and the PCR is never consumed", () => {
  const forged = mutateGenuinePayload((p) => {
    (p.get("pcrs") as Map<number, Uint8Array>).set(0, pcr(0x42));
  });
  const r = verifyNitroAttestation(forged, { now: GENUINE_TIME, certificateTime: "attestation-timestamp", policy: { ...POLICY, pcrs: { 0: hex(pcr(0x42)), 1: hex(pcr(0)), 2: hex(pcr(0)) } } });
  assert.equal(r.checks.cose_signature.status, "fail");
  assert.equal(r.checks.cose_signature.reason, "signature_invalid");
  assert.equal(r.checks.pcr_policy.status, "not_checked");
  assert.equal(r.checks.pcr_policy.reason, "claims_unverified");
  assert.equal(r.claims?.verified, false);
  assert.equal(r.overall_status, "fail");
});

test("genuine: an altered signature byte fails the signature check", () => {
  const forged = new Uint8Array(GENUINE);
  forged[forged.length - 1] = forged[forged.length - 1]! ^ 0x01;
  const r = verifyNitroAttestation(forged, { now: GENUINE_TIME, certificateTime: "attestation-timestamp" });
  assert.equal(r.checks.cose_signature.reason, "signature_invalid");
  assert.equal(r.checks.certificate_chain.status, "pass");
});

test("genuine: a broken chain (intermediate removed) fails the chain check", () => {
  const forged = mutateGenuinePayload((p) => {
    const bundle = p.get("cabundle") as Uint8Array[];
    p.set("cabundle", [bundle[0], ...bundle.slice(2)]);
  });
  const r = verifyNitroAttestation(forged, { now: GENUINE_TIME, certificateTime: "attestation-timestamp" });
  assert.equal(r.checks.certificate_chain.status, "fail");
  assert.equal(r.checks.certificate_chain.reason, "chain_issuer_mismatch");
});

test("genuine: the AWS document is untrusted under a different pinned root", () => {
  const r = verifyNitroAttestation(GENUINE, { trustBundle: SYN_BUNDLE, now: GENUINE_TIME, certificateTime: "attestation-timestamp" });
  assert.equal(r.checks.trust_root.status, "fail");
  assert.equal(r.checks.trust_root.reason, "untrusted_root");
  assert.equal(r.claims?.verified, false);
});

/** Deterministic single-byte corruption: same inputs, same flips, every run. */
function* flips(doc: Uint8Array, count: number, seed: number): Generator<Uint8Array> {
  let s = seed;
  const next = () => (s = (s * 1103515245 + 12345) & 0x7fffffff);
  for (let i = 0; i < count; i++) {
    const forged = new Uint8Array(doc);
    const at = next() % forged.length;
    forged[at] = forged[at]! ^ (1 + (next() % 255));
    yield forged;
  }
}

test("genuine: 300 single-byte corruptions never yield verified claims, and never throw", () => {
  for (const forged of flips(GENUINE, 300, 0x5eed)) {
    const r = verifyNitroAttestation(forged, { now: GENUINE_TIME, certificateTime: "attestation-timestamp" });
    assert.notEqual(r.claims?.verified, true);
    assert.equal(r.overall_status, "fail");
  }
});

test("synthetic: 300 single-byte corruptions of a PASSING document never pass", () => {
  const good = synthetic();
  assert.equal(verifyNitroAttestation(good, synOptions()).overall_status, "pass");
  for (const forged of flips(good, 300, 0xc001)) {
    const r = verifyNitroAttestation(forged, synOptions());
    assert.notEqual(r.overall_status, "pass");
  }
});

/* ── structure ────────────────────────────────────────────────────────── */

test("structure: malformed CBOR, empty and oversized input are rejected with reasons", () => {
  assert.equal(verifyNitroAttestation(Uint8Array.from([0xff, 0x00])).checks.structure.reason, "malformed_cbor");
  assert.equal(verifyNitroAttestation(new Uint8Array(0)).checks.structure.reason, "oversized_or_empty");
  assert.equal(verifyNitroAttestation(GENUINE, { maxBytes: 1024 }).checks.structure.reason, "oversized_or_empty");
  const truncated = verifyNitroAttestation(GENUINE.subarray(0, GENUINE.length - 10));
  assert.equal(truncated.checks.structure.status, "fail");
  assert.equal(truncated.overall_status, "fail");
  assert.equal(truncated.checks.cose_signature.status, "not_checked");
});

test("structure (synthetic): unsupported algorithm, extra header, unexpected field", () => {
  const es256 = verifyNitroAttestation(synthetic({ protectedHeader: new Map([[1, -7]]) }), synOptions());
  assert.equal(es256.checks.structure.reason, "unsupported_algorithm");
  const crit = verifyNitroAttestation(synthetic({ protectedHeader: new Map<number, unknown>([[1, -35], [2, [1]]]) }), synOptions());
  assert.equal(crit.checks.structure.reason, "unexpected_header");
  const extra = verifyNitroAttestation(synthetic({ extra: ["is_admin", true] }), synOptions());
  assert.equal(extra.checks.structure.reason, "unexpected_field");
});

test("structure: duplicate map keys are rejected rather than resolved", () => {
  // payload {"a": 1, "a": 2} — hand-encoded, since an encoder will not produce
  // it — with a 96-byte signature so decoding reaches the payload.
  const dup = Uint8Array.from([
    0x84, 0x44, 0xa1, 0x01, 0x38, 0x22, 0xa0,
    0x47, 0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02,
    0x58, 0x60, ...new Array(96).fill(0),
  ]);
  const r = verifyNitroAttestation(dup);
  assert.equal(r.checks.structure.status, "fail");
  assert.equal(r.checks.structure.reason, "malformed_cbor");
  assert.match(r.checks.structure.detail, /payload/);
});

/* ── synthetic positive path and policy ───────────────────────────────── */

test("synthetic: a bound, fresh, policy-matching document passes — tagged or untagged", () => {
  for (const tagged of [false, true]) {
    const r = verifyNitroAttestation(synthetic({ tagged }), synOptions());
    assert.equal(r.overall_status, "pass", r.reasons.join("; "));
    assert.equal(r.trust_bundle.id, "synthetic-test-pki");
    assert.equal(r.checks.key_binding.reason, "key_bound");
    assert.equal(r.checks.public_key.reason, "public_key_match");
    assert.equal(r.checks.pcr8_signing.status, "not_applicable");
    assert.deepEqual(r.reasons, []);
  }
});

test("synthetic: the synthetic root is NOT trusted by default", () => {
  const r = verifyNitroAttestation(synthetic(), { ...synOptions(), trustBundle: undefined });
  assert.equal(r.trust_bundle.id, AWS_NITRO_TRUST_BUNDLE.id);
  assert.equal(r.checks.trust_root.reason, "untrusted_root");
  assert.equal(r.overall_status, "fail");
});

test("synthetic: changed PCR, missing PCR, PCR8 mismatch", () => {
  const changed = verifyNitroAttestation(synthetic({ pcrs: new Map([[0, pcr(0x66)], [1, pcr(0x11)], [2, pcr(0x12)]]) }), synOptions());
  assert.equal(changed.checks.pcr_policy.reason, "pcr_mismatch");
  assert.equal(changed.overall_status, "fail");

  const pinned3 = { ...POLICY, pcrs: { ...POLICY.pcrs, 4: hex(pcr(0x44)) } };
  const missing = verifyNitroAttestation(synthetic(), synOptions({ policy: pinned3 }));
  assert.equal(missing.checks.pcr_policy.reason, "pcr_missing");

  const signed = { ...POLICY, pcr8: hex(pcr(0x88)) };
  assert.equal(verifyNitroAttestation(synthetic(), synOptions({ policy: signed })).checks.pcr8_signing.reason, "pcr8_mismatch");
  const pcr8ok = synthetic({ pcrs: new Map([[0, pcr(0x10)], [1, pcr(0x11)], [2, pcr(0x12)], [8, pcr(0x88)]]) });
  assert.equal(verifyNitroAttestation(pcr8ok, synOptions({ policy: signed })).checks.pcr8_signing.reason, "pcr8_match");
});

test("synthetic: a debug enclave fails even on a trusted chain", () => {
  const r = verifyNitroAttestation(synthetic({ pcrs: new Map([[0, pcr(0)], [1, pcr(0)], [2, pcr(0)]]) }), synOptions());
  assert.equal(r.checks.debug_mode.reason, "debug_enclave");
  assert.equal(r.overall_status, "fail");
});

test("synthetic: wrong receipt key, modified user_data, modified public_key", () => {
  const wrongKey = verifyNitroAttestation(synthetic(), synOptions({ receiptKey: { keyId: OTHER_KEY.keyId, entry: OTHER_KEY.directoryEntry } }));
  assert.equal(wrongKey.checks.key_binding.reason, "key_binding_mismatch");
  assert.equal(wrongKey.checks.public_key.reason, "public_key_mismatch");

  const ud = keyBindingUserData(RECEIPT_KEY.keyId, RECEIPT_KEY.directoryEntry);
  ud[0] = ud[0]! ^ 1;
  assert.equal(verifyNitroAttestation(synthetic({ user_data: ud }), synOptions()).checks.key_binding.reason, "key_binding_mismatch");
  assert.equal(verifyNitroAttestation(synthetic({ user_data: null }), synOptions()).checks.key_binding.reason, "user_data_absent");

  const pk = ed25519Spki(OTHER_KEY.ed25519Public);
  const r = verifyNitroAttestation(synthetic({ public_key: pk }), synOptions());
  assert.equal(r.checks.public_key.reason, "public_key_mismatch");
  assert.equal(r.checks.key_binding.status, "pass");
});

test("synthetic: public_key reserved for another protocol is not_applicable, user_data still binds", () => {
  const r = verifyNitroAttestation(synthetic({ public_key: Uint8Array.from([1, 2, 3]) }), synOptions({ policy: { ...POLICY, publicKey: "unused" } }));
  assert.equal(r.checks.public_key.status, "not_applicable");
  assert.equal(r.overall_status, "pass");
});

test("synthetic: the key binding is the documented digest of both public keys", () => {
  const expected = keyBindingUserData(RECEIPT_KEY.keyId, RECEIPT_KEY.directoryEntry);
  assert.equal(expected.length, 32);
  assert.notDeepEqual(expected, keyBindingUserData("another-id", RECEIPT_KEY.directoryEntry));
  assert.deepEqual(fromBase64Field(RECEIPT_KEY.directoryEntry.ed25519_pub), RECEIPT_KEY.ed25519Public);
});

test("synthetic: freshness — no silent downgrade, expired and future timestamps", () => {
  const noNonce = verifyNitroAttestation(synthetic({ nonce: null }), synOptions());
  assert.equal(noNonce.checks.freshness.reason, "nonce_absent");

  const window = { mode: "timestamp-window" as const, maxAgeMs: 60_000 };
  const old = verifyNitroAttestation(synthetic({ timestamp: NOW - 120_000 }), synOptions({ freshness: window }));
  assert.equal(old.checks.freshness.reason, "attestation_stale");
  const future = verifyNitroAttestation(synthetic({ timestamp: NOW + 600_000 }), synOptions({ freshness: window }));
  assert.equal(future.checks.freshness.reason, "timestamp_in_future");
  const ok = verifyNitroAttestation(synthetic(), synOptions({ freshness: window }));
  assert.equal(ok.checks.freshness.reason, "within_window");
  assert.ok(ok.checks.freshness.limitation?.includes("weaker than a nonce"));
});

test("synthetic: missing policy, freshness or receipt key is unknown — never pass", () => {
  assert.equal(verifyNitroAttestation(synthetic(), synOptions({ policy: undefined })).overall_status, "unknown");
  assert.equal(verifyNitroAttestation(synthetic(), synOptions({ freshness: undefined })).overall_status, "unknown");
  assert.equal(verifyNitroAttestation(synthetic(), synOptions({ receiptKey: undefined })).overall_status, "unknown");
  const partial = { ...POLICY, pcrs: { 0: POLICY.pcrs[0]! } };
  const r = verifyNitroAttestation(synthetic(), synOptions({ policy: partial }));
  assert.equal(r.checks.pcr_policy.reason, "policy_incomplete");
  assert.equal(r.overall_status, "unknown");
});

test("synthetic: a stale trust bundle is unknown; an expired chain fails", () => {
  const stale = trustBundleFromDer("synthetic-test-pki", "per-run", "test", [{ name: "synthetic.nitro-root", der: SYN_ROOT }], "2026-12-01T00:00:00Z");
  const r = verifyNitroAttestation(synthetic(), synOptions({ trustBundle: stale }));
  assert.equal(r.checks.trust_root.reason, "trust_bundle_stale");
  assert.equal(r.overall_status, "unknown");

  const expired = verifyNitroAttestation(synthetic({ timestamp: Date.parse("2047-01-01") - 1_000 }), synOptions({ now: Date.parse("2047-01-01") }));
  assert.equal(expired.checks.certificate_chain.reason, "certificate_expired");
});
