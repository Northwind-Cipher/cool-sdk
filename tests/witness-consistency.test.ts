/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Log consistency and the observing witness, exercised on a real multi-event
 * CooL log (tree sizes 1..8) with forged and altered inputs at every step.
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  CoolTee,
  Witness,
  attachWitness,
  consistencyProof,
  leafHash,
  merkleRoot,
  multihashDigest,
  recordLeafDataV2,
  verifyConsistency,
  verifyLogConsistency,
  verifyReceiptV2,
  withTrustedKeys,
} from "../src/phala/index";
import { generateKeypair } from "../src/keys";
import type { ReceiptV2 } from "../src/phala/types";

async function buildLog(name: string, n: number): Promise<ReceiptV2[]> {
  const cool = await CoolTee.connect({ app: { name, imageDigest: `sha256:${name}` }, capture: { flushMs: 1 } });
  const out: ReceiptV2[] = [];
  for (let i = 0; i < n; i++) out.push(await cool.record({ type: "model.execution", metadata: { name, i } }));
  await cool.close();
  return out;
}

type Mutable<T> = { -readonly [K in keyof T]: Mutable<T[K]> };
const clone = <T>(v: T): Mutable<T> => structuredClone(v) as Mutable<T>;
const flip = (s: string) => s.slice(0, -1) + (s.slice(-1) === "0" ? "1" : "0");
const flipMh = (mh: string) => `mh:sha256:${flip(mh.slice("mh:sha256:".length))}`;

test("consistency: a real 8-event log verifies at every size, pair by pair", async () => {
  const log = await buildLog("c8", 8);
  assert.deepEqual(log.map((r) => r.sth!.tree_size), [1, 2, 3, 4, 5, 6, 7, 8]);
  const r = verifyLogConsistency(log);
  assert.equal(r.ok, true, r.reasons.join("; "));
  assert.equal(r.heads.length, 8);
  assert.equal(r.pairs.length, 7);
  assert.ok(r.heads.every((h) => h.signature_ok && h.root_matches_leaves));
});

test("consistency: a modified OLD root fails", async () => {
  const log = await buildLog("old", 6);
  const bad = clone(log);
  bad[1]!.sth!.root_hash = flipMh(bad[1]!.sth!.root_hash) as never;
  const r = verifyLogConsistency(bad);
  assert.equal(r.ok, false);
  assert.ok(r.reasons.some((x) => /tree head 2/.test(x)));
});

test("consistency: a modified NEW root fails", async () => {
  const log = await buildLog("new", 6);
  const bad = clone(log);
  bad[5]!.sth!.root_hash = flipMh(bad[5]!.sth!.root_hash) as never;
  const r = verifyLogConsistency(bad);
  assert.equal(r.ok, false);
  assert.ok(r.reasons.some((x) => /tree head 6/.test(x)));
});

test("consistency: wrong tree sizes fail (verifyConsistency and the receipt-level check)", async () => {
  const log = await buildLog("sizes", 6);
  const leaves = log.map((r) => leafHash(recordLeafDataV2(r.binding_hash)));
  const proof = consistencyProof(leaves, 2);
  const old = multihashDigest(log[1]!.sth!.root_hash);
  const now = multihashDigest(log[5]!.sth!.root_hash);
  assert.equal(verifyConsistency(2, 6, old, now, proof), true);
  assert.equal(verifyConsistency(3, 6, old, now, proof), false, "wrong first size");
  // RFC 6962 verification binds the size only through the path shape, so sizes with the same
  // shape (5 and 6 here) are told apart by the signed head and the leaves — the chain check below.
  for (const wrong of [2, 3, 9]) {
    assert.equal(verifyConsistency(2, wrong, old, now, proof), false, `wrong second size ${wrong}`);
  }
  assert.equal(verifyConsistency(6, 2, now, old, proof), false, "sizes reversed");
  assert.equal(verifyConsistency(2, 6, now, old, proof), false, "roots swapped");
  assert.equal(verifyConsistency(2, 6, old, now, proof.slice(1)), false, "truncated proof");
  assert.deepEqual(merkleRoot(leaves.slice(0, 2)), old, "the signed head is the root of its leaves");

  const bad = clone(log);
  bad[3]!.sth!.tree_size = 9; // a head claiming a size the leaves do not cover
  assert.equal(verifyLogConsistency(bad).ok, false);
});

test("consistency: a forked history (two roots for one size) and a missing leaf fail", async () => {
  const a = await buildLog("fork", 4);
  const b = await buildLog("fork2", 4);
  const forked = [...a, b[3]!]; // a second, different head of size 4
  assert.equal(verifyLogConsistency(forked).ok, false);

  const missing = a.filter((_, i) => i !== 1);
  assert.equal(verifyLogConsistency(missing).ok, false);
});

test("consistency: a forged STH signature fails even when the root is right", async () => {
  const log = await buildLog("sig", 4);
  const bad = clone(log);
  const sig = bad[2]!.sth!.signature;
  bad[2]!.sth!.signature = { ...sig, ed25519: `${sig.ed25519.slice(0, -6)}AAAAAA` as typeof sig.ed25519 };
  const r = verifyLogConsistency(bad);
  assert.equal(r.ok, false);
  assert.ok(r.reasons.some((x) => /signature does not verify/.test(x)));
});

/* ── the observing witness ─────────────────────────────────────────────── */

const accept = async (r: ReceiptV2) => {
  const v = await verifyReceiptV2(r, {});
  const ok =
    v.checks.binding.status === "pass" &&
    v.checks.signature.status === "pass" &&
    v.checks.inclusion.status === "pass";
  return { ok, reasons: v.reasons };
};

test("witness: signs only after verifying the log; its key is distinct from the log's keys", async () => {
  const log = await buildLog("w1", 6);
  const key = generateKeypair("independent-witness");
  const w = new Witness(key, { verifyReceipt: accept });
  const d = await w.observe(log, 6);
  assert.equal(d.ok, true, d.reasons.join("; "));
  assert.equal(d.checks?.receipts_verified, 6);
  assert.equal(d.checks?.consistency_pairs_verified, 5);

  for (const id of [log[5]!.record.signature.key_id, log[5]!.sth!.signature.key_id]) {
    assert.notEqual(key.keyId, id);
    const e = log[5]!.key_directory[id]!;
    assert.notEqual(e.ed25519_pub, key.directoryEntry.ed25519_pub);
    assert.notEqual(e.ml_dsa_pub, key.directoryEntry.ml_dsa_pub);
  }

  const witnessed = attachWitness(log[5]!, d.statement!);
  const verdict = await verifyReceiptV2(
    withTrustedKeys(witnessed, { [key.keyId]: key.directoryEntry }),
    { witnessThreshold: 1 },
  );
  assert.equal(verdict.checks.witnesses.status, "pass");

  // With a DIFFERENT key trusted under that id, the same signature does not count.
  const other = generateKeypair(key.keyId);
  const untrusted = await verifyReceiptV2(
    withTrustedKeys(witnessed, { [key.keyId]: other.directoryEntry }),
    { witnessThreshold: 1 },
  );
  assert.notEqual(untrusted.checks.witnesses.status, "pass");
});

test("witness: refuses a forged or altered head, a tampered receipt, and a size it cannot see", async () => {
  const log = await buildLog("w2", 5);
  const w = new Witness(generateKeypair("w"), { verifyReceipt: accept });

  const forged = clone(log[4]!.sth!);
  forged.root_hash = flipMh(forged.root_hash) as never;
  const f = await w.cosignPresented(forged, log);
  assert.equal(f.ok, false);
  assert.match(f.reasons.join(" "), /not the head the log actually signed/);

  const retimed = clone(log[4]!.sth!);
  retimed.timestamp = "2000-01-01T00:00:00.000Z";
  assert.equal((await w.cosignPresented(retimed, log)).ok, false);

  const tampered = clone(log);
  tampered[2]!.binding_hash = flipMh(tampered[2]!.binding_hash) as never;
  const t = await w.observe(tampered, 5);
  assert.equal(t.ok, false);
  assert.match(t.reasons.join(" "), /does not verify/);

  assert.equal((await w.observe(log, 99)).ok, false);
  assert.equal(w.lastWitnessed, null, "nothing was signed by any refused request");
});

test("witness: signs successive heads, then refuses a rolled-back or forked log", async () => {
  const log = await buildLog("w3", 6);
  const w = new Witness(generateKeypair("w"), { verifyReceipt: accept });
  assert.equal((await w.observe(log.slice(0, 3), 3)).ok, true);
  const d = await w.observe(log, 6);
  assert.equal(d.ok, true, d.reasons.join("; "));
  assert.equal(d.checks?.previous_head_still_in_history, true);
  assert.equal(d.checks?.previous_head?.tree_size, 3, "the record names the PREVIOUS head, not the one just signed");

  const back = await w.observe(log, 4);
  assert.equal(back.ok, false, "going backwards is refused");

  const other = await buildLog("w3-other", 7);
  const fork = await w.observe(other, 7);
  assert.equal(fork.ok, false);
  assert.match(fork.reasons.join(" "), /fork or rollback/);
  assert.equal(w.lastWitnessed?.tree_size, 6);
});

test("verifier: witnessThreshold is enforced in the overall verdict, not just reported", async () => {
  const log = await buildLog("thr", 3);
  const key = generateKeypair("thr-witness");
  const w = new Witness(key, { verifyReceipt: accept });
  const d = await w.observe(log, 3);
  const witnessed = attachWitness(log[2]!, d.statement!);
  const trusted = withTrustedKeys(witnessed, { [key.keyId]: key.directoryEntry });

  const satisfied = await verifyReceiptV2(trusted, { witnessThreshold: 1 });
  assert.equal(satisfied.ok, true, satisfied.reasons.join("; "));

  const missing = await verifyReceiptV2(log[2]!, { witnessThreshold: 1 });
  assert.equal(missing.ok, false, "no witness => not ok when one is required");
  assert.ok(missing.reasons.some((r) => /witnessThreshold/.test(r)));

  const forgedSig = clone(trusted);
  forgedSig.sth!.witnesses = forgedSig.sth!.witnesses.map((x) =>
    x.id === key.keyId ? { ...x, ed25519: `${x.ed25519.slice(0, -6)}AAAAAA` as typeof x.ed25519 } : x,
  );
  assert.equal((await verifyReceiptV2(forgedSig, { witnessThreshold: 1 })).ok, false);

  // Default behaviour (no threshold) is unchanged: absent witnesses are reported, not fatal.
  assert.equal((await verifyReceiptV2(log[2]!, {})).ok, true);
});
