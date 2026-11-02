/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Log consistency and the observing witness, exercised on a real multi-event
 * CooL log (tree sizes 1..8) with forged and altered inputs at every step.
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  CoolTee,
  consistencyProof,
  leafHash,
  merkleRoot,
  multihashDigest,
  recordLeafDataV2,
  verifyConsistency,
  verifyLogConsistency,
} from "../src/phala/index";
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
