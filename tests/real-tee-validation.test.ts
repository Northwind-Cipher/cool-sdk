/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Regression and fail-closed tests that came out of the Phala Cloud real-TDX
 * validation (see artifacts/). Each test pins behaviour that was either found
 * broken against real hardware or that the validation depends on.
 *
 * The silicon is still a mock here — no unit test can conjure a TDX module — but
 * every byte of the wire format and every policy branch is exercised.
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  CoolTee,
  HttpDstackClient,
  remoteQuoteVerifier,
  verifyReceiptV2,
} from "../src/phala/index";
import { cosign, attachWitness } from "../src/phala/witness";
import { recordLeafDataV2 } from "../src/phala/record";
import { withTrustedKeys } from "../src/phala/verify";
import { generateKeypair } from "../src/keys";
import { consistencyProof, leafHash, merkleRoot, verifyConsistency } from "../src/merkle";
import { multihashDigest } from "../src/multihash";
import type { ReceiptV2 } from "../src/phala/types";
import { startMockAgent, startMockQuoteVerifier } from "./support/servers";

const ZERO_48 = `hex:${"0".repeat(96)}`;

/* ── tcb_info as a JSON string (the real agent's format) ──────────────── */

test("tcb_info delivered as a JSON string parses to the real MRTD/RTMR0-3, no zero fallback", async () => {
  const agent = await startMockAgent({ tcbInfoAsString: true });
  try {
    const info = await new HttpDstackClient({ endpoint: agent.url }).info();
    const m = info.measurement;
    assert.equal(m.mrtd, `hex:${agent.measurement.mrtd}`);
    assert.equal(m.rtmr0, `hex:${agent.measurement.rtmr0}`);
    assert.equal(m.rtmr1, `hex:${agent.measurement.rtmr1}`);
    assert.equal(m.rtmr2, `hex:${agent.measurement.rtmr2}`);
    assert.equal(m.rtmr3, `hex:${agent.measurement.rtmr3}`);
    for (const value of Object.values(m)) assert.notEqual(value, ZERO_48, "must not fall back to zeros");
    assert.equal(info.eventLog.length, 2, "event_log inside the string is parsed too");
  } finally {
    await agent.close();
  }
});

test("tcb_info as an object and as a string yield identical measurements", async () => {
  const asObject = await startMockAgent();
  const asString = await startMockAgent({ tcbInfoAsString: true });
  try {
    const a = await new HttpDstackClient({ endpoint: asObject.url }).info();
    const b = await new HttpDstackClient({ endpoint: asString.url }).info();
    assert.deepEqual(a.measurement, b.measurement);
  } finally {
    await asObject.close();
    await asString.close();
  }
});

/* ── fail-closed policy ───────────────────────────────────────────────── */

test("fail-closed 1: simulated environment with allowSimulated:false is refused", async () => {
  const cool = await CoolTee.connect({
    app: { name: "sim", imageDigest: "sha256:sim" },
    policy: { allowSimulated: false },
    capture: { flushMs: 1 },
  });
  assert.equal(cool.handshake.ok, false);
  const root = cool.handshake.steps.find((s) => s.label === "root of trust");
  assert.match(root?.detail ?? "", /simulated quote rejected/);
  await assert.rejects(() => cool.record({ type: "model.execution", metadata: { m: 1 } }));
  await cool.close();
});

test("fail-closed 2: hardware quote with no verifier configured is refused", async () => {
  const agent = await startMockAgent();
  try {
    const cool = await CoolTee.connect({
      dstack: new HttpDstackClient({ endpoint: agent.url }),
      policy: { allowSimulated: false },
      capture: { flushMs: 1 },
    });
    assert.equal(cool.handshake.ok, false);
    assert.match(
      cool.handshake.steps.find((s) => s.label === "root of trust")?.detail ?? "",
      /refusing to transmit/,
    );
    await cool.close();
  } finally {
    await agent.close();
  }
});

test("fail-closed 3: a verifier that rejects the quote closes the channel and fails verification", async () => {
  const agent = await startMockAgent();
  const dcap = await startMockQuoteVerifier({ accept: false });
  try {
    const verifier = remoteQuoteVerifier({ endpoint: dcap.url, root: "intel-dcap" });
    const cool = await CoolTee.connect({
      dstack: new HttpDstackClient({ endpoint: agent.url }),
      policy: { allowSimulated: false, verifier },
      capture: { flushMs: 1 },
    });
    assert.equal(cool.handshake.ok, false, "channel must be closed on a rejected quote");
    await cool.close();
  } finally {
    await agent.close();
    await dcap.close();
  }
});

test("fail-closed 4: a mismatched measurement pin fails the enclave domain", async () => {
  const running = await startMockAgent({ imageSeed: "running" });
  const approved = await startMockAgent({ imageSeed: "approved" });
  const dcap = await startMockQuoteVerifier({ accept: true });
  try {
    const verifier = remoteQuoteVerifier({ endpoint: dcap.url, root: "intel-dcap" });
    const cool = await CoolTee.connect({
      dstack: new HttpDstackClient({ endpoint: running.url }),
      policy: { allowSimulated: false, verifier },
      capture: { flushMs: 1 },
    });
    const receipt = await cool.record({ type: "model.execution", metadata: { m: 1 } });
    const pin = Object.fromEntries(
      Object.entries(approved.measurement).map(([k, v]) => [k, `hex:${v}`]),
    ) as never;
    const verdict = await verifyReceiptV2(receipt, {
      quoteVerifier: verifier,
      expectedMeasurement: pin,
      requireHardware: true,
    });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.checks.enclave.status, "fail");
    await cool.close();
  } finally {
    await running.close();
    await approved.close();
    await dcap.close();
  }
});

test("fail-closed 5: valid hardware evidence passes with requireHardware and a verifier", async () => {
  const agent = await startMockAgent({ tcbInfoAsString: true });
  const dcap = await startMockQuoteVerifier({ accept: true });
  try {
    const verifier = remoteQuoteVerifier({ endpoint: dcap.url, root: "intel-dcap" });
    const cool = await CoolTee.connect({
      dstack: new HttpDstackClient({ endpoint: agent.url }),
      policy: { allowSimulated: false, requireVendor: ["intel-tdx"], verifier },
      capture: { flushMs: 1 },
    });
    const receipt = await cool.record({ type: "model.execution", metadata: { m: 1 } });
    const verdict = await verifyReceiptV2(receipt, { quoteVerifier: verifier, requireHardware: true });
    assert.equal(verdict.ok, true, verdict.reasons.join("; "));
    assert.equal(verdict.checks.attestation.status, "pass");
    assert.equal(verdict.checks.enclave.status, "pass");
    await cool.close();
  } finally {
    await agent.close();
    await dcap.close();
  }
});

test("enclave cannot pass under requireHardware when attestation is unverified", async () => {
  const agent = await startMockAgent();
  const dcap = await startMockQuoteVerifier({ accept: true });
  try {
    const verifier = remoteQuoteVerifier({ endpoint: dcap.url, root: "intel-dcap" });
    const cool = await CoolTee.connect({
      dstack: new HttpDstackClient({ endpoint: agent.url }),
      policy: { allowSimulated: false, verifier },
      capture: { flushMs: 1 },
    });
    const receipt = await cool.record({ type: "model.execution", metadata: { m: 1 } });

    // Without the flag the historic behaviour is unchanged: attestation is
    // absent (reported, not verified) and the enclave binding checks still pass.
    const lax = await verifyReceiptV2(receipt, {});
    assert.equal(lax.checks.attestation.status, "absent");
    assert.equal(lax.checks.enclave.status, "pass");

    // With the flag, the same evidence must fail closed in BOTH domains' summary.
    const strict = await verifyReceiptV2(receipt, { requireHardware: true });
    assert.equal(strict.ok, false);
    assert.equal(strict.checks.attestation.status, "absent");
    assert.equal(strict.checks.enclave.status, "fail");
    assert.ok(strict.reasons.some((r) => r.startsWith("enclave: requireHardware")));

    // And with a real verifier the same receipt passes.
    const ok = await verifyReceiptV2(receipt, { requireHardware: true, quoteVerifier: verifier });
    assert.equal(ok.ok, true, ok.reasons.join("; "));
    await cool.close();
  } finally {
    await agent.close();
    await dcap.close();
  }
});

/* ── RFC 6962 consistency against a real CooL log ─────────────────────── */

test("consistency: a real CooL log grows from size 2 to size 6 and the proof verifies against signed heads", async () => {
  const cool = await CoolTee.connect({
    app: { name: "consistency", imageDigest: "sha256:c" },
    capture: { flushMs: 1 },
  });
  const receipts: ReceiptV2[] = [];
  for (let i = 0; i < 6; i++) {
    receipts.push(await cool.record({ type: "model.execution", metadata: { i } }));
  }
  const at = (size: number) => receipts[size - 1]!;
  const oldHead = at(2).sth!;
  const newHead = at(6).sth!;
  assert.equal(oldHead.tree_size, 2);
  assert.equal(newHead.tree_size, 6);

  // Both heads are signed by the log key: verify them through the real verifier.
  for (const r of [at(2), at(6)]) {
    const v = await verifyReceiptV2(r, {});
    assert.equal(v.checks.inclusion.status, "pass", v.checks.inclusion.detail);
  }

  // The leaves are public in the receipts (binding digests); recompute the proof.
  const leaves = receipts.map((r) => leafHash(recordLeafDataV2(r.binding_hash)));
  const proof = consistencyProof(leaves, 2);
  assert.ok(proof.length > 0);
  const oldRoot = multihashDigest(oldHead.root_hash);
  const newRoot = multihashDigest(newHead.root_hash);
  assert.deepEqual(oldRoot, merkleRoot(leaves.slice(0, 2)), "signed head equals recomputed root");
  assert.ok(verifyConsistency(2, 6, oldRoot, newRoot, proof), "consistency proof must verify");

  // A rewritten history must not verify.
  const forged = merkleRoot([leaves[0]!, leafHash(new Uint8Array(32).fill(7))]);
  assert.equal(verifyConsistency(2, 6, forged, newRoot, proof), false);
  // A proof for the wrong size must not verify.
  assert.equal(verifyConsistency(3, 6, oldRoot, newRoot, proof), false);
  await cool.close();
});

test("consistency: proofs verify for every (m, n) up to 12 and reject forged first roots", () => {
  const leaves = [...Array(12)].map((_, i) => leafHash(new Uint8Array(32).fill(i)));
  for (let n = 1; n <= 12; n++) {
    for (let m = 1; m <= n; m++) {
      const proof = consistencyProof(leaves.slice(0, n), m);
      const first = merkleRoot(leaves.slice(0, m));
      const second = merkleRoot(leaves.slice(0, n));
      assert.ok(verifyConsistency(m, n, first, second, proof), `m=${m} n=${n}`);
      if (m < n) {
        const forged = merkleRoot([...leaves.slice(0, m - 1), leafHash(new Uint8Array(32).fill(99))]);
        assert.equal(verifyConsistency(m, n, forged, second, proof), false, `forged m=${m} n=${n}`);
      }
    }
  }
});

/* ── witness: cryptographic separation, not organizational independence ─ */

test("witness: a distinct key's cosignature counts; the log's own self-signature does not", async () => {
  const cool = await CoolTee.connect({
    app: { name: "witness", imageDigest: "sha256:w" },
    capture: { flushMs: 1 },
  });
  const receipt = await cool.record({ type: "model.execution", metadata: { m: 1 } });
  const before = await verifyReceiptV2(receipt, {});
  assert.equal(before.checks.witnesses.status, "absent", "self-signature alone is never counted");

  const witnessKey = generateKeypair("witness-test-key");
  assert.notEqual(witnessKey.keyId, receipt.record.signature.key_id);
  const witnessed = attachWitness(receipt, cosign(receipt.sth!, witnessKey));
  const after = await verifyReceiptV2(
    withTrustedKeys(witnessed, { [witnessKey.keyId]: witnessKey.directoryEntry }),
    { witnessThreshold: 1 },
  );
  assert.equal(after.checks.witnesses.status, "pass");

  // The verifier does not know WHO operates the witness key: cryptographic
  // separation is checked, organizational independence is not and cannot be.
  const wrongKey = generateKeypair("witness-test-key");
  const untrusted = await verifyReceiptV2(
    withTrustedKeys(witnessed, { [witnessKey.keyId]: wrongKey.directoryEntry }),
    { witnessThreshold: 1 },
  );
  assert.notEqual(untrusted.checks.witnesses.status, "pass", "a witness key the verifier does not hold must not count");
  await cool.close();
});
