/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Epoch registration and sequence-gap accounting. Reports are constructed
 * directly here: the attestation verifier has its own tests, and what matters
 * at this layer is which reports the log will and will not accept.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { directoryFromKeypair, generateKeypair } from "../src/keys";
import { EpochLog, verifyEpochRegistration } from "../src/nitro/index";
import type { NitroAttestationReport, NitroCheck, ObservedReceipt } from "../src/nitro/index";

const LOG_KEY = generateKeypair("cool-log-test", { seed: new Uint8Array(32).fill(3) });
const pass: NitroCheck = { status: "pass", reason: "ok", detail: "" };

function report(binding: string, overall: "pass" | "fail" | "unknown" = "pass"): NitroAttestationReport {
  return {
    schema: "cool.nitro.attestation-report.v1",
    parser: { name: "cool-nitro", version: "1" },
    overall_status: overall,
    document_sha256: binding.repeat(2).slice(0, 64),
    trust_bundle: { id: "test", version: "1", root: "test" },
    policy: { id: "enclave", version: "3", source: "test" },
    claims: { verified: true, module_id: "m", timestamp_ms: 1, pcrs: {}, public_key: null, user_data: binding, nonce: null },
    checks: {
      structure: pass, trust_root: pass, certificate_chain: pass, cose_signature: pass, debug_mode: pass,
      pcr_policy: pass, pcr8_signing: pass, key_binding: pass, public_key: pass, freshness: pass,
    },
    reasons: overall === "pass" ? [] : ["freshness: freshness_policy_absent"],
  };
}

let tick = 0;
const clock = () => new Date(Date.UTC(2026, 9, 31, 12, 0, tick++));
const receipt = (epoch: number, sequence: number, id = `r-${epoch}-${sequence}`, key_id = "enclave-a"): ObservedReceipt =>
  ({ receipt_id: id, key_id, epoch, sequence, digest: `d-${id}` });

test("registration: the log assigns epochs, signs them, and is idempotent per key", () => {
  const log = new EpochLog(LOG_KEY, clock);
  const a = log.register(report("aa"), "enclave-a", "agent");
  assert.equal(a.registration.epoch, 1);
  assert.equal(a.registration.policy, "enclave@3");
  assert.ok(verifyEpochRegistration(a, directoryFromKeypair(LOG_KEY)));
  assert.deepEqual(log.register(report("aa"), "enclave-a", "agent"), a);

  const forged = { ...a, registration: { ...a.registration, epoch: 7 } };
  assert.equal(verifyEpochRegistration(forged, directoryFromKeypair(LOG_KEY)), false);
});

test("registration: a restart is a new key, a new epoch, and an auditable transition", () => {
  const log = new EpochLog(LOG_KEY, clock);
  log.register(report("aa"), "enclave-a", "agent");
  const b = log.register(report("bb"), "enclave-b", "agent");
  assert.equal(b.registration.epoch, 2);
  const transition = log.events().find((e) => e.kind === "epoch_transition");
  assert.deepEqual(transition && { from: transition.from, to: transition.to }, { from: 1, to: 2 });
});

test("registration: an unknown or failing attestation gets no epoch", () => {
  const log = new EpochLog(LOG_KEY, clock);
  assert.throws(() => log.register(report("aa", "unknown"), "enclave-a", "agent"), /refusing to register: attestation is unknown/);
  assert.throws(() => log.register(report("aa", "fail"), "enclave-a", "agent"), /refusing to register/);
});

test("ingest: in-order, duplicate and conflicting receipts", () => {
  const log = new EpochLog(LOG_KEY, clock);
  log.register(report("aa"), "enclave-a", "agent");
  assert.equal(log.ingest(receipt(1, 0)).outcome, "accepted");
  assert.equal(log.ingest(receipt(1, 1)).outcome, "accepted");
  assert.equal(log.ingest(receipt(1, 1)).outcome, "duplicate");
  const conflict = log.ingest(receipt(1, 1, "r-other"));
  assert.equal(conflict.outcome, "conflict");
  assert.match(conflict.detail, /first observation stands/);
  assert.equal(log.highest(1), 1);
});

test("ingest: a dropped middle receipt becomes a gap; a late copy fills it without erasing it", () => {
  const log = new EpochLog(LOG_KEY, clock);
  log.register(report("aa"), "enclave-a", "agent");
  log.ingest(receipt(1, 0));
  const jump = log.ingest(receipt(1, 3));
  assert.equal(jump.outcome, "accepted");
  assert.deepEqual(jump.gaps_opened, [1, 2]);
  assert.deepEqual(log.gaps(1).map((g) => [g.sequence, g.status]), [[1, "unresolved"], [2, "unresolved"]]);

  assert.equal(log.ingest(receipt(1, 2)).outcome, "late_fill");
  const gaps = log.gaps(1);
  assert.deepEqual(gaps.map((g) => [g.sequence, g.status]), [[1, "unresolved"], [2, "filled_late"]]);
  assert.ok(gaps[1]!.filled_at);
});

test("ingest: a dropped FINAL receipt is invisible until a later sequence arrives", () => {
  const log = new EpochLog(LOG_KEY, clock);
  log.register(report("aa"), "enclave-a", "agent");
  log.ingest(receipt(1, 0));
  log.ingest(receipt(1, 1));
  // sequence 2 is suppressed; nothing has arrived after it yet
  assert.deepEqual(log.gaps(1), []);
  log.ingest(receipt(1, 3));
  assert.deepEqual(log.gaps(1).map((g) => g.sequence), [2]);
});

test("ingest: unknown epoch, a receipt from another key, invalid sequence", () => {
  const log = new EpochLog(LOG_KEY, clock);
  log.register(report("aa"), "enclave-a", "agent");
  assert.equal(log.ingest(receipt(9, 0)).outcome, "unknown_epoch");
  assert.equal(log.ingest(receipt(1, 0, "r-x", "enclave-b")).outcome, "epoch_key_mismatch");
  assert.equal(log.ingest(receipt(1, -1)).outcome, "invalid");
  assert.equal(log.ingest(receipt(1, 1.5)).outcome, "invalid");
});
