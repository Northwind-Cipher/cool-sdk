/**
 * The evidence itself: sealing, verifying, and every way a record can be wrong.
 *
 * These assert the properties a machine can enforce on every commit: a sealed
 * record verifies and reports honestly what it is; a single edited byte breaks
 * both binding and signature; a valid quote cannot be stapled onto a record it
 * did not attest; keys are sealed to the measurement; no plaintext ever appears
 * in a receipt; and the structural validator names the field that is wrong.
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  CoolTee,
  SimulatedDstackClient,
  createUlid,
  quoteDigest,
  simulatedGpu,
  validateReceiptV2Shape,
  verifyReceiptV2,
} from "../src/phala/index";
import type { ReceiptV2 } from "../src/phala/index";

const IMAGE = "sha256:test-image-1";

async function plane(imageDigest = IMAGE) {
  return CoolTee.connect({
    app: { name: "test-plane", imageDigest },
    capture: { flushMs: 1 },
  });
}

const modelExecution = {
  type: "model.execution",
  metadata: { model: "credit-scorer", version: "2026.06.0" },
  payloads: { input: "applicant A-40182", output: "score 0.82" },
  software: { name: "scorer-svc", version: "1.4.2", digest: null },
  gpu: simulatedGpu("H200", "credit-scorer"),
} as const;

test("a sealed record verifies, and says honestly what it is", async () => {
  const cool = await plane();
  const receipt = await cool.record(modelExecution);

  const verdict = await verifyReceiptV2(receipt);

  assert.equal(verdict.ok, true);
  assert.equal(verdict.checks.binding.status, "pass");
  assert.equal(verdict.checks.signature.status, "pass");
  assert.equal(verdict.checks.inclusion.status, "pass");
  assert.equal(verdict.checks.witnesses.status, "absent");
  assert.equal(verdict.checks.attestation.status, "simulated");
  assert.equal(verdict.checks.enclave.status, "simulated");
  assert.equal(verdict.checks.anchor.status, "absent");
  assert.equal(verdict.subject?.kind, "evidence");
  assert.equal(receipt.record.schema, "cool.evidence.v1");

  // No plaintext anywhere in the receipt: payloads and metadata are committed
  // as salted hashes and discarded. (software identity is cleartext by design.)
  const serialised = JSON.stringify(receipt);
  assert.ok(!serialised.includes("applicant A-40182"), "input must never appear in a receipt");
  assert.ok(!serialised.includes("score 0.82"), "output must never appear in a receipt");
  assert.ok(!serialised.includes('"model":"credit-scorer"'), "metadata is committed, not stored");

  await cool.close();
});

test("one edited character breaks binding and signature", async () => {
  const cool = await plane();
  const receipt = await cool.record(modelExecution);
  const edited = JSON.parse(JSON.stringify(receipt)) as ReceiptV2;
  const event = (edited.record as unknown as { event: { metadata_hash: string } }).event;
  event.metadata_hash = event.metadata_hash.replace(/.$/, (c) => (c === "0" ? "1" : "0"));

  const verdict = await verifyReceiptV2(edited);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.checks.binding.status, "fail");
  assert.equal(verdict.checks.signature.status, "fail");
  await cool.close();
});

test("a valid quote from another enclave cannot be stapled on", async () => {
  const cool = await plane();
  const receipt = await cool.record(modelExecution);

  const rogue = new SimulatedDstackClient({ appName: "test-plane", imageDigest: "sha256:rogue" });
  const rogueQuote = await rogue.getQuote(receipt.attestation.key_binding!);
  assert.notEqual(quoteDigest(rogueQuote), receipt.record.runtime.tee_quote);

  const swapped: ReceiptV2 = {
    ...receipt,
    attestation: { ...receipt.attestation, quote: rogueQuote },
    key_directory: { ...receipt.key_directory, ...rogue.directory() },
  };
  const verdict = await verifyReceiptV2(swapped);

  assert.equal(verdict.ok, false);
  assert.equal(verdict.checks.enclave.status, "fail");
  assert.match(verdict.checks.enclave.detail, /swapped after signing/);
  assert.equal(verdict.checks.signature.status, "pass");
  await cool.close();
});

test("keys are sealed to the measurement: a redeploy rotates them", async () => {
  const approved = new SimulatedDstackClient({ appName: "p", imageDigest: IMAGE });
  const patched = new SimulatedDstackClient({ appName: "p", imageDigest: "sha256:patched" });

  const a = await approved.deriveKey("cool/evidence/record/v2");
  const b = await patched.deriveKey("cool/evidence/record/v2");
  assert.notDeepEqual(a, b);
  assert.notEqual(approved.measurement().mrtd, patched.measurement().mrtd);

  const cool = await plane("sha256:patched");
  const receipt = await cool.record(modelExecution);

  const pinned = await verifyReceiptV2(receipt, { expectedMeasurement: approved.measurement() });
  assert.equal(pinned.ok, false);
  assert.equal(pinned.checks.enclave.status, "fail");
  assert.match(pinned.checks.enclave.detail, /mrtd/);
  await cool.close();
});

test("every record in one client shares a log; the tree only grows", async () => {
  const cool = await plane();
  const a = await cool.record({ type: "step.one" });
  const b = await cool.record({ type: "step.two" });
  const c = await cool.record({ type: "step.three" });

  assert.equal(a.inclusion?.tree_size, 1);
  assert.equal(b.inclusion?.tree_size, 2);
  assert.equal(c.inclusion?.tree_size, 3);
  assert.equal(b.inclusion?.leaf_index, 1);
  for (const r of [a, b, c]) assert.equal((await verifyReceiptV2(r)).ok, true);
  await cool.close();
});

test("a change record carries its approval inside the signature", async () => {
  const cool = await plane();
  const receipt = await cool.change({
    kind: "agent-permission",
    ref: "support/copilot#tools",
    environment: "prod",
    before: "read:tickets",
    after: "read:tickets\nrefund:initiate",
    actor: { id: "user:dev@bank.example", method: "session" },
    approval: { policy_id: "POL-031", decision: "rejected", approvers: [] },
  });

  assert.equal(receipt.record.schema, "cool.change.v2");
  const verdict = await verifyReceiptV2(receipt);
  assert.equal(verdict.ok, true);
  assert.equal(verdict.subject?.kind, "change");

  const forged = JSON.parse(JSON.stringify(receipt)) as ReceiptV2;
  (forged.record as unknown as { change: { approval: { decision: string } } }).change.approval.decision =
    "approved";
  assert.equal((await verifyReceiptV2(forged)).checks.signature.status, "fail");
  await cool.close();
});

test("the channel refuses a mismatched endpoint without blocking the caller", async () => {
  const approved = new SimulatedDstackClient({ appName: "test-plane", imageDigest: IMAGE });
  const cool = await CoolTee.connect({
    app: { name: "test-plane", imageDigest: "sha256:someone-elses-image" },
    policy: { expectedMeasurement: approved.measurement() },
    capture: { flushMs: 1, maxRetries: 0 },
  });

  assert.equal(cool.handshake.ok, false);
  assert.ok(cool.handshake.steps.some((s) => s.label === "measurement pin" && !s.ok));

  // A fire-and-forget record must not throw into the caller.
  cool.recordAsync({ type: "model.execution", metadata: { model: "m@1" } });

  await cool.flush();
  assert.equal(cool.stats().sent, 0);
  assert.ok(cool.stats().dropped > 0);
  await cool.close();
});

test("the structural validator names the field that is wrong", () => {
  assert.equal(validateReceiptV2Shape(null).ok, false);
  assert.equal(validateReceiptV2Shape({ schema: "cool.receipt.v1" }).ok, false);

  const errors = validateReceiptV2Shape({
    schema: "cool.receipt.v2",
    record: { schema: "cool.evidence.v1", record_id: "not-a-ulid" },
    binding_hash: "nope",
    inclusion: null,
    sth: null,
    attestation: { mode: "hardware", note: "x", quote: null, expected_measurement: null, key_binding: null },
    anchor: null,
    key_directory: {},
  }).errors;

  assert.ok(errors.some((e) => e.includes("record.record_id")));
  assert.ok(errors.some((e) => e.includes("binding_hash")));
  assert.ok(errors.some((e) => e.includes("key_directory")));
});

test("ULIDs sort by time and stay monotonic inside a millisecond", () => {
  let now = 1_800_000_000_000;
  const next = createUlid(() => now);

  const first = next();
  const second = next();
  assert.equal(first.length, 26);
  assert.match(first, /^[0-9A-HJKMNP-TV-Z]{26}$/);
  assert.ok(second > first, "same millisecond must still increase");

  now += 1;
  const third = next();
  assert.ok(third > second);
  assert.equal(third.slice(0, 10) > first.slice(0, 10), true, "the time prefix advances");

  const sorted = [third, first, second].sort();
  assert.deepEqual(sorted, [first, second, third]);
});
