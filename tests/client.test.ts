/**
 * The `CooL` facade — the primary public API, driven the way a stranger drives
 * it after `npm install`.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { CooL, ConfigurationError, EvidenceError, verifyEvidence } from "../src/index";

test("new CooL() does no I/O; the first record() connects", async () => {
  const cool = new CooL({ applicationId: "my-app" });
  // Nothing is connected yet.
  assert.throws(() => cool.keyDirectory, ConfigurationError);

  const { evidence, recordId, executionId, digest } = await cool.record({
    type: "model.execution",
    metadata: { model: "my-model", version: "1.0.0" },
  });

  assert.equal(evidence.record.schema, "cool.evidence.v1");
  assert.match(recordId, /^[0-9A-HJKMNP-TV-Z]{26}$/);
  assert.equal(typeof executionId, "string");
  assert.match(digest, /^mh:sha256:[0-9a-f]{64}$/);

  const verdict = await cool.verify(evidence);
  assert.equal(verdict.ok, true);
  assert.equal(verdict.subject?.subject, "model.execution (my-app)");
  await cool.close();
});

test("record() commits metadata and payloads; the receipt carries no plaintext", async () => {
  const cool = new CooL({ applicationId: "privacy" });
  const { evidence } = await cool.record({
    type: "inference",
    metadata: { customer: "ACME-42" },
    payloads: { input: "SSN 123-45-6789", output: "APPROVED" },
  });
  const wire = JSON.stringify(evidence);
  assert.ok(!wire.includes("ACME-42"));
  assert.ok(!wire.includes("123-45-6789"));
  assert.ok(!wire.includes("APPROVED"));
  assert.equal((await verifyEvidence(evidence)).ok, true);
  await cool.close();
});

test("local mode never claims hardware; every receipt says 'simulated'", async () => {
  const cool = new CooL({ applicationId: "local" });
  const { evidence } = await cool.record({ type: "test" });
  await cool.ready();
  assert.equal(cool.environment.provider, "local");
  assert.equal(cool.environment.hardware, false);
  const verdict = await cool.verify(evidence);
  assert.equal(verdict.checks.attestation.status, "simulated");
  assert.equal(verdict.checks.enclave.status, "simulated");
  await cool.close();
});

test("requireAttestation with the local simulator is a configuration error", () => {
  assert.throws(
    () => new CooL({ attestation: { provider: "local" }, security: { requireAttestation: true } }),
    ConfigurationError,
  );
});

test("requireAttestation makes a simulated receipt fail verification", async () => {
  // provider defaults to local, but we ask verify() to require hardware.
  const cool = new CooL({ applicationId: "strict" });
  const { evidence } = await cool.record({ type: "test" });
  const verdict = await verifyEvidence(evidence, { requireHardware: true });
  assert.equal(verdict.ok, false);
  assert.ok(verdict.reasons.some((r) => r.includes("requireHardware")));
  await cool.close();
});

test("record() rejects a missing type with an actionable error", async () => {
  const cool = new CooL();
  await assert.rejects(
    // @ts-expect-error deliberately wrong
    () => cool.record({ metadata: {} }),
    (err: unknown) => err instanceof EvidenceError && err.code === "COOL_EVIDENCE_INVALID",
  );
  await cool.close();
});

test("an empty applicationId is rejected at construction", () => {
  assert.throws(() => new CooL({ applicationId: "" }), ConfigurationError);
});

test("close() is idempotent and blocks further work", async () => {
  const cool = new CooL();
  await cool.record({ type: "one" });
  await cool.close();
  await cool.close();
  await assert.rejects(() => cool.record({ type: "two" }), /closed/);
});

test("deterministic injection produces a stable record id and sequence", async () => {
  let seq = 0;
  const cool = new CooL({
    applicationId: "vectors",
    clock: () => "2026-01-01T00:00:00.000Z",
    newId: () => "00000000000000000000000000",
    seq: () => seq++,
  });
  const { evidence } = await cool.record({ type: "t", executionId: "EXEC-1" });
  assert.equal(evidence.record.record_id, "00000000000000000000000000");
  assert.equal(evidence.record.time.issued_at, "2026-01-01T00:00:00.000Z");
  assert.equal(evidence.record.time.seq, 0);
  await cool.close();
});
