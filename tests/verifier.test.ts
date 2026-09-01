/**
 * The standalone verifier: `verifyEvidence`, `formatVerdict`, and the
 * adversarial cases a security product has to fail correctly.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { CooL } from "../src/index";
import { verifyEvidence, formatVerdict } from "../src/verify";
import type { Evidence } from "../src/client";

async function evidence(): Promise<Evidence> {
  const cool = new CooL({ applicationId: "verifier-test" });
  const { evidence } = await cool.record({
    type: "model.execution",
    metadata: { model: "m", version: "1" },
    payloads: { input: "secret input", output: "secret output" },
  });
  await cool.close();
  return evidence;
}

/** A recursively-mutable view — tests need to corrupt fields the type marks readonly. */
type DeepMutable<T> = T extends object ? { -readonly [K in keyof T]: DeepMutable<T[K]> } : T;
const clone = (e: Evidence): DeepMutable<Evidence> =>
  JSON.parse(JSON.stringify(e)) as DeepMutable<Evidence>;

test("a clean record verifies and formats as VERIFIED", async () => {
  const e = await evidence();
  const verdict = await verifyEvidence(e);
  assert.equal(verdict.ok, true);
  const text = formatVerdict(verdict);
  assert.match(text, /COOL VERIFIER/);
  assert.match(text, /RESULT {6}VERIFIED/);
  assert.match(text, /OK {2}binding/);
});

test("garbage input is a structured failure, never a throw", async () => {
  for (const bad of [null, 42, "nope", {}, { schema: "cool.receipt.v2" }]) {
    const verdict = await verifyEvidence(bad);
    assert.equal(verdict.ok, false);
    assert.ok(verdict.reasons.length > 0);
  }
});

test("tampered metadata commitment breaks binding and signature", async () => {
  const e = clone(await evidence());
  (e.record as unknown as { event: { metadata_hash: string } }).event.metadata_hash =
    "mh:sha256:" + "0".repeat(64);
  const verdict = await verifyEvidence(e);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.checks.binding.status, "fail");
  assert.equal(verdict.checks.signature.status, "fail");
  assert.match(formatVerdict(verdict), /RESULT {6}FAILED/);
});

test("a swapped signature key is rejected", async () => {
  const e = clone(await evidence());
  e.record.signature.key_id = "attacker-key";
  const verdict = await verifyEvidence(e);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.checks.signature.status, "fail");
});

test("a truncated audit path fails inclusion, not binding", async () => {
  const e = clone(await evidence());
  if (e.inclusion) e.inclusion.audit_path = [];
  // tree of size 1 has an empty path, so grow the log first: two records.
  const cool = new CooL({ applicationId: "incl" });
  await cool.record({ type: "a" });
  const second = (await cool.record({ type: "b" })).evidence;
  await cool.close();
  const broken = clone(second);
  broken.inclusion!.audit_path = [];
  const verdict = await verifyEvidence(broken);
  assert.equal(verdict.checks.inclusion.status, "fail");
  assert.equal(verdict.checks.binding.status, "pass");
});

test("reordering JSON keys does not change the verdict (canonicalization)", async () => {
  const e = await evidence();
  // Rebuild every object with its keys in reverse order. The signature covers
  // canonical CBOR of the core, not the JSON byte order, so this must still pass.
  const reverseKeys = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(reverseKeys);
    if (value && typeof value === "object") {
      return Object.fromEntries(
        Object.entries(value as Record<string, unknown>)
          .reverse()
          .map(([k, v]) => [k, reverseKeys(v)]),
      );
    }
    return value;
  };
  assert.equal((await verifyEvidence(reverseKeys(e))).ok, true);
});

test("requireHardware turns a simulated pass into a fail", async () => {
  const e = await evidence();
  assert.equal((await verifyEvidence(e)).ok, true);
  assert.equal((await verifyEvidence(e, { requireHardware: true })).ok, false);
});
