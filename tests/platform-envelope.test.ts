/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * The shared evidence envelope: every check of the verification report, each
 * failure path asserted by status AND reason code.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { encode } from "cbor2";
import { canonicalCbor } from "../src/canonical";
import { fromBase64, toBase64 } from "../src/codec";
import { CooLError } from "../src/errors";
import {
  ALGORITHMS,
  TransparencyLog,
  TrustStore,
  check,
  createEnvelope,
  inspectEnvelope,
  signEnvelope,
  usableAlgorithm,
  verifyEnvelope,
  type SignedEnvelope,
  type VerifyEnvelopeOptions,
} from "../src/platform/index";
import { KEYS, T0, commitInput, iso, record, registry, trust } from "./support/platform";

const opts = (extra: Partial<VerifyEnvelopeOptions> = {}): VerifyEnvelopeOptions => ({ registry, trust: trust(), now: T0, ...extra });
const signed = (k = KEYS.source, input = commitInput()) => signEnvelope(createEnvelope(input, registry), k);

test("envelope: a well-formed signed envelope verifies, with every check reported", () => {
  const r = verifyEnvelope(signed(), opts());
  assert.equal(r.overall_status, "pass", r.reasons.join("; "));
  for (const name of ["schema_valid", "canonical_encoding_valid", "digest_valid", "signature_valid", "signer_trusted", "timestamp_valid"] as const) {
    assert.equal(r.checks[name].status, "pass", name);
  }
  assert.equal(r.checks.signer_authorized.status, "not_checked");
  assert.equal(r.checks.inclusion_proof_valid.reason, "no_checkpoint");
  assert.equal(r.checks.attestation_valid.status, "not_applicable");
  assert.equal(r.checks.evidence_complete.reason, "no_resolver");
  assert.ok(r.checks.timestamp_valid.limitation?.includes("RFC 3161"));
});

test("envelope: canonical bytes are deterministic; inspection never claims verification", () => {
  const core = createEnvelope(commitInput(), registry);
  assert.equal(signEnvelope(core, KEYS.source).digest, signEnvelope(core, KEYS.source).digest);
  const view = inspectEnvelope(signEnvelope(core, KEYS.source));
  assert.equal(view.verified, false);
});

test("envelope: invalid input is rejected at creation with a stable error", () => {
  assert.throws(() => createEnvelope(commitInput({ payload: { repository: "x", commit: "y", author: "z", signed: "yes" } }), registry), (e: unknown) => e instanceof CooLError && e.code === "COOL_EVIDENCE_INVALID" && /signed: must be a boolean/.test(e.message));
  assert.throws(() => createEnvelope(commitInput({ event_type: "nope.unknown" }), registry), /no payload schema/);
  assert.throws(() => createEnvelope(commitInput({ payload: { repository: "x", commit: "y", author: "z", signed: true, extra: 1 } }), registry), /unexpected field extra/);
  assert.throws(() => createEnvelope(commitInput({ relations: [{ type: "x", ref: "not-a-digest" as never }] }), registry), /not a digest/);
});

test("envelope: a field that would carry a secret value must be a digest", () => {
  registry.register({ id: "test.secret.v1", event_type: "test.secret", fields: { api_token: { type: "string", required: true } } });
  assert.throws(() => createEnvelope(commitInput({ event_type: "test.secret", payload: { api_token: "sk-live-123" } }), registry), /looks like a secret value/);
  const ok = createEnvelope(commitInput({ event_type: "test.secret", payload: { api_token: `mh:sha256:${"a".repeat(64)}` } }), registry);
  assert.equal(ok.payload_schema, "test.secret.v1");
});

test("envelope: editing the readable core without the bytes is caught", () => {
  const env = signed();
  const forged: SignedEnvelope = { ...env, core: { ...env.core, actor: { id: "user:someone-else", type: "human" } } };
  const r = verifyEnvelope(forged, opts());
  assert.equal(r.checks.canonical_encoding_valid.reason, "core_mismatch");
  assert.equal(r.overall_status, "fail");
});

test("envelope: altering the committed bytes (canonically, core kept in step) breaks the digest", () => {
  const env = signed();
  const altered = { ...env.core, action: "force-push" };
  const r = verifyEnvelope({ ...env, core_cbor: toBase64(canonicalCbor(altered)), core: altered }, opts());
  assert.equal(r.checks.canonical_encoding_valid.status, "pass");
  assert.equal(r.checks.digest_valid.reason, "digest_mismatch");
  assert.equal(r.checks.signature_valid.status, "not_checked");
  assert.ok(fromBase64(env.core_cbor).length > 0);
});

test("envelope: a non-canonical encoding of the same core is rejected, not normalised", () => {
  const env = signed();
  // Same content, keys deliberately out of deterministic order.
  const shuffled = Object.fromEntries(Object.entries(env.core).reverse());
  const bytes = encode(shuffled);
  const r = verifyEnvelope({ ...env, core_cbor: toBase64(bytes) }, opts());
  assert.equal(r.checks.canonical_encoding_valid.reason, "non_canonical_encoding");
});

test("envelope: invalid signature and untrusted signer are different failures", () => {
  const env = signed();
  const badSig = { ...env, signatures: [{ ...env.signatures[0]!, ed25519: env.signatures[0]!.ml_dsa.slice(0, 20) as never }] };
  const a = verifyEnvelope(badSig, opts());
  assert.equal(a.checks.signature_valid.reason, "signature_invalid");
  assert.equal(a.checks.signer_trusted.status, "not_checked");

  const b = verifyEnvelope(signed(KEYS.rogue), opts());
  assert.equal(b.checks.signature_valid.status, "pass");
  assert.equal(b.checks.signer_trusted.reason, "untrusted_key");
});

test("envelope: unknown signature algorithm and unsigned envelopes fail closed", () => {
  const env = signed();
  const unknownAlg = verifyEnvelope({ ...env, signatures: [{ ...env.signatures[0]!, alg: "rsa-1024" as never }] }, opts());
  assert.match(unknownAlg.checks.signature_valid.detail, /unsupported algorithm rsa-1024/);
  assert.equal(verifyEnvelope({ ...env, signatures: [] }, opts()).checks.signature_valid.reason, "unsigned");
  assert.equal(usableAlgorithm("rsa-1024", "signature"), null);
  assert.equal(usableAlgorithm("sha-256", "signature"), null);
  assert.ok(ALGORITHMS.every((a) => !/ml-kem|x25519|chacha/i.test(a.id)));
});

test("envelope: wrong key purpose, revoked, compromised and rotated keys", () => {
  const purpose = verifyEnvelope(signed(KEYS.log), opts());
  assert.equal(purpose.checks.signer_trusted.reason, "wrong_key_purpose");

  const revoked = trust([record(KEYS.rogue, ["evidence"], { status: "revoked", revoked_at: iso(-3_600_000) })]);
  assert.equal(verifyEnvelope(signed(KEYS.rogue), opts({ trust: revoked })).checks.signer_trusted.reason, "key_revoked");

  const compromised = trust([record(KEYS.rogue, ["evidence"], { status: "compromised", compromised_since: iso(-10) })]);
  assert.equal(verifyEnvelope(signed(KEYS.rogue), opts({ trust: compromised })).checks.signer_trusted.reason, "key_compromised");

  const rotated = trust([record(KEYS.rogue, ["evidence"], { status: "rotated", rotated_at: iso(-3_600_000), successor: "source-2" })]);
  assert.equal(verifyEnvelope(signed(KEYS.rogue), opts({ trust: rotated })).checks.signer_trusted.reason, "key_rotated");
});

test("envelope: a revoked key is accepted only with a trusted checkpoint that predates revocation", () => {
  const log = new TransparencyLog("log-a", KEYS.log, () => new Date(T0 - 7_200_000));
  const env = log.publish(signEnvelope(createEnvelope(commitInput({ occurred_at: iso(-7_300_000), observed_at: iso(-7_250_000) }), registry), KEYS.rogue));
  const revokedLater = trust([record(KEYS.rogue, ["evidence"], { status: "revoked", revoked_at: iso(-3_600_000) })]);
  const r = verifyEnvelope(env, opts({ trust: revokedLater }));
  assert.equal(r.checks.checkpoint_trusted.status, "pass");
  assert.equal(r.checks.signer_trusted.status, "pass");
  assert.match(r.checks.signer_trusted.detail, /proven to predate/);
});

test("envelope: a stale trust snapshot makes trust unknown, never pass", () => {
  const stale = trust([], { maxAgeMs: 1_000, asOf: iso(-60_000) });
  const r = verifyEnvelope(signed(), opts({ trust: stale }));
  assert.equal(r.checks.signer_trusted.reason, "trust_snapshot_stale");
  assert.equal(r.overall_status, "unknown");
});

test("envelope: contradictory and future timestamps", () => {
  const backwards = signed(KEYS.source, commitInput({ occurred_at: iso(-1_000), observed_at: iso(-3_600_000) }));
  assert.equal(verifyEnvelope(backwards, opts()).checks.timestamp_valid.reason, "occurred_after_observed");
  const future = signed(KEYS.source, commitInput({ occurred_at: iso(3_600_000), observed_at: iso(3_600_000) }));
  assert.equal(verifyEnvelope(future, opts()).checks.timestamp_valid.reason, "time_in_future");
});

test("envelope: publish gives a valid inclusion proof and a trusted, witnessed checkpoint", () => {
  const log = new TransparencyLog("log-a", KEYS.log, () => new Date(T0));
  log.publish(signed(KEYS.source, commitInput({ event_id: "e0" })));
  const env = log.publish(signed());
  const witnessed = { ...env, checkpoint: log.checkpoint(env.digest, [KEYS.witness])! };
  const r = verifyEnvelope(witnessed, opts({ witnessThreshold: 1 }));
  assert.equal(r.checks.inclusion_proof_valid.reason, "included");
  assert.equal(r.checks.checkpoint_trusted.status, "pass", r.checks.checkpoint_trusted.detail);
  assert.equal(r.overall_status, "pass");

  assert.equal(verifyEnvelope(env, opts({ witnessThreshold: 1 })).checks.checkpoint_trusted.reason, "insufficient_witnesses");
  assert.equal(verifyEnvelope(env, opts({ maxCheckpointAgeMs: -1 })).checks.checkpoint_trusted.reason, "checkpoint_stale");
});

test("envelope: a corrupted audit path, a forged head and an untrusted log all fail", () => {
  const log = new TransparencyLog("log-a", KEYS.log, () => new Date(T0));
  log.publish(signed(KEYS.source, commitInput({ event_id: "e0" })));
  const env = log.publish(signed());
  const cp = env.checkpoint!;
  const badPath = { ...env, checkpoint: { ...cp, audit_path: [`mh:sha256:${"0".repeat(64)}` as const] } };
  assert.equal(verifyEnvelope(badPath, opts()).checks.inclusion_proof_valid.reason, "inclusion_invalid");

  const forgedHead = { ...env, checkpoint: { ...cp, sth: { ...cp.sth, tree_size: 9 } } };
  assert.equal(verifyEnvelope(forgedHead, opts()).checks.checkpoint_trusted.reason, "checkpoint_signature_invalid");

  const rogueLog = new TransparencyLog("log-b", KEYS.rogue, () => new Date(T0)).publish(signed());
  assert.equal(verifyEnvelope(rogueLog, opts()).checks.checkpoint_trusted.reason, "checkpoint_signature_invalid");
  assert.equal(verifyEnvelope(signed(), opts({ requireCheckpoint: true })).checks.inclusion_proof_valid.reason, "checkpoint_required");
});

test("envelope: missing referenced evidence is reported; authorization is a separate question", () => {
  const parent = signed();
  const child = signed(KEYS.source, commitInput({ event_id: "e2", provenance: { collection_method: "derived", refs: [parent.digest] } }));
  assert.equal(verifyEnvelope(child, opts({ resolve: () => false })).checks.evidence_complete.reason, "missing_evidence");
  assert.equal(verifyEnvelope(child, opts({ resolve: (d) => d === parent.digest })).checks.evidence_complete.status, "pass");

  const denied = verifyEnvelope(signed(), opts({ authorize: () => check("fail", "not_permitted", "source-1 may not commit to acme/api") }));
  assert.equal(denied.checks.signature_valid.status, "pass");
  assert.equal(denied.checks.signer_trusted.status, "pass");
  assert.equal(denied.checks.signer_authorized.reason, "not_permitted");
  assert.equal(denied.overall_status, "fail");
});

test("envelope: unsupported envelope schema and unknown payload schema", () => {
  const env = signed();
  assert.equal(verifyEnvelope({ ...env, format: "something.else" as never }, opts()).checks.schema_valid.reason, "unsupported_schema");
  assert.equal(verifyEnvelope({ ...env, core: { ...env.core, payload_schema: "scm.commit.v9" } }, opts()).checks.schema_valid.reason, "payload_invalid");
});

test("payload registry: every Page 08 event family is registered", () => {
  const types = registry.eventTypes();
  for (const t of ["ai.inference", "scm.commit", "build.started", "build.completed", "artifact.created", "artifact.published", "dependency.inventory", "release.approved", "release.rejected", "deployment.requested", "deployment.completed", "identity.authenticated", "identity.credential_used", "authorization.evaluated", "authorization.denied", "secret.accessed", "key.used", "certificate.issued", "certificate.revoked", "configuration.changed", "configuration.drift_detected", "runtime.process", "runtime.network", "runtime.privilege_change", "incident.opened", "incident.evidence_added", "incident.closed"]) {
    assert.ok(types.includes(t), t);
  }
  assert.ok(TrustStore.empty().snapshot().keys.length === 0);
});
