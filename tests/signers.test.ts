/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * KMS / HSM signers.
 *
 * The providers are EMULATED in-process: each emulator holds the private key
 * the way the real service does (never exposed), returns public keys in the
 * provider's own format (DER SPKI for AWS, PEM for Google Cloud) and enforces
 * the provider's API rules (key spec, signing algorithm, MessageType RAW). No
 * live AWS, Google Cloud or HSM account is used — the adapters are labelled
 * `experimental` until they are run against the real services
 * (docs/key-management.md#validating-against-a-live-provider).
 */
import test from "node:test";
import assert from "node:assert/strict";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair } from "../src/keys";
import {
  awsKmsComponent, awsKmsSigner, createEnvelope, gcpKmsSigner, hybridSigner, localAsyncSigner, pkcs11Component,
  rawPublicKeyFromSpki, signEnvelopeAsync, verifyEnvelope, type AwsKmsClient, type GcpKmsClient,
} from "../src/platform/index";
import { derOid, derSeq, tlv, TAG } from "../src/platform/der";
import { createAuthorizationRequest, decide, decideAsync, verifyDecision, ToolGateway, MemoryNonceStore, verifyConfirmation } from "../src/authz/index";
import { commitInput, record, registry, trust } from "./support/platform";
import { KEYS, REFUND_POLICY, ROOT_DELEGATION, world } from "./support/authz";

const spki = (alg: "ml-dsa-65" | "ed25519", pub: Uint8Array) =>
  derSeq(derSeq(derOid(alg === "ed25519" ? "1.3.101.112" : "2.16.840.1.101.3.4.3.18")), tlv(TAG.BIT_STRING, Uint8Array.from([0, ...pub])));
const pem = (der: Uint8Array) => `-----BEGIN PUBLIC KEY-----\n${Buffer.from(der).toString("base64").match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----\n`;

/** An AWS KMS emulator: private keys stay inside; the API rules are enforced. */
function awsEmulator(seed: number) {
  const ml = ml_dsa65.keygen(new Uint8Array(32).fill(seed));
  const edSecret = new Uint8Array(32).fill(seed + 1);
  const keys: Record<string, { spec: string; pub: Uint8Array; sign(m: Uint8Array): Uint8Array }> = {
    "alias/cool-mldsa": { spec: "ML_DSA_65", pub: spki("ml-dsa-65", ml.publicKey), sign: (m) => ml_dsa65.sign(ml.secretKey, m) },
    "alias/cool-ed25519": { spec: "ECC_NIST_EDWARDS25519", pub: spki("ed25519", ed25519.getPublicKey(edSecret)), sign: (m) => ed25519.sign(m, edSecret) },
  };
  const calls: string[] = [];
  const client: AwsKmsClient = {
    async getPublicKey({ KeyId }) { const k = keys[KeyId]; if (!k) throw Object.assign(new Error("NotFoundException"), { name: "NotFoundException" }); return { PublicKey: k.pub, KeySpec: k.spec }; },
    async sign({ KeyId, Message, MessageType, SigningAlgorithm }) {
      const k = keys[KeyId];
      if (!k) throw new Error("NotFoundException");
      const allowed = k.spec === "ML_DSA_65" ? "ML_DSA_SHAKE_256" : "ED25519_SHA_512";
      if (SigningAlgorithm !== allowed || MessageType !== "RAW") throw Object.assign(new Error("InvalidKeyUsageException"), { name: "InvalidKeyUsageException" });
      calls.push(`${KeyId}:${SigningAlgorithm}`);
      return { Signature: k.sign(Message) };
    },
  };
  return { client, calls };
}

function gcpEmulator(seed: number): GcpKmsClient {
  const ml = ml_dsa65.keygen(new Uint8Array(32).fill(seed));
  const edSecret = new Uint8Array(32).fill(seed + 1);
  const versions: Record<string, { alg: string; pem: string; sign(m: Uint8Array): Uint8Array }> = {
    "projects/p/locations/global/keyRings/r/cryptoKeys/mldsa/cryptoKeyVersions/1": { alg: "PQ_SIGN_ML_DSA_65", pem: pem(spki("ml-dsa-65", ml.publicKey)), sign: (m) => ml_dsa65.sign(ml.secretKey, m) },
    "projects/p/locations/global/keyRings/r/cryptoKeys/ed/cryptoKeyVersions/1": { alg: "EC_SIGN_ED25519", pem: pem(spki("ed25519", ed25519.getPublicKey(edSecret))), sign: (m) => ed25519.sign(m, edSecret) },
  };
  return {
    async getPublicKey({ name }) { const v = versions[name]!; return { pem: v.pem, algorithm: v.alg }; },
    // The REST API returns base64 strings; the gRPC client returns bytes. Return a string to exercise that path.
    async asymmetricSign({ name, data }) { return { signature: Buffer.from(versions[name]!.sign(data)).toString("base64") }; },
  };
}

test("signers: SPKI parsing recovers raw Ed25519 and ML-DSA-65 keys and rejects others", () => {
  const ed = ed25519.getPublicKey(new Uint8Array(32).fill(3));
  assert.deepEqual(rawPublicKeyFromSpki(spki("ed25519", ed)), { algorithm: "ed25519", publicKey: ed });
  assert.equal(rawPublicKeyFromSpki(pem(spki("ml-dsa-65", ml_dsa65.keygen(new Uint8Array(32)).publicKey))).publicKey.length, 1952);
  assert.throws(() => rawPublicKeyFromSpki(derSeq(derSeq(derOid("1.2.840.10045.2.1")), tlv(TAG.BIT_STRING, Uint8Array.of(0, 4, 1)))), /unsupported public key algorithm/);
});

test("signers: an envelope signed through the AWS KMS adapter verifies exactly like a local one", async () => {
  const { client, calls } = awsEmulator(51);
  const signer = await awsKmsSigner(client, { keyId: "aws-evidence-1", mlDsaKeyId: "alias/cool-mldsa", ed25519KeyId: "alias/cool-ed25519" });
  assert.deepEqual(signer.providers, { ml_dsa: "aws-kms:alias/cool-mldsa", ed25519: "aws-kms:alias/cool-ed25519" });
  const env = await signEnvelopeAsync(createEnvelope(commitInput(), registry), signer);
  const r = verifyEnvelope(env, { registry, trust: trust([record(signer as never, ["evidence"])]) });
  assert.equal(r.overall_status, "pass", JSON.stringify(r.checks));
  assert.deepEqual(calls.sort(), ["alias/cool-ed25519:ED25519_SHA_512", "alias/cool-mldsa:ML_DSA_SHAKE_256"]);
});

test("signers: Google Cloud KMS adapter (base64 signatures, PEM keys) and PKCS#11 / local components can be mixed", async () => {
  const signer = await gcpKmsSigner(gcpEmulator(61), { keyId: "gcp-evidence-1", mlDsaVersion: "projects/p/locations/global/keyRings/r/cryptoKeys/mldsa/cryptoKeyVersions/1", ed25519Version: "projects/p/locations/global/keyRings/r/cryptoKeys/ed/cryptoKeyVersions/1" });
  const env = await signEnvelopeAsync(createEnvelope(commitInput(), registry), signer);
  assert.equal(verifyEnvelope(env, { registry, trust: trust([record(signer as never, ["evidence"])]) }).overall_status, "pass");

  // ML-DSA in AWS KMS, Ed25519 in an HSM over PKCS#11.
  const { client } = awsEmulator(71);
  const hsmSecret = new Uint8Array(32).fill(99);
  const hsm = { sign: async (mech: string, _label: string, data: Uint8Array) => { assert.equal(mech, "CKM_EDDSA"); return ed25519.sign(data, hsmSecret); } };
  const mixed = hybridSigner({ keyId: "mixed-1", mlDsa: await awsKmsComponent(client, "alias/cool-mldsa", "ml-dsa-65"), ed25519: pkcs11Component(hsm, "cool-ed25519", "ed25519", ed25519.getPublicKey(hsmSecret)) });
  const e2 = await signEnvelopeAsync(createEnvelope(commitInput(), registry), mixed);
  assert.equal(verifyEnvelope(e2, { registry, trust: trust([record(mixed as never, ["evidence"])]) }).overall_status, "pass");
});

test("signers: misconfiguration fails at signing time, not at an auditor's", async () => {
  const { client } = awsEmulator(81);
  await assert.rejects(awsKmsComponent(client, "alias/cool-ed25519", "ml-dsa-65"), /needs ML_DSA_65/);
  await assert.rejects(awsKmsComponent(client, "alias/missing", "ed25519"), /NotFound/);
  // A provider that signs with a different key than it advertises is caught by the self-check.
  const ed = await awsKmsComponent(client, "alias/cool-ed25519", "ed25519");
  const liar = { ...ed, sign: async (m: Uint8Array) => ed25519.sign(m, new Uint8Array(32).fill(1)) };
  const s = hybridSigner({ keyId: "liar", mlDsa: await awsKmsComponent(client, "alias/cool-mldsa", "ml-dsa-65"), ed25519: liar });
  await assert.rejects(s.sign(new Uint8Array([1, 2, 3])), /does not verify against the configured public key/);
  const short = hybridSigner({ keyId: "short", mlDsa: await awsKmsComponent(client, "alias/cool-mldsa", "ml-dsa-65"), ed25519: { ...ed, sign: async () => new Uint8Array(10) } });
  await assert.rejects(short.sign(new Uint8Array([1])), /returned 10 bytes/);
  await assert.rejects((await awsKmsComponent(client, "alias/cool-ed25519", "ed25519")).sign(new Uint8Array(5000)), /4096-byte/);
});

test("signers: decisions and gateway confirmations can be signed by KMS-backed keys", async () => {
  const now = Date.now();
  const { trust: authzTrust, directory } = world(now);
  const { request, secrets } = createAuthorizationRequest({ principal: "agent:refund-bot", action: "refund", resource: "order:9", audience: "acme-payments", policy_selector: "refunds", params: { order: "9", amount: 100, recipient: "c" }, delegation: "dlg_root" });
  // Same evaluator identity, signed through the async path: bytes verify identically.
  const asyncEval = localAsyncSigner(KEYS.evaluator);
  const d = await decideAsync({ request, policy: REFUND_POLICY, facts: { "refund.amount": 100 }, evaluatorKey: asyncEval });
  const sync = decide({ request, policy: REFUND_POLICY, facts: { "refund.amount": 100 }, evaluatorKey: KEYS.evaluator });
  assert.equal(d.body.decision, sync.body.decision);
  const rep = verifyDecision(d, { request, trust: authzTrust, mode: "historical", policy: REFUND_POLICY, facts: { "refund.amount": 100 } });
  assert.equal(rep.checks.signature.status, "pass");
  assert.equal(rep.checks.reproduced.status, "pass");

  const delegation = ROOT_DELEGATION({ issued_at: new Date(now - 3_600_000).toISOString(), not_before: new Date(now - 3_600_000).toISOString(), expires_at: new Date(now + 86_400_000).toISOString() });
  const gw = new ToolGateway({ id: "gw", audience: "acme-payments", key: localAsyncSigner(KEYS.gateway), trust: authzTrust, nonces: new MemoryNonceStore(), directory, roots: ["user:asha"] });
  gw.register("issue_refund", { action: "refund", resource: "order:*", async execute() { return { response: { ok: true } }; } });
  const { request: r2, secrets: s2 } = createAuthorizationRequest({ principal: "agent:refund-bot", action: "refund", resource: "order:10", audience: "acme-payments", policy_selector: "refunds", params: { order: "10", amount: 100, recipient: "c" }, delegation: delegation.body.delegation_id });
  const d2 = decide({ request: r2, policy: REFUND_POLICY, facts: { "refund.amount": 100 }, evaluatorKey: KEYS.evaluator });
  const out = await gw.invoke({ tool: "issue_refund", request: r2, params: s2.params, params_salt: s2.params_salt, decision: d2, delegation: [delegation], policy: REFUND_POLICY, facts: { "refund.amount": 100 } });
  assert.equal(out.confirmation.body.outcome, "completed");
  assert.equal(verifyConfirmation(out.confirmation, { request: r2, trust: authzTrust }).outcome, "completed");
  void secrets; void generateKeypair;
});
