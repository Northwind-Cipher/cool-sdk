/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Validate a KMS signer against a LIVE provider and record the result.
 *
 *   npm i --no-save @aws-sdk/client-kms
 *   COOL_AWS_MLDSA_KEY=alias/cool-mldsa COOL_AWS_ED25519_KEY=alias/cool-ed25519 \
 *     npm run validate:kms -- aws
 *
 *   npm i --no-save @google-cloud/kms
 *   COOL_GCP_MLDSA_VERSION=projects/…/cryptoKeyVersions/1 COOL_GCP_ED25519_VERSION=projects/…/cryptoKeyVersions/1 \
 *     npm run validate:kms -- gcp
 *
 * Keys to create first:
 *   AWS:  KeySpec ML_DSA_65 and ECC_NIST_EDWARDS25519, KeyUsage SIGN_VERIFY
 *   GCP:  algorithms PQ_SIGN_ML_DSA_65 and EC_SIGN_ED25519, purpose ASYMMETRIC_SIGN
 *
 * Signs a real envelope through the provider, verifies it with the offline
 * verifier, and writes artifacts/kms-validation/<provider>-<time>.json (public
 * keys, signature, verdict — no secrets). This is the evidence that moves a
 * provider adapter from `experimental` to `implemented`.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { awsKmsSigner, createEnvelope, gcpKmsSigner, PayloadRegistry, signEnvelopeAsync, TrustStore, verifyEnvelope, type AsyncSigner } from "../src/platform/index";

const need = (k: string) => { const v = process.env[k]; if (!v) { console.error(`set ${k}`); process.exit(2); } return v; };
const load = async (pkg: string): Promise<Record<string, any>> => { // eslint-disable-line @typescript-eslint/no-explicit-any
  try { return await import(pkg); } catch { console.error(`install the provider SDK first: npm i --no-save ${pkg}`); process.exit(2); }
};

async function main(): Promise<void> {
  const provider = process.argv[2];
  let signer: AsyncSigner;
  if (provider === "aws") {
    const { KMSClient, SignCommand, GetPublicKeyCommand } = await load("@aws-sdk/client-kms");
    const kms = new KMSClient({});
    signer = await awsKmsSigner({ sign: (i) => kms.send(new SignCommand(i)), getPublicKey: (i) => kms.send(new GetPublicKeyCommand(i)) }, { keyId: "aws-kms-validation", mlDsaKeyId: need("COOL_AWS_MLDSA_KEY"), ed25519KeyId: need("COOL_AWS_ED25519_KEY") });
  } else if (provider === "gcp") {
    const { KeyManagementServiceClient } = await load("@google-cloud/kms");
    const kms = new KeyManagementServiceClient();
    signer = await gcpKmsSigner({ asymmetricSign: async (r) => (await kms.asymmetricSign(r))[0], getPublicKey: async (r) => (await kms.getPublicKey(r))[0] }, { keyId: "gcp-kms-validation", mlDsaVersion: need("COOL_GCP_MLDSA_VERSION"), ed25519Version: need("COOL_GCP_ED25519_VERSION") });
  } else {
    console.error("usage: npm run validate:kms -- aws|gcp");
    process.exit(2);
  }
  const registry = PayloadRegistry.standard();
  const now = new Date();
  const core = createEnvelope({ event_type: "tool.invoked", occurred_at: now.toISOString(), source: { system: "cool-kms-validation" }, actor: { id: "service:cool-kms-validation", type: "service" }, action: "invoke", resource: { type: "tool", ref: "kms-validation" }, payload: { tool: "kms-validation", request_id: `kms_${now.getTime()}` } }, registry);
  const env = await signEnvelopeAsync(core, signer);
  const trust = new TrustStore({ schema: "cool.trust-snapshot.v1", id: "kms-validation", as_of: now.toISOString(), keys: [{ key_id: signer.keyId, entry: signer.directoryEntry, purposes: ["evidence"], owner: provider, valid_from: new Date(now.getTime() - 60_000).toISOString(), status: "active" }] });
  const report = verifyEnvelope(env, { registry, trust });
  const artifact = { schema: "cool.kms-validation.v1", provider, providers: signer.providers, recorded_at: now.toISOString(), node: process.version, envelope: env, overall_status: report.overall_status, outcome: report.outcome, reasons: report.reasons };
  const dir = join("artifacts", "kms-validation");
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${provider}-${now.toISOString().replace(/[:.]/g, "-")}.json`);
  writeFileSync(file, `${JSON.stringify(artifact, null, 2)}\n`);
  console.log(`${report.overall_status === "pass" ? "PASSED" : "FAILED"} (${report.outcome}) — ${file}`);
  process.exit(report.overall_status === "pass" ? 0 : 1);
}

void main();
