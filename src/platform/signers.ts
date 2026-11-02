/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Remote signing: KMS and HSM providers behind the hybrid signature.
 *
 * A CooL signature is ML-DSA-65 (FIPS 204, pure, empty context) AND Ed25519
 * (RFC 8032, pure) over the same message; both must verify. A provider-backed
 * signer is therefore two COMPONENT signers — one per algorithm — which may
 * live in different places (e.g. ML-DSA in AWS KMS, Ed25519 in an HSM).
 *
 * Every remote signature is verified locally against the configured public key
 * before it is returned (`selfCheck`), so a misconfigured key id, a wrong
 * algorithm or a provider fault fails at signing time, not at an auditor's.
 *
 * Provider SDKs are NOT dependencies. Each adapter takes the smallest client
 * shape it needs; the AWS SDK v3, the Google Cloud KMS client and a PKCS#11
 * binding satisfy those shapes with a two-line wrapper (docs/key-management.md).
 * Network calls happen only inside the client you pass in.
 *
 * Provider support for the hybrid (both algorithms required):
 *   AWS KMS          ML_DSA_65 / ML_DSA_SHAKE_256 + ECC_NIST_EDWARDS25519 / ED25519_SHA_512, MessageType RAW
 *   Google Cloud KMS PQ_SIGN_ML_DSA_65 + EC_SIGN_ED25519 (both pure; raw data)
 *   PKCS#11 HSM      CKM_ML_DSA (PKCS#11 3.2) + CKM_EDDSA (3.0), where the HSM supports them
 *   Azure Key Vault  unsupported — offers neither Ed25519 nor ML-DSA; use it for neither component
 */
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { ed25519 } from "@noble/curves/ed25519";
import { CooLError } from "../errors";
import { fromBase64Field, toBase64Field } from "../codec";
import { hybridVerify, SIGNATURE_ALG } from "../sign";
import type { DirectoryEntry, KeyPair, SignatureBlock } from "../types";
import { bitStringBytes, child, decodeOid, expectTag, parseDer, TAG } from "./der";

export type ComponentAlgorithm = "ml-dsa-65" | "ed25519";

/** One half of the hybrid: signs raw messages with one algorithm. */
export interface ComponentSigner {
  readonly algorithm: ComponentAlgorithm;
  /** Raw public key: 1952 bytes (ML-DSA-65) or 32 bytes (Ed25519). */
  readonly publicKey: Uint8Array;
  /** Where the private key lives — reported, never secret. */
  readonly provider: string;
  sign(message: Uint8Array): Promise<Uint8Array>;
}

/** The async counterpart of `Signer`, for providers that cannot sign synchronously. */
export interface AsyncSigner {
  readonly keyId: string;
  readonly directoryEntry: DirectoryEntry;
  readonly providers: { readonly ml_dsa: string; readonly ed25519: string };
  sign(message: Uint8Array): Promise<SignatureBlock>;
}

const PUB_LEN: Record<ComponentAlgorithm, number> = { "ml-dsa-65": 1952, ed25519: 32 };
const SIG_LEN: Record<ComponentAlgorithm, number> = { "ml-dsa-65": 3309, ed25519: 64 };

function checkComponent(c: ComponentSigner, expected: ComponentAlgorithm): void {
  if (c.algorithm !== expected) throw new CooLError("COOL_CONFIGURATION_INVALID", `the ${expected} component is a ${c.algorithm} signer`);
  if (c.publicKey.length !== PUB_LEN[expected]) throw new CooLError("COOL_CONFIGURATION_INVALID", `${expected} public key must be ${PUB_LEN[expected]} bytes, got ${c.publicKey.length}`);
}

/**
 * Combine two component signers into a CooL hybrid signer. Signs both halves
 * concurrently; with `selfCheck` (default on) the pair is verified before it is
 * returned.
 */
export function hybridSigner(options: { readonly keyId: string; readonly mlDsa: ComponentSigner; readonly ed25519: ComponentSigner; readonly selfCheck?: boolean }): AsyncSigner {
  checkComponent(options.mlDsa, "ml-dsa-65");
  checkComponent(options.ed25519, "ed25519");
  const directoryEntry: DirectoryEntry = { ml_dsa_pub: toBase64Field(options.mlDsa.publicKey), ed25519_pub: toBase64Field(options.ed25519.publicKey) };
  const selfCheck = options.selfCheck ?? true;
  return {
    keyId: options.keyId,
    directoryEntry,
    providers: { ml_dsa: options.mlDsa.provider, ed25519: options.ed25519.provider },
    async sign(message) {
      const [m, e] = await Promise.all([options.mlDsa.sign(message), options.ed25519.sign(message)]);
      for (const [alg, sig] of [["ml-dsa-65", m], ["ed25519", e]] as const) {
        if (!(sig instanceof Uint8Array) || sig.length !== SIG_LEN[alg]) {
          throw new CooLError("COOL_CRYPTOGRAPHY_FAILED", `the ${alg} provider returned ${sig instanceof Uint8Array ? `${sig.length} bytes` : "no bytes"}, expected ${SIG_LEN[alg]}`);
        }
      }
      const block: SignatureBlock = { alg: SIGNATURE_ALG, key_id: options.keyId, ml_dsa: toBase64Field(m), ed25519: toBase64Field(e) };
      if (selfCheck) {
        const r = hybridVerify(message, block, directoryEntry);
        if (!r.ok) throw new CooLError("COOL_CRYPTOGRAPHY_FAILED", `provider signature does not verify against the configured public key (ml-dsa ${r.mlDsaOk ? "ok" : "BAD"}, ed25519 ${r.ed25519Ok ? "ok" : "BAD"}); check the key ids and algorithms`);
      }
      return block;
    },
  };
}

/** Wrap an in-memory keypair as an AsyncSigner (tests, local development). */
export function localAsyncSigner(key: KeyPair): AsyncSigner {
  return hybridSigner({
    keyId: key.keyId,
    mlDsa: { algorithm: "ml-dsa-65", provider: "local", publicKey: publicFromEntry(key.directoryEntry.ml_dsa_pub), sign: async (m) => ml_dsa65.sign(key.mlDsaSecret, m) },
    ed25519: { algorithm: "ed25519", provider: "local", publicKey: publicFromEntry(key.directoryEntry.ed25519_pub), sign: async (m) => ed25519.sign(m, key.ed25519Secret) },
  });
}

const publicFromEntry = (field: DirectoryEntry["ml_dsa_pub"]): Uint8Array => fromBase64Field(field);

/* ── public keys from providers ───────────────────────────────────────── */

const OID_ED25519 = "1.3.101.112";
const OID_ML_DSA_65 = "2.16.840.1.101.3.4.3.18";

/** Raw public key from a DER SubjectPublicKeyInfo (what AWS GetPublicKey returns, or a PEM body). */
export function rawPublicKeyFromSpki(spki: Uint8Array | string): { algorithm: ComponentAlgorithm; publicKey: Uint8Array } {
  let der: Uint8Array;
  if (typeof spki === "string") {
    const body = spki.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, "");
    der = Uint8Array.from(Buffer.from(body, "base64"));
  } else der = spki;
  const root = expectTag(parseDer(der), TAG.SEQUENCE, "SubjectPublicKeyInfo");
  const alg = decodeOid(child(expectTag(child(root, 0, "algorithm"), TAG.SEQUENCE, "AlgorithmIdentifier"), 0, "algorithm OID"));
  const key = bitStringBytes(child(root, 1, "subjectPublicKey"));
  const algorithm: ComponentAlgorithm | undefined = alg === OID_ED25519 ? "ed25519" : alg === OID_ML_DSA_65 ? "ml-dsa-65" : undefined;
  if (!algorithm) throw new CooLError("COOL_CONFIGURATION_INVALID", `unsupported public key algorithm ${alg} (need Ed25519 ${OID_ED25519} or ML-DSA-65 ${OID_ML_DSA_65})`);
  if (key.length !== PUB_LEN[algorithm]) throw new CooLError("COOL_CONFIGURATION_INVALID", `${algorithm} public key is ${key.length} bytes, expected ${PUB_LEN[algorithm]}`);
  return { algorithm, publicKey: Uint8Array.from(key) };
}

/* ── AWS KMS ──────────────────────────────────────────────────────────── */

/**
 * The slice of AWS KMS this needs. With the AWS SDK v3:
 *
 *   const kms = new KMSClient({ region });
 *   const client = {
 *     sign: (i) => kms.send(new SignCommand(i)),
 *     getPublicKey: (i) => kms.send(new GetPublicKeyCommand(i)),
 *   };
 */
export interface AwsKmsClient {
  sign(input: { KeyId: string; Message: Uint8Array; MessageType: "RAW"; SigningAlgorithm: string }): Promise<{ Signature?: Uint8Array }>;
  getPublicKey(input: { KeyId: string }): Promise<{ PublicKey?: Uint8Array; KeySpec?: string }>;
}

const AWS_ALG: Record<ComponentAlgorithm, { keySpec: string; signing: string }> = {
  "ml-dsa-65": { keySpec: "ML_DSA_65", signing: "ML_DSA_SHAKE_256" },
  ed25519: { keySpec: "ECC_NIST_EDWARDS25519", signing: "ED25519_SHA_512" },
};

/** One component backed by an AWS KMS key. Fetches and checks the public key once. */
export async function awsKmsComponent(client: AwsKmsClient, keyId: string, algorithm: ComponentAlgorithm): Promise<ComponentSigner> {
  const pub = await client.getPublicKey({ KeyId: keyId });
  if (!pub.PublicKey) throw new CooLError("COOL_CONFIGURATION_INVALID", `AWS KMS returned no public key for ${keyId}`);
  if (pub.KeySpec && pub.KeySpec !== AWS_ALG[algorithm].keySpec) throw new CooLError("COOL_CONFIGURATION_INVALID", `AWS KMS key ${keyId} is ${pub.KeySpec}; the ${algorithm} component needs ${AWS_ALG[algorithm].keySpec}`);
  const raw = rawPublicKeyFromSpki(pub.PublicKey);
  if (raw.algorithm !== algorithm) throw new CooLError("COOL_CONFIGURATION_INVALID", `AWS KMS key ${keyId} holds an ${raw.algorithm} key, not ${algorithm}`);
  return {
    algorithm,
    publicKey: raw.publicKey,
    provider: `aws-kms:${keyId}`,
    async sign(message) {
      if (message.length > 4096) throw new CooLError("COOL_CRYPTOGRAPHY_FAILED", "AWS KMS RAW signing is limited to 4096-byte messages");
      const out = await client.sign({ KeyId: keyId, Message: message, MessageType: "RAW", SigningAlgorithm: AWS_ALG[algorithm].signing });
      if (!out.Signature) throw new CooLError("COOL_CRYPTOGRAPHY_FAILED", `AWS KMS returned no signature for ${keyId}`);
      return Uint8Array.from(out.Signature);
    },
  };
}

/** A hybrid signer with both halves in AWS KMS. */
export async function awsKmsSigner(client: AwsKmsClient, options: { readonly keyId: string; readonly mlDsaKeyId: string; readonly ed25519KeyId: string }): Promise<AsyncSigner> {
  const [mlDsa, ed] = await Promise.all([awsKmsComponent(client, options.mlDsaKeyId, "ml-dsa-65"), awsKmsComponent(client, options.ed25519KeyId, "ed25519")]);
  return hybridSigner({ keyId: options.keyId, mlDsa, ed25519: ed });
}

/* ── Google Cloud KMS ─────────────────────────────────────────────────── */

/**
 * The slice of Cloud KMS this needs. With @google-cloud/kms:
 *
 *   const kms = new KeyManagementServiceClient();
 *   const client = {
 *     asymmetricSign: async (r) => (await kms.asymmetricSign(r))[0],
 *     getPublicKey: async (r) => (await kms.getPublicKey(r))[0],
 *   };
 */
export interface GcpKmsClient {
  asymmetricSign(request: { name: string; data: Uint8Array }): Promise<{ signature?: Uint8Array | string | null }>;
  getPublicKey(request: { name: string }): Promise<{ pem?: string | null; algorithm?: string | null }>;
}

const GCP_ALG: Record<ComponentAlgorithm, string> = { "ml-dsa-65": "PQ_SIGN_ML_DSA_65", ed25519: "EC_SIGN_ED25519" };

/** One component backed by a Cloud KMS CryptoKeyVersion (`projects/…/cryptoKeyVersions/N`). */
export async function gcpKmsComponent(client: GcpKmsClient, versionName: string, algorithm: ComponentAlgorithm): Promise<ComponentSigner> {
  const pub = await client.getPublicKey({ name: versionName });
  if (!pub.pem) throw new CooLError("COOL_CONFIGURATION_INVALID", `Cloud KMS returned no public key for ${versionName}`);
  if (pub.algorithm && pub.algorithm !== GCP_ALG[algorithm]) throw new CooLError("COOL_CONFIGURATION_INVALID", `Cloud KMS key ${versionName} is ${pub.algorithm}; the ${algorithm} component needs ${GCP_ALG[algorithm]}`);
  const raw = rawPublicKeyFromSpki(pub.pem);
  if (raw.algorithm !== algorithm) throw new CooLError("COOL_CONFIGURATION_INVALID", `Cloud KMS key ${versionName} holds an ${raw.algorithm} key, not ${algorithm}`);
  return {
    algorithm,
    publicKey: raw.publicKey,
    provider: `gcp-kms:${versionName}`,
    async sign(message) {
      const out = await client.asymmetricSign({ name: versionName, data: message });
      if (!out.signature) throw new CooLError("COOL_CRYPTOGRAPHY_FAILED", `Cloud KMS returned no signature for ${versionName}`);
      return typeof out.signature === "string" ? Uint8Array.from(Buffer.from(out.signature, "base64")) : Uint8Array.from(out.signature);
    },
  };
}

export async function gcpKmsSigner(client: GcpKmsClient, options: { readonly keyId: string; readonly mlDsaVersion: string; readonly ed25519Version: string }): Promise<AsyncSigner> {
  const [mlDsa, ed] = await Promise.all([gcpKmsComponent(client, options.mlDsaVersion, "ml-dsa-65"), gcpKmsComponent(client, options.ed25519Version, "ed25519")]);
  return hybridSigner({ keyId: options.keyId, mlDsa, ed25519: ed });
}

/* ── PKCS#11 HSM ──────────────────────────────────────────────────────── */

/**
 * The slice of a PKCS#11 session this needs: sign `data` with the private key
 * object labelled `label` using `mechanism`. With `pkcs11js` (or graphene-pk11)
 * that is C_SignInit + C_Sign on an open, logged-in session.
 */
export interface Pkcs11Session {
  sign(mechanism: "CKM_ML_DSA" | "CKM_EDDSA", label: string, data: Uint8Array): Promise<Uint8Array>;
}

export function pkcs11Component(session: Pkcs11Session, label: string, algorithm: ComponentAlgorithm, publicKey: Uint8Array | string): ComponentSigner {
  const pub = typeof publicKey === "string" || publicKey.length > PUB_LEN[algorithm] ? rawPublicKeyFromSpki(publicKey).publicKey : publicKey;
  return {
    algorithm,
    publicKey: pub,
    provider: `pkcs11:${label}`,
    sign: (message) => session.sign(algorithm === "ml-dsa-65" ? "CKM_ML_DSA" : "CKM_EDDSA", label, message),
  };
}
