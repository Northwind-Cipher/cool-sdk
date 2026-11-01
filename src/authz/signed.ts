/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Signed protocol objects: principals, delegations, requests, decisions and
 * confirmations all share one shape.
 *
 * The digest is SHA-256 over a domain label and the canonical CBOR of the
 * body; the hybrid signature is over a second domain label and that digest.
 * The signer's public keys travel with the object so it verifies offline, but
 * TRUST is never taken from the object: the verifier looks the key id up in
 * its own trust snapshot (or principal directory) and refuses a carried key
 * that differs from the trusted one — key substitution.
 */
import { canonicalCbor } from "../canonical";
import { bytesEqual, concatBytes, fromBase64Field, utf8 } from "../codec";
import { mhSha256, multihashDigest } from "../multihash";
import { hybridSign, hybridVerify } from "../sign";
import type { DirectoryEntry, KeyPair, Multihash, SignatureBlock } from "../types";
import { check, type Check } from "../platform/status";
import type { KeyPurpose, TrustStore } from "../platform/trust";

export interface Signed<T> {
  readonly body: T;
  readonly digest: Multihash;
  readonly signature: SignatureBlock;
  readonly signer: DirectoryEntry;
}

/** Drop undefined members so canonical CBOR is well-defined. */
export function clean<T>(value: T): T {
  if (Array.isArray(value)) return value.map(clean) as T;
  if (value && typeof value === "object" && !(value instanceof Uint8Array)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) if (v !== undefined) out[k] = clean(v);
    return out as T;
  }
  return value;
}

export function digestOf(context: string, body: unknown): Multihash {
  return mhSha256(concatBytes(utf8(`${context}\0`), canonicalCbor(clean(body))));
}

const sigMessage = (context: string, digest: Multihash) => concatBytes(utf8(`${context}.sig\0`), multihashDigest(digest));

export function signObject<T>(context: string, body: T, key: KeyPair): Signed<T> {
  const b = clean(body);
  const digest = digestOf(context, b);
  return { body: b, digest, signature: hybridSign(sigMessage(context, digest), key), signer: key.directoryEntry };
}

const sameKey = (a: DirectoryEntry, b: DirectoryEntry) =>
  bytesEqual(fromBase64Field(a.ed25519_pub), fromBase64Field(b.ed25519_pub)) && bytesEqual(fromBase64Field(a.ml_dsa_pub), fromBase64Field(b.ml_dsa_pub));

/** Integrity and signature of a signed object, against an expected public key when one is known. */
export function verifyIntegrity<T>(context: string, s: Signed<T>, expectedKey?: DirectoryEntry): { readonly integrity: Check; readonly signature: Check } {
  let integrity: Check;
  try {
    integrity = digestOf(context, s.body) === s.digest
      ? check("pass", "digest_matches", s.digest, { algorithm: "sha-256" })
      : check("fail", "digest_mismatch", `the ${context} body does not match its digest`);
  } catch (err) {
    integrity = check("fail", "malformed", `the ${context} body cannot be canonically encoded: ${(err as Error).message}`);
  }
  if (integrity.status !== "pass") return { integrity, signature: check("not_checked", "prerequisite_failed", "integrity failed") };
  if (expectedKey && !sameKey(expectedKey, s.signer)) {
    return { integrity, signature: check("fail", "key_substitution", `the carried key for ${s.signature.key_id} differs from the trusted key`) };
  }
  const ok = hybridVerify(sigMessage(context, s.digest), s.signature, expectedKey ?? s.signer).ok;
  return {
    integrity,
    signature: ok ? check("pass", "signature_valid", `signed by ${s.signature.key_id}`, { algorithm: "ml-dsa-65+ed25519" }) : check("fail", "signature_invalid", `the ${context} signature does not verify`),
  };
}

/** Integrity, signature and trust of an object signed by a key from the trust snapshot. */
export function verifyTrusted<T>(context: string, s: Signed<T>, trust: TrustStore, purpose: KeyPurpose, now: number): { readonly integrity: Check; readonly signature: Check; readonly trusted: Check } {
  const rec = trust.get(s.signature.key_id);
  const { integrity, signature } = verifyIntegrity(context, s, rec?.entry);
  const trusted = signature.status !== "pass" ? check("not_checked", "prerequisite_failed", "signature not valid") : trust.evaluate({ keyId: s.signature.key_id, purpose, now });
  return { integrity, signature, trusted };
}
