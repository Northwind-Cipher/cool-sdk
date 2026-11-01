/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Algorithm registry: every identifier CooL writes into evidence, and its
 * status. Verification looks identifiers up here and fails closed on anything
 * unknown or retired — there is no "best effort" path for an algorithm the
 * verifier does not recognise, and no silent downgrade to a weaker one.
 *
 * Adding an algorithm is a reviewed change to this table plus test vectors.
 * Hybrid key agreement (ML-KEM-1024 + X25519) is deliberately NOT listed: it
 * is not implemented, and no combiner has been reviewed.
 */
export type AlgorithmPurpose = "signature" | "digest" | "canonicalization" | "commitment" | "transparency";
export type AlgorithmStatus = "active" | "deprecated" | "retired";

export interface AlgorithmEntry {
  readonly id: string;
  readonly purpose: AlgorithmPurpose;
  readonly status: AlgorithmStatus;
  readonly spec: string;
}

export const ALGORITHMS: readonly AlgorithmEntry[] = [
  { id: "ml-dsa-65+ed25519", purpose: "signature", status: "active", spec: "FIPS 204 ML-DSA-65 and RFC 8032 Ed25519; both must verify" },
  { id: "sha-256", purpose: "digest", status: "active", spec: "FIPS 180-4" },
  { id: "cbor-cde", purpose: "canonicalization", status: "active", spec: "RFC 8949 §4.2 core deterministic encoding (cbor2 cdeEncodeOptions)" },
  { id: "salted-sha-256", purpose: "commitment", status: "active", spec: "SHA-256 over a 128-bit random salt and the value" },
  { id: "hmac-sha-256", purpose: "commitment", status: "active", spec: "RFC 2104 HMAC-SHA-256 keyed commitment over the salt and the value; resists guessing low-entropy values" },
  { id: "rfc6962-sha-256", purpose: "transparency", status: "active", spec: "RFC 6962 Merkle tree hash with SHA-256" },
];

/** Look an algorithm up for a purpose. Unknown, wrong-purpose or retired → null. */
export function usableAlgorithm(id: string, purpose: AlgorithmPurpose): AlgorithmEntry | null {
  const entry = ALGORITHMS.find((a) => a.id === id);
  if (!entry || entry.purpose !== purpose || entry.status === "retired") return null;
  return entry;
}
