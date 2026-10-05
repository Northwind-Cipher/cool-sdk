/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * The workload's own mesh key: reading it, and signing the binding with it.
 *
 * Contrast's initializer generates a P-256 key inside the confidential pod,
 * sends the public half to the Coordinator over aTLS, and writes the private
 * half to `/contrast/tls-config/key.pem` as PKCS#8 with mode 0400
 * (`initializer/main.go`). That key is the pod's proof of being the pod the
 * Coordinator certified, so CooL uses it for exactly one thing: signing a
 * commitment to its own signing identity.
 *
 * Note what CooL does NOT do with it. It never signs application data, never
 * opens connections with it, and never copies it anywhere. The key stays the
 * service mesh's credential; CooL borrows it for one statement at start-up.
 */
import { p256 } from "@noble/curves/p256";
import { p384 } from "@noble/curves/p384";
import { sha256, sha384 } from "@noble/hashes/sha2";
import { toBase64Field } from "../codec";
import type { Base64Field } from "../types";
import { TAG, childrenOf, expectTag, oidToString, readOnly, type DerNode } from "./asn1";
import { ALGORITHM } from "./oid";
import { CertificateError, pemBlocks, type Curve } from "./x509";

/** A private key recovered from a PEM file, with the curve it belongs to. */
export interface PrivateKey {
  readonly curve: Curve;
  /** The raw scalar, big-endian, padded to the curve's field size. */
  readonly scalar: Uint8Array;
}

const CURVE_BY_OID: Readonly<Record<string, Curve>> = {
  [ALGORITHM.P256]: "P-256",
  [ALGORITHM.P384]: "P-384",
};

const SCALAR_BYTES: Readonly<Record<Curve, number>> = { "P-256": 32, "P-384": 48 };

/**
 * Parse an EC private key from PEM.
 *
 * Accepts both shapes that occur in a Contrast deployment: PKCS#8
 * (a `PRIVATE KEY` PEM label, what the initializer writes) and SEC1 (an
 * `EC PRIVATE KEY` label, what the Coordinator's recovery path emits). Which
 * one a file uses is not something a caller should have to know.
 */
export function parsePrivateKey(pem: string): PrivateKey {
  const pkcs8 = pemBlocks(pem, "PRIVATE KEY");
  if (pkcs8.length > 0) return parsePkcs8(pkcs8[0]!);
  const sec1 = pemBlocks(pem, "EC PRIVATE KEY");
  if (sec1.length > 0) return parseSec1(readOnly(sec1[0]!));
  throw new CertificateError(
    "no 'PRIVATE KEY' or 'EC PRIVATE KEY' block found — expected the mesh key from /contrast/tls-config/key.pem",
  );
}

function parsePkcs8(der: Uint8Array): PrivateKey {
  const parts = childrenOf(expectTag(readOnly(der), TAG.SEQUENCE, "PrivateKeyInfo"));
  const algNode = parts[1];
  const keyNode = parts[2];
  if (!algNode || !keyNode) throw new CertificateError("PrivateKeyInfo: unexpected shape");

  const algParts = childrenOf(expectTag(algNode, TAG.SEQUENCE, "privateKeyAlgorithm"));
  const algOidNode = algParts[0];
  if (!algOidNode) throw new CertificateError("privateKeyAlgorithm: missing OID");
  if (oidToString(algOidNode.contents) !== ALGORITHM.EC_PUBLIC_KEY) {
    throw new CertificateError("mesh key is not an EC key");
  }
  const paramsNode = algParts[1];
  const declared = paramsNode ? CURVE_BY_OID[oidToString(paramsNode.contents)] : undefined;

  expectTag(keyNode, TAG.OCTET_STRING, "PrivateKeyInfo.privateKey");
  const inner = parseSec1(readOnly(keyNode.contents), declared);
  return inner;
}

/** ECPrivateKey ::= SEQUENCE { version, privateKey OCTET STRING, [0] params, [1] pub } */
function parseSec1(node: DerNode, declaredCurve?: Curve): PrivateKey {
  const parts = childrenOf(expectTag(node, TAG.SEQUENCE, "ECPrivateKey"));
  const scalarNode = parts[1];
  if (!scalarNode) throw new CertificateError("ECPrivateKey: missing privateKey");
  expectTag(scalarNode, TAG.OCTET_STRING, "ECPrivateKey.privateKey");

  let curve = declaredCurve;
  for (const part of parts) {
    if (part.tag !== 0xa0) continue; // [0] EXPLICIT parameters
    const oidNode = childrenOf(part)[0];
    if (oidNode) curve = CURVE_BY_OID[oidToString(oidNode.contents)] ?? curve;
  }
  // Fall back to the scalar length, which distinguishes the two curves CooL
  // supports unambiguously.
  curve ??= scalarNode.contents.length === 48 ? "P-384" : "P-256";

  const width = SCALAR_BYTES[curve];
  if (scalarNode.contents.length > width) {
    throw new CertificateError(`${curve} scalar is ${scalarNode.contents.length} bytes, expected ≤ ${width}`);
  }
  const scalar = new Uint8Array(width);
  scalar.set(scalarNode.contents, width - scalarNode.contents.length);
  return { curve, scalar };
}

/** The signature algorithm OID CooL records for a binding made with `curve`. */
export function bindingAlgorithm(curve: Curve): string {
  return curve === "P-256" ? ALGORITHM.ECDSA_SHA256 : ALGORITHM.ECDSA_SHA384;
}

/**
 * Sign the binding statement with the workload's mesh key.
 *
 * Emits a DER `ECDSA-Sig-Value`, the same encoding X.509 uses, so the verifier
 * has one signature path for certificates and for this statement.
 */
export function signBinding(message: Uint8Array, key: PrivateKey): Base64Field {
  if (key.curve === "P-256") {
    return toBase64Field(p256.sign(sha256(message), key.scalar, { prehash: false }).toDERRawBytes());
  }
  return toBase64Field(p384.sign(sha384(message), key.scalar, { prehash: false }).toDERRawBytes());
}
