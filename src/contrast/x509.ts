/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Just enough X.509 to verify a Contrast certificate chain offline.
 *
 * Scope is deliberately narrow. This is not a TLS stack and must never be used
 * as one: there is no name verification against a hostname, no revocation, no
 * path-length arithmetic, no policy mapping. What it does is the one thing CooL
 * needs — take the PEM a Contrast workload holds, recover the claims the
 * Coordinator wrote into it, and check the signatures linking leaf to
 * intermediate to a root the reader pinned.
 *
 * Two facts about Contrast's PKI shaped this file, both read out of
 * `internal/ca/ca.go`:
 *
 *   • The CA is CROSS-SIGNING. The mesh CA certificate is self-signed with the
 *     intermediate key; the intermediate certificate carries that same key but
 *     is signed by the root key. A workload's `certChain.pem` is
 *     `leaf ‖ intermediate`, so the chain to the root is checkable from the
 *     workload's own files plus the pinned root — which is what keeps this
 *     verification offline.
 *   • The keys differ by tier. Coordinator CA keys are P-384 (the seed engine
 *     fixes `elliptic.P384`); a workload's own key is P-256 (the initializer
 *     generates `ecdsa.GenerateKey(elliptic.P256(), …)`). Both curves are
 *     therefore supported, and the signature digest follows the certificate's
 *     own algorithm identifier rather than an assumption.
 *
 * Browser-safe on purpose: no `node:crypto`, no file access. An auditor should
 * be able to verify a Contrast-bound receipt in a tab.
 */
import { p256 } from "@noble/curves/p256";
import { p384 } from "@noble/curves/p384";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2";
import { fromBase64, toHex } from "../codec";
import {
  TAG,
  bitStringBytes,
  childrenOf,
  expectTag,
  oidToString,
  readOnly,
  type DerNode,
} from "./asn1";
import { ALGORITHM, X509 } from "./oid";

/** Raised when a certificate cannot be parsed or a chain cannot be verified. */
export class CertificateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CertificateError";
  }
}

/** One extension, kept as raw `extnValue` bytes for the claim decoders. */
export interface Extension {
  readonly oid: string;
  readonly critical: boolean;
  /** The `extnValue` OCTET STRING's contents — still DER, usually. */
  readonly value: Uint8Array;
}

/** A named curve CooL can verify against. */
export type Curve = "P-256" | "P-384";

/** A parsed subject public key. */
export interface PublicKey {
  readonly curve: Curve;
  /** The uncompressed SEC1 point, as it appears in the certificate. */
  readonly point: Uint8Array;
}

/** A parsed certificate. Only the fields the integration actually consults. */
export interface Certificate {
  /** `tbsCertificate` bytes — exactly what the issuer's signature covers. */
  readonly tbs: Uint8Array;
  readonly serial: string;
  /** Issuer name, DER-encoded, for exact comparison against a candidate issuer. */
  readonly issuerDer: Uint8Array;
  readonly subjectDer: Uint8Array;
  /** Common name, when the subject has one. Contrast puts the first DNS SAN here. */
  readonly subjectCommonName: string | null;
  readonly issuerCommonName: string | null;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly publicKey: PublicKey;
  readonly isCa: boolean;
  readonly extensions: readonly Extension[];
  /** DNS-type subject alternative names. */
  readonly dnsNames: readonly string[];
  /** IP-type subject alternative names, as dotted/colon strings. */
  readonly ipAddresses: readonly string[];
  /** URI-type subject alternative names (Contrast allows SPIFFE ids here). */
  readonly uris: readonly string[];
  readonly signatureAlgorithm: string;
  /** The raw `signatureValue` BIT STRING payload: a DER `ECDSA-Sig-Value`. */
  readonly signature: Uint8Array;
  /** The whole certificate, DER. */
  readonly der: Uint8Array;
}

/* ── PEM ──────────────────────────────────────────────────────────────── */

/** Everything that is not base64, stripped in one linear pass. */
const NOT_BASE64 = /[^A-Za-z0-9+/=]/g;

/**
 * Pull every DER block out of a PEM document, in order.
 *
 * `certChain.pem` holds two certificates and the chain order matters, so the
 * caller gets a list rather than a map.
 *
 * Deliberately an `indexOf` scan rather than a regular expression. The obvious
 * pattern — `/-----BEGIN (X)-----([\s\S]*?)-----END \1-----/g` — backtracks
 * polynomially on crafted input, and this function is fed PEM out of receipts
 * an attacker chose. A verifier that can be stalled by the bytes it is checking
 * is a denial-of-service vector, so the parse is linear by construction.
 * (Found by CodeQL `js/polynomial-redos`, not by inspection.)
 */
export function pemBlocks(pem: string, label = "CERTIFICATE"): Uint8Array[] {
  const begin = `-----BEGIN ${label}-----`;
  const end = `-----END ${label}-----`;
  const out: Uint8Array[] = [];

  let cursor = 0;
  for (;;) {
    const start = pem.indexOf(begin, cursor);
    if (start === -1) return out;
    const bodyStart = start + begin.length;
    const stop = pem.indexOf(end, bodyStart);
    if (stop === -1) return out;
    out.push(fromBase64(pem.slice(bodyStart, stop).replace(NOT_BASE64, "")));
    cursor = stop + end.length;
  }
}

/** Parse every certificate in a PEM document. */
export function parseCertificates(pem: string): Certificate[] {
  const blocks = pemBlocks(pem, "CERTIFICATE");
  if (blocks.length === 0) throw new CertificateError("no CERTIFICATE block found in PEM input");
  return blocks.map((der, index) => {
    try {
      return parseCertificate(der);
    } catch (error) {
      throw new CertificateError(`certificate ${index}: ${(error as Error).message}`);
    }
  });
}

/** Parse exactly one certificate from a PEM document. */
export function parseCertificate(der: Uint8Array): Certificate {
  const root = readOnly(der);
  expectTag(root, TAG.SEQUENCE, "Certificate");
  const [tbsNode, algNode, sigNode] = childrenOf(root);
  if (!tbsNode || !algNode || !sigNode) {
    throw new CertificateError("Certificate: expected three elements");
  }
  expectTag(tbsNode, TAG.SEQUENCE, "tbsCertificate");

  const fields = childrenOf(tbsNode);
  let index = 0;
  // version is [0] EXPLICIT and optional; absence means v1.
  if (fields[index] && fields[index]!.tag === 0xa0) index++;

  const serialNode = fields[index++];
  if (!serialNode) throw new CertificateError("tbsCertificate: missing serialNumber");
  const serial = toHex(serialNode.contents);

  const signatureAlgNode = fields[index++];
  if (!signatureAlgNode) throw new CertificateError("tbsCertificate: missing signature");

  const issuerNode = fields[index++];
  if (!issuerNode) throw new CertificateError("tbsCertificate: missing issuer");

  const validityNode = fields[index++];
  if (!validityNode) throw new CertificateError("tbsCertificate: missing validity");
  const [notBeforeNode, notAfterNode] = childrenOf(validityNode);
  if (!notBeforeNode || !notAfterNode) throw new CertificateError("validity: expected two times");

  const subjectNode = fields[index++];
  if (!subjectNode) throw new CertificateError("tbsCertificate: missing subject");

  const spkiNode = fields[index++];
  if (!spkiNode) throw new CertificateError("tbsCertificate: missing subjectPublicKeyInfo");

  let extensions: Extension[] = [];
  for (; index < fields.length; index++) {
    const field = fields[index]!;
    if (field.tag !== 0xa3) continue; // [3] EXPLICIT Extensions
    const inner = childrenOf(field)[0];
    if (!inner) throw new CertificateError("extensions: empty [3] wrapper");
    extensions = childrenOf(expectTag(inner, TAG.SEQUENCE, "Extensions")).map(parseExtension);
  }

  const sans = subjectAltNames(extensions);

  return {
    tbs: tbsNode.raw,
    serial,
    issuerDer: issuerNode.raw,
    subjectDer: subjectNode.raw,
    subjectCommonName: commonName(subjectNode),
    issuerCommonName: commonName(issuerNode),
    notBefore: parseTime(notBeforeNode),
    notAfter: parseTime(notAfterNode),
    publicKey: parseSpki(spkiNode),
    isCa: basicConstraintsCa(extensions),
    extensions,
    dnsNames: sans.dns,
    ipAddresses: sans.ip,
    uris: sans.uri,
    signatureAlgorithm: algorithmOid(algNode),
    signature: bitStringBytes(sigNode),
    der,
  };
}

function parseExtension(node: DerNode): Extension {
  const parts = childrenOf(expectTag(node, TAG.SEQUENCE, "Extension"));
  const oidNode = parts[0];
  if (!oidNode) throw new CertificateError("Extension: missing OID");
  const oid = oidToString(expectTag(oidNode, TAG.OID, "Extension.extnID").contents);
  let critical = false;
  let valueNode = parts[1];
  if (valueNode && valueNode.tag === TAG.BOOLEAN) {
    critical = valueNode.contents[0] !== 0x00;
    valueNode = parts[2];
  }
  if (!valueNode) throw new CertificateError(`Extension ${oid}: missing extnValue`);
  expectTag(valueNode, TAG.OCTET_STRING, `Extension ${oid}.extnValue`);
  return { oid, critical, value: valueNode.contents };
}

function algorithmOid(node: DerNode): string {
  const first = childrenOf(expectTag(node, TAG.SEQUENCE, "AlgorithmIdentifier"))[0];
  if (!first) throw new CertificateError("AlgorithmIdentifier: missing algorithm");
  return oidToString(expectTag(first, TAG.OID, "AlgorithmIdentifier.algorithm").contents);
}

function parseSpki(node: DerNode): PublicKey {
  const [algNode, keyNode] = childrenOf(expectTag(node, TAG.SEQUENCE, "SubjectPublicKeyInfo"));
  if (!algNode || !keyNode) throw new CertificateError("SubjectPublicKeyInfo: expected two fields");
  const algParts = childrenOf(expectTag(algNode, TAG.SEQUENCE, "spki.algorithm"));
  const algOidNode = algParts[0];
  const paramsNode = algParts[1];
  if (!algOidNode) throw new CertificateError("spki.algorithm: missing OID");
  const algOid = oidToString(expectTag(algOidNode, TAG.OID, "spki.algorithm").contents);
  if (algOid !== ALGORITHM.EC_PUBLIC_KEY) {
    throw new CertificateError(
      `unsupported public key algorithm ${algOid} — Contrast PKI uses EC keys`,
    );
  }
  if (!paramsNode) throw new CertificateError("spki.algorithm: missing named curve");
  const curveOid = oidToString(expectTag(paramsNode, TAG.OID, "spki.namedCurve").contents);
  const curve = curveOid === ALGORITHM.P256 ? "P-256" : curveOid === ALGORITHM.P384 ? "P-384" : null;
  if (!curve) throw new CertificateError(`unsupported named curve ${curveOid}`);

  const point = bitStringBytes(keyNode);
  const expected = curve === "P-256" ? 65 : 97;
  if (point.length !== expected || point[0] !== 0x04) {
    throw new CertificateError(`${curve} public key is not an uncompressed SEC1 point`);
  }
  return { curve, point };
}

/** Pull the LAST common name out of a Name, which is the most specific RDN. */
function commonName(name: DerNode): string | null {
  let found: string | null = null;
  for (const rdn of childrenOf(expectTag(name, TAG.SEQUENCE, "Name"))) {
    for (const attribute of childrenOf(rdn)) {
      const [typeNode, valueNode] = childrenOf(attribute);
      if (!typeNode || !valueNode) continue;
      if (oidToString(typeNode.contents) !== X509.COMMON_NAME) continue;
      found = new TextDecoder().decode(valueNode.contents);
    }
  }
  return found;
}

function basicConstraintsCa(extensions: readonly Extension[]): boolean {
  const ext = extensions.find((e) => e.oid === X509.BASIC_CONSTRAINTS);
  if (!ext) return false;
  const seq = readOnly(ext.value);
  const first = childrenOf(expectTag(seq, TAG.SEQUENCE, "BasicConstraints"))[0];
  return first !== undefined && first.tag === TAG.BOOLEAN && first.contents[0] !== 0x00;
}

/** GeneralName context tags from RFC 5280 §4.2.1.6. */
const GENERAL_NAME = { DNS: 0x82, URI: 0x86, IP: 0x87 } as const;

function subjectAltNames(extensions: readonly Extension[]): {
  dns: string[];
  ip: string[];
  uri: string[];
} {
  const out = { dns: [] as string[], ip: [] as string[], uri: [] as string[] };
  const ext = extensions.find((e) => e.oid === X509.SUBJECT_ALT_NAME);
  if (!ext) return out;
  const decoder = new TextDecoder();
  for (const name of childrenOf(expectTag(readOnly(ext.value), TAG.SEQUENCE, "SubjectAltName"))) {
    switch (name.tag) {
      case GENERAL_NAME.DNS:
        out.dns.push(decoder.decode(name.contents));
        break;
      case GENERAL_NAME.URI:
        out.uri.push(decoder.decode(name.contents));
        break;
      case GENERAL_NAME.IP:
        out.ip.push(formatIp(name.contents));
        break;
      default:
        break;
    }
  }
  return out;
}

function formatIp(bytes: Uint8Array): string {
  if (bytes.length === 4) return Array.from(bytes).join(".");
  if (bytes.length === 16) {
    const groups: string[] = [];
    for (let i = 0; i < 16; i += 2) {
      groups.push(((bytes[i]! << 8) | bytes[i + 1]!).toString(16));
    }
    return groups.join(":");
  }
  return `0x${toHex(bytes)}`;
}

/** Parse UTCTime / GeneralizedTime. Certificates are the only source here. */
function parseTime(node: DerNode): Date {
  const text = new TextDecoder().decode(node.contents);
  if (node.tag === TAG.UTC_TIME) {
    const match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    if (!match) throw new CertificateError(`unsupported UTCTime '${text}'`);
    const yy = Number(match[1]);
    const year = yy < 50 ? 2000 + yy : 1900 + yy;
    return new Date(
      Date.UTC(year, Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6])),
    );
  }
  if (node.tag === TAG.GENERALIZED_TIME) {
    const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    if (!match) throw new CertificateError(`unsupported GeneralizedTime '${text}'`);
    return new Date(
      Date.UTC(
        Number(match[1]),
        Number(match[2]) - 1,
        Number(match[3]),
        Number(match[4]),
        Number(match[5]),
        Number(match[6]),
      ),
    );
  }
  throw new CertificateError(`unsupported time tag 0x${node.tag.toString(16)}`);
}

/* ── signature verification ───────────────────────────────────────────── */

const DIGEST = {
  [ALGORITHM.ECDSA_SHA256]: sha256,
  [ALGORITHM.ECDSA_SHA384]: sha384,
  [ALGORITHM.ECDSA_SHA512]: sha512,
} as const;

function curveOf(key: PublicKey): typeof p256 | typeof p384 {
  return key.curve === "P-256" ? p256 : p384;
}

/**
 * Verify an ECDSA signature over `message` under `key`.
 *
 * `signature` is a DER `ECDSA-Sig-Value` — the form both X.509 and CooL's
 * workload binding use, so there is one code path for certificates and for the
 * binding statement.
 */
export function verifyEcdsa(
  message: Uint8Array,
  signature: Uint8Array,
  key: PublicKey,
  algorithmOidValue: string,
): boolean {
  const hash = DIGEST[algorithmOidValue as keyof typeof DIGEST];
  if (!hash) return false;
  try {
    const curve = curveOf(key);
    // Parsed from DER, then re-encoded compact: noble's verify takes the
    // fixed-width r‖s form, and going through its own parser rejects a
    // malformed or non-canonical DER signature before any maths happens.
    const sig = curve.Signature.fromDER(signature).toCompactRawBytes();
    return curve.verify(sig, hash(message), key.point, { prehash: false });
  } catch {
    return false;
  }
}

/** Verify that `certificate` was signed by `issuer`'s key. */
export function verifySignedBy(certificate: Certificate, issuer: Certificate): boolean {
  return verifyEcdsa(
    certificate.tbs,
    certificate.signature,
    issuer.publicKey,
    certificate.signatureAlgorithm,
  );
}

/** The outcome of checking a chain. Never throws; failures are returned. */
export interface ChainResult {
  readonly ok: boolean;
  /** Leaf first, then each issuer used, ending at the trusted root. */
  readonly path: readonly Certificate[];
  readonly detail: string;
}

/**
 * Verify `chain` (leaf first) up to one of `roots`.
 *
 * Deliberately simple and deliberately strict: every link must be signed by the
 * next certificate, every non-leaf must assert `CA:TRUE`, the issuer name must
 * match the subject name byte-for-byte, and the path must terminate in a root
 * the CALLER supplied. A chain that merely ends in a self-signed certificate it
 * carried along itself is NOT trusted — that is the whole difference between
 * pinning Contrast's Coordinator and believing whatever a pod hands you.
 *
 * `at` lets a verifier check a receipt long after the certificate expired, which
 * is the normal case for an audit: pass the receipt's issue time and the
 * validity window is checked against that instead of today.
 */
export function verifyChain(
  chain: readonly Certificate[],
  roots: readonly Certificate[],
  at: Date = new Date(),
): ChainResult {
  if (chain.length === 0) return { ok: false, path: [], detail: "empty certificate chain" };
  if (roots.length === 0) {
    return { ok: false, path: [], detail: "no trusted root supplied to verify the chain against" };
  }

  const path: Certificate[] = [];
  let current = chain[0]!;
  path.push(current);

  for (let depth = 0; depth < chain.length + roots.length + 1; depth++) {
    if (current.notBefore.getTime() > at.getTime()) {
      return { ok: false, path, detail: `${describe(current)} is not valid until ${current.notBefore.toISOString()}` };
    }
    if (current.notAfter.getTime() < at.getTime()) {
      return { ok: false, path, detail: `${describe(current)} expired ${current.notAfter.toISOString()}` };
    }

    // A root that signed the current certificate ends the walk.
    const root = roots.find(
      (candidate) =>
        sameName(candidate.subjectDer, current.issuerDer) && verifySignedBy(current, candidate),
    );
    if (root) {
      path.push(root);
      return {
        ok: true,
        path,
        detail: `chain of ${path.length} verified to pinned root ${describe(root)}`,
      };
    }

    const issuer = chain.find(
      (candidate) =>
        candidate !== current &&
        sameName(candidate.subjectDer, current.issuerDer) &&
        verifySignedBy(current, candidate),
    );
    if (!issuer) {
      return {
        ok: false,
        path,
        detail: `no issuer for ${describe(current)} (issuer ${current.issuerCommonName ?? "?"}) among the supplied chain or pinned roots`,
      };
    }
    if (!issuer.isCa) {
      return { ok: false, path, detail: `${describe(issuer)} signed a certificate but is not a CA` };
    }
    path.push(issuer);
    current = issuer;
  }

  return { ok: false, path, detail: "certificate chain does not terminate in a pinned root" };
}

function sameName(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function describe(certificate: Certificate): string {
  return `'${certificate.subjectCommonName ?? `serial ${certificate.serial.slice(0, 12)}`}'`;
}

/** Find one extension by OID. */
export function extensionByOid(
  certificate: Certificate,
  oid: string,
): Extension | undefined {
  return certificate.extensions.find((e) => e.oid === oid);
}
