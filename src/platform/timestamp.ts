/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * RFC 3161 trusted timestamps.
 *
 * A Time-Stamping Authority signs "this digest existed at genTime". CooL uses
 * it as a second, independent time source next to OpenTimestamps: stamp a
 * checkpoint or envelope digest, keep the token, verify it offline later.
 *
 *   createTimestampRequest(digest)        → DER TimeStampReq (send it yourself, or…)
 *   requestTimestamp(url, digest)         → the ONE networked call; opt-in
 *   verifyTimestampToken(token, options)  → offline; never throws on bad input
 *
 * Verification checks, each reported separately:
 *   status           PKIStatus granted / grantedWithMods
 *   imprint          messageImprint is SHA-256 of exactly the expected digest
 *   nonce            matches the request's nonce, when one is given
 *   signed_attrs     contentType = id-ct-TSTInfo, messageDigest = hash(TSTInfo),
 *                    signingCertificate(V2) names the signer certificate
 *   signature        RSA PKCS#1 v1.5 or ECDSA (SHA-256/384/512) over the signed attributes
 *   signer_certificate  extendedKeyUsage is exactly id-kp-timeStamping and critical (RFC 3161 §2.3)
 *   chain            signer → intermediates → a PINNED trust anchor, valid at genTime
 *
 * Not checked: revocation (CRL/OCSP need the network) — stated as a limitation
 * in every report. RSASSA-PSS-signed tokens are reported `unsupported`.
 */
import { X509Certificate, createHash, createPublicKey, randomBytes, verify as cryptoVerify } from "node:crypto";
import { check, type Check } from "./status";
import { classifyOutcome, type Outcome } from "./outcome";
import {
  DerError, TAG, certificateExtensions, child, decodeOid, decodeTime, derBool, derInteger, derNull, derOctets, derOid, derSeq,
  expectTag, integerBytes, integerValue, parseDer, type DerNode,
} from "./der";

const OID = {
  sha256: "2.16.840.1.101.3.4.2.1",
  sha384: "2.16.840.1.101.3.4.2.2",
  sha512: "2.16.840.1.101.3.4.2.3",
  sha1: "1.3.14.3.2.26",
  signedData: "1.2.840.113549.1.7.2",
  tstInfo: "1.2.840.113549.1.9.16.1.4",
  contentType: "1.2.840.113549.1.9.3",
  messageDigest: "1.2.840.113549.1.9.4",
  signingCertificate: "1.2.840.113549.1.9.16.2.12",
  signingCertificateV2: "1.2.840.113549.1.9.16.2.47",
  rsaEncryption: "1.2.840.113549.1.1.1",
  sha256WithRSA: "1.2.840.113549.1.1.11",
  sha384WithRSA: "1.2.840.113549.1.1.12",
  sha512WithRSA: "1.2.840.113549.1.1.13",
  rsassaPss: "1.2.840.113549.1.1.10",
  ecdsaSha256: "1.2.840.10045.4.3.2",
  ecdsaSha384: "1.2.840.10045.4.3.3",
  ecdsaSha512: "1.2.840.10045.4.3.4",
  extKeyUsage: "2.5.29.37",
  timeStamping: "1.3.6.1.5.5.7.3.8",
} as const;

const HASH_BY_OID: Record<string, "sha256" | "sha384" | "sha512" | "sha1"> = {
  [OID.sha256]: "sha256", [OID.sha384]: "sha384", [OID.sha512]: "sha512", [OID.sha1]: "sha1",
};

/** A pinned TSA trust anchor. */
export interface TsaTrustAnchor {
  readonly name: string;
  /** DER bytes of the anchor certificate (a root, or an intermediate you choose to pin). */
  readonly der: Uint8Array;
}

/* ── request ──────────────────────────────────────────────────────────── */

export interface TimestampRequest {
  readonly der: Uint8Array;
  /** Hex nonce, to check in the response. */
  readonly nonce: string;
  readonly digest: Uint8Array;
}

/** Build a DER TimeStampReq for a 32-byte SHA-256 digest, with a fresh nonce and certReq. */
export function createTimestampRequest(digest: Uint8Array, options: { readonly nonce?: Uint8Array; readonly policy?: string } = {}): TimestampRequest {
  if (digest.length !== 32) throw new Error("RFC 3161 request: expected a 32-byte SHA-256 digest");
  const nonce = options.nonce ?? new Uint8Array(randomBytes(8));
  const nonceBytes = nonce[0]! & 0x80 ? Uint8Array.from([0, ...nonce]) : nonce;
  const der = derSeq(
    derInteger(1),
    derSeq(derSeq(derOid(OID.sha256), derNull()), derOctets(digest)),
    ...(options.policy ? [derOid(options.policy)] : []),
    derInteger(nonceBytes),
    derBool(true),
  );
  return { der, nonce: Buffer.from(integerBytes(parseDer(derInteger(nonceBytes)))).toString("hex"), digest: Uint8Array.from(digest) };
}

/**
 * POST a request to a TSA (`Content-Type: application/timestamp-query`). The
 * only networked function in this module; nothing else calls it.
 */
export async function requestTimestamp(url: string, digest: Uint8Array, options: { readonly fetch?: typeof fetch; readonly timeoutMs?: number } = {}): Promise<{ readonly token: Uint8Array; readonly request: TimestampRequest }> {
  const request = createTimestampRequest(digest);
  const f = options.fetch ?? fetch;
  const res = await f(url, {
    method: "POST",
    headers: { "content-type": "application/timestamp-query", accept: "application/timestamp-reply" },
    body: Buffer.from(request.der),
    signal: AbortSignal.timeout(options.timeoutMs ?? 15_000),
  });
  if (!res.ok) throw new Error(`TSA ${url} answered HTTP ${res.status}`);
  return { token: new Uint8Array(await res.arrayBuffer()), request };
}

/* ── verification ─────────────────────────────────────────────────────── */

export interface TimestampChecks {
  readonly status: Check;
  readonly imprint: Check;
  readonly nonce: Check;
  readonly signed_attrs: Check;
  readonly signature: Check;
  readonly signer_certificate: Check;
  readonly chain: Check;
}

export interface TimestampReport {
  readonly outcome: Outcome;
  readonly checks: TimestampChecks;
  readonly reasons: readonly string[];
  /** The TSA's asserted time, ISO 8601. Present only when the token parsed. */
  readonly gen_time?: string;
  readonly serial?: string;
  readonly policy?: string;
  readonly tsa?: { readonly subject: string; readonly fingerprint256: string };
  readonly anchor?: string;
  readonly limitations: readonly string[];
}

export interface VerifyTimestampOptions {
  /** The 32-byte SHA-256 digest that was stamped. */
  readonly digest: Uint8Array;
  readonly trustAnchors: readonly TsaTrustAnchor[];
  /** Hex nonce from the request; when given, it must match. */
  readonly nonce?: string;
  /** Extra intermediates (DER) the token omitted. */
  readonly intermediates?: readonly Uint8Array[];
  /** Refuse larger inputs before parsing. Default 64 KiB (real tokens are a few KiB). */
  readonly maxBytes?: number;
}

const NOT = (r: string) => check("not_checked", "prerequisite_failed", r);
const LIMITATIONS = ["revocation of the TSA certificate is not checked (no CRL/OCSP offline)", "the TSA is trusted for time only; the stamped digest says nothing about content"];

interface ParsedToken {
  readonly statusValue: number | null;
  readonly signedData: DerNode;
  readonly tstInfoBytes: Uint8Array;
  readonly tstInfo: DerNode;
  readonly certs: readonly Uint8Array[];
  readonly signerInfo: DerNode;
}

/** Accept a TimeStampResp or a bare TimeStampToken (ContentInfo). */
function parseToken(bytes: Uint8Array): ParsedToken {
  const root = expectTag(parseDer(bytes), TAG.SEQUENCE, "TimeStampResp/ContentInfo");
  let statusValue: number | null = null;
  let contentInfo = root;
  if (root.children[0]?.tag === TAG.SEQUENCE) {
    const statusInfo = root.children[0];
    statusValue = integerValue(child(statusInfo, 0, "PKIStatus"));
    const ci = root.children[1];
    if (!ci) return { statusValue, signedData: root, tstInfoBytes: new Uint8Array(), tstInfo: root, certs: [], signerInfo: root };
    contentInfo = expectTag(ci, TAG.SEQUENCE, "timeStampToken");
  }
  if (decodeOid(child(contentInfo, 0, "contentType")) !== OID.signedData) throw new DerError("timeStampToken is not CMS SignedData");
  const signedData = expectTag(child(expectTag(child(contentInfo, 1, "content"), 0xa0, "[0] content"), 0, "SignedData"), TAG.SEQUENCE, "SignedData");
  if (integerValue(child(signedData, 0, "SignedData version")) !== 3) throw new DerError("SignedData version must be 3 for id-ct-TSTInfo (RFC 5652 §5.1)");
  expectTag(child(signedData, 1, "digestAlgorithms"), TAG.SET, "digestAlgorithms");
  const encap = expectTag(child(signedData, 2, "encapContentInfo"), TAG.SEQUENCE, "encapContentInfo");
  if (decodeOid(child(encap, 0, "eContentType")) !== OID.tstInfo) throw new DerError("eContentType is not id-ct-TSTInfo");
  const eContent = expectTag(child(expectTag(child(encap, 1, "eContent"), 0xa0, "[0] eContent"), 0, "eContent"), TAG.OCTET_STRING, "eContent");
  const tstInfoBytes = eContent.content;
  const tstInfo = expectTag(parseDer(tstInfoBytes), TAG.SEQUENCE, "TSTInfo");
  const certs: Uint8Array[] = [];
  let i = 3;
  if (signedData.children[i]?.tag === 0xa0) { for (const c of signedData.children[i]!.children) if (c.tag === TAG.SEQUENCE) certs.push(c.raw); i++; }
  if (signedData.children[i]?.tag === 0xa1) i++;
  const signerInfos = expectTag(child(signedData, i, "signerInfos"), TAG.SET, "signerInfos");
  if (signerInfos.children.length !== 1) throw new DerError(`expected exactly one SignerInfo, found ${signerInfos.children.length}`);
  return { statusValue, signedData, tstInfoBytes, tstInfo, certs, signerInfo: expectTag(signerInfos.children[0], TAG.SEQUENCE, "SignerInfo") };
}

/** AlgorithmIdentifier parameters must be absent or NULL for the algorithms accepted here. */
function algParamsAbsentOrNull(alg: DerNode): void {
  expectTag(alg, TAG.SEQUENCE, "AlgorithmIdentifier");
  if (alg.children.length > 2 || (alg.children[1] && (alg.children[1].tag !== TAG.NULL || alg.children[1].content.length !== 0))) throw new DerError("unexpected AlgorithmIdentifier parameters");
}

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && Buffer.from(a).equals(Buffer.from(b));
const normHex = (h: string) => h.toLowerCase().replace(/^0+/, "") || "0";
const fp256 = (der: Uint8Array) => createHash("sha256").update(der).digest("hex");

/** Verify an RFC 3161 token offline. Never throws on malformed input: it fails. */
export function verifyTimestampToken(token: Uint8Array, options: VerifyTimestampOptions): TimestampReport {
  let parsed: ParsedToken;
  try {
    if (token.length > (options.maxBytes ?? 65_536)) throw new DerError(`token is ${token.length} bytes, above the ${options.maxBytes ?? 65_536}-byte limit`);
    parsed = parseToken(token);
  } catch (err) {
    const malformed = check("fail", "malformed", `not a parseable RFC 3161 token: ${(err as Error).message}`);
    const checks: TimestampChecks = { status: malformed, imprint: NOT("token did not parse"), nonce: NOT("token did not parse"), signed_attrs: NOT("token did not parse"), signature: NOT("token did not parse"), signer_certificate: NOT("token did not parse"), chain: NOT("token did not parse") };
    return { outcome: "invalid", checks, reasons: [`status: malformed`], limitations: LIMITATIONS };
  }
  try {
    return verifyParsed(parsed, options);
  } catch (err) {
    const c = check("fail", "malformed", `token structure is invalid: ${(err as Error).message}`);
    const checks: TimestampChecks = { status: c, imprint: NOT("structure invalid"), nonce: NOT("structure invalid"), signed_attrs: NOT("structure invalid"), signature: NOT("structure invalid"), signer_certificate: NOT("structure invalid"), chain: NOT("structure invalid") };
    return { outcome: "invalid", checks, reasons: ["status: malformed"], limitations: LIMITATIONS };
  }
}

function verifyParsed(p: ParsedToken, o: VerifyTimestampOptions): TimestampReport {
  const status = p.statusValue === null || p.statusValue === 0 || p.statusValue === 1
    ? check("pass", "granted", p.statusValue === 1 ? "granted with modifications" : "granted")
    : check("fail", "tsa_rejected", `the TSA returned PKIStatus ${p.statusValue}`);
  if (status.status !== "pass") {
    const checks: TimestampChecks = { status, imprint: NOT("TSA rejected"), nonce: NOT("TSA rejected"), signed_attrs: NOT("TSA rejected"), signature: NOT("TSA rejected"), signer_certificate: NOT("TSA rejected"), chain: NOT("TSA rejected") };
    return finish(checks, {});
  }

  /* TSTInfo */
  const t = p.tstInfo;
  const policy = decodeOid(child(t, 1, "policy"));
  const mi = expectTag(child(t, 2, "messageImprint"), TAG.SEQUENCE, "messageImprint");
  const miAlg = decodeOid(child(expectTag(child(mi, 0, "hashAlgorithm"), TAG.SEQUENCE, "hashAlgorithm"), 0, "hash OID"));
  const miHash = expectTag(child(mi, 1, "hashedMessage"), TAG.OCTET_STRING, "hashedMessage").content;
  const serial = hex(integerBytes(child(t, 3, "serialNumber")));
  const genTimeMs = decodeTime(expectTag(child(t, 4, "genTime"), TAG.GENERALIZED_TIME, "genTime"));
  const nonceNode = t.children.slice(5).find((c) => c.tag === TAG.INTEGER);
  const tokenNonce = nonceNode ? hex(integerBytes(nonceNode)) : undefined;

  const imprint = miAlg !== OID.sha256
    ? check("fail", "unsupported_algorithm", `messageImprint uses ${miAlg}; CooL stamps SHA-256 digests`)
    : eq(miHash, o.digest) ? check("pass", "imprint_matches", `the token stamps ${hex(o.digest)}`) : check("fail", "imprint_mismatch", "the token stamps a different digest");
  const nonce = o.nonce === undefined
    ? check("not_applicable", "no_nonce_expected", tokenNonce ? `token nonce ${tokenNonce} not compared (none supplied)` : "no nonce")
    : tokenNonce !== undefined && normHex(tokenNonce) === normHex(o.nonce) ? check("pass", "nonce_matches", tokenNonce) : check("fail", "nonce_mismatch", `token nonce ${tokenNonce ?? "(none)"} ≠ request nonce ${o.nonce}`);

  /* SignerInfo */
  const si = p.signerInfo;
  const sid = child(si, 1, "sid");
  const digestAlg = decodeOid(child(expectTag(child(si, 2, "digestAlgorithm"), TAG.SEQUENCE, "digestAlgorithm"), 0, "digest OID"));
  const hashName = HASH_BY_OID[digestAlg];
  const signedAttrsNode = expectTag(child(si, 3, "signedAttrs"), 0xa0, "signedAttrs");
  const sigAlgId = expectTag(child(si, 4, "signatureAlgorithm"), TAG.SEQUENCE, "signatureAlgorithm");
  const sigAlg = decodeOid(child(sigAlgId, 0, "signature OID"));
  const signatureBytes = expectTag(child(si, 5, "signature"), TAG.OCTET_STRING, "signature").content;

  const siVersion = integerValue(child(si, 0, "SignerInfo version"));
  if (sid.tag === TAG.SEQUENCE ? siVersion !== 1 : sid.tag === 0x80 ? siVersion !== 3 : true) throw new DerError("SignerInfo version does not match its sid form");
  algParamsAbsentOrNull(child(si, 2, "digestAlgorithm"));
  algParamsAbsentOrNull(sigAlgId);
  const listed = p.signedData.children[1]!.children.map((a) => { algParamsAbsentOrNull(a); return decodeOid(child(a, 0, "digestAlgorithm OID")); });
  if (!listed.includes(digestAlg)) throw new DerError("SignedData.digestAlgorithms does not list the SignerInfo digest algorithm");

  const attrs = new Map<string, DerNode>();
  for (const a of signedAttrsNode.children) {
    const id = decodeOid(child(a, 0, "attrType"));
    if (attrs.has(id)) throw new DerError(`duplicate signed attribute ${id}`);
    attrs.set(id, expectTag(child(a, 1, "attrValues"), TAG.SET, "attrValues"));
  }

  /* find the signer certificate via signingCertificate(V2) */
  const pool = [...p.certs, ...(o.intermediates ?? [])];
  let signerDer: Uint8Array | undefined;
  let essProblem = "";
  const v2 = attrs.get(OID.signingCertificateV2);
  const v1 = attrs.get(OID.signingCertificate);
  if (v2 || v1) {
    const essSeq = expectTag(child(expectTag(child(v2 ?? v1!, 0, "SigningCertificate"), TAG.SEQUENCE, "SigningCertificate"), 0, "certs"), TAG.SEQUENCE, "certs");
    const first = expectTag(child(essSeq, 0, "ESSCertID"), TAG.SEQUENCE, "ESSCertID");
    let essHashAlg = "sha1";
    let certHash: Uint8Array;
    if (v2) {
      if (first.children[0]?.tag === TAG.SEQUENCE) {
        const h = HASH_BY_OID[decodeOid(child(first.children[0], 0, "ESS hash OID"))];
        if (!h) throw new DerError("unsupported ESSCertIDv2 hash");
        essHashAlg = h;
        certHash = expectTag(child(first, 1, "certHash"), TAG.OCTET_STRING, "certHash").content;
      } else {
        essHashAlg = "sha256";
        certHash = expectTag(child(first, 0, "certHash"), TAG.OCTET_STRING, "certHash").content;
      }
    } else certHash = expectTag(child(first, 0, "certHash"), TAG.OCTET_STRING, "certHash").content;
    signerDer = pool.find((c) => eq(new Uint8Array(createHash(essHashAlg).update(c).digest()), certHash));
    if (!signerDer) essProblem = "no supplied certificate matches the signingCertificate hash";
  } else essProblem = "signingCertificate(V2) attribute is missing (RFC 5816 / RFC 3161 §2.4.1)";

  /* signed attributes */
  const ct = attrs.get(OID.contentType);
  const md = attrs.get(OID.messageDigest);
  let signed_attrs: Check;
  if (!hashName || hashName === "sha1") signed_attrs = check("fail", "unsupported_algorithm", `SignerInfo digest algorithm ${digestAlg} is not accepted`);
  else if (!ct || decodeOid(child(ct, 0, "contentType")) !== OID.tstInfo) signed_attrs = check("fail", "content_type_mismatch", "signed contentType is not id-ct-TSTInfo");
  else if (!md || !eq(expectTag(child(md, 0, "messageDigest"), TAG.OCTET_STRING, "messageDigest").content, new Uint8Array(createHash(hashName).update(p.tstInfoBytes).digest()))) signed_attrs = check("fail", "message_digest_mismatch", "the signed messageDigest does not match the TSTInfo — the token was altered");
  else if (essProblem) signed_attrs = check("fail", "signer_certificate_unbound", essProblem);
  else signed_attrs = check("pass", "attributes_bound", `contentType, messageDigest (${hashName}) and signingCertificate${v2 ? "V2" : ""} are consistent`);

  if (!signerDer) {
    const checks: TimestampChecks = { status, imprint, nonce, signed_attrs, signature: NOT("signer certificate not found"), signer_certificate: NOT("signer certificate not found"), chain: NOT("signer certificate not found") };
    return finish(checks, { gen_time: new Date(genTimeMs).toISOString(), serial, policy });
  }
  const signer = new X509Certificate(signerDer);

  if (sid.tag === TAG.SEQUENCE) {
    // IssuerAndSerialNumber must name the bound certificate exactly: same issuer Name bytes, same serial.
    const tbs = child(parseDer(signerDer), 0, "tbsCertificate");
    const offset = tbs.children[0]?.tag === 0xa0 ? 1 : 0;
    const certSerial = integerBytes(child(tbs, offset, "certificate serial"));
    const certIssuer = child(tbs, offset + 2, "certificate issuer").raw;
    if (!eq(child(sid, 0, "sid issuer").raw, certIssuer) || !eq(integerBytes(child(sid, 1, "sid serial")), certSerial)) {
      signed_attrs = check("fail", "signer_identifier_mismatch", "SignerInfo sid (issuer and serial) does not name the certificate bound by signingCertificate");
    }
  }

  /* signature over the DER SET OF signed attributes (tag rewritten 0xA0 → 0x31) */
  let signature: Check;
  const signedBytes = Uint8Array.from(signedAttrsNode.raw);
  signedBytes[0] = TAG.SET;
  const rsa = [OID.rsaEncryption, OID.sha256WithRSA, OID.sha384WithRSA, OID.sha512WithRSA] as string[];
  const ec = [OID.ecdsaSha256, OID.ecdsaSha384, OID.ecdsaSha512] as string[];
  if (sigAlg === OID.rsassaPss) signature = check("fail", "unsupported_algorithm", "RSASSA-PSS-signed tokens are not supported yet");
  else if (!hashName || hashName === "sha1" || (!rsa.includes(sigAlg) && !ec.includes(sigAlg))) signature = check("fail", "unsupported_algorithm", `signature algorithm ${sigAlg} is not accepted`);
  else {
    let ok = false;
    try { ok = cryptoVerify(hashName, signedBytes, createPublicKey(signer.publicKey.export({ type: "spki", format: "pem" })), signatureBytes); } catch { ok = false; }
    signature = ok ? check("pass", "signature_valid", `${hashName} ${rsa.includes(sigAlg) ? "RSA" : "ECDSA"} by ${signer.subject.replace(/\n/g, ", ")}`) : check("fail", "signature_invalid", "the TSA signature over the signed attributes does not verify");
  }

  /* signer certificate: EKU timeStamping only, critical; valid at genTime */
  let signer_certificate: Check;
  const exts = certificateExtensions(signerDer);
  const eku = exts.get(OID.extKeyUsage);
  const ekus = signer.keyUsage ?? [];
  if (!eku) signer_certificate = check("fail", "not_a_tsa_certificate", "the signer certificate has no extendedKeyUsage");
  else if (!eku.critical) signer_certificate = check("fail", "not_a_tsa_certificate", "extendedKeyUsage must be critical for a TSA certificate (RFC 3161 §2.3)");
  else if (ekus.length !== 1 || ekus[0] !== OID.timeStamping) signer_certificate = check("fail", "not_a_tsa_certificate", `extendedKeyUsage must be exactly id-kp-timeStamping, got ${ekus.join(", ")}`);
  else if (genTimeMs < Date.parse(signer.validFrom) || genTimeMs > Date.parse(signer.validTo)) signer_certificate = check("fail", "certificate_expired", `genTime ${new Date(genTimeMs).toISOString()} is outside the TSA certificate validity`);
  else signer_certificate = check("pass", "tsa_certificate", "timeStamping-only EKU (critical), valid at genTime");

  /* chain to a pinned anchor */
  const { check: chain, anchor } = buildChain(signer, pool.map((d) => new X509Certificate(d)), o.trustAnchors, genTimeMs);

  return finish({ status, imprint, nonce, signed_attrs, signature, signer_certificate, chain }, {
    gen_time: new Date(genTimeMs).toISOString(), serial, policy,
    tsa: { subject: signer.subject.replace(/\n/g, ", "), fingerprint256: fp256(signerDer) },
    ...(anchor ? { anchor } : {}),
  });
}

function buildChain(leaf: X509Certificate, pool: readonly X509Certificate[], anchors: readonly TsaTrustAnchor[], at: number): { check: Check; anchor?: string } {
  if (anchors.length === 0) return { check: check("unknown", "no_trust_anchor", "no TSA trust anchor was supplied; the signature cannot be attributed") };
  const pinned = anchors.map((a) => ({ name: a.name, cert: new X509Certificate(a.der), fp: fp256(a.der) }));
  const valid = (c: X509Certificate) => at >= Date.parse(c.validFrom) && at <= Date.parse(c.validTo);
  let current = leaf;
  const path: string[] = [];
  for (let depth = 0; depth < 8; depth++) {
    const self = pinned.find((a) => a.fp === fp256(new Uint8Array(current.raw)));
    if (self && depth > 0) return { check: check("pass", "chain_valid", `${[...path, self.name].join(" → ")}`), anchor: self.name };
    const anchor = pinned.find((a) => current.checkIssued(a.cert) && current.verify(a.cert.publicKey));
    if (anchor) {
      if (!valid(anchor.cert)) return { check: check("fail", "certificate_expired", `anchor ${anchor.name} is not valid at genTime`) };
      return { check: check("pass", "chain_valid", [...path, current.subject.split("\n").find((l) => l.startsWith("CN="))?.slice(3) ?? "certificate", anchor.name].join(" → ")), anchor: anchor.name };
    }
    const issuer = pool.find((c) => c.fingerprint256 !== current.fingerprint256 && current.checkIssued(c) && current.verify(c.publicKey));
    if (!issuer) return { check: check("fail", "untrusted_root", "the TSA certificate does not chain to a pinned trust anchor") };
    if (!issuer.ca) return { check: check("fail", "chain_invalid", "an issuing certificate is not a CA") };
    if (!valid(issuer)) return { check: check("fail", "certificate_expired", "an intermediate is not valid at genTime") };
    path.push(current.subject.split("\n").find((l) => l.startsWith("CN="))?.slice(3) ?? "certificate");
    current = issuer;
  }
  return { check: check("fail", "chain_invalid", "certificate chain too long") };
}

function finish(checks: TimestampChecks, extra: Omit<TimestampReport, "outcome" | "checks" | "reasons" | "limitations">): TimestampReport {
  const { outcome, reasons } = classifyOutcome(checks as unknown as Record<string, Check>, ["status", "imprint", "nonce", "signed_attrs", "signature", "signer_certificate", "chain"]);
  return { outcome, checks, reasons, ...extra, limitations: LIMITATIONS };
}
