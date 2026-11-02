/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Offline verification of an AWS Nitro Enclaves attestation document.
 *
 * The document is a CBOR COSE_Sign1 (ES384) whose payload carries the module
 * id, a timestamp, the locked PCRs, the signing certificate, its CA bundle and
 * three optional protocol fields: public_key, user_data and nonce. The format
 * and the validation order follow AWS's "Verifying the root of trust".
 *
 * The order of operations is the security property:
 *
 *   1. structure     strict decode, size limits, header allowlist, no unknown fields
 *   2. trust root    cabundle[0] must be byte-identical to a pinned root
 *   3. chain         root → intermediates → leaf: issuer, signature, CA flag, validity
 *   4. signature     COSE_Sign1 Sig_structure verified with the leaf's P-384 key
 *
 * Only if 2–4 all pass are the claims consumed. Until then every claim-based
 * check reports `not_checked` with reason "claims_unverified": a PCR value in
 * a decoded map means nothing before the signature over it is known good.
 *
 *   5. debug mode    PCR0–2 all zero means a debug enclave; always a fail
 *   6. PCR policy    caller-pinned PCR0–2 (+ optional extras); PCR8 explicit
 *   7. key binding   user_data must equal the CooL key-binding digest
 *   8. public_key    must be the receipt Ed25519 key, unless policy says unused
 *   9. freshness     nonce (preferred) or timestamp window — never a silent downgrade
 *
 * Every check reports pass | fail | unknown | not_applicable | not_checked and
 * a stable reason code. The overall status is `pass` only when every required
 * check passed; anything unknown or unchecked makes the whole report `unknown`,
 * never `pass`.
 *
 * Limits, stated so nobody has to discover them: X.509 path checks are done
 * with node:crypto (issuer linkage, signature, CA flag, validity), not a full
 * RFC 5280 validator — path-length, key-usage and name constraints are not
 * evaluated. AWS says CRLs are not used for this PKI, so revocation is not
 * checked; an offline pass means "valid under the local trust bundle and
 * policy", not "not revoked since the bundle was last reviewed".
 */
import { X509Certificate, createHash, verify as cryptoVerify } from "node:crypto";
import { Tag, decode, encode } from "cbor2";
import { canonicalCbor } from "../canonical";
import { bytesEqual, concatBytes, fromBase64Field, toHex, utf8 } from "../codec";
import { sha256Bytes } from "../hash";
import type { DirectoryEntry } from "../types";
import { AWS_NITRO_TRUST_BUNDLE, type NitroTrustBundle } from "./trust-root";

/* ── report types ─────────────────────────────────────────────────────── */

export type NitroCheckStatus = "pass" | "fail" | "unknown" | "not_applicable" | "not_checked";

export interface NitroCheck {
  readonly status: NitroCheckStatus;
  /** Stable, machine-readable reason code. */
  readonly reason: string;
  readonly detail: string;
  /** What a pass here does NOT establish, when that is worth saying. */
  readonly limitation?: string;
}

export interface NitroChecks {
  readonly structure: NitroCheck;
  readonly trust_root: NitroCheck;
  readonly certificate_chain: NitroCheck;
  readonly cose_signature: NitroCheck;
  readonly debug_mode: NitroCheck;
  readonly pcr_policy: NitroCheck;
  readonly pcr8_signing: NitroCheck;
  readonly key_binding: NitroCheck;
  readonly public_key: NitroCheck;
  readonly freshness: NitroCheck;
}

/** Claims as decoded. `verified` is false unless trust root, chain and signature all passed. */
export interface NitroClaims {
  readonly verified: boolean;
  readonly module_id: string;
  readonly timestamp_ms: number;
  readonly pcrs: Readonly<Record<number, string>>;
  readonly public_key: string | null;
  readonly user_data: string | null;
  readonly nonce: string | null;
}

export interface NitroAttestationReport {
  readonly schema: "cool.nitro.attestation-report.v1";
  readonly parser: { readonly name: "cool-nitro"; readonly version: "1" };
  readonly overall_status: "pass" | "fail" | "unknown";
  /** Lowercase hex SHA-256 of the exact bytes verified. */
  readonly document_sha256: string;
  readonly trust_bundle: { readonly id: string; readonly version: string; readonly root: string | null };
  readonly policy: { readonly id: string; readonly version: string; readonly source: string } | null;
  readonly claims: NitroClaims | null;
  readonly checks: NitroChecks;
  readonly reasons: readonly string[];
}

/* ── policy and options ───────────────────────────────────────────────── */

/**
 * Expected measurements. PCR0 (image), PCR1 (kernel/boot) and PCR2
 * (application) are mandatory. PCR8 must be stated explicitly: a hex value when
 * the enclave image is signed and the signing certificate is part of the
 * policy, or "not_applicable" when it is not — the verifier will not guess.
 */
export interface NitroPcrPolicy {
  readonly id: string;
  readonly version: string;
  /** Where these values came from (a reproducible build, a release manifest…). */
  readonly source: string;
  /** Hex PCR values by index. Must include 0, 1 and 2. */
  readonly pcrs: Readonly<Record<number, string>>;
  readonly pcr8: string | "not_applicable";
  /**
   * How the attestation's public_key field is used. "receipt-ed25519" (default)
   * requires it to be the receipt key's Ed25519 SubjectPublicKeyInfo. "unused"
   * reports not_applicable — for deployments where public_key carries another
   * protocol's key (for example a KMS recipient key) and user_data alone binds
   * the receipt key.
   */
  readonly publicKey?: "receipt-ed25519" | "unused";
}

/** Single-use nonce memory for replay detection. */
export interface NonceLedger {
  has(nonceHex: string): boolean;
  add(nonceHex: string): void;
}

export type NitroFreshness =
  | { readonly mode: "nonce"; readonly expected: Uint8Array; readonly ledger?: NonceLedger }
  | { readonly mode: "timestamp-window"; readonly maxAgeMs: number; readonly clockSkewMs?: number };

export interface VerifyNitroOptions {
  /** Defaults to the pinned AWS G1 bundle. */
  readonly trustBundle?: NitroTrustBundle;
  readonly policy?: NitroPcrPolicy;
  /** The receipt key the attestation must bind. */
  readonly receiptKey?: { readonly keyId: string; readonly entry: DirectoryEntry };
  /** Required for a pass. Absent → freshness is not_checked and the report is unknown. */
  readonly freshness?: NitroFreshness;
  /** Verification time, ms since epoch. Defaults to Date.now(). */
  readonly now?: number;
  /**
   * Instant at which certificate validity is judged. "now" (default) is the
   * live rule AWS describes. "attestation-timestamp" is for archived evidence:
   * leaf certificates live for hours, so a document verified later can only be
   * judged at the time it claims to have been made — the report says so.
   */
  readonly certificateTime?: "now" | "attestation-timestamp";
  /** Maximum accepted document size in bytes. Default 16 KiB. */
  readonly maxBytes?: number;
}

/* ── key binding ──────────────────────────────────────────────────────── */

/** Domain-separation label for the user_data key binding. */
export const KEY_BINDING_CONTEXT = "cool.nitro.key-binding.v1";

/**
 * The 32 bytes an enclave puts in user_data to bind a CooL hybrid key.
 *
 * SHA-256 over a domain label and the canonical CBOR of the key id and both
 * public keys. ML-DSA-65 public keys are 1952 bytes — larger than the 1024-byte
 * NSM field limit — so the binding is a digest, and the verifier recomputes it
 * from the key directory carried in the receipt.
 */
export function keyBindingUserData(keyId: string, entry: DirectoryEntry): Uint8Array {
  const structure = {
    ctx: KEY_BINDING_CONTEXT,
    key_id: keyId,
    keys: [
      { alg: "ml-dsa-65", pub: fromBase64Field(entry.ml_dsa_pub) },
      { alg: "ed25519", pub: fromBase64Field(entry.ed25519_pub) },
    ],
  };
  return sha256Bytes(concatBytes(utf8(`${KEY_BINDING_CONTEXT}\0`), canonicalCbor(structure)));
}

const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

/** DER SubjectPublicKeyInfo for a raw Ed25519 key — what goes in public_key. */
export function ed25519Spki(rawPublicKey: Uint8Array): Uint8Array {
  if (rawPublicKey.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  return concatBytes(ED25519_SPKI_PREFIX, rawPublicKey);
}

/** The simplest ledger: an in-memory set. Persist it for anything long-lived. */
export function memoryNonceLedger(): NonceLedger {
  const seen = new Set<string>();
  return { has: (n) => seen.has(n), add: (n) => void seen.add(n) };
}

/* ── decoding ─────────────────────────────────────────────────────────── */

const DECODE = { preferMap: true, rejectDuplicateKeys: true } as const;
const ES384 = -35;
const KNOWN_FIELDS = new Set([
  "module_id", "digest", "timestamp", "pcrs", "certificate", "cabundle", "public_key", "user_data", "nonce",
]);

class Malformed extends Error {
  constructor(readonly reason: string, detail: string) {
    super(detail);
  }
}

interface Decoded {
  readonly protectedBytes: Uint8Array;
  readonly payloadBytes: Uint8Array;
  readonly signature: Uint8Array;
  readonly moduleId: string;
  readonly timestampMs: number;
  readonly pcrs: ReadonlyMap<number, Uint8Array>;
  readonly certificate: Uint8Array;
  readonly cabundle: readonly Uint8Array[];
  readonly publicKey: Uint8Array | null;
  readonly userData: Uint8Array | null;
  readonly nonce: Uint8Array | null;
}

const isBytes = (v: unknown): v is Uint8Array => v instanceof Uint8Array;

function optionalBytes(payload: Map<unknown, unknown>, field: string): Uint8Array | null {
  const v = payload.get(field);
  if (v === undefined || v === null) return null;
  if (!isBytes(v) || v.length > 1024) throw new Malformed("invalid_field", `${field} must be bytes of at most 1024`);
  return v;
}

function decodeDocument(raw: Uint8Array, maxBytes: number): Decoded {
  if (raw.length === 0 || raw.length > maxBytes) {
    throw new Malformed("oversized_or_empty", `document is ${raw.length} bytes; accepted range is 1..${maxBytes}`);
  }
  let outer: unknown;
  try {
    outer = decode(raw, DECODE);
  } catch (err) {
    throw new Malformed("malformed_cbor", `outer CBOR did not decode: ${(err as Error).message}`);
  }
  if (outer instanceof Tag) {
    if (outer.tag !== 18) throw new Malformed("unexpected_tag", `CBOR tag ${String(outer.tag)} is not COSE_Sign1 (18)`);
    outer = outer.contents;
  }
  if (!Array.isArray(outer) || outer.length !== 4) {
    throw new Malformed("not_cose_sign1", "COSE_Sign1 must be a 4-element array");
  }
  const [protectedBytes, unprotected, payloadBytes, signature] = outer as unknown[];
  if (!isBytes(protectedBytes) || !isBytes(payloadBytes) || !isBytes(signature)) {
    throw new Malformed("not_cose_sign1", "protected header, payload and signature must be byte strings");
  }
  if (!(unprotected instanceof Map) || unprotected.size !== 0) {
    throw new Malformed("unexpected_header", "the unprotected header must be empty");
  }

  let header: unknown;
  try {
    header = decode(protectedBytes, DECODE);
  } catch (err) {
    throw new Malformed("malformed_cbor", `protected header did not decode: ${(err as Error).message}`);
  }
  if (!(header instanceof Map) || header.size !== 1 || !header.has(1)) {
    throw new Malformed("unexpected_header", "the protected header must contain exactly the algorithm");
  }
  if (header.get(1) !== ES384) {
    throw new Malformed("unsupported_algorithm", `algorithm ${String(header.get(1))} is not ES384 (-35)`);
  }
  if (signature.length !== 96) {
    throw new Malformed("invalid_signature_encoding", `ES384 signature must be 96 bytes, got ${signature.length}`);
  }

  let payload: unknown;
  try {
    payload = decode(payloadBytes, DECODE);
  } catch (err) {
    throw new Malformed("malformed_cbor", `payload did not decode: ${(err as Error).message}`);
  }
  if (!(payload instanceof Map)) throw new Malformed("invalid_payload", "payload must be a map");
  for (const key of payload.keys()) {
    if (typeof key !== "string" || !KNOWN_FIELDS.has(key)) {
      throw new Malformed("unexpected_field", `unexpected payload field ${String(key)}`);
    }
  }

  const moduleId = payload.get("module_id");
  if (typeof moduleId !== "string" || moduleId.length === 0) throw new Malformed("invalid_field", "module_id must be text");
  if (payload.get("digest") !== "SHA384") throw new Malformed("invalid_field", "digest must be \"SHA384\"");

  const ts = payload.get("timestamp");
  const timestampMs = typeof ts === "bigint" ? Number(ts) : ts;
  if (typeof timestampMs !== "number" || !Number.isSafeInteger(timestampMs) || timestampMs <= 0) {
    throw new Malformed("invalid_field", "timestamp must be a positive integer (ms since epoch)");
  }

  const rawPcrs = payload.get("pcrs");
  if (!(rawPcrs instanceof Map) || rawPcrs.size === 0) throw new Malformed("invalid_field", "pcrs must be a non-empty map");
  const pcrs = new Map<number, Uint8Array>();
  for (const [index, value] of rawPcrs) {
    if (typeof index !== "number" || !Number.isInteger(index) || index < 0 || index > 31) {
      throw new Malformed("invalid_field", `PCR index ${String(index)} is outside 0..31`);
    }
    if (!isBytes(value) || value.length !== 48) {
      throw new Malformed("invalid_field", `PCR${index} must be 48 bytes for SHA384`);
    }
    pcrs.set(index, value);
  }

  const certificate = payload.get("certificate");
  if (!isBytes(certificate) || certificate.length < 1 || certificate.length > 1024) {
    throw new Malformed("invalid_field", "certificate must be 1..1024 bytes of DER");
  }
  const cabundle = payload.get("cabundle");
  if (!Array.isArray(cabundle) || cabundle.length === 0) {
    throw new Malformed("invalid_field", "cabundle must be a non-empty array");
  }
  for (const cert of cabundle) {
    if (!isBytes(cert) || cert.length < 1 || cert.length > 1024) {
      throw new Malformed("invalid_field", "every cabundle entry must be 1..1024 bytes of DER");
    }
  }

  return {
    protectedBytes,
    payloadBytes,
    signature,
    moduleId,
    timestampMs,
    pcrs,
    certificate,
    cabundle: cabundle as Uint8Array[],
    publicKey: optionalBytes(payload, "public_key"),
    userData: optionalBytes(payload, "user_data"),
    nonce: optionalBytes(payload, "nonce"),
  };
}

/* ── checks ───────────────────────────────────────────────────────────── */

const check = (status: NitroCheckStatus, reason: string, detail: string, limitation?: string): NitroCheck =>
  limitation ? { status, reason, detail, limitation } : { status, reason, detail };

const NOT_CHECKED = (why: string): NitroCheck => check("not_checked", "claims_unverified", why);

function certTimes(cert: X509Certificate): { from: number; to: number } {
  return { from: Date.parse(cert.validFrom), to: Date.parse(cert.validTo) };
}

function verifyChain(doc: Decoded, at: number, atLabel: string): NitroCheck {
  let chain: X509Certificate[];
  try {
    chain = [...doc.cabundle, doc.certificate].map((der) => new X509Certificate(der));
  } catch (err) {
    return check("fail", "invalid_certificate_encoding", `a certificate did not parse: ${(err as Error).message}`);
  }
  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i]!;
    const { from, to } = certTimes(cert);
    if (!(at >= from)) return check("fail", "certificate_not_yet_valid", `certificate ${i} is not valid until ${cert.validFrom} (${atLabel})`);
    if (!(at <= to)) return check("fail", "certificate_expired", `certificate ${i} expired ${cert.validTo} (${atLabel})`);
    if (i === 0) continue;
    const parent = chain[i - 1]!;
    if (!parent.ca) return check("fail", "ca_flag_missing", `certificate ${i - 1} issues certificate ${i} but is not a CA`);
    if (!cert.checkIssued(parent)) return check("fail", "chain_issuer_mismatch", `certificate ${i} was not issued by certificate ${i - 1}`);
    let signed: boolean;
    try {
      signed = cert.verify(parent.publicKey);
    } catch {
      signed = false;
    }
    if (!signed) return check("fail", "chain_signature_invalid", `certificate ${i} signature does not verify under certificate ${i - 1}`);
  }
  if (chain[chain.length - 1]!.ca) return check("fail", "leaf_is_ca", "the signing certificate must not be a CA");
  return check(
    "pass",
    "chain_valid",
    `${chain.length} certificates chain to the root (validity judged at ${atLabel})`,
    "issuer, signature, CA flag and validity only; path-length, key-usage and name constraints are not evaluated; no revocation (AWS publishes no CRL for this PKI)",
  );
}

function verifyCoseSignature(doc: Decoded): NitroCheck {
  let leaf: X509Certificate;
  try {
    leaf = new X509Certificate(doc.certificate);
  } catch {
    return check("fail", "invalid_certificate_encoding", "the signing certificate did not parse");
  }
  // A corrupted certificate can parse yet carry an undecodable key, and
  // OpenSSL then throws rather than returning false. Hostile input must
  // produce a report, never an exception (found by the corruption test).
  let ok: boolean;
  try {
    const details = leaf.publicKey.asymmetricKeyDetails;
    if (leaf.publicKey.asymmetricKeyType !== "ec" || details?.namedCurve !== "secp384r1") {
      return check("fail", "unsupported_algorithm", "the signing certificate does not hold a P-384 key");
    }
    // RFC 9052 §4.4: Sig_structure = ["Signature1", protected, external_aad, payload]
    const toBeSigned = encode(["Signature1", doc.protectedBytes, new Uint8Array(0), doc.payloadBytes]);
    ok = cryptoVerify("sha384", toBeSigned, { key: leaf.publicKey, dsaEncoding: "ieee-p1363" }, doc.signature);
  } catch (err) {
    return check("fail", "invalid_certificate_key", `the signing certificate's key is unusable: ${(err as Error).message}`);
  }
  return ok
    ? check("pass", "signature_valid", "COSE_Sign1 ES384 signature verifies under the signing certificate")
    : check("fail", "signature_invalid", "COSE_Sign1 signature does not verify — the payload or signature was altered");
}

function verifyDebug(doc: Decoded): NitroCheck {
  const zero = [0, 1, 2].every((i) => {
    const v = doc.pcrs.get(i);
    return v !== undefined && v.every((b) => b === 0);
  });
  return zero
    ? check("fail", "debug_enclave", "PCR0, PCR1 and PCR2 are all zero: the enclave was started in debug mode, so its memory is observable by the host")
    : check("pass", "not_debug", "PCR0–2 are non-zero");
}

function verifyPcrs(doc: Decoded, policy: NitroPcrPolicy | undefined): { pcrs: NitroCheck; pcr8: NitroCheck } {
  if (!policy) {
    return {
      pcrs: check("not_checked", "no_policy", "no expected-PCR policy was supplied"),
      pcr8: check("not_checked", "no_policy", "no expected-PCR policy was supplied"),
    };
  }
  const missing = [0, 1, 2].filter((i) => policy.pcrs[i] === undefined);
  if (missing.length > 0) {
    const c = check("unknown", "policy_incomplete", `policy ${policy.id}@${policy.version} does not pin PCR${missing.join(", PCR")}`);
    return { pcrs: c, pcr8: c };
  }
  let pcrs = check("pass", "pcrs_match", `pinned PCRs match policy ${policy.id}@${policy.version} (${policy.source})`);
  for (const [key, expected] of Object.entries(policy.pcrs)) {
    const index = Number(key);
    const actual = doc.pcrs.get(index);
    if (!actual) {
      pcrs = check("fail", "pcr_missing", `PCR${index} is pinned by policy but absent from the document`);
      break;
    }
    if (toHex(actual) !== expected.toLowerCase()) {
      pcrs = check("fail", "pcr_mismatch", `PCR${index} is ${toHex(actual).slice(0, 16)}…, policy expects ${expected.slice(0, 16)}…`);
      break;
    }
  }
  let pcr8: NitroCheck;
  if (policy.pcr8 === "not_applicable") {
    pcr8 = check("not_applicable", "image_not_signed", "policy states the enclave image is not signed; PCR8 is not compared");
  } else {
    const actual = doc.pcrs.get(8);
    pcr8 = !actual
      ? check("fail", "pcr_missing", "policy expects a signed image but PCR8 is absent")
      : toHex(actual) === policy.pcr8.toLowerCase()
        ? check("pass", "pcr8_match", "PCR8 matches the expected signing certificate")
        : check("fail", "pcr8_mismatch", "PCR8 does not match the expected image-signing certificate");
  }
  return { pcrs, pcr8 };
}

function verifyBinding(doc: Decoded, options: VerifyNitroOptions): { binding: NitroCheck; publicKey: NitroCheck } {
  const key = options.receiptKey;
  const mode = options.policy?.publicKey ?? "receipt-ed25519";
  if (!key) {
    const c = check("not_checked", "no_receipt_key", "no receipt key was supplied, so nothing binds this attestation to a signer");
    return { binding: c, publicKey: mode === "unused" ? check("not_applicable", "public_key_unused", "policy does not use public_key") : c };
  }
  const expected = keyBindingUserData(key.keyId, key.entry);
  const binding = !doc.userData
    ? check("fail", "user_data_absent", "user_data is absent, so the receipt key is not bound")
    : bytesEqual(doc.userData, expected)
      ? check("pass", "key_bound", `user_data binds receipt key ${key.keyId} (${KEY_BINDING_CONTEXT})`)
      : check("fail", "key_binding_mismatch", `user_data does not bind receipt key ${key.keyId}`);

  let publicKey: NitroCheck;
  if (mode === "unused") {
    publicKey = check("not_applicable", "public_key_unused", "policy reserves public_key for another protocol; user_data alone binds the key");
  } else {
    const spki = ed25519Spki(fromBase64Field(key.entry.ed25519_pub));
    publicKey = !doc.publicKey
      ? check("fail", "public_key_absent", "policy requires public_key to carry the receipt Ed25519 key")
      : bytesEqual(doc.publicKey, spki)
        ? check("pass", "public_key_match", "public_key is the receipt Ed25519 key")
        : check("fail", "public_key_mismatch", "public_key is not the receipt Ed25519 key");
  }
  return { binding, publicKey };
}

function verifyFreshness(doc: Decoded, options: VerifyNitroOptions, now: number): NitroCheck {
  const f = options.freshness;
  if (!f) return check("not_checked", "freshness_policy_absent", "no freshness policy was supplied");
  if (f.mode === "nonce") {
    if (!doc.nonce) return check("fail", "nonce_absent", "nonce mode was required but the document carries no nonce (no fallback to timestamp)");
    if (!bytesEqual(doc.nonce, f.expected)) return check("fail", "nonce_mismatch", "the document's nonce is not the challenge that was issued");
    const hex = toHex(doc.nonce);
    if (f.ledger?.has(hex)) return check("fail", "nonce_replayed", "this nonce was already consumed; the document is a replay");
    f.ledger?.add(hex);
    return check(
      "pass",
      "nonce_fresh",
      "the document binds the issued challenge",
      f.ledger ? undefined : "no nonce ledger supplied: replay of this exact challenge is not detected",
    );
  }
  const skew = f.clockSkewMs ?? 60_000;
  const age = now - doc.timestampMs;
  if (age < -skew) return check("fail", "timestamp_in_future", `the document is dated ${-age} ms in the future (skew allowance ${skew} ms)`);
  if (age > f.maxAgeMs) return check("fail", "attestation_stale", `the document is ${age} ms old; the policy allows ${f.maxAgeMs} ms`);
  return check(
    "pass",
    "within_window",
    `the document is ${Math.max(age, 0)} ms old (limit ${f.maxAgeMs} ms)`,
    "timestamp-window freshness is weaker than a nonce: it shows recency, not that this verifier's challenge was answered",
  );
}

/* ── entry point ──────────────────────────────────────────────────────── */

const REQUIRED: ReadonlyArray<keyof NitroChecks> = [
  "structure", "trust_root", "certificate_chain", "cose_signature", "debug_mode",
  "pcr_policy", "pcr8_signing", "key_binding", "public_key", "freshness",
];

function summarise(checks: NitroChecks): { overall: "pass" | "fail" | "unknown"; reasons: string[] } {
  const reasons: string[] = [];
  let overall: "pass" | "fail" | "unknown" = "pass";
  for (const name of REQUIRED) {
    const c = checks[name];
    if (c.status === "pass" || c.status === "not_applicable") continue;
    reasons.push(`${name}: ${c.reason}`);
    if (c.status === "fail") overall = "fail";
    else if (overall === "pass") overall = "unknown";
  }
  return { overall, reasons };
}

/**
 * Verify an attestation document entirely offline.
 *
 * Never throws for bad input: a malformed or hostile document produces a
 * report whose structure check failed. It throws only for programmer errors in
 * the options (for example a non-32-byte Ed25519 key in the receipt directory).
 */
export function verifyNitroAttestation(raw: Uint8Array, options: VerifyNitroOptions = {}): NitroAttestationReport {
  const bundle = options.trustBundle ?? AWS_NITRO_TRUST_BUNDLE;
  const now = options.now ?? Date.now();
  const documentSha256 = createHash("sha256").update(raw).digest("hex");
  const policyRef = options.policy
    ? { id: options.policy.id, version: options.policy.version, source: options.policy.source }
    : null;

  let doc: Decoded;
  try {
    doc = decodeDocument(raw, options.maxBytes ?? 16 * 1024);
  } catch (err) {
    if (!(err instanceof Malformed)) throw err;
    const skipped = check("not_checked", "structure_invalid", "not evaluated: the document did not decode");
    const checks: NitroChecks = {
      structure: check("fail", err.reason, err.message),
      trust_root: skipped, certificate_chain: skipped, cose_signature: skipped, debug_mode: skipped,
      pcr_policy: skipped, pcr8_signing: skipped, key_binding: skipped, public_key: skipped, freshness: skipped,
    };
    const { overall, reasons } = summarise(checks);
    return {
      schema: "cool.nitro.attestation-report.v1", parser: { name: "cool-nitro", version: "1" },
      overall_status: overall, document_sha256: documentSha256,
      trust_bundle: { id: bundle.id, version: bundle.version, root: null },
      policy: policyRef, claims: null, checks, reasons,
    };
  }

  const root = bundle.roots.find((r) => bytesEqual(r.der, doc.cabundle[0]!));
  let trustRoot: NitroCheck;
  if (!root) {
    trustRoot = check("fail", "untrusted_root", `cabundle[0] is not a root in bundle ${bundle.id}@${bundle.version}`);
  } else if (bundle.expiresAt && now > Date.parse(bundle.expiresAt)) {
    trustRoot = check("unknown", "trust_bundle_stale", `bundle ${bundle.id}@${bundle.version} was due for review by ${bundle.expiresAt}`);
  } else {
    trustRoot = check("pass", "root_pinned", `chains to ${root.name} (sha256 ${root.fingerprintSha256.slice(0, 16)}…) from ${bundle.id}@${bundle.version}`);
  }

  const certAt = options.certificateTime === "attestation-timestamp" ? doc.timestampMs : now;
  const certLabel = options.certificateTime === "attestation-timestamp"
    ? `the attestation timestamp ${new Date(doc.timestampMs).toISOString()}, not now`
    : `verification time ${new Date(now).toISOString()}`;
  const chain = verifyChain(doc, certAt, certLabel);
  const signature = verifyCoseSignature(doc);

  const verified = trustRoot.status === "pass" && chain.status === "pass" && signature.status === "pass";
  const why = "not evaluated: trust root, certificate chain and signature must all pass before claims are used";
  const pcr = verified ? verifyPcrs(doc, options.policy) : { pcrs: NOT_CHECKED(why), pcr8: NOT_CHECKED(why) };
  const bind = verified ? verifyBinding(doc, options) : { binding: NOT_CHECKED(why), publicKey: NOT_CHECKED(why) };

  const checks: NitroChecks = {
    structure: check("pass", "well_formed", "COSE_Sign1 ES384 with a well-formed attestation payload"),
    trust_root: trustRoot,
    certificate_chain: chain,
    cose_signature: signature,
    debug_mode: verified ? verifyDebug(doc) : NOT_CHECKED(why),
    pcr_policy: pcr.pcrs,
    pcr8_signing: pcr.pcr8,
    key_binding: bind.binding,
    public_key: bind.publicKey,
    freshness: verified ? verifyFreshness(doc, options, now) : NOT_CHECKED(why),
  };
  const { overall, reasons } = summarise(checks);
  const hexOrNull = (b: Uint8Array | null) => (b ? toHex(b) : null);
  return {
    schema: "cool.nitro.attestation-report.v1",
    parser: { name: "cool-nitro", version: "1" },
    overall_status: overall,
    document_sha256: documentSha256,
    trust_bundle: { id: bundle.id, version: bundle.version, root: root?.name ?? null },
    policy: policyRef,
    claims: {
      verified,
      module_id: doc.moduleId,
      timestamp_ms: doc.timestampMs,
      pcrs: Object.fromEntries([...doc.pcrs].map(([i, v]) => [i, toHex(v)])),
      public_key: hexOrNull(doc.publicKey),
      user_data: hexOrNull(doc.userData),
      nonce: hexOrNull(doc.nonce),
    },
    checks,
    reasons,
  };
}
