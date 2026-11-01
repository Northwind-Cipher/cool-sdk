/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The technology-neutral evidence envelope, `cool.envelope.v1`.
 *
 * One record shape for every module. The envelope says who (actor), what
 * (action on a resource), where it came from (source, provenance), when
 * (occurred vs observed), and carries a typed, versioned payload. It is built
 * on the same primitives as `cool.receipt.v2` — canonical CBOR, SHA-256
 * multihash, hybrid ML-DSA-65 + Ed25519 signatures, RFC 6962 inclusion — so
 * there is one cryptographic core, not two. Existing receipts are untouched.
 *
 * The pipeline is explicit, one step per function, so no call does more than
 * its name says:
 *
 *   createEnvelope → canonicalize → commit → signEnvelope → (publish) → verifyEnvelope
 *
 * The signed form carries the exact canonical bytes (`core_cbor`). The
 * verifier checks that those bytes decode to the stated core AND re-encode to
 * themselves, so a non-canonical or ambiguous encoding is caught rather than
 * normalised away.
 */
import { createHash } from "node:crypto";
import { decode } from "cbor2";
import { canonicalCbor } from "../canonical";
import { bytesEqual, concatBytes, fromBase64, toBase64, utf8 } from "../codec";
import { leafHash, verifyInclusion } from "../merkle";
import { isMultihash, mhSha256, multihashDigest } from "../multihash";
import { sthCore, sthSigningMessage } from "../record";
import { hybridSign, hybridVerify } from "../sign";
import { ulid } from "../phala/ulid";
import { CooLError } from "../errors";
import type { KeyDirectory, KeyPair, Multihash, SignatureBlock, STH } from "../types";
import { verifyNitroAttestation, type VerifyNitroOptions } from "../nitro/attestation";
import { usableAlgorithm } from "./algorithms";
import type { PayloadRegistry } from "./payloads";
import { check, overallOf, type Check, type OverallStatus } from "./status";
import type { KeyPurpose, TrustStore } from "./trust";

export const ENVELOPE_SCHEMA = "cool.envelope.v1";
const DIGEST_DOMAIN = utf8("cool.envelope.v1\0");
const SIGNATURE_DOMAIN = utf8("cool.envelope.sig.v1\0");

export type ActorType = "human" | "workload" | "service" | "unknown";
export type CollectionMethod = "emitted" | "observed" | "imported" | "derived";

export interface EnvelopeInput {
  readonly event_type: string;
  /** Defaults to the registry's current schema for the event type. */
  readonly payload_schema?: string;
  readonly occurred_at: string;
  /** When CooL saw it. Defaults to now. */
  readonly observed_at?: string;
  readonly source: { readonly system: string; readonly instance?: string; readonly event_id?: string };
  readonly actor: { readonly id: string; readonly type: ActorType; readonly issuer?: string };
  readonly action: string;
  readonly resource: { readonly type: string; readonly ref: string };
  readonly payload: Readonly<Record<string, unknown>>;
  readonly provenance?: { readonly collection_method: CollectionMethod; readonly refs?: readonly Multihash[] };
  readonly relations?: ReadonlyArray<{ readonly type: string; readonly ref: Multihash }>;
  readonly policy?: { readonly policy_id: string; readonly policy_version: string; readonly decision: string; readonly decision_ref: Multihash };
  readonly sequence?: { readonly epoch: number; readonly number: number };
  /** Attestation document this evidence relies on (raw bytes); referenced by digest. */
  readonly attestation?: { readonly platform: "aws-nitro"; readonly document: Uint8Array };
  /** Override the generated id (deterministic tests, idempotent retries). */
  readonly event_id?: string;
}

export interface EnvelopeCore {
  readonly schema: typeof ENVELOPE_SCHEMA;
  readonly event_id: string;
  readonly event_type: string;
  readonly payload_schema: string;
  readonly occurred_at: string;
  readonly observed_at: string;
  readonly source: EnvelopeInput["source"];
  readonly actor: EnvelopeInput["actor"];
  readonly action: string;
  readonly resource: EnvelopeInput["resource"];
  readonly provenance: { readonly collection_method: CollectionMethod; readonly refs: readonly Multihash[] };
  readonly relations: ReadonlyArray<{ readonly type: string; readonly ref: Multihash }>;
  readonly policy?: EnvelopeInput["policy"];
  readonly sequence?: EnvelopeInput["sequence"];
  readonly attestation_ref?: string;
  readonly payload: Readonly<Record<string, unknown>>;
}

export interface Checkpoint {
  readonly sth: STH;
  readonly leaf_index: number;
  readonly audit_path: readonly Multihash[];
}

export interface SignedEnvelope {
  readonly format: "cool.signed-envelope.v1";
  readonly core: EnvelopeCore;
  readonly encoding: "cbor-cde";
  /** base64 of the exact canonical bytes that were committed. */
  readonly core_cbor: string;
  readonly digest_alg: "sha-256";
  readonly digest: Multihash;
  readonly signatures: readonly SignatureBlock[];
  readonly key_directory: KeyDirectory;
  readonly checkpoint?: Checkpoint;
  readonly attestation?: { readonly platform: "aws-nitro"; readonly document: string };
}

/** Remove undefined members so canonical CBOR never sees them. */
function clean<T>(value: T): T {
  if (Array.isArray(value)) return value.map(clean) as T;
  if (value && typeof value === "object" && !(value instanceof Uint8Array)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) if (v !== undefined) out[k] = clean(v);
    return out as T;
  }
  return value;
}

/** Build and validate an unsigned core. Throws COOL_EVIDENCE_INVALID on bad input. */
export function createEnvelope(input: EnvelopeInput, registry: PayloadRegistry, now: () => Date = () => new Date()): EnvelopeCore {
  const schemaId = input.payload_schema ?? registry.schemaFor(input.event_type);
  if (!schemaId) throw new CooLError("COOL_EVIDENCE_INVALID", `no payload schema for event type ${input.event_type}`, { action: "register a schema or use a known event type" });
  const schema = registry.get(schemaId);
  if (!schema || schema.event_type !== input.event_type) {
    throw new CooLError("COOL_EVIDENCE_INVALID", `payload schema ${schemaId} does not describe ${input.event_type}`);
  }
  const problems = registry.validate(schemaId, input.payload);
  if (problems.length) throw new CooLError("COOL_EVIDENCE_INVALID", `invalid ${input.event_type} payload: ${problems.join("; ")}`);
  for (const t of [input.occurred_at, input.observed_at].filter(Boolean) as string[]) {
    if (Number.isNaN(Date.parse(t))) throw new CooLError("COOL_EVIDENCE_INVALID", `not an ISO-8601 time: ${t}`);
  }
  for (const ref of [...(input.provenance?.refs ?? []), ...(input.relations ?? []).map((x) => x.ref)]) {
    if (!isMultihash(ref)) throw new CooLError("COOL_EVIDENCE_INVALID", `reference ${ref} is not a digest`);
  }
  return clean({
    schema: ENVELOPE_SCHEMA,
    event_id: input.event_id ?? ulid(),
    event_type: input.event_type,
    payload_schema: schemaId,
    occurred_at: input.occurred_at,
    observed_at: input.observed_at ?? now().toISOString(),
    source: input.source,
    actor: input.actor,
    action: input.action,
    resource: input.resource,
    provenance: { collection_method: input.provenance?.collection_method ?? "emitted", refs: [...(input.provenance?.refs ?? [])] },
    relations: [...(input.relations ?? [])],
    policy: input.policy,
    sequence: input.sequence,
    attestation_ref: input.attestation ? createHash("sha256").update(input.attestation.document).digest("hex") : undefined,
    payload: input.payload,
  } as EnvelopeCore);
}

/** The exact bytes that are committed and signed. */
export function canonicalize(core: EnvelopeCore): Uint8Array {
  return canonicalCbor(core);
}

/** SHA-256 multihash over the domain label and the canonical bytes. */
export function commit(coreCbor: Uint8Array): Multihash {
  return mhSha256(concatBytes(DIGEST_DOMAIN, coreCbor));
}

function signatureMessage(digest: Multihash): Uint8Array {
  return concatBytes(SIGNATURE_DOMAIN, multihashDigest(digest));
}

/**
 * Anything that can produce a hybrid signature: an in-memory keypair, or a
 * KMS/HSM-backed provider that never exposes the private key. Only
 * `localSigner` ships; a remote provider implements this interface.
 */
export interface Signer {
  readonly keyId: string;
  readonly directoryEntry: KeyPair["directoryEntry"];
  sign(message: Uint8Array): SignatureBlock;
}

export function localSigner(key: KeyPair): Signer {
  return { keyId: key.keyId, directoryEntry: key.directoryEntry, sign: (m) => hybridSign(m, key) };
}

const asSigner = (k: Signer | KeyPair): Signer => ("sign" in k && typeof k.sign === "function" ? k : localSigner(k as KeyPair));

/** Sign a core with one or more keys. Pure: no network, no storage. */
export function signEnvelope(core: EnvelopeCore, keys: Signer | KeyPair | ReadonlyArray<Signer | KeyPair>, attestation?: EnvelopeInput["attestation"]): SignedEnvelope {
  const list = (Array.isArray(keys) ? keys : [keys]).map(asSigner);
  if (list.length === 0) throw new CooLError("COOL_CRYPTOGRAPHY_FAILED", "at least one signing key is required");
  if (attestation && createHash("sha256").update(attestation.document).digest("hex") !== core.attestation_ref) {
    throw new CooLError("COOL_EVIDENCE_INVALID", "the attestation document is not the one the core references");
  }
  const bytes = canonicalize(core);
  const digest = commit(bytes);
  const message = signatureMessage(digest);
  return clean({
    format: "cool.signed-envelope.v1",
    core,
    encoding: "cbor-cde",
    core_cbor: toBase64(bytes),
    digest_alg: "sha-256",
    digest,
    signatures: list.map((k) => k.sign(message)),
    key_directory: Object.fromEntries(list.map((k) => [k.keyId, k.directoryEntry])),
    attestation: attestation ? { platform: attestation.platform, document: toBase64(attestation.document) } : undefined,
  } as SignedEnvelope);
}

/** Attach a transparency checkpoint (from a log the caller published to). */
export function withCheckpoint(env: SignedEnvelope, checkpoint: Checkpoint): SignedEnvelope {
  return { ...env, checkpoint };
}

/** The leaf a log stores for an envelope: its 32-byte digest. */
export function envelopeLeaf(env: Pick<SignedEnvelope, "digest">): Uint8Array {
  return multihashDigest(env.digest);
}

/** Read an envelope WITHOUT verifying it. The result says so. */
export function inspectEnvelope(env: SignedEnvelope): { readonly verified: false; readonly notice: string; readonly core: EnvelopeCore } {
  return { verified: false, notice: "inspection only — nothing here has been verified", core: env.core };
}

/* ── verification ─────────────────────────────────────────────────────── */

export interface EnvelopeChecks {
  readonly schema_valid: Check;
  readonly canonical_encoding_valid: Check;
  readonly digest_valid: Check;
  readonly signature_valid: Check;
  readonly signer_trusted: Check;
  readonly signer_authorized: Check;
  readonly timestamp_valid: Check;
  readonly inclusion_proof_valid: Check;
  readonly checkpoint_trusted: Check;
  readonly attestation_valid: Check;
  readonly evidence_complete: Check;
}

export interface VerificationReport {
  readonly schema: "cool.verification-report.v1";
  readonly subject: { readonly event_id: string; readonly event_type: string; readonly digest: string } | null;
  readonly overall_status: OverallStatus;
  readonly checks: EnvelopeChecks;
  readonly reasons: readonly string[];
  readonly verified_at: string;
}

export interface VerifyEnvelopeOptions {
  readonly registry: PayloadRegistry;
  readonly trust: TrustStore;
  /** Purpose the signer must be trusted for. Default "evidence". */
  readonly purpose?: KeyPurpose | ((eventType: string) => KeyPurpose);
  readonly now?: number;
  readonly clockSkewMs?: number;
  /** Fail when there is no checkpoint. Default false (inclusion is then not_checked). */
  readonly requireCheckpoint?: boolean;
  readonly maxCheckpointAgeMs?: number;
  readonly witnessThreshold?: number;
  readonly requireAttestation?: boolean;
  /** Options for an attached Nitro attestation; receiptKey is filled in from the signer. */
  readonly nitro?: Omit<VerifyNitroOptions, "receiptKey">;
  /** Authorization is a policy question; supply it to have signer_authorized evaluated. */
  readonly authorize?: (core: EnvelopeCore, signerKeyId: string) => Check;
  /** Resolve a referenced digest; supply it to have evidence_complete evaluated. */
  readonly resolve?: (ref: Multihash) => boolean;
}

const NC = (why: string) => check("not_checked", "prerequisite_failed", why);

export function verifyEnvelope(env: SignedEnvelope, options: VerifyEnvelopeOptions): VerificationReport {
  const now = options.now ?? Date.now();
  const skew = options.clockSkewMs ?? 5 * 60_000;
  const verified_at = new Date(now).toISOString();
  const core = env?.core;

  // schema
  let schema: Check;
  if (env?.format !== "cool.signed-envelope.v1" || core?.schema !== ENVELOPE_SCHEMA) {
    schema = check("fail", "unsupported_schema", `not a ${ENVELOPE_SCHEMA} signed envelope`);
  } else {
    const ps = options.registry.get(core.payload_schema);
    const problems = !ps ? [`unknown payload schema ${core.payload_schema}`]
      : ps.event_type !== core.event_type ? [`payload schema ${core.payload_schema} is not for ${core.event_type}`]
        : options.registry.validate(core.payload_schema, core.payload);
    schema = problems.length
      ? check("fail", "payload_invalid", problems.join("; "), { algorithm: core.payload_schema })
      : check("pass", "schema_valid", `${ENVELOPE_SCHEMA} with payload ${core.payload_schema}`, { algorithm: core.payload_schema });
  }
  if (schema.status === "fail") {
    const skipped = NC("not evaluated: the envelope schema is invalid");
    const checks: EnvelopeChecks = {
      schema_valid: schema, canonical_encoding_valid: skipped, digest_valid: skipped, signature_valid: skipped,
      signer_trusted: skipped, signer_authorized: skipped, timestamp_valid: skipped, inclusion_proof_valid: skipped,
      checkpoint_trusted: skipped, attestation_valid: skipped, evidence_complete: skipped,
    };
    return { schema: "cool.verification-report.v1", subject: null, overall_status: "fail", checks, reasons: [`schema_valid: ${schema.reason}`], verified_at };
  }

  // canonical encoding
  let bytes: Uint8Array | null = null;
  let canonical: Check;
  try {
    bytes = fromBase64(env.core_cbor);
    const decoded = decode(bytes, { rejectDuplicateKeys: true });
    canonical = !bytesEqual(canonicalCbor(decoded), bytes)
      ? check("fail", "non_canonical_encoding", "core_cbor is not in deterministic (CDE) form", { algorithm: "cbor-cde" })
      : !bytesEqual(canonicalize(core), bytes)
        ? check("fail", "core_mismatch", "the readable core does not match the committed bytes", { algorithm: "cbor-cde" })
        : check("pass", "canonical", "committed bytes are canonical and match the core", { algorithm: "cbor-cde" });
  } catch (err) {
    canonical = check("fail", "malformed_encoding", `core_cbor did not decode: ${(err as Error).message}`);
  }

  // digest
  const digest = canonical.status !== "pass" || !bytes ? NC("not evaluated: encoding check failed")
    : env.digest_alg !== "sha-256" || !usableAlgorithm(env.digest_alg, "digest") ? check("fail", "unsupported_algorithm", `digest algorithm ${String(env.digest_alg)} is not accepted`)
      : commit(bytes) === env.digest ? check("pass", "digest_matches", env.digest, { algorithm: "sha-256", evidence_ref: env.digest })
        : check("fail", "digest_mismatch", "recomputed digest differs from the stated digest", { algorithm: "sha-256" });

  // signatures
  let signature: Check;
  const validSigners: string[] = [];
  if (digest.status !== "pass") signature = NC("not evaluated: digest check failed");
  else if (!env.signatures?.length) signature = check("fail", "unsigned", "the envelope carries no signature");
  else {
    const failures: string[] = [];
    for (const sig of env.signatures) {
      if (!usableAlgorithm(sig.alg, "signature")) { failures.push(`${sig.key_id}: unsupported algorithm ${sig.alg}`); continue; }
      const entry = env.key_directory?.[sig.key_id];
      if (!entry) { failures.push(`${sig.key_id}: public key not carried`); continue; }
      if (hybridVerify(signatureMessage(env.digest), sig, entry).ok) validSigners.push(sig.key_id);
      else failures.push(`${sig.key_id}: does not verify`);
    }
    signature = failures.length
      ? check("fail", "signature_invalid", failures.join("; "), { algorithm: "ml-dsa-65+ed25519" })
      : check("pass", "signature_valid", `verified for ${validSigners.join(", ")}`, { algorithm: "ml-dsa-65+ed25519" });
  }

  // checkpoint and inclusion (before trust: a trusted checkpoint proves signing time)
  let inclusion: Check;
  let checkpoint: Check;
  let provenBefore: number | undefined;
  const cp = env.checkpoint;
  if (!cp) {
    const status = options.requireCheckpoint ? "fail" : "not_checked";
    inclusion = check(status, options.requireCheckpoint ? "checkpoint_required" : "no_checkpoint", "the envelope carries no transparency checkpoint");
    checkpoint = check(status, options.requireCheckpoint ? "checkpoint_required" : "no_checkpoint", "the envelope carries no transparency checkpoint");
  } else if (digest.status !== "pass") {
    inclusion = NC("not evaluated: digest check failed");
    checkpoint = NC("not evaluated: digest check failed");
  } else {
    let included = false;
    try {
      included = verifyInclusion(leafHash(envelopeLeaf(env)), cp.leaf_index, cp.sth.tree_size, cp.audit_path.map(multihashDigest), multihashDigest(cp.sth.root_hash));
    } catch { included = false; }
    inclusion = included
      ? check("pass", "included", `leaf ${cp.leaf_index} of ${cp.sth.tree_size} in ${cp.sth.log_id}`, { algorithm: "rfc6962-sha-256" })
      : check("fail", "inclusion_invalid", "the audit path does not lead to the checkpoint root", { algorithm: "rfc6962-sha-256" });

    const logKey = options.trust.get(cp.sth.signature.key_id);
    const sthOk = !!logKey && hybridVerify(sthSigningMessage(sthCore(cp.sth)), cp.sth.signature, logKey.entry).ok;
    const logTrust = options.trust.evaluate({ keyId: cp.sth.signature.key_id, purpose: "log", now });
    const age = now - Date.parse(cp.sth.timestamp);
    const witnessKeys = cp.sth.witnesses.filter((w) => {
      const rec = options.trust.get(w.id);
      if (!w.external || !rec || options.trust.evaluate({ keyId: w.id, purpose: "witness", now }).status !== "pass") return false;
      return hybridVerify(sthSigningMessage(sthCore(cp.sth)), { alg: w.alg, key_id: w.id, ml_dsa: w.ml_dsa, ed25519: w.ed25519 }, rec.entry).ok;
    });
    const need = options.witnessThreshold ?? 0;
    if (!sthOk) checkpoint = check("fail", "checkpoint_signature_invalid", `tree head signature by ${cp.sth.signature.key_id} does not verify against the trusted key`);
    else if (logTrust.status !== "pass") checkpoint = check(logTrust.status === "unknown" ? "unknown" : "fail", logTrust.reason, logTrust.detail);
    else if (options.maxCheckpointAgeMs !== undefined && age > options.maxCheckpointAgeMs) checkpoint = check("unknown", "checkpoint_stale", `checkpoint is ${age} ms old (limit ${options.maxCheckpointAgeMs})`);
    else if (witnessKeys.length < need) checkpoint = check("fail", "insufficient_witnesses", `${witnessKeys.length} trusted witness signature(s), ${need} required`);
    else {
      checkpoint = check("pass", "checkpoint_trusted", `tree head ${cp.sth.tree_size} signed by trusted log key; ${witnessKeys.length} trusted witness(es)`, {
        limitation: "a trusted checkpoint shows what the log committed to, not that every event was logged",
      });
      if (inclusion.status === "pass") provenBefore = Date.parse(cp.sth.timestamp);
    }
  }

  // signer trust (separate from signature validity)
  const purposeOpt = options.purpose ?? "evidence";
  const purpose = typeof purposeOpt === "function" ? purposeOpt(core.event_type) : purposeOpt;
  let trusted: Check;
  if (signature.status !== "pass") trusted = NC("not evaluated: no valid signature");
  else {
    const results = validSigners.map((id) => options.trust.evaluate({ keyId: id, purpose, now, claimedSignedAt: Date.parse(core.observed_at), ...(provenBefore !== undefined ? { provenSignedBefore: provenBefore } : {}) }));
    trusted = results.find((c) => c.status === "fail") ?? results.find((c) => c.status === "unknown") ?? results[0]!;
  }

  const authorized = !options.authorize ? check("not_checked", "no_policy_context", "authorization needs policy context; none supplied")
    : trusted.status !== "pass" ? NC("not evaluated: signer not trusted")
      : options.authorize(core, validSigners[0]!);

  // timestamps
  const occurred = Date.parse(core.occurred_at);
  const observed = Date.parse(core.observed_at);
  const timeLimit = "event-reported and collector-observed times only; no RFC 3161 trusted timestamp (not implemented)";
  const timestamp = Number.isNaN(occurred) || Number.isNaN(observed) ? check("fail", "invalid_time", "unparseable time field")
    : occurred > observed + skew ? check("fail", "occurred_after_observed", `occurred_at ${core.occurred_at} is after observed_at ${core.observed_at}`)
      : observed > now + skew ? check("fail", "time_in_future", `observed_at ${core.observed_at} is in the future`)
        : cp && checkpoint.status === "pass" && observed > Date.parse(cp.sth.timestamp) + skew ? check("fail", "observed_after_checkpoint", "observed_at is later than the checkpoint that includes it")
          : check("pass", "times_consistent", "occurred ≤ observed ≤ now (within skew)", { limitation: timeLimit });

  // attestation
  let attestation: Check;
  if (!env.attestation) {
    attestation = options.requireAttestation ? check("fail", "attestation_required", "attestation is required but absent") : check("not_applicable", "no_attestation", "the envelope does not rely on attestation");
  } else if (signature.status !== "pass") {
    attestation = NC("not evaluated: no valid signature");
  } else {
    const doc = fromBase64(env.attestation.document);
    const ref = createHash("sha256").update(doc).digest("hex");
    if (ref !== core.attestation_ref) attestation = check("fail", "attestation_not_bound", "the attached document is not the one the signed core references");
    else {
      const signer = validSigners[0]!;
      const report = verifyNitroAttestation(doc, { ...(options.nitro ?? {}), receiptKey: { keyId: signer, entry: env.key_directory[signer]! } });
      attestation = check(report.overall_status === "pass" ? "pass" : report.overall_status, report.overall_status === "pass" ? "attestation_valid" : "attestation_not_valid", report.reasons.join("; ") || "all Nitro checks passed", { evidence_ref: report.document_sha256, algorithm: report.parser.name + "/" + report.parser.version });
    }
  }

  // completeness
  const refs = [...core.provenance.refs, ...core.relations.map((x) => x.ref)];
  let complete: Check;
  if (!options.resolve) complete = check("not_checked", "no_resolver", "no evidence store supplied to resolve references");
  else {
    const missing = refs.filter((ref) => !options.resolve!(ref));
    complete = missing.length ? check("fail", "missing_evidence", `missing: ${missing.join(", ")}`) : check("pass", "references_resolved", `${refs.length} reference(s) resolved`);
  }

  const checks: EnvelopeChecks = {
    schema_valid: schema, canonical_encoding_valid: canonical, digest_valid: digest, signature_valid: signature,
    signer_trusted: trusted, signer_authorized: authorized, timestamp_valid: timestamp, inclusion_proof_valid: inclusion,
    checkpoint_trusted: checkpoint, attestation_valid: attestation, evidence_complete: complete,
  };
  const required = ["schema_valid", "canonical_encoding_valid", "digest_valid", "signature_valid", "signer_trusted", "timestamp_valid", "attestation_valid"];
  if (cp || options.requireCheckpoint) required.push("inclusion_proof_valid", "checkpoint_trusted");
  if (options.authorize) required.push("signer_authorized");
  if (options.resolve) required.push("evidence_complete");
  const { overall, reasons } = overallOf(checks as unknown as Record<string, Check>, required);
  return {
    schema: "cool.verification-report.v1",
    subject: { event_id: core.event_id, event_type: core.event_type, digest: env.digest },
    overall_status: overall,
    checks,
    reasons,
    verified_at,
  };
}
