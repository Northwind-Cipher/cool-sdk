/**
 * CooL — Cryptographic Observability & On-chain Ledger.
 *
 * The default entry point. It gives you the high-level client, the independent
 * verifier, the typed error set, and the cryptographic primitives the evidence
 * model is built from. Everything advanced — the change-record model, direct
 * dstack clients, the quote/anchor/witness/policy machinery — lives behind
 * `cool-nwc/phala`.
 *
 *     import { CooL, verifyEvidence } from "cool-nwc";
 *
 * The SDK makes no network calls of its own and carries no telemetry.
 */

/* ── the client ──────────────────────────────────────────────────────── */
export { CooL } from "./client";
export type {
  AttestationConfig,
  CooLOptions,
  Environment,
  Evidence,
  EvidenceResult,
  RecordInput,
  SecurityConfig,
} from "./client";

/* ── the verifier ────────────────────────────────────────────────────── */
export {
  verifyEvidence,
  formatVerdict,
  domainOrder,
  withTrustedKeys,
} from "./verify";
export type {
  Verdict,
  VerdictCheck,
  VerdictChecks,
  VerdictSubject,
  VerifyOptions,
  DomainStatus,
} from "./verify";

/* ── record + verdict types ──────────────────────────────────────────── */
export type {
  ReceiptV2,
  VerdictV2,
  VerdictChecksV2,
  DomainCheckV2,
  DomainStatusV2,
  EvidenceCoreV1,
  EvidenceSubject,
  EvidenceCommitments,
  SoftwareIdentity,
  ChangeCoreV2,
  Measurement,
  QuoteEnvelope,
  RuntimeBlockV2,
  TeeVendor,
  RuntimeMode,
  GpuAttestationRef,
} from "./phala/types";

/* ── errors ──────────────────────────────────────────────────────────── */
export {
  CooLError,
  ConfigurationError,
  DstackUnavailableError,
  AttestationRequiredError,
  AttestationError,
  EvidenceError,
  ClosedError,
} from "./errors";
export type { CooLErrorCode } from "./errors";

/* ── cryptographic primitives ────────────────────────────────────────── */
export { canonicalCbor, jsonProjection } from "./canonical";
export { sha256Bytes, randomSalt, saltedCommit } from "./hash";
export { mhSha256, multihashFromDigest, multihashDigest, isMultihash } from "./multihash";
export { generateKeypair, directoryFromKeypair, mergeDirectories } from "./keys";
export { hybridSign, hybridVerify, SIGNATURE_ALG } from "./sign";
export {
  leafHash,
  nodeHash,
  merkleRoot,
  inclusionProof,
  verifyInclusion,
  consistencyProof,
  verifyConsistency,
} from "./merkle";
export { MemoryLog } from "./log-memory";
export type {
  Multihash,
  HexField,
  Base64Field,
  SignatureAlg,
  SignatureBlock,
  DirectoryEntry,
  KeyDirectory,
  KeyPair,
  STH,
  STHCore,
  Witness,
  Inclusion,
  RecordTime,
} from "./types";
