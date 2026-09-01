/**
 * `cool.receipt.v2` — the CooL receipt envelope.
 *
 * A receipt carries a signed record core, its binding commitment, an optional
 * RFC 6962 inclusion proof + signed tree head, an attestation block, an optional
 * public-chain anchor, and the key directory needed to verify all of it offline.
 *
 * Two record cores share this envelope, the signing rules, the log and the
 * verifier:
 *
 *   • `cool.evidence.v1` — a generic execution-evidence record: an event type,
 *     a salted commitment to its metadata, and optional salted commitments to
 *     sensitive input / output / state. This is the primary record the SDK
 *     produces. It never carries raw application data.
 *   • `cool.change.v2` — a change someone made to an AI system (a prompt edit,
 *     a model bump, a widened agent permission), with a governance decision
 *     sealed alongside it.
 *
 * Three properties a verifier can check with no access to CooL, Phala, or the
 * customer:
 *
 *   1. WHERE it ran   — the enclave measurement (MRTD + RTMRs) is inside the
 *                       signed core, so it cannot be swapped after the fact.
 *   2. WHO signed it  — the quote's `report_data` commits to the very public key
 *                       the record is signed with, so "an attested enclave holds
 *                       this key" and "this key signed this record" are one chain
 *                       rather than two adjacent assertions.
 *   3. WHICH workload  — the software identity and optional GPU attestation
 *                       reference carried in the record.
 *
 * Honesty rule, enforced by the verifier: a domain is
 * only ever `pass` when it was actually checked against a hardware root of trust.
 * A record produced against the built-in simulator reports `simulated` — never
 * `pass` — everywhere it matters. `simulated` is a real signature over a real
 * quote structure with a real key-binding; what it is missing is Intel/AMD/NVIDIA
 * as the root. That distinction is the whole point, so it is never blurred.
 */
import type {
  Base64Field,
  HexField,
  Inclusion,
  KeyDirectory,
  Multihash,
  RecordTime,
  SignatureBlock,
  STH,
} from "../types";

/* ── hardware identity ────────────────────────────────────────────────── */

/** The silicon a record was produced on. `none` means no TEE was involved. */
export type TeeVendor = "none" | "intel-tdx" | "amd-sev-snp" | "nvidia-cc";

/**
 * How much of the attestation path was real.
 * - `hardware`  — a vendor quote was produced by real silicon.
 * - `simulated` — the built-in simulator produced a structurally complete quote
 *                 under a CooL-held root. Useful for tests, demos and CI; it is
 *                 NOT evidence of confidentiality and is never reported as one.
 * - `mock`      — no attestation path at all (what v1 always was).
 */
export type RuntimeMode = "mock" | "simulated" | "hardware";

/** Which authority a quote chains to. `cool-sim-root` is explicitly not a vendor. */
export type AttestationRoot = "intel-dcap" | "amd-kds" | "nvidia-nras" | "cool-sim-root" | "none";

/** Wire format of the attached quote. */
export type QuoteFormat = "dstack.tdx.v4" | "dstack.sevsnp.v1" | "nvidia.cc.v1" | "cool.sim.v1";

/**
 * A TDX-shaped measurement set.
 *
 * `mrtd` is the build-time measurement of the TD image — it changes if a single
 * byte of the deployed image changes. The RTMRs are runtime-extended registers
 * (dstack extends them with the app-compose digest, the instance identity, and
 * the event log). Both halves are pinned by the customer, which is what makes
 * "unmodified CooL code" a checkable statement rather than a promise.
 */
export interface Measurement {
  readonly mrtd: HexField;
  readonly rtmr0: HexField;
  readonly rtmr1: HexField;
  readonly rtmr2: HexField;
  readonly rtmr3: HexField;
}

/** The attested body of a quote: what the silicon (or the simulator) signs. */
export interface QuoteBody {
  readonly vendor: TeeVendor;
  readonly measurement: Measurement;
  /**
   * The 64 bytes of user data the TD asks the hardware to bind into the quote.
   * CooL always fills it with a commitment to the enclave's signing identity —
   * see {@link enclaveReportData}. Recomputing it from `key_directory` is what
   * proves the signing key never left the measured code.
   */
  readonly report_data: Multihash;
  /** Vendor TCB evaluation, verbatim (e.g. `UpToDate`, `SWHardeningNeeded`). */
  readonly tcb_status: string;
  /** dstack application id — stable across restarts and upgrades. */
  readonly app_id: string;
  /** dstack instance id — this particular CVM. */
  readonly instance_id: string;
  readonly issued_at: string;
}

/**
 * A quote plus everything needed to check it offline.
 *
 * On hardware, `raw` carries the vendor-native quote bytes and `signature` is
 * null — the bytes are verified against Intel DCAP / AMD KDS / NVIDIA NRAS
 * collateral by a {@link QuoteVerifier}, not by us. In the simulator the
 * relationship inverts: `raw` is null and `signature` is a hybrid signature over
 * the canonical body, made by the simulator's root key.
 */
export interface QuoteEnvelope {
  readonly format: QuoteFormat;
  readonly root: AttestationRoot;
  readonly body: QuoteBody;
  readonly signature: SignatureBlock | null;
  readonly raw: Base64Field | null;
}

/** A reference to a confidential-GPU attestation for the workload itself. */
export interface GpuAttestationRef {
  readonly vendor: "nvidia-cc";
  /** e.g. `H200`, `H100`, `B300`. */
  readonly gpu_model: string;
  /** Commitment to the NRAS evidence bundle (the bundle itself is large). */
  readonly evidence_hash: Multihash;
  /** What the attestation service said. `simulated` when no NRAS was contacted. */
  readonly verdict: "verified" | "unverified" | "simulated";
}

/**
 * The v2 runtime block. Unlike v1's frozen `mock` shape, this is part of the
 * signed core AND carries real values — so an attacker cannot re-label a record
 * as "produced in a TEE" without breaking the signature.
 *
 * `tee_quote` is a hash rather than the quote itself: the core stays small, and
 * because the hash is inside the signed bytes the quote in the receipt envelope
 * is still covered by the record signature (Build Plan §4).
 */
export interface RuntimeBlockV2 {
  readonly tee_vendor: TeeVendor;
  readonly mode: RuntimeMode;
  readonly enclave_measurement: Measurement | null;
  readonly tee_quote: Multihash | null;
  readonly gpu: GpuAttestationRef | null;
}

/* ── record cores ─────────────────────────────────────────────────────── */

/** Software identity for the workload that produced a record. */
export interface SoftwareIdentity {
  readonly name: string;
  readonly version: string;
  /** Content digest of the workload artefact (image, bundle, model), if known. */
  readonly digest: Multihash | null;
}

/**
 * Salted commitments to sensitive payloads that stay in the caller's
 * environment. Each is `mh:sha256(salt ‖ bytes)` with the salt stored beside
 * it, so an auditor can later be shown the value and check it against the
 * sealed record. All optional — a record may commit to none of them.
 */
export interface EvidenceCommitments {
  readonly input: Multihash | null;
  readonly input_salt: HexField | null;
  readonly output: Multihash | null;
  readonly output_salt: HexField | null;
  readonly state: Multihash | null;
  readonly state_salt: HexField | null;
}

/** The substance of a generic evidence record: what happened, described in metadata. */
export interface EvidenceSubject {
  /**
   * A dotted event type, e.g. `model.execution`, `agent.action`,
   * `artifact.created`, `policy.decision`, or an application-defined string.
   */
  readonly type: string;
  /** The application that produced the evidence. */
  readonly application_id: string;
  /** Stable id for the run / session / request this evidence belongs to. */
  readonly execution_id: string;
  /** Salted commitment to the canonical CBOR of the caller's metadata object. */
  readonly metadata_hash: Multihash;
  readonly metadata_salt: HexField;
  /** Optional salted commitments to sensitive input / output / state. */
  readonly commitments: EvidenceCommitments;
  /** Identity of the software that produced this evidence, if declared. */
  readonly software: SoftwareIdentity | null;
}

/**
 * A generic execution-evidence record (`cool.evidence.v1`).
 *
 * The primary record the SDK produces. It commits to an event type and to a
 * salted hash of the caller's metadata; it never carries raw application data.
 * It shares the envelope, the signing rules, the transparency log and the
 * verifier with change records.
 */
export interface EvidenceCoreV1 {
  readonly schema: "cool.evidence.v1";
  readonly record_id: string;
  readonly time: RecordTime;
  readonly event: EvidenceSubject;
  readonly runtime: RuntimeBlockV2;
}

/** What kind of AI change a change record describes. */
export type ChangeKind =
  | "prompt"
  | "model"
  | "params"
  | "policy"
  | "dataset"
  | "agent-permission"
  | "tool";

/** How the change reached production — the actor, not the author. */
export interface ChangeActor {
  /** e.g. `ci:github-actions`, `user:priya@bank.example`, `agent:refund-bot`. */
  readonly id: string;
  /** e.g. `oidc`, `session`, `service-account`. */
  readonly method: string;
}

/** The governance decision attached to a change, if the policy engine produced one. */
export interface ChangeApproval {
  readonly policy_id: string;
  readonly decision: "auto-approved" | "approved" | "rejected" | "waived";
  readonly approvers: readonly string[];
}

/** The substance of a change record: what moved, from what, to what. */
export interface ChangeSubject {
  readonly kind: ChangeKind;
  /** Stable path of the thing that changed, e.g. `billing/refund-agent#system`. */
  readonly ref: string;
  readonly environment: string;
  /** Salted commitment to the previous value; null for a first write. */
  readonly before_hash: Multihash | null;
  readonly before_salt: HexField | null;
  readonly after_hash: Multihash;
  /**
   * Salts are stored alongside their commitments so an auditor can later be
   * shown the prompt itself and check it against the sealed record. Without
   * them a short, low-entropy value (a temperature, a one-line system prompt)
   * would be guessable from its hash.
   */
  readonly after_salt: HexField;
  /** Commitment to the unified diff — lets an auditor be shown the diff later. */
  readonly diff_hash: Multihash;
  readonly actor: ChangeActor;
  readonly approval: ChangeApproval | null;
}

/**
 * A change record (`cool.change.v2`).
 *
 * The prompt edit, the model bump, the loosened agent permission. It shares the
 * envelope, the signing rules, the log and the verifier with evidence records,
 * so a single transparency log covers "what the system did" and "what we
 * changed about it".
 */
export interface ChangeCoreV2 {
  readonly schema: "cool.change.v2";
  readonly record_id: string;
  readonly time: RecordTime;
  readonly change: ChangeSubject;
  readonly runtime: RuntimeBlockV2;
}

/** Either flavour of core. Both hash, sign, log and verify identically. */
export type RecordCoreV2 = EvidenceCoreV1 | ChangeCoreV2;

/** A v2 core plus its detached hybrid signature. */
export type SignedRecordV2 = RecordCoreV2 & { readonly signature: SignatureBlock };

/* ── receipt envelope ─────────────────────────────────────────────────── */

/**
 * The v2 attestation block. Carries the full quote (hashed into the signed core)
 * plus the measurement the deployment pinned, so a verifier can answer both
 * "is this quote real?" and "is it the code I approved?".
 */
export interface AttestationV2 {
  readonly mode: RuntimeMode;
  readonly note: string;
  readonly quote: QuoteEnvelope | null;
  /** The measurement the operator committed to before any data flowed. */
  readonly expected_measurement: Measurement | null;
  /** Recomputable commitment to the signing identity — see {@link QuoteBody.report_data}. */
  readonly key_binding: Multihash | null;
}

/**
 * A public-chain anchor for a tree head.
 *
 * Every other proof in a receipt is signed by someone, and a signature can be
 * made at any time by whoever holds the key. This one cannot: if the head is
 * committed inside a Bitcoin block, it existed before that block was mined, and
 * no later key compromise changes that.
 *
 * The proof is a detached OpenTimestamps file, base64-encoded — byte-identical
 * to what the `ots` tool writes, so an auditor can extract it and run
 * `ots verify` without any CooL code.
 */
export interface AnchorProof {
  readonly kind: "opentimestamps";
  readonly chain: "bitcoin";
  /** The tree head root this proof is about. Must match the receipt's STH. */
  readonly target: Multihash;
  readonly tree_size: number;
  /** The detached `.ots` proof, base64. */
  readonly proof: string;
  /** The calendars that accepted the digest — independent, and not ours. */
  readonly calendars: readonly string[];
  readonly submitted_at: string;
  /** Block heights the proof commits into, once the calendars have aggregated. */
  readonly heights: readonly number[];
}

/** The full `cool.receipt.v2` envelope. Self-contained and offline-verifiable. */
export interface ReceiptV2 {
  readonly schema: "cool.receipt.v2";
  readonly record: SignedRecordV2;
  readonly binding_hash: Multihash;
  readonly inclusion: Inclusion | null;
  readonly sth: STH | null;
  readonly attestation: AttestationV2;
  readonly anchor: AnchorProof | null;
  readonly key_directory: KeyDirectory;
}

/* ── verdicts ─────────────────────────────────────────────────────────── */

/**
 * Per-domain status. `simulated` exists so the simulator can be reported
 * accurately instead of being flattened into either `pass` or `mock`; `pending`
 * exists because a Bitcoin anchor is genuinely in flight for an hour or so
 * after submission, and calling that either a pass or an absence would be a
 * lie in one direction or the other.
 */
export type DomainStatusV2 = "pass" | "fail" | "absent" | "mock" | "simulated" | "pending";

export interface DomainCheckV2 {
  readonly status: DomainStatusV2;
  readonly detail: string;
}

/**
 * The seven trust domains of a v2 verdict. `enclave` is the one v1 could not
 * have: it answers "was the key that signed this record held by the attested
 * code, and was that code the code we pinned?".
 */
export interface VerdictChecksV2 {
  readonly binding: DomainCheckV2;
  readonly signature: DomainCheckV2;
  readonly inclusion: DomainCheckV2;
  readonly witnesses: DomainCheckV2;
  readonly attestation: DomainCheckV2;
  readonly enclave: DomainCheckV2;
  readonly anchor: DomainCheckV2;
}

export interface VerdictSubjectV2 {
  readonly kind: "evidence" | "change";
  /** Event type for evidence records; the changed ref for change records. */
  readonly subject: string;
  readonly issued_at: string;
  readonly record_id: string;
  readonly key_id: string;
  readonly tee: string;
}

export interface VerdictV2 {
  readonly ok: boolean;
  readonly schema: "cool.receipt.v2";
  readonly subject: VerdictSubjectV2 | null;
  readonly checks: VerdictChecksV2;
  readonly reasons: readonly string[];
}

/** Options for {@link import("./verify").verifyReceiptV2}. */
export interface VerifyOptionsV2 {
  /** Minimum INDEPENDENT (`external: true`) witness co-signatures. Default 0. */
  readonly witnessThreshold?: number;
  /**
   * Pin the deployment's measurement. When set, the enclave domain FAILS on any
   * mismatch instead of merely reporting what it saw — this is the check that
   * makes "unmodified CooL code" enforceable in production.
   */
  readonly expectedMeasurement?: Measurement;
  /**
   * Require a hardware root. With this on, a simulated receipt cannot be `ok` —
   * the setting a regulated deployment turns on and never turns off again.
   */
  readonly requireHardware?: boolean;
}
