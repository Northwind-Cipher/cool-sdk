/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Epochs, sequences and detectable gaps — the log side of the Nitro path.
 *
 * An enclave generates a fresh signing key per boot. The log, not the enclave,
 * assigns that key an epoch: registration takes a verified attestation report
 * and produces a signed record binding (epoch, key id, key binding, attestation
 * digest, workload, policy version, time). A caller cannot choose its epoch.
 *
 * Within an epoch the enclave numbers its receipts 0, 1, 2… The log records
 * what it observed, and only that:
 *
 *   • accepted      the next sequence, or a later one (opening gaps below it)
 *   • duplicate     the same receipt again — idempotent, no state change
 *   • conflict      a different receipt claiming an already-used sequence
 *   • late_fill     a receipt for a sequence previously recorded as a gap
 *   • unknown_epoch / epoch_key_mismatch / invalid
 *
 * A gap is evidence of absence, not of malice: the log cannot tell suppression
 * from a crash, a network fault or a shutdown, and it does not try. A dropped
 * FINAL receipt is invisible until a later sequence arrives. A late fill does
 * not erase a gap — the gap's status moves to `filled_late` and the record of
 * having been missing stays.
 *
 * Receipt signatures are verified by the caller before ingest; this module
 * orders and accounts for receipts, it does not judge them.
 */
import { canonicalCbor } from "../canonical";
import { toHex } from "../codec";
import { hybridSign, hybridVerify } from "../sign";
import type { KeyDirectory, KeyPair, SignatureBlock } from "../types";
import type { NitroAttestationReport } from "./attestation";

export interface EpochRegistration {
  readonly schema: "cool.nitro.epoch-registration.v1";
  readonly epoch: number;
  readonly key_id: string;
  /** Hex of the attested user_data key binding. */
  readonly key_binding: string;
  /** Hex SHA-256 of the attestation document the registration was based on. */
  readonly attestation_sha256: string;
  readonly workload_id: string;
  readonly policy: string;
  readonly registered_at: string;
}

export interface SignedEpochRegistration {
  readonly registration: EpochRegistration;
  readonly signature: SignatureBlock;
}

export interface ObservedReceipt {
  readonly receipt_id: string;
  readonly key_id: string;
  readonly epoch: number;
  readonly sequence: number;
  /** Hex digest of the signed receipt bytes, used to tell duplicates from conflicts. */
  readonly digest: string;
}

export type IngestOutcome =
  | "accepted" | "duplicate" | "conflict" | "late_fill" | "unknown_epoch" | "epoch_key_mismatch" | "invalid";

export interface IngestResult {
  readonly outcome: IngestOutcome;
  readonly epoch: number;
  readonly sequence: number;
  /** Sequences newly recorded as missing by this ingest. */
  readonly gaps_opened: readonly number[];
  readonly detail: string;
}

export interface SequenceGap {
  readonly epoch: number;
  readonly sequence: number;
  readonly status: "unresolved" | "filled_late";
  readonly detected_at: string;
  readonly filled_at?: string;
}

export type EpochEvent =
  | { readonly kind: "registered"; readonly at: string; readonly epoch: number; readonly workload_id: string }
  | { readonly kind: "epoch_transition"; readonly at: string; readonly workload_id: string; readonly from: number; readonly to: number }
  | { readonly kind: "gap_opened"; readonly at: string; readonly epoch: number; readonly sequence: number }
  | { readonly kind: "gap_filled_late"; readonly at: string; readonly epoch: number; readonly sequence: number }
  | { readonly kind: "conflict"; readonly at: string; readonly epoch: number; readonly sequence: number };

/** Domain separation for registration signatures. */
const REGISTRATION_CONTEXT = "cool.nitro.epoch-registration.v1\0";

function registrationBytes(registration: EpochRegistration): Uint8Array {
  const body = canonicalCbor(registration);
  const out = new Uint8Array(REGISTRATION_CONTEXT.length + body.length);
  out.set(new TextEncoder().encode(REGISTRATION_CONTEXT), 0);
  out.set(body, REGISTRATION_CONTEXT.length);
  return out;
}

/** Verify a registration record offline against the log's key directory. */
export function verifyEpochRegistration(signed: SignedEpochRegistration, directory: KeyDirectory): boolean {
  const entry = directory[signed.signature.key_id];
  if (!entry) return false;
  return hybridVerify(registrationBytes(signed.registration), signed.signature, entry).ok;
}

interface EpochState {
  readonly signed: SignedEpochRegistration;
  readonly seen: Map<number, ObservedReceipt>;
  readonly gaps: Map<number, SequenceGap>;
  highest: number;
}

export class EpochLog {
  readonly #key: KeyPair;
  readonly #clock: () => Date;
  readonly #epochs = new Map<number, EpochState>();
  readonly #byBinding = new Map<string, number>();
  readonly #latestByWorkload = new Map<string, number>();
  readonly #events: EpochEvent[] = [];
  #next = 1;

  constructor(logKey: KeyPair, clock: () => Date = () => new Date()) {
    this.#key = logKey;
    this.#clock = clock;
  }

  /**
   * Assign an epoch to an attested receipt key.
   *
   * Refuses anything but a fully passing report whose key binding passed — an
   * unknown or failing attestation does not get an epoch. Registering the same
   * key binding again returns the original record unchanged.
   */
  register(report: NitroAttestationReport, keyId: string, workloadId: string): SignedEpochRegistration {
    if (report.overall_status !== "pass" || report.checks.key_binding.status !== "pass" || !report.claims?.user_data) {
      throw new Error(`refusing to register: attestation is ${report.overall_status} (${report.reasons.join("; ") || "no reasons"})`);
    }
    const binding = report.claims.user_data;
    const existing = this.#byBinding.get(binding);
    if (existing !== undefined) return this.#epochs.get(existing)!.signed;

    const at = this.#clock().toISOString();
    const epoch = this.#next++;
    const registration: EpochRegistration = {
      schema: "cool.nitro.epoch-registration.v1",
      epoch,
      key_id: keyId,
      key_binding: binding,
      attestation_sha256: report.document_sha256,
      workload_id: workloadId,
      policy: report.policy ? `${report.policy.id}@${report.policy.version}` : "none",
      registered_at: at,
    };
    const signed = { registration, signature: hybridSign(registrationBytes(registration), this.#key) };
    this.#epochs.set(epoch, { signed, seen: new Map(), gaps: new Map(), highest: -1 });
    this.#byBinding.set(binding, epoch);
    this.#events.push({ kind: "registered", at, epoch, workload_id: workloadId });
    const previous = this.#latestByWorkload.get(workloadId);
    if (previous !== undefined) this.#events.push({ kind: "epoch_transition", at, workload_id: workloadId, from: previous, to: epoch });
    this.#latestByWorkload.set(workloadId, epoch);
    return signed;
  }

  /** Account for one already signature-verified receipt. */
  ingest(receipt: ObservedReceipt): IngestResult {
    const { epoch, sequence } = receipt;
    const result = (outcome: IngestOutcome, detail: string, gaps_opened: number[] = []): IngestResult =>
      ({ outcome, epoch, sequence, gaps_opened, detail });

    if (!Number.isSafeInteger(sequence) || sequence < 0) return result("invalid", "sequence must be a non-negative integer");
    const state = this.#epochs.get(epoch);
    if (!state) return result("unknown_epoch", `epoch ${epoch} was never assigned by this log`);
    if (state.signed.registration.key_id !== receipt.key_id) {
      return result("epoch_key_mismatch", `epoch ${epoch} belongs to ${state.signed.registration.key_id}, not ${receipt.key_id}`);
    }

    const at = this.#clock().toISOString();
    const prior = state.seen.get(sequence);
    if (prior) {
      if (prior.receipt_id === receipt.receipt_id && prior.digest === receipt.digest) {
        return result("duplicate", "already recorded; no change");
      }
      this.#events.push({ kind: "conflict", at, epoch, sequence });
      return result("conflict", `sequence ${sequence} is already held by receipt ${prior.receipt_id}; the first observation stands`);
    }

    state.seen.set(sequence, receipt);
    const gap = state.gaps.get(sequence);
    if (gap) {
      state.gaps.set(sequence, { ...gap, status: "filled_late", filled_at: at });
      this.#events.push({ kind: "gap_filled_late", at, epoch, sequence });
      return result("late_fill", `sequence ${sequence} arrived after it was recorded missing at ${gap.detected_at}`);
    }

    const opened: number[] = [];
    for (let s = state.highest + 1; s < sequence; s++) {
      state.gaps.set(s, { epoch, sequence: s, status: "unresolved", detected_at: at });
      this.#events.push({ kind: "gap_opened", at, epoch, sequence: s });
      opened.push(s);
    }
    state.highest = Math.max(state.highest, sequence);
    return result("accepted", opened.length ? `accepted; sequences ${opened.join(", ")} recorded missing` : "accepted", opened);
  }

  /** Every gap ever recorded, filled or not, in (epoch, sequence) order. */
  gaps(epoch?: number): SequenceGap[] {
    const out: SequenceGap[] = [];
    for (const [e, state] of [...this.#epochs].sort((a, b) => a[0] - b[0])) {
      if (epoch !== undefined && e !== epoch) continue;
      out.push(...[...state.gaps.values()].sort((a, b) => a.sequence - b.sequence));
    }
    return out;
  }

  /** The append-only audit trail of registrations, transitions, gaps and conflicts. */
  events(): readonly EpochEvent[] {
    return [...this.#events];
  }

  /** Highest sequence observed in an epoch, or -1. */
  highest(epoch: number): number {
    return this.#epochs.get(epoch)?.highest ?? -1;
  }
}

/** Hex helper re-exported for callers building {@link ObservedReceipt.digest}. */
export const digestHex = toHex;
