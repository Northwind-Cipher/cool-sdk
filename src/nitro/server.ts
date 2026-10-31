/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * The receiving side of the Nitro path: register, ingest, acknowledge,
 * checkpoint.
 *
 *   register  verify the enclave's attestation (bound to its key), then assign
 *             an epoch with a signed registration record
 *   ingest    verify the receipt envelope against the registered key, account
 *             for its [epoch].[sequence], append accepted receipts to the
 *             RFC 6962 log, and return a SIGNED acknowledgement
 *   checkpoint  a signed tree head, optionally co-signed by witnesses
 *
 * Nothing a receipt says is taken on trust: its signature must verify under
 * the key that was attested at registration, its sequence must belong to that
 * key's epoch, and a mutated receipt is rejected without being stored or
 * "normalised". In-process reference implementation: state is in memory.
 */
import { canonicalCbor } from "../canonical";
import { hybridSign } from "../sign";
import type { DirectoryEntry, KeyPair, SignatureBlock } from "../types";
import { verifyEnvelope, type SignedEnvelope } from "../platform/envelope";
import type { PayloadRegistry } from "../platform/payloads";
import { TransparencyLog } from "../platform/transparency";
import { TrustStore, type KeyRecord } from "../platform/trust";
import { verifyNitroAttestation, type VerifyNitroOptions } from "./attestation";
import { EpochLog, type IngestOutcome, type SignedEpochRegistration } from "./epochs";

export interface Ack {
  readonly schema: "cool.nitro.ack.v1";
  readonly digest: string;
  readonly epoch: number;
  readonly sequence: number;
  readonly outcome: IngestOutcome | "rejected";
  readonly detail: string;
  readonly leaf_index?: number;
  readonly acknowledged_at: string;
}

export interface SignedAck {
  readonly ack: Ack;
  readonly signature: SignatureBlock;
}

export class NitroLogServer {
  readonly #logKey: KeyPair;
  readonly #epochs: EpochLog;
  readonly #log: TransparencyLog;
  readonly #enclaveKeys: KeyRecord[] = [];
  readonly #clock: () => Date;

  constructor(readonly options: {
    readonly logKey: KeyPair;
    readonly logId: string;
    readonly registry: PayloadRegistry;
    /** Policy, freshness and trust bundle for enclave attestations. */
    readonly attestation: Omit<VerifyNitroOptions, "receiptKey">;
    readonly clock?: () => Date;
  }) {
    this.#logKey = options.logKey;
    this.#clock = options.clock ?? (() => new Date());
    this.#epochs = new EpochLog(options.logKey, this.#clock);
    this.#log = new TransparencyLog(options.logId, options.logKey, this.#clock);
  }

  get epochs(): EpochLog {
    return this.#epochs;
  }

  /** Register an enclave key on the strength of its attestation document. */
  register(document: Uint8Array, keyId: string, entry: DirectoryEntry, workloadId: string): SignedEpochRegistration {
    const report = verifyNitroAttestation(document, { ...this.options.attestation, receiptKey: { keyId, entry }, now: this.#clock().getTime() });
    const signed = this.#epochs.register(report, keyId, workloadId);
    if (!this.#enclaveKeys.some((k) => k.key_id === keyId)) {
      this.#enclaveKeys.push({ key_id: keyId, entry, purposes: ["evidence"], owner: `enclave:${workloadId}`, valid_from: new Date(0).toISOString(), status: "active" });
    }
    return signed;
  }

  #trust(): TrustStore {
    return new TrustStore({ schema: "cool.trust-snapshot.v1", id: "nitro-registered-enclaves", as_of: this.#clock().toISOString(), keys: [...this.#enclaveKeys] });
  }

  #ack(ack: Omit<Ack, "schema" | "acknowledged_at">): SignedAck {
    const full: Ack = { schema: "cool.nitro.ack.v1", ...ack, acknowledged_at: this.#clock().toISOString() };
    return { ack: full, signature: hybridSign(canonicalCbor(full), this.#logKey) };
  }

  /** Ingest one receipt (already de-framed). */
  ingest(env: SignedEnvelope): SignedAck {
    const seq = env?.core?.sequence;
    if (!seq) return this.#ack({ digest: String(env?.digest), epoch: -1, sequence: -1, outcome: "rejected", detail: "receipt carries no [epoch].[sequence]" });
    const report = verifyEnvelope(env, {
      registry: this.options.registry,
      trust: this.#trust(),
      now: this.#clock().getTime(),
      // The attestation was verified at registration, where freshness applies;
      // per receipt, the binding to the registered key is what matters.
      nitro: { ...this.options.attestation, freshness: { mode: "timestamp-window", maxAgeMs: Number.MAX_SAFE_INTEGER }, certificateTime: "attestation-timestamp" },
    });
    const crypto = ["schema_valid", "canonical_encoding_valid", "digest_valid", "signature_valid", "signer_trusted", "attestation_valid"] as const;
    const bad = crypto.find((name) => report.checks[name].status !== "pass" && report.checks[name].status !== "not_applicable");
    if (bad) return this.#ack({ digest: env.digest, epoch: seq.epoch, sequence: seq.number, outcome: "rejected", detail: `${bad}: ${report.checks[bad].reason}` });
    const signer = env.signatures[0]!.key_id;
    const result = this.#epochs.ingest({ receipt_id: env.core.event_id, key_id: signer, epoch: seq.epoch, sequence: seq.number, digest: env.digest });
    let leaf: number | undefined;
    if (result.outcome === "accepted" || result.outcome === "late_fill" || result.outcome === "duplicate") {
      leaf = this.#log.publish(env).checkpoint?.leaf_index;
    }
    return this.#ack({ digest: env.digest, epoch: seq.epoch, sequence: seq.number, outcome: result.outcome, detail: result.detail, ...(leaf !== undefined ? { leaf_index: leaf } : {}) });
  }

  /** A checkpoint for a published receipt, co-signed by the given witnesses. */
  checkpoint(digest: string, witnesses: readonly KeyPair[] = []) {
    return this.#log.checkpoint(digest, witnesses);
  }
}
