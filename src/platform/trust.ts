/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Trust: which keys a verifier accepts, for what, and until when.
 *
 * Three questions are kept apart because they have different answers:
 *
 *   signature_valid   did this key sign these bytes?      (cryptography)
 *   signer_trusted    is this key one we accept, for this purpose, now?  (here)
 *   signer_authorized may this signer do this action?     (policy, elsewhere)
 *
 * A key record carries purpose, owner, validity and status. Revocation and
 * compromise are handled conservatively: a signer can backdate its own
 * timestamp, so a revoked key is accepted only for evidence whose signing time
 * is proven by something else — a trusted log checkpoint dated before the
 * revocation. A compromised key is rejected from `compromised_since` onward
 * regardless, and before that only with the same independent proof.
 *
 * A trust snapshot has an `as_of` time. Past `max_age_ms`, every trust answer
 * becomes `unknown` ("trust_snapshot_stale"): the keys may still be right, but
 * the verifier cannot know about revocations it has not been told of.
 */
import type { DirectoryEntry } from "../types";
import { check, type Check } from "./status";

export type KeyPurpose = "evidence" | "log" | "witness" | "builder" | "policy" | "enforcement" | "source";
export type KeyStatus = "active" | "rotated" | "revoked" | "compromised";

export interface KeyRecord {
  readonly key_id: string;
  readonly entry: DirectoryEntry;
  readonly purposes: readonly KeyPurpose[];
  readonly owner: string;
  readonly valid_from: string;
  readonly valid_until?: string;
  readonly status: KeyStatus;
  /** For rotated keys: when the successor took over. */
  readonly rotated_at?: string;
  readonly successor?: string;
  readonly revoked_at?: string;
  readonly compromised_since?: string;
}

export interface TrustSnapshot {
  readonly schema: "cool.trust-snapshot.v1";
  readonly id: string;
  readonly as_of: string;
  /** How long this snapshot may be relied on. Absent → no freshness claim (reported). */
  readonly max_age_ms?: number;
  readonly keys: readonly KeyRecord[];
}

export interface TrustQuery {
  readonly keyId: string;
  readonly purpose: KeyPurpose;
  /** Verification time, ms. */
  readonly now: number;
  /** Signing time claimed by the evidence itself — informational only. */
  readonly claimedSignedAt?: number;
  /** Signing time proven independently (e.g. a trusted checkpoint), ms. */
  readonly provenSignedBefore?: number;
}

export class TrustStore {
  readonly #keys = new Map<string, KeyRecord>();
  readonly #snapshot: Omit<TrustSnapshot, "keys">;

  constructor(snapshot: TrustSnapshot) {
    if (snapshot.schema !== "cool.trust-snapshot.v1") throw new Error(`unsupported trust snapshot ${String(snapshot.schema)}`);
    this.#snapshot = { schema: snapshot.schema, id: snapshot.id, as_of: snapshot.as_of, ...(snapshot.max_age_ms ? { max_age_ms: snapshot.max_age_ms } : {}) };
    for (const k of snapshot.keys) this.#keys.set(k.key_id, k);
  }

  static empty(id = "empty"): TrustStore {
    return new TrustStore({ schema: "cool.trust-snapshot.v1", id, as_of: new Date(0).toISOString(), keys: [] });
  }

  get(keyId: string): KeyRecord | undefined {
    return this.#keys.get(keyId);
  }

  snapshot(): TrustSnapshot {
    return { ...this.#snapshot, keys: [...this.#keys.values()] };
  }

  /** Decide whether `keyId` is trusted for `purpose` at the given time. */
  evaluate(q: TrustQuery): Check {
    const ref = `${this.#snapshot.id}@${this.#snapshot.as_of}`;
    const k = this.#keys.get(q.keyId);
    if (!k) return check("fail", "untrusted_key", `key ${q.keyId} is not in trust snapshot ${ref}`, { evidence_ref: ref });
    if (!k.purposes.includes(q.purpose)) {
      return check("fail", "wrong_key_purpose", `key ${q.keyId} is trusted for ${k.purposes.join(", ")}, not ${q.purpose}`, { evidence_ref: ref });
    }
    const at = q.provenSignedBefore ?? q.claimedSignedAt ?? q.now;
    if (at < Date.parse(k.valid_from)) return check("fail", "key_not_yet_valid", `key ${q.keyId} is valid from ${k.valid_from}`, { evidence_ref: ref });
    if (k.valid_until && at > Date.parse(k.valid_until)) return check("fail", "key_expired", `key ${q.keyId} expired ${k.valid_until}`, { evidence_ref: ref });

    if (k.status === "compromised") {
      const since = Date.parse(k.compromised_since ?? k.valid_from);
      if (q.provenSignedBefore === undefined || q.provenSignedBefore >= since) {
        return check("fail", "key_compromised", `key ${q.keyId} is compromised since ${k.compromised_since ?? k.valid_from}; no independent proof the signature predates it`, { evidence_ref: ref });
      }
    }
    if (k.status === "revoked") {
      const revoked = Date.parse(k.revoked_at ?? k.valid_from);
      if (q.provenSignedBefore === undefined || q.provenSignedBefore >= revoked) {
        return check("fail", "key_revoked", `key ${q.keyId} was revoked ${k.revoked_at ?? "(time not recorded)"}; a signature can only be accepted with independent proof it predates that`, { evidence_ref: ref });
      }
    }
    if (k.status === "rotated" && k.rotated_at) {
      const rotated = Date.parse(k.rotated_at);
      if ((q.provenSignedBefore ?? q.claimedSignedAt ?? q.now) > rotated) {
        return check("fail", "key_rotated", `key ${q.keyId} was superseded by ${k.successor ?? "a successor"} at ${k.rotated_at}`, { evidence_ref: ref });
      }
    }

    if (this.#snapshot.max_age_ms !== undefined && q.now - Date.parse(this.#snapshot.as_of) > this.#snapshot.max_age_ms) {
      return check("unknown", "trust_snapshot_stale", `trust snapshot ${ref} is older than ${this.#snapshot.max_age_ms} ms; revocations since then are unknown`, { evidence_ref: ref });
    }
    const limitation = this.#snapshot.max_age_ms === undefined
      ? "the snapshot states no freshness bound, so revocations after its as_of time are not reflected"
      : undefined;
    const historic = k.status !== "active" ? ` (status ${k.status}; accepted because signing is proven to predate it)` : "";
    return check("pass", "key_trusted", `key ${q.keyId} is trusted for ${q.purpose} by ${k.owner}${historic}`, { evidence_ref: ref, ...(limitation ? { limitation } : {}) });
  }
}
