/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Principals: who is acting, independent of model names and display labels.
 *
 * A principal has a stable id, an issuer, an owner/tenant, an identity basis
 * (self-asserted, issuer-attested, hardware-bound, federated) and a set of
 * keys over time. Keys rotate without the principal changing. Every change is
 * an issuer-signed lifecycle event, so a verifier can ask "what was this
 * principal's state, and which keys were bound, AT the time of the event?" and
 * get the same answer anyone else would.
 *
 * Unknown, suspended, revoked, decommissioned or expired principals are never
 * silently accepted. A model hash is not an identity: an agent principal may
 * name a workload, but the workload is a separate claim.
 */
import type { DirectoryEntry, KeyPair } from "../types";
import { check, type Check } from "../platform/status";
import type { TrustStore } from "../platform/trust";
import { signObject, verifyIntegrity, verifyTrusted, type Signed } from "./signed";

export type PrincipalKind = "agent" | "human" | "service" | "workload";
export type IdentityBasis = "self_asserted" | "issuer_attested" | "hardware_bound" | "federated";
export type PrincipalStatus = "active" | "suspended" | "revoked" | "decommissioned";

export interface PrincipalRecord {
  readonly schema: "cool.principal.v1";
  readonly principal_id: string;
  readonly kind: PrincipalKind;
  readonly issuer: string;
  readonly owner: string;
  readonly tenant?: string;
  readonly basis: IdentityBasis;
  /** The human or service that sponsors an agent. */
  readonly sponsor?: string;
  /** For a delegated child agent: its parent agent. */
  readonly parent?: string;
  readonly workload_id?: string;
  readonly created_at: string;
  readonly expires_at?: string;
  /** Keys bound at creation. */
  readonly keys: ReadonlyArray<{ readonly key_id: string; readonly entry: DirectoryEntry }>;
}

export type PrincipalEventKind = "key_bound" | "key_retired" | "suspended" | "reinstated" | "revoked" | "decommissioned";

export interface PrincipalEvent {
  readonly schema: "cool.principal-event.v1";
  readonly event_id: string;
  readonly principal_id: string;
  readonly kind: PrincipalEventKind;
  readonly at: string;
  readonly key_id?: string;
  readonly entry?: DirectoryEntry;
  readonly reason?: string;
}

export const enrollPrincipal = (record: Omit<PrincipalRecord, "schema">, issuerKey: KeyPair): Signed<PrincipalRecord> =>
  signObject("cool.principal.v1", { schema: "cool.principal.v1", ...record }, issuerKey);

export const principalEvent = (event: Omit<PrincipalEvent, "schema">, issuerKey: KeyPair): Signed<PrincipalEvent> =>
  signObject("cool.principal-event.v1", { schema: "cool.principal-event.v1", ...event }, issuerKey);

interface Entry {
  readonly record: PrincipalRecord;
  readonly events: PrincipalEvent[];
}

export interface PrincipalState {
  readonly known: boolean;
  readonly status: PrincipalStatus | "unknown";
  readonly record?: PrincipalRecord;
  readonly keys: ReadonlyMap<string, DirectoryEntry>;
}

/**
 * A verifier-side view of principals, built only from signed records whose
 * issuer is trusted (purpose `identity_issuer`). Nothing is accepted unsigned.
 */
export class PrincipalDirectory {
  readonly #entries = new Map<string, Entry>();

  constructor(readonly trust: TrustStore, readonly now: () => number = () => Date.now()) {}

  /** Admit a signed principal record. Returns why not, if not. */
  enroll(s: Signed<PrincipalRecord>): Check {
    const v = verifyTrusted("cool.principal.v1", s, this.trust, "identity_issuer", this.now());
    if (v.integrity.status !== "pass") return v.integrity;
    if (v.signature.status !== "pass") return v.signature;
    if (v.trusted.status !== "pass") return v.trusted;
    if (s.body.issuer !== s.signature.key_id) return check("fail", "issuer_mismatch", `record names issuer ${s.body.issuer} but is signed by ${s.signature.key_id}`);
    if (this.#entries.has(s.body.principal_id)) return check("fail", "duplicate_principal", `${s.body.principal_id} is already enrolled`);
    this.#entries.set(s.body.principal_id, { record: s.body, events: [] });
    return check("pass", "enrolled", `${s.body.kind} ${s.body.principal_id} (${s.body.basis}) issued by ${s.body.issuer}`);
  }

  /** Apply a signed lifecycle event; only the principal's issuer may sign it. */
  apply(s: Signed<PrincipalEvent>): Check {
    const e = this.#entries.get(s.body.principal_id);
    if (!e) return check("fail", "unknown_principal", `${s.body.principal_id} is not enrolled`);
    const issuer = this.trust.get(e.record.issuer);
    const v = verifyIntegrity("cool.principal-event.v1", s, issuer?.entry);
    if (v.integrity.status !== "pass") return v.integrity;
    if (v.signature.status !== "pass") return v.signature;
    if (s.signature.key_id !== e.record.issuer) return check("fail", "issuer_mismatch", `only ${e.record.issuer} may change ${s.body.principal_id}`);
    if (s.body.kind === "key_bound" && (!s.body.key_id || !s.body.entry)) return check("fail", "malformed", "key_bound needs key_id and entry");
    e.events.push(s.body);
    e.events.sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
    return check("pass", "applied", `${s.body.kind} on ${s.body.principal_id} at ${s.body.at}`);
  }

  /** State as of a point in time — events after it are ignored. */
  stateAt(principalId: string, at: number): PrincipalState {
    const e = this.#entries.get(principalId);
    if (!e || at < Date.parse(e.record.created_at)) return { known: false, status: "unknown", keys: new Map() };
    let status: PrincipalStatus = "active";
    const keys = new Map(e.record.keys.map((k) => [k.key_id, k.entry]));
    for (const ev of e.events) {
      if (Date.parse(ev.at) > at) break;
      if (ev.kind === "key_bound") keys.set(ev.key_id!, ev.entry!);
      else if (ev.kind === "key_retired") keys.delete(ev.key_id!);
      else if (ev.kind === "suspended") status = status === "active" ? "suspended" : status;
      else if (ev.kind === "reinstated") status = status === "suspended" ? "active" : status;
      else if (ev.kind === "revoked") status = "revoked";
      else if (ev.kind === "decommissioned") status = "decommissioned";
    }
    return { known: true, status, record: e.record, keys };
  }

  /** Is this principal usable at `at` — optionally with this key? */
  check(principalId: string, at: number, keyId?: string): Check {
    const s = this.stateAt(principalId, at);
    if (!s.known) return check("fail", "unknown_principal", `${principalId} is not known at ${new Date(at).toISOString()}`);
    if (s.record?.expires_at && at > Date.parse(s.record.expires_at)) return check("fail", "principal_expired", `${principalId} expired ${s.record.expires_at}`);
    if (s.status !== "active") return check("fail", `principal_${s.status}`, `${principalId} is ${s.status} at ${new Date(at).toISOString()}`);
    if (keyId && !s.keys.has(keyId)) return check("fail", "key_not_bound", `key ${keyId} is not bound to ${principalId} at ${new Date(at).toISOString()}`);
    return check("pass", "principal_active", `${principalId} active${keyId ? ` with key ${keyId}` : ""} at ${new Date(at).toISOString()} (${s.record!.basis})`);
  }

  keyAt(principalId: string, keyId: string, at: number): DirectoryEntry | undefined {
    return this.stateAt(principalId, at).keys.get(keyId);
  }
}
