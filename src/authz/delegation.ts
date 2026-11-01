/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Delegation: scoped, expiring, revocable authority from one principal to
 * another — human→agent, agent→agent, service→agent.
 *
 * A delegation names delegator, delegate, scope (actions, resources, an
 * optional amount ceiling), audience, validity window, a nonce and its parent.
 * It is signed by a key bound to the delegator at the time of issue.
 *
 * Chain verification walks root → leaf and refuses:
 *   • privilege amplification — a child scope must be a subset of its parent
 *   • broken links — each child's delegator must be its parent's delegate
 *   • cycles and over-deep chains
 *   • expired, not-yet-valid or revoked links, as of the event time
 *   • signatures by keys not bound to the delegator at issue time
 *   • a request outside the leaf's scope or audience
 * The result is fail-closed: any problem is a fail, never a partial permit.
 */
import type { KeyPair } from "../types";
import { check, type Check } from "../platform/status";
import type { PrincipalDirectory } from "./principal";
import { signObject, verifyIntegrity, type Signed } from "./signed";

export interface Scope {
  readonly actions: readonly string[];
  /** Exact ids, or prefixes ending in `*`. */
  readonly resources: readonly string[];
  readonly max_amount?: number;
}

export interface Delegation {
  readonly schema: "cool.delegation.v1";
  readonly delegation_id: string;
  readonly delegator: string;
  readonly delegate: string;
  readonly scope: Scope;
  readonly audience: string;
  readonly not_before: string;
  readonly expires_at: string;
  readonly nonce: string;
  readonly parent?: string;
  readonly issued_at: string;
}

export const grantDelegation = (d: Omit<Delegation, "schema">, delegatorKey: KeyPair): Signed<Delegation> =>
  signObject("cool.delegation.v1", { schema: "cool.delegation.v1", ...d }, delegatorKey);

/** Does a scope pattern cover one concrete resource id? */
const covers = (pattern: string, value: string) => (pattern.endsWith("*") ? value.startsWith(pattern.slice(0, -1)) : pattern === value);

/**
 * Is child pattern `r` within parent pattern `p`? An exact parent covers only
 * itself; a wildcard parent covers anything under its prefix, including
 * narrower wildcards. A wildcard child is never within an exact parent.
 */
const within = (r: string, p: string) => {
  if (!p.endsWith("*")) return !r.endsWith("*") && r === p;
  const prefix = p.slice(0, -1);
  return (r.endsWith("*") ? r.slice(0, -1) : r).startsWith(prefix);
};

/** Why `child` is not within `parent`, or null if it is. */
export function scopeExcess(child: Scope, parent: Scope): string | null {
  const extraAction = child.actions.find((a) => !parent.actions.includes(a));
  if (extraAction) return `action ${extraAction} is not in the parent scope`;
  const extraResource = child.resources.find((r) => !parent.resources.some((p) => within(r, p)));
  if (extraResource) return `resource ${extraResource} is not covered by the parent scope`;
  if (parent.max_amount !== undefined && (child.max_amount === undefined || child.max_amount > parent.max_amount)) {
    return `amount ceiling ${child.max_amount ?? "unbounded"} exceeds the parent's ${parent.max_amount}`;
  }
  return null;
}

export interface ChainRequest {
  readonly requester: string;
  readonly action: string;
  readonly resource: string;
  readonly audience: string;
  readonly amount?: number;
}

export interface ChainOptions {
  readonly directory: PrincipalDirectory;
  /** Principals allowed to originate authority (e.g. an organisation owner). */
  readonly roots: readonly string[];
  /** The event time the chain is judged at. */
  readonly at: number;
  readonly revoked?: ReadonlySet<string>;
  readonly maxDepth?: number;
}

/** Verify a chain (root first) for one concrete request. */
export function verifyDelegationChain(chain: readonly Signed<Delegation>[], request: ChainRequest, o: ChainOptions): Check {
  if (chain.length === 0) return check("fail", "no_delegation", "no delegation chain was presented");
  const maxDepth = o.maxDepth ?? 4;
  if (chain.length > maxDepth) return check("fail", "delegation_too_deep", `chain depth ${chain.length} exceeds ${maxDepth}`);
  const seenIds = new Set<string>();
  const seenPrincipals = new Set<string>([chain[0]!.body.delegator]);
  for (let i = 0; i < chain.length; i++) {
    const s = chain[i]!;
    const d = s.body;
    const ref = `delegation ${d.delegation_id}`;
    if (seenIds.has(d.delegation_id) || seenPrincipals.has(d.delegate)) return check("fail", "delegation_cycle", `${ref} repeats a link or principal`);
    seenIds.add(d.delegation_id);
    seenPrincipals.add(d.delegate);
    const issuedAt = Date.parse(d.issued_at);
    const key = o.directory.keyAt(d.delegator, s.signature.key_id, issuedAt);
    if (!key) return check("fail", "key_not_bound", `${ref}: key ${s.signature.key_id} is not bound to ${d.delegator} at issue time`);
    const v = verifyIntegrity("cool.delegation.v1", s, key);
    if (v.integrity.status !== "pass") return v.integrity;
    if (v.signature.status !== "pass") return check("fail", v.signature.reason, `${ref}: ${v.signature.detail}`);
    for (const [who, when] of [[d.delegator, issuedAt], [d.delegator, o.at], [d.delegate, o.at]] as const) {
      const c = o.directory.check(who, when);
      if (c.status !== "pass") return check("fail", c.reason, `${ref}: ${c.detail}`);
    }
    if (o.revoked?.has(d.delegation_id)) return check("fail", "delegation_revoked", `${ref} is revoked`);
    if (o.at < Date.parse(d.not_before)) return check("fail", "delegation_not_yet_valid", `${ref} is valid from ${d.not_before}`);
    if (o.at > Date.parse(d.expires_at)) return check("fail", "delegation_expired", `${ref} expired ${d.expires_at}`);
    if (i === 0) {
      if (d.parent) return check("fail", "broken_chain", `${ref} claims a parent but is presented as the root`);
      if (!o.roots.includes(d.delegator)) return check("fail", "untrusted_root", `${d.delegator} may not originate authority`);
    } else {
      const p = chain[i - 1]!.body;
      if (d.parent !== p.delegation_id || d.delegator !== p.delegate) return check("fail", "broken_chain", `${ref} does not continue ${p.delegation_id}`);
      const excess = scopeExcess(d.scope, p.scope);
      if (excess) return check("fail", "privilege_amplification", `${ref}: ${excess}`);
      if (Date.parse(d.expires_at) > Date.parse(p.expires_at)) return check("fail", "privilege_amplification", `${ref} outlives its parent`);
    }
  }
  const leaf = chain[chain.length - 1]!.body;
  if (leaf.delegate !== request.requester) return check("fail", "wrong_delegate", `the chain authorises ${leaf.delegate}, not ${request.requester}`);
  if (leaf.audience !== "*" && leaf.audience !== request.audience) return check("fail", "wrong_audience", `the chain is for ${leaf.audience}, not ${request.audience}`);
  if (!leaf.scope.actions.includes(request.action)) return check("fail", "scope_exceeded", `action ${request.action} is not delegated`);
  if (!leaf.scope.resources.some((p) => covers(p, request.resource))) return check("fail", "scope_exceeded", `resource ${request.resource} is not delegated`);
  if (leaf.scope.max_amount !== undefined && (request.amount === undefined || request.amount > leaf.scope.max_amount)) {
    return check("fail", "scope_exceeded", `amount ${request.amount ?? "unstated"} exceeds the delegated ceiling ${leaf.scope.max_amount}`);
  }
  return check("pass", "chain_valid", `${chain.length}-link chain from ${chain[0]!.body.delegator} authorises ${request.requester} to ${request.action} ${request.resource}`);
}
