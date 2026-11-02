/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The canonical authorization request: it binds the exact action and target.
 *
 * A request names principal, action, resource, audience, policy selector, an
 * unpredictable nonce, issue and expiry times, an optional delegation and the
 * planned execution context. Its parameters and context are NOT in it — only
 * commitments to them, so a public receipt never carries a payment amount, a
 * recipient or a prompt. The plaintext and salt travel privately to the
 * enforcement boundary, which recomputes the commitment before acting.
 *
 * Normalization rules (so equivalent requests commit identically and any
 * security-relevant change changes the commitment):
 *   • strings are Unicode NFC-normalized
 *   • numbers must be safe integers; decimals travel as strings ("12.50")
 *   • NaN, Infinity, bigint, functions and dates are rejected
 *   • an absent key and a key set to undefined are the same (omitted);
 *     null is a value and is kept
 *   • maps are ordered by deterministic CBOR; arrays keep their order
 *
 * Commitments are salted SHA-256 by default. Where values are guessable and a
 * tenant can hold a secret, use a keyed commitment (HMAC-SHA-256) instead so a
 * public digest cannot be dictionary-attacked.
 */
import { createHmac, randomBytes } from "node:crypto";
import { canonicalCbor } from "../canonical";
import { concatBytes, fromHex, toHex, utf8 } from "../codec";
import { mhSha256, multihashFromDigest } from "../multihash";
import type { Multihash } from "../types";
import { CooLError } from "../errors";
import { clean, digestOf } from "./signed";
import type { ExecutionContext } from "./execution";

export type CommitmentScheme = "salted-sha-256" | "hmac-sha-256";

export interface AuthorizationRequest {
  readonly schema: "cool.authz-request.v1";
  readonly request_id: string;
  readonly principal: string;
  readonly action: string;
  readonly resource: string;
  readonly audience: string;
  readonly policy_selector: string;
  readonly params_commitment: Multihash;
  readonly context_commitment: Multihash;
  readonly commitment_scheme: CommitmentScheme;
  readonly nonce: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly delegation?: string;
  readonly execution?: ExecutionContext;
}

/** What stays with the requester and the enforcement boundary — never published. */
export interface RequestSecrets {
  readonly params: Readonly<Record<string, unknown>>;
  readonly params_salt: string;
  readonly context: Readonly<Record<string, unknown>>;
  readonly context_salt: string;
}

export interface RequestInput {
  readonly principal: string;
  readonly action: string;
  readonly resource: string;
  readonly audience: string;
  readonly policy_selector: string;
  readonly params: Readonly<Record<string, unknown>>;
  readonly context?: Readonly<Record<string, unknown>>;
  readonly delegation?: string;
  readonly execution?: ExecutionContext;
  readonly ttlMs?: number;
  readonly now?: number;
  readonly request_id?: string;
  readonly nonce?: string;
  /** Tenant secret for keyed commitments. Absent → salted SHA-256. */
  readonly commitmentKey?: Uint8Array;
}

/** Normalize a value per the rules above. Throws COOL_EVIDENCE_INVALID. */
export function normalize(value: unknown, path = "$"): unknown {
  if (value === null) return null;
  if (typeof value === "string") return value.normalize("NFC");
  if (typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new CooLError("COOL_EVIDENCE_INVALID", `${path}: ${value} is not a safe integer; send decimals as strings`);
    return value;
  }
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return value.map((v, i) => normalize(v, `${path}[${i}]`));
  if (typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (v === undefined) continue;
      out[k.normalize("NFC")] = normalize(v, `${path}.${k}`);
    }
    return out;
  }
  throw new CooLError("COOL_EVIDENCE_INVALID", `${path}: ${typeof value} values cannot be committed`);
}

const DOMAIN = { params: "cool.authz.params.v1\0", context: "cool.authz.context.v1\0" } as const;

/** Commit to a value: salted SHA-256, or HMAC-SHA-256 under a tenant key. */
export function commitValue(kind: keyof typeof DOMAIN, value: unknown, salt: string, key?: Uint8Array): Multihash {
  const body = concatBytes(utf8(DOMAIN[kind]), fromHex(salt), canonicalCbor(normalize(value)));
  if (key) return multihashFromDigest(new Uint8Array(createHmac("sha256", key).update(body).digest()));
  return mhSha256(body);
}

/** Build a request. Returns the publishable request and the private secrets. */
export function createAuthorizationRequest(input: RequestInput): { readonly request: AuthorizationRequest; readonly secrets: RequestSecrets } {
  const now = input.now ?? Date.now();
  const params_salt = toHex(new Uint8Array(randomBytes(16)));
  const context_salt = toHex(new Uint8Array(randomBytes(16)));
  const context = input.context ?? {};
  const request = clean<AuthorizationRequest>({
    schema: "cool.authz-request.v1",
    request_id: input.request_id ?? `req_${toHex(new Uint8Array(randomBytes(12)))}`,
    principal: input.principal,
    action: input.action.normalize("NFC"),
    resource: input.resource.normalize("NFC"),
    audience: input.audience,
    policy_selector: input.policy_selector,
    params_commitment: commitValue("params", input.params, params_salt, input.commitmentKey),
    context_commitment: commitValue("context", context, context_salt, input.commitmentKey),
    commitment_scheme: input.commitmentKey ? "hmac-sha-256" : "salted-sha-256",
    nonce: input.nonce ?? toHex(new Uint8Array(randomBytes(16))),
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + (input.ttlMs ?? 5 * 60_000)).toISOString(),
    delegation: input.delegation,
    execution: input.execution,
  });
  return { request, secrets: { params: input.params, params_salt, context, context_salt } };
}

export const requestDigest = (r: AuthorizationRequest): Multihash => digestOf("cool.authz-request.v1", r);

/** Does this plaintext match the request's commitment? (parameter-substitution check) */
export function paramsMatch(r: AuthorizationRequest, params: Readonly<Record<string, unknown>>, salt: string, key?: Uint8Array): boolean {
  try {
    return commitValue("params", params, salt, key) === r.params_commitment;
  } catch {
    return false;
  }
}

export function contextMatches(r: AuthorizationRequest, context: Readonly<Record<string, unknown>>, salt: string, key?: Uint8Array): boolean {
  try {
    return commitValue("context", context, salt, key) === r.context_commitment;
  } catch {
    return false;
  }
}
