/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * CooL Identity & Authority.
 *
 * CooL is not an identity provider, vault or KMS. It records what those
 * systems assert and evaluates it, keeping three things apart: a valid
 * signature, a trusted signer, and an authorized action.
 *
 * Credential lifecycle transitions that change the outside world (rotation,
 * revocation) are REQUESTED here and only become final when the provider
 * confirms. A provider timeout leaves the credential in `unknown` — never
 * "rotated" by optimism.
 */
import type { EnvelopeInput } from "../envelope";

export type CredentialState =
  | "active" | "rotation_requested" | "rotated" | "revocation_requested" | "revoked" | "compromised" | "unknown";

export interface ProviderResult {
  readonly confirmed: boolean;
  readonly timedOut?: boolean;
  readonly at: string;
}

/** One credential's lifecycle, emitting a `credential.lifecycle` input per transition. */
export class CredentialLifecycle {
  #state: CredentialState = "active";
  readonly #records: EnvelopeInput[] = [];

  constructor(readonly credentialRef: string, readonly provider: string, readonly subject: string) {}

  get state(): CredentialState {
    return this.#state;
  }

  records(): readonly EnvelopeInput[] {
    return [...this.#records];
  }

  #move(to: CredentialState, actor: string, at: string, confirmed: boolean): void {
    this.#records.push({
      event_type: "credential.lifecycle",
      occurred_at: at,
      source: { system: this.provider },
      actor: { id: actor, type: actor.startsWith("provider:") ? "service" : "human" },
      action: to,
      resource: { type: "credential", ref: this.credentialRef },
      payload: { credential_ref: this.credentialRef, from_state: this.#state, to_state: to, provider: this.provider, confirmed },
    });
    this.#state = to;
  }

  requestRotation(actor: string, at: string): void {
    if (this.#state !== "active") throw new Error(`cannot rotate a credential in state ${this.#state}`);
    this.#move("rotation_requested", actor, at, false);
  }

  requestRevocation(actor: string, at: string): void {
    if (this.#state === "revoked") throw new Error("already revoked");
    this.#move("revocation_requested", actor, at, false);
  }

  markCompromised(actor: string, at: string): void {
    this.#move("compromised", actor, at, false);
  }

  /** Apply the provider's answer to a pending request. */
  providerResult(result: ProviderResult): CredentialState {
    const pending = this.#state;
    if (pending !== "rotation_requested" && pending !== "revocation_requested" && pending !== "unknown") {
      throw new Error(`no pending request in state ${pending}`);
    }
    const done: CredentialState = pending === "revocation_requested" ? "revoked" : "rotated";
    if (result.timedOut) this.#move("unknown", `provider:${this.provider}`, result.at, false);
    else if (result.confirmed) this.#move(pending === "unknown" ? "rotated" : done, `provider:${this.provider}`, result.at, true);
    return this.#state;
  }
}

export interface Grant {
  readonly actor: string;
  readonly resource: string;
  readonly action: string;
  readonly environment: string;
}

/**
 * An authorization matrix: explicit grants, default deny. `*` matches any
 * value in a position. The result names the grant that allowed it, or why not.
 */
export class AuthorizationMatrix {
  constructor(readonly grants: readonly Grant[]) {}

  evaluate(request: Grant & { readonly actorKnown: boolean }): { readonly decision: "allow" | "deny"; readonly reason: string; readonly record: EnvelopeInput } {
    const m = (g: string, v: string) => g === "*" || g === v;
    const grant = request.actorKnown
      ? this.grants.find((g) => m(g.actor, request.actor) && m(g.resource, request.resource) && m(g.action, request.action) && m(g.environment, request.environment))
      : undefined;
    const decision = grant ? "allow" : "deny";
    const reason = !request.actorKnown ? "unknown_identity" : grant ? `grant:${grant.actor}/${grant.resource}/${grant.action}/${grant.environment}` : "no_matching_grant";
    return {
      decision,
      reason,
      record: {
        event_type: decision === "allow" ? "authorization.evaluated" : "authorization.denied",
        occurred_at: new Date().toISOString(),
        source: { system: "cool-authz" },
        actor: { id: request.actor, type: request.actorKnown ? "human" : "unknown" },
        action: request.action,
        resource: { type: "resource", ref: request.resource },
        payload: decision === "allow"
          ? { subject: request.actor, permission: request.action, resource_ref: request.resource, environment: request.environment, decision }
          : { subject: request.actor, permission: request.action, resource_ref: request.resource, reason },
      },
    };
  }
}

/** Single-use token guard: a token id seen twice within its lifetime is a replay. */
export class ReplayGuard {
  readonly #seen = new Map<string, number>();

  constructor(readonly ttlMs: number) {}

  check(tokenId: string, now: number): "fresh" | "replayed" {
    for (const [id, exp] of this.#seen) if (exp < now) this.#seen.delete(id);
    if (this.#seen.has(tokenId)) return "replayed";
    this.#seen.set(tokenId, now + this.ttlMs);
    return "fresh";
  }
}
