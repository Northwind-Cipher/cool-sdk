/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Authorization decisions: a concrete request, evaluated against an identified
 * policy, producing a typed and signed result.
 *
 *   permit | deny | indeterminate | error
 *
 * The decision is bound to the request digest, the policy digest, the
 * evaluator id and version, a digest of every input fact, the request nonce
 * and the time. What the signature proves is limited and stated:
 *
 *   assurance "trusted"       the evaluator signed this result; you trust it
 *   assurance "reproducible"  the policy is deterministic (cool.policy.v1) and
 *                             the facts were committed, so anyone holding the
 *                             policy and facts can re-run it and must get the
 *                             same result — `verifyDecision` does exactly that
 *
 * Nothing here is a mathematical proof that the policy was satisfied; no
 * zero-knowledge construction is used or implied.
 *
 * A permit decision does not execute anything. Execution happens only at an
 * enforcement boundary (see gateway.ts), which records an external
 * confirmation of what it actually did.
 */
import { randomBytes } from "node:crypto";
import { toHex } from "../codec";
import type { KeyPair, Multihash } from "../types";
import { evaluatePolicy, policyDigest, type Facts, type PolicyDocument } from "../platform/policy";
import { check, type Check } from "../platform/status";
import { classifyOutcome, type Outcome } from "../platform/outcome";
import type { TrustStore } from "../platform/trust";
import { verifyDelegationChain, type Delegation } from "./delegation";
import type { PrincipalDirectory } from "./principal";
import { requestDigest, type AuthorizationRequest } from "./request";
import { digestOf, signObject, verifyTrusted, type Signed } from "./signed";

export type AuthzDecisionValue = "permit" | "deny" | "indeterminate" | "error";
export type Assurance = "trusted" | "reproducible";

export const EVALUATOR = { id: "cool-nwc/policy-engine", version: "cool.policy.v1/1" } as const;

export interface AuthorizationDecision {
  readonly schema: "cool.authz-decision.v1";
  readonly decision_id: string;
  readonly decision: AuthzDecisionValue;
  readonly request_id: string;
  readonly request_digest: Multihash;
  readonly principal: string;
  readonly nonce: string;
  readonly policy: { readonly id: string; readonly version: string; readonly digest: Multihash };
  readonly evaluator: { readonly id: string; readonly version: string };
  readonly input_digest: Multihash;
  readonly assurance: Assurance;
  readonly reasons: readonly string[];
  readonly decided_at: string;
  /** Never later than the request's expiry. */
  readonly valid_until: string;
}

/** The facts the engine sees: the caller's facts plus the request's own fields. */
export function decisionFacts(request: AuthorizationRequest, facts: Facts): Facts {
  return { ...facts, "request.principal": request.principal, "request.action": request.action, "request.resource": request.resource, "request.audience": request.audience };
}

const MAP: Record<string, AuthzDecisionValue> = { allow: "permit", audit_only: "permit", deny: "deny", quarantine: "deny", require_approval: "indeterminate", defer: "indeterminate" };

/** Evaluate and sign. Pure apart from the decision id. */
export function decide(input: {
  readonly request: AuthorizationRequest;
  readonly policy: PolicyDocument;
  readonly facts: Facts;
  readonly evaluatorKey: KeyPair;
  readonly now?: number;
  readonly decisionId?: string;
}): Signed<AuthorizationDecision> {
  const now = input.now ?? Date.now();
  const allFacts = decisionFacts(input.request, input.facts);
  let decision: AuthzDecisionValue;
  let reasons: string[];
  let pdigest: Multihash;
  try {
    pdigest = policyDigest(input.policy);
    if (now > Date.parse(input.request.expires_at)) {
      decision = "deny";
      reasons = ["request_expired"];
    } else {
      const r = evaluatePolicy(input.policy, allFacts, { now: new Date(now) });
      decision = MAP[r.decision]!;
      reasons = [...r.reason_codes];
    }
  } catch (err) {
    decision = "error";
    reasons = [`evaluation_error:${(err as Error).message.slice(0, 120)}`];
    pdigest = digestOf("cool.policy.invalid", input.policy);
  }
  return signObject("cool.authz-decision.v1", {
    schema: "cool.authz-decision.v1",
    decision_id: input.decisionId ?? `dec_${toHex(new Uint8Array(randomBytes(12)))}`,
    decision,
    request_id: input.request.request_id,
    request_digest: requestDigest(input.request),
    principal: input.request.principal,
    nonce: input.request.nonce,
    policy: { id: input.policy.id, version: input.policy.version, digest: pdigest },
    evaluator: { ...EVALUATOR },
    input_digest: digestOf("cool.authz.facts.v1", allFacts),
    assurance: "reproducible",
    reasons,
    decided_at: new Date(now).toISOString(),
    valid_until: input.request.expires_at,
  } satisfies AuthorizationDecision, input.evaluatorKey);
}

export interface DecisionChecks {
  readonly integrity: Check;
  readonly signature: Check;
  readonly evaluator_trusted: Check;
  readonly request_binding: Check;
  readonly policy_binding: Check;
  readonly reproduced: Check;
  readonly freshness: Check;
  readonly principal_state: Check;
  readonly delegation: Check;
}

export interface DecisionReport {
  readonly schema: "cool.authz-decision-report.v1";
  readonly decision: AuthzDecisionValue;
  readonly assurance: Assurance;
  readonly outcome: Outcome;
  readonly checks: DecisionChecks;
  readonly reasons: readonly string[];
}

export interface VerifyDecisionOptions {
  readonly request: AuthorizationRequest;
  readonly trust: TrustStore;
  /** "enforcement": must still be valid now. "historical": judged at decision time. */
  readonly mode: "enforcement" | "historical";
  readonly now?: number;
  /** Supply the policy to check the binding; add facts to replay it. */
  readonly policy?: PolicyDocument;
  readonly facts?: Facts;
  readonly directory?: PrincipalDirectory;
  readonly delegation?: { readonly chain: readonly Signed<Delegation>[]; readonly roots: readonly string[]; readonly revoked?: ReadonlySet<string>; readonly amount?: number };
}

export function verifyDecision(s: Signed<AuthorizationDecision>, o: VerifyDecisionOptions): DecisionReport {
  const now = o.now ?? Date.now();
  const d = s.body;
  const v = verifyTrusted("cool.authz-decision.v1", s, o.trust, "evaluator", now);
  const r = o.request;
  const bindingProblems = [
    requestDigest(r) !== d.request_digest && "request digest",
    r.request_id !== d.request_id && "request id",
    r.principal !== d.principal && "principal",
    r.nonce !== d.nonce && "nonce",
  ].filter(Boolean);
  const request_binding = bindingProblems.length
    ? check("fail", "request_mismatch", `decision does not bind this request: ${bindingProblems.join(", ")} differ`)
    : check("pass", "request_bound", `decision ${d.decision_id} binds request ${r.request_id}`);

  const policy_binding = !o.policy ? check("not_checked", "no_policy", "policy not supplied; the decision is accepted on the evaluator's signature (assurance: trusted)")
    : policyDigest(o.policy) !== d.policy.digest ? check("fail", "policy_mismatch", `supplied policy ${o.policy.id}@${o.policy.version} is not the one evaluated (${d.policy.id}@${d.policy.version})`)
      : check("pass", "policy_bound", `${d.policy.id}@${d.policy.version} ${d.policy.digest.slice(0, 22)}…`);

  let reproduced: Check;
  if (d.evaluator.id !== EVALUATOR.id || d.evaluator.version !== EVALUATOR.version) {
    reproduced = check("unknown", "unsupported_evaluator", `evaluator ${d.evaluator.id}@${d.evaluator.version} cannot be replayed by this verifier`);
  } else if (!o.policy || !o.facts) {
    reproduced = check("not_checked", "no_replay_inputs", "policy and facts not both supplied; replay not attempted");
  } else if (policy_binding.status !== "pass") {
    reproduced = check("not_checked", "prerequisite_failed", "policy binding failed");
  } else {
    const allFacts = decisionFacts(r, o.facts);
    if (digestOf("cool.authz.facts.v1", allFacts) !== d.input_digest) reproduced = check("fail", "input_mismatch", "the supplied facts are not the ones evaluated");
    else {
      const again = Date.parse(d.decided_at) > Date.parse(r.expires_at) ? "deny" : MAP[evaluatePolicy(o.policy, allFacts, { now: new Date(d.decided_at) }).decision];
      reproduced = again === d.decision ? check("pass", "replayed_identically", `re-evaluation gives ${again}`) : check("fail", "replay_mismatch", `re-evaluation gives ${again}, the record says ${d.decision}`);
    }
  }

  const decidedAt = Date.parse(d.decided_at);
  const freshness = decidedAt < Date.parse(r.issued_at) - 60_000 ? check("fail", "decided_before_request", "the decision predates its request")
    : Date.parse(d.valid_until) > Date.parse(r.expires_at) ? check("fail", "validity_exceeds_request", "the decision claims validity beyond the request")
      : o.mode === "enforcement" && now > Date.parse(d.valid_until) ? check("fail", "decision_expired", `the decision expired ${d.valid_until}`)
        : check("pass", "fresh", o.mode === "enforcement" ? `valid until ${d.valid_until}` : `decided within the request window`);

  const principal_state = !o.directory ? check("not_checked", "no_directory", "no principal directory supplied") : o.directory.check(r.principal, decidedAt);

  let delegation: Check;
  if (!r.delegation) delegation = check("not_applicable", "no_delegation", "the request does not rely on delegated authority");
  else if (!o.delegation || !o.directory) delegation = check("not_checked", "no_chain", "the request names a delegation but no chain (or directory) was supplied");
  else {
    const leaf = o.delegation.chain[o.delegation.chain.length - 1];
    delegation = leaf?.body.delegation_id !== r.delegation ? check("fail", "wrong_delegation", `the chain's leaf is not ${r.delegation}`)
      : verifyDelegationChain(o.delegation.chain, { requester: r.principal, action: r.action, resource: r.resource, audience: r.audience, ...(o.delegation.amount !== undefined ? { amount: o.delegation.amount } : {}) }, { directory: o.directory, roots: o.delegation.roots, at: decidedAt, ...(o.delegation.revoked ? { revoked: o.delegation.revoked } : {}) });
  }

  const checks: DecisionChecks = { integrity: v.integrity, signature: v.signature, evaluator_trusted: v.trusted, request_binding, policy_binding, reproduced, freshness, principal_state, delegation };
  const { outcome, reasons } = classifyOutcome(checks as unknown as Record<string, Check>, Object.keys(checks));
  return { schema: "cool.authz-decision-report.v1", decision: d.decision, assurance: reproduced.status === "pass" ? "reproducible" : "trusted", outcome, checks, reasons };
}
