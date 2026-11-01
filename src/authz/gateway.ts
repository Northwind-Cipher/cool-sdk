/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * A tool-call enforcement boundary for agents.
 *
 * The gateway OWNS execution of the tools registered with it, so it is the
 * authoritative system for what happened. An agent cannot reach a protected
 * tool except through `invoke`, which, in order:
 *
 *   1. checks the tool and action match the request
 *   2. recomputes the parameter commitment from the plaintext (substitution check)
 *   3. verifies the decision: signature, trusted evaluator, request binding,
 *      freshness, principal state and delegation chain
 *   4. requires `permit` — deny, indeterminate and error are rejected
 *   5. checks audience and the observed execution context against the request
 *   6. consumes the nonce atomically — a replay is rejected; an unavailable
 *      store is rejected too (fail-closed for protected tools)
 *   7. runs the tool, and signs an external confirmation of the real outcome
 *
 * Every outcome — completed, rejected, failed — is confirmed and signed, so a
 * denial is evidence too. "Rejected" here means the tool did not run.
 */
import { randomBytes } from "node:crypto";
import { canonicalCbor } from "../canonical";
import { toHex } from "../codec";
import { mhSha256 } from "../multihash";
import type { KeyPair, Multihash } from "../types";
import type { Facts, PolicyDocument } from "../platform/policy";
import type { TrustStore } from "../platform/trust";
import { verifyDecision, type AuthorizationDecision, type DecisionReport } from "./decision";
import type { Delegation } from "./delegation";
import { compareExecution, type ExecutionContext } from "./execution";
import type { PrincipalDirectory } from "./principal";
import type { NonceStore } from "./replay";
import { paramsMatch, requestDigest, type AuthorizationRequest } from "./request";
import { signObject, verifyTrusted, type Signed } from "./signed";
import { check, type Check } from "../platform/status";

export type ConfirmationOutcome = "completed" | "rejected" | "failed";

export interface ExternalConfirmation {
  readonly schema: "cool.external-confirmation.v1";
  readonly confirmation_id: string;
  readonly target: string;
  readonly tool: string;
  readonly request_id: string;
  readonly request_digest: Multihash;
  readonly decision_id?: string;
  readonly outcome: ConfirmationOutcome;
  readonly reason: string;
  readonly response_digest?: Multihash;
  readonly external_ref?: string;
  readonly confirmed_at: string;
}

export interface ToolDefinition {
  readonly action: string;
  /** Resource prefix this tool acts on (exact id, or prefix ending in `*`). */
  readonly resource: string;
  /** Runs the side effect. Returns the response and an optional external reference. */
  execute(params: Readonly<Record<string, unknown>>): Promise<{ readonly response: unknown; readonly external_ref?: string }>;
}

export interface GatewayOptions {
  readonly id: string;
  readonly audience: string;
  readonly key: KeyPair;
  readonly trust: TrustStore;
  readonly nonces: NonceStore;
  readonly directory?: PrincipalDirectory;
  readonly roots?: readonly string[];
  readonly revokedDelegations?: () => ReadonlySet<string>;
  /** What workload is actually executing tools right now. */
  readonly observedExecution?: () => ExecutionContext | undefined;
  readonly now?: () => number;
}

export interface Invocation {
  readonly tool: string;
  readonly request: AuthorizationRequest;
  readonly params: Readonly<Record<string, unknown>>;
  readonly params_salt: string;
  readonly decision: Signed<AuthorizationDecision>;
  readonly delegation?: readonly Signed<Delegation>[];
  /** When the policy and facts are available, the gateway replays the decision too. */
  readonly policy?: PolicyDocument;
  readonly facts?: Facts;
  readonly commitmentKey?: Uint8Array;
}

export interface InvocationResult {
  readonly confirmation: Signed<ExternalConfirmation>;
  readonly decisionReport?: DecisionReport;
  readonly response?: unknown;
}

const covers = (pattern: string, value: string) => (pattern.endsWith("*") ? value.startsWith(pattern.slice(0, -1)) : pattern === value);

export class ToolGateway {
  readonly #tools = new Map<string, ToolDefinition>();
  readonly #o: GatewayOptions;

  constructor(options: GatewayOptions) {
    this.#o = options;
  }

  register(name: string, tool: ToolDefinition): void {
    if (this.#tools.has(name)) throw new Error(`tool ${name} is already registered`);
    this.#tools.set(name, tool);
  }

  #confirm(inv: Invocation, outcome: ConfirmationOutcome, reason: string, extra: { response_digest?: Multihash; external_ref?: string } = {}): Signed<ExternalConfirmation> {
    const now = this.#o.now?.() ?? Date.now();
    return signObject("cool.external-confirmation.v1", {
      schema: "cool.external-confirmation.v1",
      confirmation_id: `conf_${toHex(new Uint8Array(randomBytes(12)))}`,
      target: this.#o.id,
      tool: inv.tool,
      request_id: inv.request.request_id,
      request_digest: requestDigest(inv.request),
      decision_id: inv.decision?.body?.decision_id,
      outcome,
      reason,
      ...extra,
      confirmed_at: new Date(now).toISOString(),
    } satisfies ExternalConfirmation, this.#o.key);
  }

  async invoke(inv: Invocation): Promise<InvocationResult> {
    const now = this.#o.now?.() ?? Date.now();
    const r = inv.request;
    const tool = this.#tools.get(inv.tool);
    const reject = (reason: string, decisionReport?: DecisionReport): InvocationResult => ({ confirmation: this.#confirm(inv, "rejected", reason), ...(decisionReport ? { decisionReport } : {}) });

    if (!tool) return reject("unknown_tool");
    if (tool.action !== r.action || !covers(tool.resource, r.resource)) return reject("tool_action_mismatch");
    if (r.audience !== this.#o.audience) return reject("wrong_audience");
    if (!paramsMatch(r, inv.params, inv.params_salt, inv.commitmentKey)) return reject("parameter_mismatch");

    const amount = typeof inv.params["amount"] === "number" ? (inv.params["amount"] as number) : undefined;
    const report = verifyDecision(inv.decision, {
      request: r,
      trust: this.#o.trust,
      mode: "enforcement",
      now,
      ...(inv.policy ? { policy: inv.policy } : {}),
      ...(inv.facts ? { facts: inv.facts } : {}),
      ...(this.#o.directory ? { directory: this.#o.directory } : {}),
      ...(inv.delegation ? { delegation: { chain: inv.delegation, roots: this.#o.roots ?? [], revoked: this.#o.revokedDelegations?.() ?? new Set(), ...(amount !== undefined ? { amount } : {}) } } : {}),
    });
    // Required at the boundary: everything except replay inputs the caller chose not to send.
    const blocking = Object.entries(report.checks).find(([name, c]) => c.status === "fail" || (c.status !== "pass" && c.status !== "not_applicable" && !(["policy_binding", "reproduced"].includes(name) && c.status === "not_checked")));
    if (blocking) return reject(`decision_not_acceptable:${blocking[0]}:${blocking[1].reason}`, report);
    if (r.delegation && report.checks.delegation.status !== "pass") return reject("delegation_not_verified", report);
    if (report.decision !== "permit") return reject(`decision_${report.decision}`, report);

    const exec = compareExecution(r.execution, this.#o.observedExecution?.());
    if (exec.status === "fail" || exec.status === "unknown") return reject(exec.reason, report);

    const consumed = await this.#o.nonces.consume(this.#o.audience, r.nonce, r.request_id);
    if (consumed === "replayed") return reject("replayed", report);
    if (consumed === "unavailable") return reject("replay_store_unavailable", report);

    try {
      const out = await tool.execute(inv.params);
      return {
        confirmation: this.#confirm(inv, "completed", "executed", { response_digest: mhSha256(canonicalCbor(JSON.parse(JSON.stringify(out.response ?? null)))), ...(out.external_ref ? { external_ref: out.external_ref } : {}) }),
        decisionReport: report,
        response: out.response,
      };
    } catch (err) {
      return { confirmation: this.#confirm(inv, "failed", `tool_error:${(err as Error).message.slice(0, 120)}`), decisionReport: report };
    }
  }
}

/** Verify a confirmation offline: signed by a trusted enforcement key, for this request. */
export function verifyConfirmation(s: Signed<ExternalConfirmation>, o: { readonly request: AuthorizationRequest; readonly trust: TrustStore; readonly now?: number }): { readonly outcome: ConfirmationOutcome | "unverified"; readonly checks: Record<string, Check> } {
  const v = verifyTrusted("cool.external-confirmation.v1", s, o.trust, "enforcement", o.now ?? Date.now());
  const binding = s.body.request_digest === requestDigest(o.request) && s.body.request_id === o.request.request_id
    ? check("pass", "request_bound", `confirms ${o.request.request_id}`)
    : check("fail", "request_mismatch", "the confirmation is for a different request");
  const checks = { integrity: v.integrity, signature: v.signature, enforcement_trusted: v.trusted, request_binding: binding };
  const ok = Object.values(checks).every((c) => c.status === "pass");
  return { outcome: ok ? s.body.outcome : "unverified", checks };
}
