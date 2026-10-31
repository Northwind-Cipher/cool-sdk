/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Enforcement: asking an authoritative system to act, and recording what it
 * actually did.
 *
 * CooL never claims to have blocked or admitted anything on its own say-so.
 * The layers stay separate:
 *
 *   decision      the policy engine's verdict (PolicyDecisionRecord)
 *   request       CooL asks an adapter to act          → "requested"
 *   execution     the external system answers          → accepted | completed | failed | rejected
 *   confirmation  CooL re-reads the external state     → confirmed: true | false
 *
 * Safe defaults: the coordinator is DISABLED unless constructed with
 * `enabled: true`; every request is a DRY RUN unless the caller passes
 * `dryRun: false` AND the decision came from a policy in enforce mode. A
 * request id is an idempotency key: repeating it returns the first result and
 * never acts twice. A timeout is `timed_out` with `confirmed: false` — state
 * unknown until `reconcile` asks the external system what really happened.
 */
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync } from "node:fs";
import { basename, join } from "node:path";
import { canonicalCbor } from "../canonical";
import { mhSha256 } from "../multihash";
import type { Multihash } from "../types";
import type { Decision, PolicyDecisionRecord } from "./policy";

export type EnforcementState = "not_executed" | "accepted" | "completed" | "failed" | "rejected" | "timed_out" | "unknown";

export interface EnforcementRequest {
  readonly request_id: string;
  readonly adapter: string;
  readonly action: string;
  readonly target: string;
  readonly params: Readonly<Record<string, string>>;
  readonly decision_ref: Multihash;
  readonly dry_run: boolean;
  readonly requested_at: string;
}

export interface EnforcementResult {
  readonly request_id: string;
  readonly adapter: string;
  readonly state: EnforcementState;
  /** True only when CooL re-read the external system and saw the effect. */
  readonly confirmed: boolean;
  readonly external_ref?: string;
  readonly detail: string;
  readonly observed_at: string;
}

/** An integration with a system that has authority to act. */
export interface EnforcementAdapter {
  readonly id: string;
  /** What this adapter needs, stated up front so operators can scope it. */
  readonly permissions: readonly string[];
  readonly actions: readonly string[];
  /** Which policy decisions may trigger each action. */
  readonly allowedDecisions: Readonly<Record<string, readonly Decision[]>>;
  execute(request: EnforcementRequest, signal: AbortSignal): Promise<Omit<EnforcementResult, "confirmed" | "observed_at">>;
  /** Re-read external state: did the requested effect actually happen? */
  confirm(request: EnforcementRequest): Promise<{ readonly confirmed: boolean; readonly detail: string; readonly external_ref?: string }>;
}

export interface AuditEvent {
  readonly kind: "requested" | "result" | "reconciled" | "refused";
  readonly request: EnforcementRequest;
  readonly result?: EnforcementResult;
  readonly at: string;
}

export interface CoordinatorOptions {
  readonly enabled?: boolean;
  readonly timeoutMs?: number;
  readonly audit?: (event: AuditEvent) => void;
  readonly clock?: () => Date;
}

export class EnforcementCoordinator {
  readonly #enabled: boolean;
  readonly #timeoutMs: number;
  readonly #audit: (event: AuditEvent) => void;
  readonly #clock: () => Date;
  readonly #results = new Map<string, EnforcementResult>();
  readonly #requests = new Map<string, EnforcementRequest>();

  constructor(options: CoordinatorOptions = {}) {
    this.#enabled = options.enabled ?? false;
    this.#timeoutMs = options.timeoutMs ?? 30_000;
    this.#audit = options.audit ?? (() => undefined);
    this.#clock = options.clock ?? (() => new Date());
  }

  get enabled(): boolean {
    return this.#enabled;
  }

  async request(
    decision: PolicyDecisionRecord,
    adapter: EnforcementAdapter,
    action: string,
    target: string,
    options: { readonly requestId: string; readonly dryRun?: boolean; readonly params?: Readonly<Record<string, string>> },
  ): Promise<EnforcementResult> {
    const prior = this.#results.get(options.requestId);
    if (prior) return prior;

    const at = this.#clock().toISOString();
    const wantLive = options.dryRun === false;
    const live = wantLive && this.#enabled && decision.enforced;
    const request: EnforcementRequest = {
      request_id: options.requestId,
      adapter: adapter.id,
      action,
      target,
      params: options.params ?? {},
      decision_ref: mhSha256(canonicalCbor(decision)),
      dry_run: !live,
      requested_at: at,
    };
    this.#requests.set(request.request_id, request);
    this.#audit({ kind: "requested", request, at });

    const finish = (r: Omit<EnforcementResult, "observed_at">): EnforcementResult => {
      const result = { ...r, observed_at: this.#clock().toISOString() };
      this.#results.set(request.request_id, result);
      this.#audit({ kind: r.state === "rejected" && !live ? "refused" : "result", request, result, at: result.observed_at });
      return result;
    };

    if (!adapter.actions.includes(action)) {
      return finish({ request_id: request.request_id, adapter: adapter.id, state: "rejected", confirmed: false, detail: `adapter ${adapter.id} does not support ${action}` });
    }
    if (!(adapter.allowedDecisions[action] ?? []).includes(decision.decision)) {
      return finish({ request_id: request.request_id, adapter: adapter.id, state: "rejected", confirmed: false, detail: `decision ${decision.decision} does not permit ${action}` });
    }
    if (!live) {
      const why = !wantLive ? "dry run requested" : !this.#enabled ? "enforcement is disabled on this coordinator" : "policy is in observe mode";
      return finish({ request_id: request.request_id, adapter: adapter.id, state: "not_executed", confirmed: false, detail: `${why}: would ${action} ${target}` });
    }

    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<"timeout">((resolve) => {
      timer = setTimeout(() => { controller.abort(); resolve("timeout"); }, this.#timeoutMs);
    });
    try {
      const outcome = await Promise.race([adapter.execute(request, controller.signal), timeout]);
      if (outcome === "timeout") {
        return finish({ request_id: request.request_id, adapter: adapter.id, state: "timed_out", confirmed: false, detail: `no answer within ${this.#timeoutMs} ms; external state unknown until reconciled` });
      }
      let confirmed = false;
      let detail = outcome.detail;
      if (outcome.state === "completed") {
        const c = await adapter.confirm(request);
        confirmed = c.confirmed;
        detail = `${outcome.detail}; confirmation: ${c.detail}`;
      }
      return finish({ ...outcome, confirmed, detail });
    } catch (err) {
      return finish({ request_id: request.request_id, adapter: adapter.id, state: "unknown", confirmed: false, detail: `adapter error: ${(err as Error).message}; external state unknown until reconciled` });
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /** Ask the external system what actually happened to an unresolved request. */
  async reconcile(requestId: string, adapter: EnforcementAdapter): Promise<EnforcementResult> {
    const request = this.#requests.get(requestId);
    const prior = this.#results.get(requestId);
    if (!request || !prior) throw new Error(`unknown enforcement request ${requestId}`);
    if (request.dry_run) return prior;
    const c = await adapter.confirm(request);
    const result: EnforcementResult = {
      ...prior,
      state: c.confirmed ? "completed" : prior.state === "timed_out" || prior.state === "unknown" ? "unknown" : prior.state,
      confirmed: c.confirmed,
      detail: `reconciled: ${c.detail}`,
      ...(c.external_ref ? { external_ref: c.external_ref } : {}),
      observed_at: this.#clock().toISOString(),
    };
    this.#results.set(requestId, result);
    this.#audit({ kind: "reconciled", request, result, at: result.observed_at });
    return result;
  }
}

/* ── reference adapter: a local deployment target ─────────────────────── */

const sha256File = (path: string) => `mh:sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;

/**
 * A real, local deployment target: a directory that only accepts an artifact
 * whose bytes hash to the digest the request names. The TARGET recomputes the
 * digest itself — it does not take CooL's word — so a tampered artifact is
 * refused at the actual enforcement point.
 *
 * It stands in for a cluster admission controller in demos and tests. It is
 * not Kubernetes, and results from it say nothing about any other target.
 *
 * Permissions: write access to `root` only.
 */
export class LocalDirectoryTarget implements EnforcementAdapter {
  readonly id: string;
  readonly permissions: readonly string[];
  readonly actions = ["admit"] as const;
  readonly allowedDecisions = { admit: ["allow", "audit_only"] as const };

  constructor(readonly root: string, id = "local-directory") {
    this.id = id;
    this.permissions = [`write ${root}`];
    mkdirSync(root, { recursive: true });
  }

  async execute(request: EnforcementRequest): Promise<Omit<EnforcementResult, "confirmed" | "observed_at">> {
    const source = request.params["artifact_path"];
    const expected = request.params["artifact_digest"];
    const base = { request_id: request.request_id, adapter: this.id };
    if (!source || !expected) return { ...base, state: "rejected", detail: "artifact_path and artifact_digest are required" };
    if (!existsSync(source)) return { ...base, state: "rejected", detail: `artifact ${source} does not exist` };
    const actual = sha256File(source);
    if (actual !== expected) {
      return { ...base, state: "rejected", detail: `target recomputed ${actual}; the request names ${expected} — refused` };
    }
    const dest = join(this.root, basename(source));
    copyFileSync(source, `${dest}.partial`);
    renameSync(`${dest}.partial`, dest);
    return { ...base, state: "completed", external_ref: dest, detail: `deployed ${basename(source)} to ${this.root}` };
  }

  async confirm(request: EnforcementRequest): Promise<{ confirmed: boolean; detail: string; external_ref?: string }> {
    const source = request.params["artifact_path"];
    if (!source) return { confirmed: false, detail: "no artifact named" };
    const dest = join(this.root, basename(source));
    if (!existsSync(dest)) return { confirmed: false, detail: `${dest} is not present` };
    const ok = sha256File(dest) === request.params["artifact_digest"];
    return ok ? { confirmed: true, detail: `${dest} present with the approved digest`, external_ref: dest } : { confirmed: false, detail: `${dest} present but its digest differs` };
  }
}
