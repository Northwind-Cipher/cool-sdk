/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * CooL Runtime Guard: ingest runtime signals, correlate, decide, respond.
 *
 * It is not an EDR. It takes signed runtime events from existing sensors,
 * refuses to act on anything it cannot attribute (an event whose signer is not
 * trusted is recorded as source-asserted and never triggers a response),
 * de-duplicates by source event id, and notices when a source goes quiet —
 * suppressed telemetry shows up as a heartbeat gap, not as "all clear".
 *
 * Responses go through the shared policy engine and enforcement coordinator,
 * so they are dry runs unless enforcement is explicitly enabled.
 */
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import type { SignedEnvelope, VerificationReport } from "../envelope";
import type { EnforcementAdapter, EnforcementCoordinator, EnforcementRequest, EnforcementResult } from "../enforcement";
import { evaluatePolicy, type PolicyDecisionRecord, type PolicyDocument } from "../policy";

export type IngestOutcome = "accepted" | "duplicate" | "untrusted_source" | "rejected";

export const RUNTIME_POLICY: PolicyDocument = {
  schema: "cool.policy.v1",
  id: "runtime-guard",
  version: "1.0.0",
  mode: "observe",
  default: "allow",
  on_unknown: "audit_only",
  rules: [
    { id: "privilege-escalation", when: { all: [{ fact: "event.type", op: "eq", value: "runtime.privilege_change" }, { fact: "privilege.to", op: "in", value: ["root", "admin", "cluster-admin"] }] }, decision: "quarantine", reason: "privilege_escalation" },
    { id: "unexpected-egress", when: { all: [{ fact: "event.type", op: "eq", value: "runtime.network" }, { not: { fact: "network.destination_allowed", op: "eq", value: true } }] }, decision: "require_approval", reason: "unexpected_egress" },
    { id: "unknown-executable", when: { all: [{ fact: "event.type", op: "eq", value: "runtime.process" }, { fact: "process.known", op: "eq", value: false }] }, decision: "audit_only", reason: "unknown_executable" },
  ],
};

export class RuntimeGuard {
  readonly #seen = new Set<string>();
  readonly #heartbeats = new Map<string, { at: number; sequence: number }>();
  readonly #sequenceGaps: Array<{ source: string; missing: number[] }> = [];

  constructor(readonly options: { readonly allowedDestinations?: readonly string[]; readonly knownExecutables?: readonly string[]; readonly policy?: PolicyDocument } = {}) {}

  /** Accept one verified runtime event. */
  ingest(env: SignedEnvelope, report: VerificationReport): IngestOutcome {
    if (report.checks.signature_valid.status !== "pass") return "rejected";
    if (report.checks.signer_trusted.status !== "pass") return "untrusted_source";
    const key = `${env.core.source.system}/${env.core.source.instance ?? ""}/${env.core.source.event_id ?? env.digest}`;
    if (this.#seen.has(key)) return "duplicate";
    this.#seen.add(key);
    if (env.core.event_type === "runtime.heartbeat") {
      const source = String(env.core.payload["source"]);
      const seq = Number(env.core.payload["sequence"]);
      const prev = this.#heartbeats.get(source);
      if (prev && seq > prev.sequence + 1) this.#sequenceGaps.push({ source, missing: Array.from({ length: seq - prev.sequence - 1 }, (_, i) => prev.sequence + 1 + i) });
      if (!prev || seq > prev.sequence) this.#heartbeats.set(source, { at: Date.parse(env.core.occurred_at), sequence: seq });
    }
    return "accepted";
  }

  /** Sources silent for longer than allowed, plus heartbeat sequence gaps. */
  telemetryGaps(now: number, maxSilenceMs: number): { readonly silent: readonly string[]; readonly sequenceGaps: ReadonlyArray<{ source: string; missing: number[] }> } {
    const silent = [...this.#heartbeats].filter(([, h]) => now - h.at > maxSilenceMs).map(([s]) => s);
    return { silent, sequenceGaps: [...this.#sequenceGaps] };
  }

  /** Decide on one event. Unknown facts stay unknown. */
  decide(env: SignedEnvelope, now = new Date()): PolicyDecisionRecord {
    const p = env.core.payload;
    const facts = {
      "event.type": env.core.event_type,
      "privilege.to": p["to"],
      "network.destination_allowed": env.core.event_type === "runtime.network" && this.options.allowedDestinations ? this.options.allowedDestinations.includes(String(p["destination"])) : undefined,
      "process.known": env.core.event_type === "runtime.process" && this.options.knownExecutables && p["executable_digest"] ? this.options.knownExecutables.includes(String(p["executable_digest"])) : undefined,
    };
    return evaluatePolicy(this.options.policy ?? RUNTIME_POLICY, facts, { now, inputRefs: [env.digest] });
  }

  /** Ask the response adapter to isolate a workload when the decision calls for it. */
  async respond(env: SignedEnvelope, decision: PolicyDecisionRecord, coordinator: EnforcementCoordinator, adapter: EnforcementAdapter, dryRun = true): Promise<EnforcementResult | null> {
    if (decision.decision !== "quarantine" && decision.decision !== "deny") return null;
    return coordinator.request(decision, adapter, "isolate", String(env.core.payload["workload"]), {
      requestId: `isolate:${env.digest}`,
      ...(dryRun ? {} : { dryRun: false }),
      params: { workload: String(env.core.payload["workload"]) },
    });
  }
}

/**
 * Reference response target: a local deny-list file that a sidecar or proxy
 * reads. Real side effect, locally scoped. Confirmation re-reads the file.
 */
export class LocalDenylistTarget implements EnforcementAdapter {
  readonly id = "local-denylist";
  readonly actions = ["isolate"];
  readonly allowedDecisions = { isolate: ["quarantine", "deny"] as const };
  readonly permissions: readonly string[];

  constructor(readonly path: string) {
    this.permissions = [`write ${path}`];
    if (!existsSync(path)) writeFileSync(path, "");
  }

  async execute(request: EnforcementRequest): Promise<Omit<EnforcementResult, "confirmed" | "observed_at">> {
    const workload = request.params["workload"];
    if (!workload) return { request_id: request.request_id, adapter: this.id, state: "rejected", detail: "no workload named" };
    if (!this.#listed(workload)) appendFileSync(this.path, `${workload}\n`);
    return { request_id: request.request_id, adapter: this.id, state: "completed", detail: `${workload} added to ${this.path}`, external_ref: this.path };
  }

  async confirm(request: EnforcementRequest): Promise<{ confirmed: boolean; detail: string }> {
    const w = request.params["workload"] ?? "";
    return this.#listed(w) ? { confirmed: true, detail: `${w} is on the deny-list` } : { confirmed: false, detail: `${w} is not on the deny-list` };
  }

  #listed(workload: string): boolean {
    return readFileSync(this.path, "utf8").split("\n").includes(workload);
  }
}
