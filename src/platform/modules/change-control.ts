/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * CooL Change Control: approved configuration, drift, staged rollout.
 *
 * An approval is bound to a digest. Applying anything else — even a one-byte
 * edit after approval — makes the approval not match, and a stale or
 * self-granted approval is a fact the policy can deny on. Rollout moves stage
 * by stage only on a passing health signal; an unknown health signal holds,
 * it never promotes. Rollback is itself a change and needs an approval.
 */
import type { Multihash } from "../../types";
import type { EnvelopeInput } from "../envelope";
import type { Facts, PolicyDocument } from "../policy";

export interface Approval {
  readonly approver: string;
  readonly approved_digest: Multihash;
  readonly approved_at: string;
}

export function changeFacts(input: {
  readonly author: string;
  readonly appliedDigest: Multihash;
  readonly approval?: Approval;
  readonly maxApprovalAgeMs: number;
  readonly now: number;
}): Facts {
  const a = input.approval;
  return {
    "approval.present": !!a,
    "approval.matches_applied": a ? a.approved_digest === input.appliedDigest : undefined,
    "approval.stale": a ? input.now - Date.parse(a.approved_at) > input.maxApprovalAgeMs : undefined,
    "approval.self_approved": a ? a.approver === input.author : undefined,
  };
}

export const CHANGE_POLICY: PolicyDocument = {
  schema: "cool.policy.v1",
  id: "change-control",
  version: "1.0.0",
  mode: "enforce",
  default: "allow",
  on_unknown: "require_approval",
  rules: [
    { id: "needs-approval", when: { fact: "approval.present", op: "eq", value: false }, decision: "require_approval", reason: "approval_missing" },
    { id: "approved-bytes", when: { fact: "approval.matches_applied", op: "eq", value: false }, decision: "deny", reason: "changed_after_approval" },
    { id: "fresh-approval", when: { fact: "approval.stale", op: "eq", value: true }, decision: "require_approval", reason: "approval_stale" },
    { id: "four-eyes", when: { fact: "approval.self_approved", op: "eq", value: true }, decision: "deny", reason: "self_approval" },
  ],
};

/** A drift record, or null when the observed configuration is the approved one. */
export function detectDrift(configRef: string, expected: Multihash, observed: Multihash, at: string): EnvelopeInput | null {
  if (expected === observed) return null;
  return {
    event_type: "configuration.drift_detected",
    occurred_at: at,
    source: { system: "cool-change-control", instance: configRef },
    actor: { id: "cool:drift-detector", type: "service" },
    action: "detect_drift",
    resource: { type: "configuration", ref: configRef },
    provenance: { collection_method: "observed" },
    payload: { config_ref: configRef, expected_digest: expected, observed_digest: observed },
  };
}

export type Health = "pass" | "fail" | "unknown";

/** Staged rollout: promote on pass, hold on unknown, roll back on fail (with approval). */
export class RolloutController {
  #stage = 0;
  #state: "rolling" | "done" | "rolled_back" | "rollback_pending" = "rolling";
  readonly #records: EnvelopeInput[] = [];

  constructor(readonly rolloutId: string, readonly artifactDigest: Multihash, readonly stages: ReadonlyArray<{ readonly name: string; readonly percent: number }>) {
    if (stages.length === 0) throw new Error("a rollout needs at least one stage");
  }

  get stage(): string {
    return this.stages[this.#stage]!.name;
  }

  get state(): string {
    return this.#state;
  }

  records(): readonly EnvelopeInput[] {
    return [...this.#records];
  }

  #record(health: Health, action: "promote" | "hold" | "rollback", at: string): void {
    const s = this.stages[this.#stage]!;
    this.#records.push({
      event_type: "rollout.stage",
      occurred_at: at,
      source: { system: "cool-rollout", event_id: `${this.rolloutId}:${this.#records.length}` },
      actor: { id: "cool:rollout-controller", type: "service" },
      action,
      resource: { type: "rollout", ref: this.rolloutId },
      payload: { rollout_id: this.rolloutId, artifact_digest: this.artifactDigest, stage: s.name, percent: s.percent, health, action },
    });
  }

  /** Report the health of the current stage; returns what the controller does. */
  report(health: Health, at: string): "promote" | "hold" | "rollback" | "done" {
    if (this.#state !== "rolling") throw new Error(`rollout is ${this.#state}`);
    if (health === "fail") {
      this.#record(health, "rollback", at);
      this.#state = "rollback_pending";
      return "rollback";
    }
    if (health === "unknown") {
      this.#record(health, "hold", at);
      return "hold";
    }
    this.#record(health, "promote", at);
    if (this.#stage === this.stages.length - 1) {
      this.#state = "done";
      return "done";
    }
    this.#stage++;
    return "promote";
  }

  /** Execute a pending rollback. Unapproved rollbacks are refused. */
  rollback(approval: { readonly approver: string } | undefined): "rolled_back" | "rejected" {
    if (this.#state !== "rollback_pending" && this.#state !== "rolling") return "rejected";
    if (!approval?.approver) return "rejected";
    this.#state = "rolled_back";
    return "rolled_back";
  }
}
