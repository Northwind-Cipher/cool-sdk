/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * CooL Incident Evidence: a case built from evidence references.
 *
 * An incident does not copy conclusions. It references envelopes by digest,
 * labels each one from its own verification report, and exports a signed
 * bundle whose timeline, gaps and contradictions the recipient recomputes.
 */
import type { KeyPair, Multihash } from "../../types";
import { exportBundle, type EvidenceBundle } from "../bundle";
import { buildTimeline, type EvidenceLabel, type Timeline } from "../correlation";
import type { EnvelopeInput, SignedEnvelope, VerificationReport } from "../envelope";
import type { PolicyDecisionRecord } from "../policy";
import type { TrustStore } from "../trust";

export type Severity = "low" | "medium" | "high" | "critical";

export class IncidentCase {
  readonly #evidence = new Map<Multihash, { env: SignedEnvelope; report?: VerificationReport }>();
  readonly #decisions: PolicyDecisionRecord[] = [];
  #closed = false;

  constructor(readonly incidentId: string, readonly title: string, readonly severity: Severity) {}

  opened(at: string, by: string): EnvelopeInput {
    return {
      event_type: "incident.opened",
      occurred_at: at,
      source: { system: "cool-incidents", event_id: this.incidentId },
      actor: { id: by, type: "human" },
      action: "open",
      resource: { type: "incident", ref: this.incidentId },
      payload: { incident_id: this.incidentId, title: this.title, severity: this.severity },
    };
  }

  /** Add evidence; returns the `incident.evidence_added` input that references it. */
  add(env: SignedEnvelope, report: VerificationReport | undefined, at: string, by: string): EnvelopeInput {
    if (this.#closed) throw new Error(`incident ${this.incidentId} is closed`);
    this.#evidence.set(env.digest, { env, ...(report ? { report } : {}) });
    const label: EvidenceLabel = !report ? "unknown"
      : report.overall_status === "pass" ? "verified"
        : report.checks.signature_valid.status === "pass" && report.checks.signer_trusted.status !== "pass" ? "source-asserted"
          : report.overall_status === "fail" ? "contradicted" : "unknown";
    return {
      event_type: "incident.evidence_added",
      occurred_at: at,
      source: { system: "cool-incidents", event_id: `${this.incidentId}:${env.digest}` },
      actor: { id: by, type: "human" },
      action: "add_evidence",
      resource: { type: "incident", ref: this.incidentId },
      relations: [{ type: "evidence", ref: env.digest }],
      payload: { incident_id: this.incidentId, evidence_ref: env.digest, label },
    };
  }

  addDecision(d: PolicyDecisionRecord): void {
    this.#decisions.push(d);
  }

  close(resolution: string, at: string, by: string): EnvelopeInput {
    this.#closed = true;
    return {
      event_type: "incident.closed",
      occurred_at: at,
      source: { system: "cool-incidents", event_id: `${this.incidentId}:closed` },
      actor: { id: by, type: "human" },
      action: "close",
      resource: { type: "incident", ref: this.incidentId },
      payload: { incident_id: this.incidentId, resolution },
    };
  }

  timeline(): Timeline {
    const items = [...this.#evidence.values()];
    return buildTimeline(items.map((i) => i.env), items.every((i) => i.report) ? items.map((i) => i.report!) : undefined);
  }

  /** Export every referenced envelope (plus the case's own records) as a signed bundle. */
  export(caseRecords: readonly SignedEnvelope[], trust: TrustStore, exporter: KeyPair, now?: Date): EvidenceBundle {
    return exportBundle({
      title: `incident ${this.incidentId}: ${this.title}`,
      envelopes: [...[...this.#evidence.values()].map((i) => i.env), ...caseRecords],
      decisions: this.#decisions,
      trust,
      exporter,
      ...(now ? { now } : {}),
    });
  }
}
