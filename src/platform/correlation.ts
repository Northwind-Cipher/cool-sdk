/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Correlation and timelines for incident reconstruction.
 *
 * Links are built from evidence, never from assumptions, and every link says
 * how it was made:
 *
 *   deterministic  explicit relation/provenance references, or a shared stable
 *                  identifier (artifact digest, deployment id, build id, …)
 *   heuristic      same actor within a bounded time window — a lead, not a fact
 *
 * Each link records the matching fields and the rule version. Timeline entries
 * carry a label: verified, source-asserted (signed, but the signer is not
 * trusted), unknown, contradicted (times or sequences that cannot both be
 * true) or missing (referenced but absent). Heuristic links are labelled
 * inferred. Contradictions and gaps are kept, never smoothed away.
 */
import type { Multihash } from "../types";
import type { SignedEnvelope, VerificationReport } from "./envelope";

export const CORRELATION_RULES = "cool.correlation.v1";

export type EvidenceLabel = "verified" | "source-asserted" | "inferred" | "unknown" | "contradicted" | "missing";

export interface Link {
  readonly from: Multihash;
  readonly to: Multihash;
  readonly kind: "deterministic" | "heuristic";
  readonly rule: string;
  readonly fields: readonly string[];
  readonly label: "verified" | "inferred";
}

export interface TimelineEntry {
  readonly at: string;
  readonly digest: Multihash;
  readonly event_id: string;
  readonly event_type: string;
  readonly actor: string;
  readonly summary: string;
  readonly label: EvidenceLabel;
  readonly notes: readonly string[];
}

export interface Timeline {
  readonly rules: string;
  readonly entries: readonly TimelineEntry[];
  readonly links: readonly Link[];
  readonly gaps: ReadonlyArray<{ readonly ref: Multihash; readonly referenced_by: string }>;
  readonly contradictions: readonly string[];
}

const STABLE_IDS = ["artifact_digest", "deployment_id", "build_id", "release_id", "incident_id", "credential_ref", "config_ref", "rollout_id", "request_id"] as const;

export interface CorrelateOptions {
  /** Window for heuristic same-actor links. Default 10 minutes. 0 disables. */
  readonly heuristicWindowMs?: number;
}

export function correlate(envelopes: readonly SignedEnvelope[], options: CorrelateOptions = {}): Link[] {
  const links: Link[] = [];
  const known = new Set(envelopes.map((e) => e.digest));
  for (const e of envelopes) {
    for (const ref of e.core.provenance.refs) if (known.has(ref)) links.push({ from: e.digest, to: ref, kind: "deterministic", rule: `${CORRELATION_RULES}/provenance`, fields: ["provenance.refs"], label: "verified" });
    for (const rel of e.core.relations) if (known.has(rel.ref)) links.push({ from: e.digest, to: rel.ref, kind: "deterministic", rule: `${CORRELATION_RULES}/relation:${rel.type}`, fields: ["relations"], label: "verified" });
  }
  for (let i = 0; i < envelopes.length; i++) {
    for (let j = i + 1; j < envelopes.length; j++) {
      const a = envelopes[i]!;
      const b = envelopes[j]!;
      const shared = STABLE_IDS.filter((f) => a.core.payload[f] !== undefined && a.core.payload[f] === b.core.payload[f]);
      if (a.core.payload["artifact_digests"] && typeof b.core.payload["artifact_digest"] === "string" && (a.core.payload["artifact_digests"] as string[]).includes(b.core.payload["artifact_digest"] as string)) shared.push("artifact_digest" as never);
      if (shared.length) links.push({ from: a.digest, to: b.digest, kind: "deterministic", rule: `${CORRELATION_RULES}/shared-id`, fields: [...new Set(shared)], label: "verified" });
    }
  }
  const window = options.heuristicWindowMs ?? 10 * 60_000;
  if (window > 0) {
    for (let i = 0; i < envelopes.length; i++) {
      for (let j = i + 1; j < envelopes.length; j++) {
        const a = envelopes[i]!;
        const b = envelopes[j]!;
        if (a.core.actor.id !== b.core.actor.id || a.core.actor.type === "unknown") continue;
        if (links.some((l) => (l.from === a.digest && l.to === b.digest) || (l.from === b.digest && l.to === a.digest))) continue;
        if (Math.abs(Date.parse(a.core.occurred_at) - Date.parse(b.core.occurred_at)) <= window) {
          links.push({ from: a.digest, to: b.digest, kind: "heuristic", rule: `${CORRELATION_RULES}/same-actor-window:${window}ms`, fields: ["actor.id", "occurred_at"], label: "inferred" });
        }
      }
    }
  }
  return links;
}

function summarise(e: SignedEnvelope): string {
  const p = e.core.payload;
  const key = STABLE_IDS.find((f) => p[f] !== undefined);
  return `${e.core.action} ${e.core.resource.type}:${e.core.resource.ref}${key ? ` (${key}=${String(p[key]).slice(0, 32)})` : ""}`;
}

/** Order evidence by occurrence and label each entry from its verification report. */
export function buildTimeline(envelopes: readonly SignedEnvelope[], reports?: readonly VerificationReport[], options: CorrelateOptions = {}): Timeline {
  const links = correlate(envelopes, options);
  const known = new Set(envelopes.map((e) => e.digest));
  const contradictions: string[] = [];
  const gaps: Array<{ ref: Multihash; referenced_by: string }> = [];

  for (const e of envelopes) {
    for (const ref of [...e.core.provenance.refs, ...e.core.relations.map((r) => r.ref)]) {
      if (!known.has(ref)) gaps.push({ ref, referenced_by: e.core.event_id });
    }
  }
  // Pairs whose order is fixed by meaning: a completion cannot precede its request.
  const pairs: Array<[string, string, string]> = [["deployment.requested", "deployment.completed", "deployment_id"], ["build.started", "build.completed", "build_id"], ["incident.opened", "incident.closed", "incident_id"]];
  for (const [first, then, key] of pairs) {
    for (const a of envelopes.filter((e) => e.core.event_type === first)) {
      for (const b of envelopes.filter((e) => e.core.event_type === then && e.core.payload[key] === a.core.payload[key])) {
        if (Date.parse(b.core.occurred_at) < Date.parse(a.core.occurred_at)) {
          contradictions.push(`${then} ${String(b.core.payload[key])} at ${b.core.occurred_at} precedes ${first} at ${a.core.occurred_at}`);
        }
      }
    }
  }

  const entries: TimelineEntry[] = envelopes.map((e, i) => {
    const r = reports?.[i];
    const notes: string[] = [];
    let label: EvidenceLabel = "unknown";
    if (r) {
      if (r.overall_status === "pass") label = "verified";
      else if (r.checks.signature_valid.status === "pass" && r.checks.signer_trusted.status !== "pass") label = "source-asserted";
      else if (r.overall_status === "fail") { label = "contradicted"; notes.push(...r.reasons); }
      else notes.push(...r.reasons);
      if (r.checks.evidence_complete.status === "fail") notes.push(r.checks.evidence_complete.detail);
    } else notes.push("not verified");
    if (contradictions.some((c) => c.includes(String(e.core.payload["deployment_id"] ?? e.core.payload["build_id"] ?? e.core.payload["incident_id"] ?? "\u0000")))) {
      label = "contradicted";
      notes.push("timestamp contradiction with a related event");
    }
    return { at: e.core.occurred_at, digest: e.digest, event_id: e.core.event_id, event_type: e.core.event_type, actor: e.core.actor.id, summary: summarise(e), label, notes };
  });
  for (const g of gaps) {
    entries.push({ at: "", digest: g.ref, event_id: "", event_type: "unknown", actor: "", summary: `referenced by ${g.referenced_by} but not present`, label: "missing", notes: [] });
  }
  entries.sort((a, b) => (a.at === b.at ? a.digest.localeCompare(b.digest) : a.at === "" ? 1 : b.at === "" ? -1 : a.at.localeCompare(b.at)));
  return { rules: CORRELATION_RULES, entries, links, gaps, contradictions };
}
