/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Portable evidence bundles: everything needed to re-verify a set of events
 * somewhere else, offline.
 *
 * A bundle holds signed envelopes, the policy decisions they cite, the public
 * half of the trust snapshot the exporter used, and a deterministic manifest
 * (entries sorted by digest, then digested) signed by the exporter.
 *
 * The verifier trusts none of the exporter's conclusions. It recomputes every
 * envelope report, checks the manifest against the contents, resolves every
 * reference inside the bundle, and builds the timeline itself. The trust
 * snapshot inside the bundle is used only when the caller supplies none, and
 * the report then says the trust was self-asserted by the exporter.
 */
import { canonicalCbor } from "../canonical";
import { mhSha256, multihashDigest } from "../multihash";
import { concatBytes, utf8 } from "../codec";
import { hybridSign, hybridVerify } from "../sign";
import type { KeyPair, Multihash, SignatureBlock } from "../types";
import { verifyEnvelope, type SignedEnvelope, type VerificationReport, type VerifyEnvelopeOptions } from "./envelope";
import type { PolicyDecisionRecord } from "./policy";
import { check, overallOf, type Check, type OverallStatus } from "./status";
import { TrustStore, type TrustSnapshot } from "./trust";
import { buildTimeline, type Timeline } from "./correlation";

export interface BundleManifestEntry {
  readonly kind: "envelope" | "decision";
  readonly id: string;
  readonly digest: Multihash;
}

export interface EvidenceBundle {
  readonly schema: "cool.bundle.v1";
  readonly created_at: string;
  readonly title: string;
  readonly envelopes: readonly SignedEnvelope[];
  readonly decisions: readonly PolicyDecisionRecord[];
  readonly trust_snapshot: TrustSnapshot;
  readonly manifest: { readonly entries: readonly BundleManifestEntry[]; readonly digest: Multihash };
  readonly signature: SignatureBlock;
  readonly exporter_key: { readonly key_id: string; readonly ml_dsa_pub: string; readonly ed25519_pub: string };
}

const MANIFEST_DOMAIN = utf8("cool.bundle.manifest.v1\0");

function manifestOf(envelopes: readonly SignedEnvelope[], decisions: readonly PolicyDecisionRecord[]) {
  const entries: BundleManifestEntry[] = [
    ...envelopes.map((e) => ({ kind: "envelope" as const, id: e.core.event_id, digest: e.digest })),
    ...decisions.map((d) => ({ kind: "decision" as const, id: `${d.policy_id}@${d.policy_version}:${d.evaluated_at}`, digest: mhSha256(canonicalCbor(d)) })),
  ].sort((a, b) => (a.digest < b.digest ? -1 : a.digest > b.digest ? 1 : 0));
  return { entries, digest: mhSha256(concatBytes(MANIFEST_DOMAIN, canonicalCbor(entries))) };
}

export function exportBundle(input: {
  readonly title: string;
  readonly envelopes: readonly SignedEnvelope[];
  readonly decisions?: readonly PolicyDecisionRecord[];
  readonly trust: TrustStore;
  readonly exporter: KeyPair;
  readonly now?: Date;
}): EvidenceBundle {
  const decisions = input.decisions ?? [];
  const manifest = manifestOf(input.envelopes, decisions);
  return {
    schema: "cool.bundle.v1",
    created_at: (input.now ?? new Date()).toISOString(),
    title: input.title,
    envelopes: input.envelopes,
    decisions,
    trust_snapshot: input.trust.snapshot(),
    manifest,
    signature: hybridSign(multihashDigest(manifest.digest), input.exporter),
    exporter_key: { key_id: input.exporter.keyId, ...input.exporter.directoryEntry },
  };
}

export interface BundleReport {
  readonly schema: "cool.bundle-report.v1";
  readonly overall_status: OverallStatus;
  readonly checks: {
    readonly manifest_valid: Check;
    readonly exporter_signature_valid: Check;
    readonly trust_source: Check;
    readonly envelopes_valid: Check;
    readonly evidence_complete: Check;
    readonly decisions_bound: Check;
  };
  readonly envelopes: ReadonlyArray<{ readonly event_id: string; readonly event_type: string; readonly overall_status: OverallStatus; readonly reasons: readonly string[] }>;
  readonly timeline: Timeline;
  readonly reasons: readonly string[];
}

/** Import and verify a bundle from its JSON form, recomputing everything. */
export function verifyBundle(
  bundle: EvidenceBundle,
  options: Omit<VerifyEnvelopeOptions, "trust" | "resolve"> & { readonly trust?: TrustStore },
): BundleReport {
  if (bundle?.schema !== "cool.bundle.v1") throw new Error(`not a cool.bundle.v1 bundle`);
  const recomputed = manifestOf(bundle.envelopes, bundle.decisions);
  // The manifest digest covers every entry, so one comparison detects any
  // added, removed or altered envelope or decision.
  const manifest = recomputed.digest === bundle.manifest.digest
    ? check("pass", "manifest_matches", `${recomputed.entries.length} entries; ${recomputed.digest}`)
    : check("fail", "manifest_mismatch", "the bundle contents do not match its manifest (added, removed or altered entries)");

  const exporterOk = hybridVerify(multihashDigest(bundle.manifest.digest), bundle.signature, {
    ml_dsa_pub: bundle.exporter_key.ml_dsa_pub as `base64:${string}`,
    ed25519_pub: bundle.exporter_key.ed25519_pub as `base64:${string}`,
  }).ok && bundle.signature.key_id === bundle.exporter_key.key_id;
  const exporter = exporterOk
    ? check("pass", "exporter_signed", `manifest signed by ${bundle.exporter_key.key_id}`, { limitation: "proves who exported the bundle, not that the exporter is trusted" })
    : check("fail", "exporter_signature_invalid", "the manifest signature does not verify");

  const trust = options.trust ?? new TrustStore(bundle.trust_snapshot);
  const trustSource = options.trust
    ? check("pass", "verifier_trust", "signers judged against the verifier's own trust snapshot")
    : check("unknown", "self_asserted_trust", "no trust snapshot supplied: signers judged against the exporter's snapshot, which proves nothing about trust");

  const byDigest = new Set(bundle.envelopes.map((e) => e.digest));
  const reports: VerificationReport[] = bundle.envelopes.map((e) => verifyEnvelope(e, { ...options, trust, resolve: (ref) => byDigest.has(ref) }));
  const failed = reports.filter((r) => r.overall_status === "fail");
  const unknown = reports.filter((r) => r.overall_status === "unknown");
  const envelopes = failed.length ? check("fail", "envelope_failed", `${failed.length} of ${reports.length} envelope(s) failed`)
    : unknown.length ? check("unknown", "envelope_unknown", `${unknown.length} of ${reports.length} envelope(s) could not be decided`)
      : check("pass", "all_envelopes_valid", `${reports.length} envelope(s) verified`);

  const missing = reports.filter((r) => r.checks.evidence_complete.status === "fail");
  const complete = missing.length
    ? check("fail", "missing_evidence", missing.map((r) => `${r.subject?.event_id}: ${r.checks.evidence_complete.detail}`).join("; "))
    : check("pass", "references_resolved", "every reference resolves inside the bundle");

  const decisionDigests = new Set(bundle.decisions.map((d) => mhSha256(canonicalCbor(d))));
  const unbound = bundle.envelopes.filter((e) => e.core.policy && !decisionDigests.has(e.core.policy.decision_ref));
  const decisions = unbound.length
    ? check("fail", "decision_missing", `${unbound.length} envelope(s) cite a policy decision not in the bundle`)
    : check("pass", "decisions_bound", `${bundle.decisions.length} decision(s); every citation resolves`);

  const checks = { manifest_valid: manifest, exporter_signature_valid: exporter, trust_source: trustSource, envelopes_valid: envelopes, evidence_complete: complete, decisions_bound: decisions };
  const { overall, reasons } = overallOf(checks, Object.keys(checks));
  return {
    schema: "cool.bundle-report.v1",
    overall_status: overall,
    checks,
    envelopes: reports.map((r, i) => ({ event_id: bundle.envelopes[i]!.core.event_id, event_type: bundle.envelopes[i]!.core.event_type, overall_status: r.overall_status, reasons: r.reasons })),
    timeline: buildTimeline(bundle.envelopes, reports),
    reasons,
  };
}
