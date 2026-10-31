/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * CooL Supply Chain: source → build → artifact → release → deployment.
 *
 * This module adds no new security model. It builds typed envelope inputs,
 * turns verification reports into policy facts, and drives the shared policy
 * engine and enforcement coordinator. The deployment gate is the spec's first
 * milestone: an artifact whose bytes do not match its signed provenance is
 * refused — by the deployment target itself, which recomputes the digest.
 */
import { statSync } from "node:fs";
import { basename } from "node:path";
import type { Multihash } from "../../types";
import { fileDigest } from "../connectors";
import type { EnvelopeInput, SignedEnvelope, VerificationReport } from "../envelope";
import type { EnforcementAdapter, EnforcementCoordinator, EnforcementResult } from "../enforcement";
import { evaluatePolicy, type Facts, type PolicyDecisionRecord, type PolicyDocument } from "../policy";

export interface BuildDescription {
  readonly buildId: string;
  readonly builderId: string;
  readonly repository: string;
  readonly commit: string;
  readonly artifactPath: string;
  readonly finishedAt: string;
}

/** Provenance for one build: `build.completed` and `artifact.created` inputs. */
export function buildProvenance(build: BuildDescription): { readonly build: EnvelopeInput; readonly artifact: EnvelopeInput; readonly digest: Multihash } {
  const digest = fileDigest(build.artifactPath);
  const actor = { id: build.builderId, type: "workload" as const };
  return {
    digest,
    build: {
      event_type: "build.completed",
      occurred_at: build.finishedAt,
      source: { system: "builder", instance: build.builderId, event_id: build.buildId },
      actor,
      action: "build",
      resource: { type: "repository", ref: build.repository },
      payload: { build_id: build.buildId, builder_id: build.builderId, source_repository: build.repository, source_commit: build.commit, result: "success", artifact_digests: [digest] },
    },
    artifact: {
      event_type: "artifact.created",
      occurred_at: build.finishedAt,
      source: { system: "builder", instance: build.builderId, event_id: `${build.buildId}:artifact` },
      actor,
      action: "create",
      resource: { type: "artifact", ref: basename(build.artifactPath) },
      payload: { artifact_name: basename(build.artifactPath), artifact_digest: digest, build_id: build.buildId, size_bytes: statSync(build.artifactPath).size },
    },
  };
}

export interface ArtifactEvidence {
  readonly artifactPath: string;
  readonly build: SignedEnvelope;
  readonly artifact: SignedEnvelope;
  readonly buildReport: VerificationReport;
  readonly artifactReport: VerificationReport;
  readonly trustedBuilders: readonly string[];
  readonly allowedRepositories: readonly string[];
  readonly sbom?: SignedEnvelope;
}

/**
 * Facts for a release policy. A fact is left UNDEFINED (unknown) when the
 * evidence needed to decide it is missing or unverified — never defaulted.
 */
export function artifactFacts(e: ArtifactEvidence): Facts {
  const verified = e.buildReport.overall_status === "pass" && e.artifactReport.overall_status === "pass";
  const claimed = e.artifact.core.payload["artifact_digest"] as string;
  const subjects = (e.build.core.payload["artifact_digests"] as string[] | undefined) ?? [];
  let actual: string | undefined;
  try { actual = fileDigest(e.artifactPath); } catch { actual = undefined; }
  return {
    "provenance.verified": verified,
    "artifact.digest": actual,
    "artifact.digest_matches": actual === undefined ? undefined : actual === claimed,
    "provenance.subject_matches": verified ? subjects.includes(claimed) : undefined,
    "builder.trusted": verified ? e.trustedBuilders.includes(String(e.build.core.payload["builder_id"])) : undefined,
    "source.repository_allowed": verified ? e.allowedRepositories.includes(String(e.build.core.payload["source_repository"])) : undefined,
    "build.succeeded": verified ? e.build.core.payload["result"] === "success" : undefined,
    "sbom.present": e.sbom ? e.sbom.core.payload["artifact_digest"] === claimed : false,
  };
}

/** The reference release policy: production deploys fail closed. */
export const RELEASE_POLICY: PolicyDocument = {
  schema: "cool.policy.v1",
  id: "release-gate",
  version: "1.0.0",
  description: "Admit an artifact only with verified provenance from a trusted builder and matching bytes.",
  mode: "enforce",
  default: "allow",
  on_unknown: "deny",
  rules: [
    { id: "provenance-verified", when: { fact: "provenance.verified", op: "eq", value: false }, decision: "deny", reason: "provenance_unverified" },
    { id: "bytes-match", when: { fact: "artifact.digest_matches", op: "eq", value: false }, decision: "deny", reason: "artifact_digest_mismatch" },
    { id: "subject-match", when: { fact: "provenance.subject_matches", op: "eq", value: false }, decision: "deny", reason: "wrong_provenance_subject" },
    { id: "trusted-builder", when: { fact: "builder.trusted", op: "eq", value: false }, decision: "deny", reason: "untrusted_builder" },
    { id: "allowed-source", when: { fact: "source.repository_allowed", op: "eq", value: false }, decision: "deny", reason: "source_not_allowed" },
    { id: "build-success", when: { fact: "build.succeeded", op: "eq", value: false }, decision: "deny", reason: "build_failed" },
    { id: "sbom", when: { fact: "sbom.present", op: "eq", value: false }, decision: "audit_only", reason: "sbom_missing", on_unknown: "audit_only" },
  ],
};

export interface GateResult {
  readonly decision: PolicyDecisionRecord;
  readonly enforcement: EnforcementResult;
  /** Inputs for `deployment.requested` and `deployment.completed`, to be signed and published. */
  readonly records: readonly EnvelopeInput[];
}

/** Evaluate the release policy and ask the deployment target to admit or not. */
export async function gateDeployment(input: {
  readonly evidence: ArtifactEvidence;
  readonly policy?: PolicyDocument;
  readonly coordinator: EnforcementCoordinator;
  readonly target: EnforcementAdapter;
  readonly deploymentId: string;
  readonly environment: string;
  readonly requestedBy: string;
  readonly dryRun?: boolean;
  readonly now?: () => Date;
}): Promise<GateResult> {
  const now = input.now ?? (() => new Date());
  const facts = artifactFacts(input.evidence);
  const decision = evaluatePolicy(input.policy ?? RELEASE_POLICY, facts, { now: now(), inputRefs: [input.evidence.build.digest, input.evidence.artifact.digest] });
  const digest = (facts["artifact.digest"] as string | undefined) ?? (input.evidence.artifact.core.payload["artifact_digest"] as string);
  const requested: EnvelopeInput = {
    event_type: "deployment.requested",
    occurred_at: now().toISOString(),
    source: { system: "cool-gate", event_id: input.deploymentId },
    actor: { id: input.requestedBy, type: "human" },
    action: "request_deploy",
    resource: { type: "environment", ref: input.environment },
    provenance: { collection_method: "emitted", refs: [input.evidence.build.digest, input.evidence.artifact.digest] },
    payload: { deployment_id: input.deploymentId, artifact_digest: digest, environment: input.environment, target: input.target.id },
  };
  // audit_only admits but leaves a flag in the decision record; everything else refuses.
  const enforcement = decision.decision === "allow" || decision.decision === "audit_only"
    ? await input.coordinator.request(decision, input.target, "admit", input.environment, {
      requestId: input.deploymentId,
      ...(input.dryRun === false ? { dryRun: false } : {}),
      params: { artifact_path: input.evidence.artifactPath, artifact_digest: input.evidence.artifact.core.payload["artifact_digest"] as string },
    })
    : { request_id: input.deploymentId, adapter: input.target.id, state: "not_executed" as const, confirmed: false, detail: `policy decided ${decision.decision}: ${decision.reason_codes.join(", ")}`, observed_at: now().toISOString() };
  const outcome = enforcement.state === "completed" && enforcement.confirmed ? "succeeded" : enforcement.state === "not_executed" || enforcement.state === "rejected" ? "rejected" : "failed";
  const completed: EnvelopeInput = {
    event_type: "deployment.completed",
    occurred_at: enforcement.observed_at,
    source: { system: input.target.id, event_id: input.deploymentId },
    actor: { id: `adapter:${input.target.id}`, type: "service" },
    action: "deploy",
    resource: { type: "environment", ref: input.environment },
    payload: { deployment_id: input.deploymentId, artifact_digest: digest, environment: input.environment, target: input.target.id, outcome, confirmed: enforcement.confirmed },
  };
  return { decision, enforcement, records: [requested, completed] };
}
