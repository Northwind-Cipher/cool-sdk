/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * The CooL platform: one evidence envelope, one verification vocabulary, one
 * policy engine, and five modules on top.
 *
 *   import { CoolClient, TrustStore, TransparencyLog } from "cool-nwc/platform";
 *
 * See docs/platform.md for the architecture and docs/status/ for what is
 * implemented, partial or absent.
 */
export { CoolClient, redact } from "./client";
export type { CoolClientConfig, PolicyMode } from "./client";
export {
  ENVELOPE_SCHEMA,
  canonicalize,
  commit,
  createEnvelope,
  envelopeLeaf,
  inspectEnvelope,
  localSigner,
  signEnvelope,
  verifyEnvelope,
  withCheckpoint,
} from "./envelope";
export type {
  ActorType,
  Checkpoint,
  CollectionMethod,
  EnvelopeChecks,
  EnvelopeCore,
  EnvelopeInput,
  SignedEnvelope,
  Signer,
  VerificationReport,
  VerifyEnvelopeOptions,
} from "./envelope";
export { PayloadRegistry } from "./payloads";
export type { PayloadSchema } from "./payloads";
export { TrustStore } from "./trust";
export type { KeyPurpose, KeyRecord, KeyStatus, TrustQuery, TrustSnapshot } from "./trust";
export { ALGORITHMS, usableAlgorithm } from "./algorithms";
export type { AlgorithmEntry } from "./algorithms";
export { check, overallOf } from "./status";
export type { Check, CheckStatus, OverallStatus } from "./status";
export { PolicyRegistry, evaluatePolicy, overrideDecision, policyDigest, simulatePolicy, validatePolicy } from "./policy";
export type { Condition, Decision, Facts, MatchedRule, PolicyDecisionRecord, PolicyDocument, PolicyLifecycleEvent, PolicyRule, PolicyState } from "./policy";
export { EnforcementCoordinator, LocalDirectoryTarget } from "./enforcement";
export type { AuditEvent, EnforcementAdapter, EnforcementRequest, EnforcementResult, EnforcementState } from "./enforcement";
export { TransparencyLog } from "./transparency";
export { exportBundle, verifyBundle } from "./bundle";
export type { BundleReport, EvidenceBundle } from "./bundle";
export { CORRELATION_RULES, buildTimeline, correlate } from "./correlation";
export type { EvidenceLabel, Link, Timeline, TimelineEntry } from "./correlation";
export { FileConfigConnector, GitConnector, fileDigest, runConnector } from "./connectors";
export type { Connector, ConnectorRun } from "./connectors";
export { RELEASE_POLICY, artifactFacts, buildProvenance, gateDeployment } from "./modules/supply-chain";
export type { ArtifactEvidence, BuildDescription, GateResult } from "./modules/supply-chain";
export { AuthorizationMatrix, CredentialLifecycle, ReplayGuard } from "./modules/identity";
export type { CredentialState, Grant } from "./modules/identity";
export { CHANGE_POLICY, RolloutController, changeFacts, detectDrift } from "./modules/change-control";
export type { Approval, Health } from "./modules/change-control";
export { LocalDenylistTarget, RUNTIME_POLICY, RuntimeGuard } from "./modules/runtime-guard";
export { IncidentCase } from "./modules/incidents";
export type { Severity } from "./modules/incidents";
