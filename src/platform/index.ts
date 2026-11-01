/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The open CooL evidence core: one evidence envelope, one verification
 * vocabulary, trust and key lifecycle, transparency, portable bundles and
 * reference connectors. Policy, enforcement, incident reconstruction and the
 * five operational modules are part of the commercial CooL platform.
 *
 *   import { CoolClient, TrustStore, TransparencyLog } from "cool-nwc/platform";
 *
 * See docs/platform.md for the architecture and docs/status/ for what is
 * implemented, partial or absent.
 */
export { CoolClient, redact } from "./client";
export type { CoolClientConfig } from "./client";
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
export { TransparencyLog } from "./transparency";
export { exportBundle, verifyBundle } from "./bundle";
export type { BundleEntry, BundleReport, DecisionRecord, EvidenceBundle } from "./bundle";
export { FileConfigConnector, GitConnector, fileDigest, runConnector } from "./connectors";
export type { Connector, ConnectorRun } from "./connectors";
