/**
 * `@cool/tee` — the confidential-compute tier of the CooL SDK.
 *
 * Everything Phala-shaped lives behind this one entry point, and everything
 * behind it is swappable: dstack is reached through a three-method interface, the
 * root of trust through a verifier interface, and inference through a backend
 * function. That is deliberate. The customer's evidence should outlive any
 * decision about whose silicon it ran on, and a partnership is worth more when
 * neither side is holding the other in place.
 *
 * Typical wiring, production:
 *
 *     const cool = await CoolTee.connect({
 *       dstack: new HttpDstackClient({ endpoint: "http://localhost:8090" }),
 *       expectedMeasurement: PINNED,                 // the image you approved
 *       policy: { allowSimulated: false, expectedMeasurement: PINNED },
 *     });
 *
 *     const receipt = await cool.record({ type: "model.execution", metadata: { model: "m@1" } });
 *
 * Typical wiring, laptop or CI: drop `dstack` and pass `app`. Same code path,
 * simulated quotes, and every receipt says so in its own attestation block.
 */
export { CoolTee } from "./client";
export type { ChangeRequest, CoolTeeOptions, RecordRequest } from "./client";

export { EvidencePlane } from "./engine";
export type {
  CaptureEvent,
  ChangeEvent,
  EvidenceEvent,
  EvidencePayloads,
  EvidencePlaneOptions,
} from "./engine";

export { CaptureQueue } from "./capture";
export type { CaptureOptions, CaptureStats } from "./capture";

export { HttpDstackClient, SimulatedDstackClient } from "./dstack";
export type {
  DstackClient,
  EnclaveEvent,
  EnclaveInfo,
  HttpDstackOptions,
  SimulatedDstackOptions,
} from "./dstack";

export { KEY_PATH, sealedKeypair, sealedKeyset } from "./kms";
export type { SealedKeyOptions, SealedKeyset } from "./kms";

export {
  attestEndpoint,
  AttestedChannel,
  ChannelClosedError,
} from "./ratls";
export type { AttestationHandshake, AttestationPolicy, HandshakeStep } from "./ratls";

export {
  checkQuoteStructure,
  enclaveReportData,
  measurementDiff,
  measurementEquals,
  measurementDigest,
  quoteDigest,
  quoteSigningMessage,
  remoteQuoteVerifier,
  reportDataBytes,
  shortMeasurement,
  signSimulatedQuote,
  simulatedQuoteVerifier,
  SIM_ROOT_KEY_ID,
} from "./quote";
export type { QuoteVerification, QuoteVerifier, RemoteVerifierOptions } from "./quote";

export {
  bindingHashV2,
  coreOfV2,
  recordLeafDataV2,
  recordSigningMessageV2,
  recordSubjectLabel,
  signedRecordV2,
} from "./record";

export { validateReceiptV2Shape } from "./structure";
export type { ShapeResult } from "./structure";

export { domainOrder, verifyReceiptV2, withTrustedKeys } from "./verify";
export type { VerifyArgsV2 } from "./verify";

export { gpuRefFromReport, PHALA_GPUS, PHALA_MODELS, simulatedGpu } from "./gpu";
export type { InferenceAttestationReport, PhalaGpu, PhalaModel } from "./gpu";

export { createUlid, ulid } from "./ulid";

export { diffStat, lineDiff, unifiedDiff } from "./diff";
export type { DiffLine } from "./diff";


export { DEFAULT_POLICY, approvalFrom, evaluate, policyHash } from "./policy";
export type {
  Decision,
  PolicyInput,
  PolicyMatch,
  PolicyOutcome,
  PolicyRule,
  PolicySet,
} from "./policy";

export { disclosableFields, disclose, verifyDisclosure } from "./disclose";
export type { DisclosableField, Disclosure, DisclosureVerdict } from "./disclose";

export {
  anchorHead,
  attachAnchor,
  upgradeProof,
  submit as submitToCalendars,
  upgrade as upgradeTimestamp,
  parseProof,
  serialiseProof,
  verifyAnchor,
  explorerHeaders,
  reachable,
  base64ToBytes,
  bytesToBase64,
  CALENDARS,
} from "./anchor";
export type { AnchorCheck, BlockHeaderSource, Timestamp as AnchorTimestamp } from "./anchor";
export { attachWitness, cosign, countWitnesses } from "./witness";
export type { WitnessStatement } from "./witness";

export { OBLIGATIONS, coverage, gaps } from "./compliance";
export type { Coverage, Obligation } from "./compliance";

export { buildAuditPack, verifyAuditPack } from "./pack";
export type { AuditPack, AuditPackEntry, BuildPackOptions, PackVerdict } from "./pack";

export { actorOf, environmentOf, groupBy, query, subjectOf, summarise } from "./query";
export type { Query, Summary } from "./query";

export type { AppendResult, EvidenceLog } from "./log";

export * from "./types";
