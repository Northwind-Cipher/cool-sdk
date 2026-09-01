/**
 * `cool-nwc/tee` — the full surface: the high-level {@link CooL} client plus the
 * entire confidential-compute tier (`cool-nwc/phala`) in one import.
 *
 * Most applications want `cool-nwc` (the curated entry) or `cool-nwc/phala` (the
 * advanced tier). This exists for code that needs both halves and does not want
 * to import from two places.
 */
export * from "./phala/index";
export { CooL } from "./client";
export type {
  AttestationConfig,
  CooLOptions,
  Environment,
  EvidenceResult,
  RecordInput,
  SecurityConfig,
} from "./client";
export { verifyEvidence, formatVerdict } from "./verify";
export {
  CooLError,
  ConfigurationError,
  DstackUnavailableError,
  AttestationRequiredError,
  AttestationError,
  EvidenceError,
  ClosedError,
} from "./errors";
export type { CooLErrorCode } from "./errors";
