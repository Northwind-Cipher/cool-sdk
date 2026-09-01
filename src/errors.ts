/**
 * Typed errors.
 *
 * Every error CooL throws is one of these, carries a stable machine-readable
 * `code`, and — where it can — an `action` telling the caller what to do about
 * it. Configuration and usage mistakes throw; a malformed or tampered *receipt*
 * never throws, it comes back as a failed verdict.
 */

/** Stable, machine-readable error codes. */
export type CooLErrorCode =
  | "COOL_CONFIGURATION_INVALID"
  | "COOL_DSTACK_UNAVAILABLE"
  | "COOL_ATTESTATION_REQUIRED"
  | "COOL_ATTESTATION_FAILED"
  | "COOL_EVIDENCE_INVALID"
  | "COOL_SERIALIZATION_FAILED"
  | "COOL_CRYPTOGRAPHY_FAILED"
  | "COOL_TRANSPARENCY_FAILED"
  | "COOL_VERIFICATION_FAILED"
  | "COOL_CLOSED";

/** Base class for every error CooL throws. */
export class CooLError extends Error {
  readonly code: CooLErrorCode;
  /** A short instruction for the caller: what to change or run. */
  readonly action: string | undefined;

  constructor(
    code: CooLErrorCode,
    message: string,
    options: { cause?: unknown; action?: string } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = new.target.name;
    this.code = code;
    this.action = options.action;
  }
}

/** A constructor option was missing, malformed, or contradictory. */
export class ConfigurationError extends CooLError {
  constructor(message: string, action?: string) {
    super("COOL_CONFIGURATION_INVALID", message, action === undefined ? {} : { action });
  }
}

/** dstack was requested but its guest-agent socket / endpoint is unreachable. */
export class DstackUnavailableError extends CooLError {
  constructor(message: string, options: { cause?: unknown; action?: string } = {}) {
    super("COOL_DSTACK_UNAVAILABLE", message, options);
  }
}

/** A hardware root of trust was required by policy and is not present. */
export class AttestationRequiredError extends CooLError {
  constructor(message: string, action?: string) {
    super("COOL_ATTESTATION_REQUIRED", message, action === undefined ? {} : { action });
  }
}

/** The attestation handshake with the evidence plane failed. */
export class AttestationError extends CooLError {
  constructor(message: string, options: { cause?: unknown; action?: string } = {}) {
    super("COOL_ATTESTATION_FAILED", message, options);
  }
}

/** A value handed to `record()` could not be turned into evidence. */
export class EvidenceError extends CooLError {
  constructor(message: string, options: { cause?: unknown; action?: string } = {}) {
    super("COOL_EVIDENCE_INVALID", message, options);
  }
}

/** The client has been closed and can no longer accept work. */
export class ClosedError extends CooLError {
  constructor() {
    super("COOL_CLOSED", "this CooL client has been closed", {
      action: "create a new CooL client",
    });
  }
}
