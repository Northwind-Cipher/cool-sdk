/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * AWS Nitro Enclaves: offline attestation verification, the in-enclave
 * receipt sealer (behind an NsmSource), vsock framing, the log server with
 * and a normalized attestation result shared with the TDX path. The log server
 * (epochs, gaps, acknowledgements) is part of the commercial CooL platform. Nothing here has run inside a real enclave — see docs/nitro.md.
 *
 *   import { verifyNitroAttestation, NitroReceiptSealer } from "cool-nwc/nitro";
 */
export { CommandNsmSource, NitroReceiptSealer } from "./receipt";
export type { EpochAssignment, NsmRequest, NsmSource } from "./receipt";
export { FRAME_VERSION, FrameDecoder, FrameError, FrameType, MAX_FRAME_BYTES, encodeFrame, forwardFrames } from "./vsock";
export type { Frame } from "./vsock";
export { normalizeNitro, normalizeTdx } from "./normalize";
export type { NormalizedAttestation } from "./normalize";
export {
  KEY_BINDING_CONTEXT,
  ed25519Spki,
  keyBindingUserData,
  memoryNonceLedger,
  verifyNitroAttestation,
} from "./attestation";
export type {
  NitroAttestationReport,
  NitroCheck,
  NitroCheckStatus,
  NitroChecks,
  NitroClaims,
  NitroFreshness,
  NitroPcrPolicy,
  NonceLedger,
  VerifyNitroOptions,
} from "./attestation";
export { AWS_NITRO_ROOT_G1_FINGERPRINT, AWS_NITRO_TRUST_BUNDLE, trustBundleFromDer } from "./trust-root";
export type { NitroTrustBundle, NitroTrustRoot } from "./trust-root";
