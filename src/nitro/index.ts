/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * AWS Nitro Enclaves: offline attestation verification, the in-enclave
 * receipt sealer (behind an NsmSource), vsock framing, the log server with
 * epoch and gap accounting, and a normalized attestation result shared with
 * the TDX path. Nothing here has run inside a real enclave — see docs/nitro.md.
 *
 *   import { verifyNitroAttestation, NitroReceiptSealer, NitroLogServer } from "cool-nwc/nitro";
 */
export { CommandNsmSource, NitroReceiptSealer } from "./receipt";
export type { NsmRequest, NsmSource } from "./receipt";
export { FRAME_VERSION, FrameDecoder, FrameError, FrameType, MAX_FRAME_BYTES, encodeFrame, forwardFrames } from "./vsock";
export type { Frame } from "./vsock";
export { NitroLogServer } from "./server";
export type { Ack, SignedAck } from "./server";
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
export { EpochLog, digestHex, verifyEpochRegistration } from "./epochs";
export type {
  EpochEvent,
  EpochRegistration,
  IngestOutcome,
  IngestResult,
  ObservedReceipt,
  SequenceGap,
  SignedEpochRegistration,
} from "./epochs";
export { AWS_NITRO_ROOT_G1_FINGERPRINT, AWS_NITRO_TRUST_BUNDLE, trustBundleFromDer } from "./trust-root";
export type { NitroTrustBundle, NitroTrustRoot } from "./trust-root";
