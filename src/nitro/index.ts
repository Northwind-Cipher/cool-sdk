/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * AWS Nitro Enclaves: offline attestation verification and log-side epoch and
 * gap accounting. The in-enclave half (requesting a document from /dev/nsm and
 * sealing receipts) is not part of this package yet — see docs/nitro.md.
 *
 *   import { verifyNitroAttestation, EpochLog } from "cool-nwc/nitro";
 */
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
