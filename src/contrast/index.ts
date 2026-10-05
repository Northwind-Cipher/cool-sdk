/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * `cool-nwc/contrast` — CooL × Edgeless Systems Contrast.
 *
 * ## What each side provides
 *
 * Contrast protects the workload WHILE IT RUNS. It launches pods as confidential
 * containers on Intel TDX or AMD SEV-SNP, and a Coordinator — itself a
 * confidential VM — admits a pod only if its attestation report matches the
 * reference values in a signed manifest.
 *
 * CooL makes what happened INSIDE that workload independently checkable. It
 * seals each AI change and each execution event into a hybrid-signed,
 * transparency-logged receipt that an auditor can verify offline, years later,
 * trusting neither CooL nor the operator.
 *
 * Neither covers the other. Contrast can prove a pod was confidential and say
 * nothing about which prompt it was running; CooL can prove a prompt changed and
 * say nothing about whether the process that said so was protected. Together
 * they answer one question end to end: *this* AI change record was produced by
 * *this* confidential workload, and here is why you need not take anyone's word
 * for either half.
 *
 * ## How the two are joined
 *
 * Contrast's attestation is not a quote handed to the workload — it is a
 * CREDENTIAL. The Coordinator verifies the pod's SNP/TDX report, then issues a
 * mesh certificate that carries the claims it verified as X.509 extensions
 * (MRTD, RTMRs, HOSTDATA, `WorkloadSecretID`) and binds them to a P-256 key only
 * that pod holds. So CooL binds to it on both sides:
 *
 *   SEALING      the CooL signing key is derived (HKDF) from
 *                `/contrast/secrets/workload-secret-seed`, which the Coordinator
 *                releases only to a pod that passed attestation. Outside the
 *                attested workload the key is not derivable.
 *
 *   CERTIFYING   the pod's mesh key signs a commitment to that CooL public key.
 *                The certificate chain travels in the receipt; the identity it
 *                states travels INSIDE the signed record core.
 *
 * The result is one chain with no gap in it:
 *
 *     AI change  →  CooL receipt  →  hybrid signature (ML-DSA-65 + Ed25519)
 *                →  key binding signed by the pod's mesh key
 *                →  mesh certificate: measurements + policy hash
 *                →  Coordinator root CA (pinned via `contrast verify`)
 *                →  confidential execution
 *
 * A receipt from workload A cannot be presented as workload B's: the binding
 * signature verifies only under A's certificate, and A's certificate says — in
 * the Coordinator's hand — that it is A. Edit the sealed identity instead and
 * the record signature breaks.
 *
 * ## Using it
 *
 *     import { CooL } from "cool-nwc";
 *     import { ContrastWorkload } from "cool-nwc/contrast";
 *
 *     const runtime = await ContrastWorkload.open({ requireConfidential: true });
 *     const cool = new CooL({ applicationId: "refund-agent", runtime });
 *
 *     await cool.record({ type: "model.execution", metadata: { model: "m@1" } });
 *
 * And to verify, with the root an auditor obtained themselves:
 *
 *     import { verifyEvidence } from "cool-nwc";
 *
 *     const verdict = await verifyEvidence(receipt, {
 *       coordinatorRootCA: readFileSync("verify/coordinator-root-ca.pem", "utf8"),
 *       expectedManifest: readFileSync("manifest.json"),
 *       requireHardware: true,
 *     });
 *
 * ## The boundary this module will not cross
 *
 * A Contrast credential is an attestation statement by an authority, not a
 * vendor quote. CooL's verifier therefore does NOT claim to have checked Intel
 * DCAP or AMD KDS itself — it checks that the credential chains to a Coordinator
 * root the READER pinned, and the `workload` verdict domain says exactly that.
 * Without a pinned root the domain reports rather than passes; on a Contrast
 * `insecure` (non-CC) platform, where the certificate carries no claims at all,
 * it reports `simulated` and never more.
 */

/* ── the workload side (Node: reads /contrast/...) ───────────────────── */
export {
  ContrastWorkload,
  ContrastUnavailableError,
  CONTRAST_FILES,
  CONTRAST_ROOT,
} from "./workload";
export type { ContrastWorkloadOptions, FileReader } from "./workload";

/* ── the verifier side (browser-safe) ────────────────────────────────── */
export { verifyWorkloadDomain, coordinatorRootDigest, manifestDigest } from "./verify";
export type { WorkloadVerifyOptions } from "./verify";

/* ── identity and binding ────────────────────────────────────────────── */
export {
  CONTRAST_KEY_PATH,
  bindingCommitment,
  bindingMessage,
  bindingStatement,
  identityFromCertificate,
  registerDiff,
  registersDigest,
  teeOfCertificate,
} from "./identity";
export type { BindingStatement, IdentityOptions } from "./identity";

/* ── the manifest ────────────────────────────────────────────────────── */
export { parseManifest, policyFor, workloadPolicyHashes } from "./manifest";
export type { ContrastManifest, ManifestPolicy } from "./manifest";

/* ── X.509 and keys, for callers doing their own checks ──────────────── */
export {
  CertificateError,
  extensionByOid,
  parseCertificate,
  parseCertificates,
  pemBlocks,
  verifyChain,
  verifyEcdsa,
  verifySignedBy,
} from "./x509";
export type { Certificate, ChainResult, Curve, Extension, PublicKey } from "./x509";
export { bindingAlgorithm, parsePrivateKey, signBinding } from "./key";
export type { PrivateKey } from "./key";

/* ── the OID table, transcribed from Contrast's source ──────────────── */
export * as oid from "./oid";

/* ── receipt-level types ─────────────────────────────────────────────── */
export type {
  WorkloadAttestationV1,
  WorkloadBinding,
  WorkloadIdentityV1,
  WorkloadPlatform,
  WorkloadTee,
} from "../phala/types";
