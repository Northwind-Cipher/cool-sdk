/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * The object identifiers CooL reads out of a Contrast mesh certificate.
 *
 * Every value here is transcribed from Contrast's own source so there is one
 * place to check it against upstream:
 *
 *   `internal/oid/oid.go`                       the three root OIDs below
 *   `internal/attestation/tdx/extensions.go`    the TDX claim numbering
 *   `internal/attestation/snp/extensions.go`    the SNP claim numbering
 *
 * Contrast's Coordinator calls `report.ClaimsToCertExtension()` when it issues a
 * workload's mesh certificate (`coordinator/internal/meshapi/meshapi.go`), which
 * writes the whole attestation report into the certificate as extensions under
 * these arcs. That is the fact the entire integration rests on: the credential a
 * Contrast workload holds is not merely signed by an authority that checked the
 * hardware — it *carries the measurements that authority checked*.
 *
 * Verified against certificates produced by `internal/ca.NewAttestedMeshCert`;
 * see `tests/fixtures/contrast/` and `tests/contrast-conformance.test.ts`.
 */

/** Root arc for a raw SNP report (`oid.RawSNPReport`). */
export const SNP_ROOT = "1.3.9901.2.1";

/** Root arc for a raw TDX report (`oid.RawTDXReport`). */
export const TDX_ROOT = "1.3.9901.2.2";

/**
 * Root arc used on development platforms without confidential-computing
 * hardware (`oid.RawInsecureReport`).
 *
 * Contrast's insecure validator returns NO certificate extensions at all
 * (`internal/attestation/insecure/validator.go` — `ClaimsToCertExtension`
 * returns `nil, nil`), so a certificate from such a deployment carries none of
 * the claims below. CooL treats that absence as decisive: a credential with no
 * measurements can never support a hardware claim.
 */
export const INSECURE_ROOT = "1.3.9901.2.99";

/** The workload secret id, written as raw bytes (`oid.WorkloadSecretOID`). */
export const WORKLOAD_SECRET_ID = "1.3.9901.3.1";

/**
 * TDX claims CooL reads.
 *
 * `MR_CONFIG_ID` is the load-bearing one: Contrast's TDX report implements
 * `HostData()` as `MrConfigId[:32]` (`internal/attestation/tdx/validator.go`),
 * and HostData is the key of the manifest's `Policies` map — the policy hash,
 * i.e. the digest of the pod's initdata document. So the certificate states
 * which manifest entry authorised this workload.
 */
export const TDX = {
  MR_SEAM: `${TDX_ROOT}.9`,
  TD_ATTRIBUTES: `${TDX_ROOT}.12`,
  XFAM: `${TDX_ROOT}.13`,
  MR_TD: `${TDX_ROOT}.14`,
  MR_CONFIG_ID: `${TDX_ROOT}.15`,
  RTMR0: `${TDX_ROOT}.18`,
  RTMR1: `${TDX_ROOT}.19`,
  RTMR2: `${TDX_ROOT}.20`,
  RTMR3: `${TDX_ROOT}.21`,
  TD_REPORT_DATA: `${TDX_ROOT}.22`,
} as const;

/**
 * SNP claims CooL reads.
 *
 * `HOST_DATA` plays the same role as TDX's MRCONFIGID — SNP's report has a
 * dedicated HostData field, so `HostData()` returns it directly
 * (`internal/attestation/snp/validator.go`).
 */
export const SNP = {
  REPORT_DATA: `${SNP_ROOT}.21`,
  MEASUREMENT: `${SNP_ROOT}.22`,
  HOST_DATA: `${SNP_ROOT}.23`,
  CHIP_ID: `${SNP_ROOT}.32`,
} as const;

/* ── standard X.509 ───────────────────────────────────────────────────── */

export const X509 = {
  SUBJECT_ALT_NAME: "2.5.29.17",
  BASIC_CONSTRAINTS: "2.5.29.19",
  KEY_USAGE: "2.5.29.15",
  COMMON_NAME: "2.5.4.3",
} as const;

/** Public-key and signature algorithms a Contrast PKI uses. */
export const ALGORITHM = {
  EC_PUBLIC_KEY: "1.2.840.10045.2.1",
  P256: "1.2.840.10045.3.1.7",
  P384: "1.3.132.0.34",
  P521: "1.3.132.0.35",
  ECDSA_SHA256: "1.2.840.10045.4.3.2",
  ECDSA_SHA384: "1.2.840.10045.4.3.3",
  ECDSA_SHA512: "1.2.840.10045.4.3.4",
} as const;
