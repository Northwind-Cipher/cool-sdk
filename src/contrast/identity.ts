/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Reading a Contrast workload's identity, and binding CooL's key to it.
 *
 * This file is the hinge of the integration, so it is worth being precise about
 * what it does and does not establish.
 *
 * Contrast's Coordinator is itself a confidential VM. A reader attests it once,
 * out of band, with `contrast verify`: that call performs remote attestation of
 * the Coordinator CVM against the reference values in the manifest and writes
 * out `verify/coordinator-root-ca.pem`. From then on, the Coordinator's
 * signature means something — and the Coordinator spends it by issuing each
 * workload a mesh certificate after checking that workload's own SNP/TDX report
 * against the manifest (`coordinator/internal/meshapi/meshapi.go`). Crucially
 * it writes the claims it checked INTO the certificate, so the credential is
 * not just "approved" — it states the measurements behind the approval.
 *
 * CooL therefore does two things, and needs both:
 *
 *   1. DERIVE its signing key from the Contrast workload secret
 *      (`/contrast/secrets/workload-secret-seed`). That secret is released only
 *      to a pod whose attestation report matched the manifest, so outside the
 *      attested workload the CooL key is not derivable at all. This is the same
 *      sealing property CooL already relies on from dstack-KMS, obtained from
 *      Contrast's own key release instead.
 *
 *   2. PROVE the key belongs to this specific workload, by signing a commitment
 *      to the CooL public keys with the mesh certificate's private key
 *      (`/contrast/tls-config/key.pem`) and shipping the certificate chain
 *      alongside. A verifier recomputes the commitment from the receipt's own
 *      key directory and checks the signature under the leaf certificate.
 *
 * Step 2 is what stops a valid receipt from workload A being presented as
 * workload B's: the binding signature only verifies under A's certificate, and
 * A's certificate says — in the Coordinator's hand — that it is A.
 *
 * What this does NOT establish: that any hardware was involved. That rests on
 * the Coordinator having done its job, and on the reader having attested the
 * Coordinator. On a Contrast `insecure` platform there are no claims in the
 * certificate at all, and {@link identityFromCertificate} reports `insecure` so
 * nothing downstream can round it up.
 */
import type { Base64Field, DirectoryEntry, HexField, Multihash } from "../types";
import type { WorkloadIdentityV1, WorkloadTee } from "../phala/types";
import { canonicalCbor } from "../canonical";
import { concatBytes, toHexField, utf8 } from "../codec";
import { mhSha256 } from "../multihash";
import { innerOctetString } from "./asn1";
import { SNP, TDX, WORKLOAD_SECRET_ID } from "./oid";
import { CertificateError, extensionByOid, type Certificate } from "./x509";

/** Domain-separation tag for the statement the mesh key signs. */
const BINDING_TAG = "cool/contrast/key-binding/v1";

/** Derivation paths for keys sealed to a Contrast workload secret. */
export const CONTRAST_KEY_PATH = {
  record: "cool/contrast/record/v1",
  log: "cool/contrast/log/v1",
} as const;

/* ── identity ─────────────────────────────────────────────────────────── */

/** The TDX registers CooL lifts out of a mesh certificate, by claim OID. */
const TDX_REGISTERS: readonly (readonly [string, string])[] = [
  ["mrtd", TDX.MR_TD],
  ["rtmr0", TDX.RTMR0],
  ["rtmr1", TDX.RTMR1],
  ["rtmr2", TDX.RTMR2],
  ["rtmr3", TDX.RTMR3],
  ["mrseam", TDX.MR_SEAM],
];

/** The SNP registers CooL lifts out of a mesh certificate. */
const SNP_REGISTERS: readonly (readonly [string, string])[] = [
  ["measurement", SNP.MEASUREMENT],
  ["chip_id", SNP.CHIP_ID],
];

function claimBytes(certificate: Certificate, oid: string): Uint8Array | null {
  const extension = extensionByOid(certificate, oid);
  if (!extension) return null;
  try {
    return innerOctetString(extension.value);
  } catch (error) {
    throw new CertificateError(`extension ${oid}: ${(error as Error).message}`);
  }
}

/**
 * Which confidential-computing technology a certificate's claims came from.
 *
 * Decided by which claim arc is actually present, never by configuration — an
 * operator asserting `intel-tdx` must not be able to make an SNP or claimless
 * certificate report as TDX.
 */
export function teeOfCertificate(certificate: Certificate): WorkloadTee {
  if (extensionByOid(certificate, TDX.MR_TD)) return "intel-tdx";
  if (extensionByOid(certificate, SNP.MEASUREMENT)) return "amd-sev-snp";
  return "insecure";
}

/** Options an operator supplies that the certificate cannot tell us. */
export interface IdentityOptions {
  /** DER of the Coordinator root CA this deployment trusts. */
  readonly coordinatorRootDer?: Uint8Array;
  /** The exact `manifest.json` bytes the deployment pinned. */
  readonly manifest?: Uint8Array;
}

/**
 * Recover a workload identity from a Contrast mesh certificate.
 *
 * Pure: the same certificate and options always yield the same identity, which
 * is what lets a verifier recompute this and compare it against the identity
 * sealed inside a signed record.
 */
export function identityFromCertificate(
  certificate: Certificate,
  options: IdentityOptions = {},
): WorkloadIdentityV1 {
  const tee = teeOfCertificate(certificate);

  const registers: Record<string, HexField> = {};
  const source = tee === "intel-tdx" ? TDX_REGISTERS : tee === "amd-sev-snp" ? SNP_REGISTERS : [];
  for (const [name, oid] of source) {
    const bytes = claimBytes(certificate, oid);
    if (bytes) registers[name] = toHexField(bytes) as HexField;
  }

  // HostData is the policy hash. TDX carries it in the low 32 bytes of
  // MRCONFIGID (Contrast: `MrConfigId[:32]`); SNP has a dedicated field.
  let policyHash: HexField | null = null;
  if (tee === "intel-tdx") {
    const mrConfigId = claimBytes(certificate, TDX.MR_CONFIG_ID);
    if (mrConfigId && mrConfigId.length >= 32) {
      policyHash = toHexField(mrConfigId.subarray(0, 32)) as HexField;
    }
  } else if (tee === "amd-sev-snp") {
    const hostData = claimBytes(certificate, SNP.HOST_DATA);
    if (hostData) policyHash = toHexField(hostData.subarray(0, 32)) as HexField;
  }

  const secretIdBytes = claimBytes(certificate, WORKLOAD_SECRET_ID);
  const workloadSecretId = secretIdBytes ? new TextDecoder().decode(secretIdBytes) : null;

  const sans = [...certificate.dnsNames, ...certificate.ipAddresses, ...certificate.uris];

  return {
    schema: "cool.workload.v1",
    platform: "contrast",
    tee,
    policy_hash: policyHash,
    workload_secret_id: workloadSecretId,
    workload_name: certificate.dnsNames[0] ?? certificate.subjectCommonName ?? null,
    sans,
    registers,
    registers_digest: registersDigest(registers),
    coordinator_root: options.coordinatorRootDer
      ? mhSha256(options.coordinatorRootDer)
      : null,
    manifest_digest: options.manifest ? mhSha256(options.manifest) : null,
  };
}

/** One commitment over a register map — the value a deployment pins. */
export function registersDigest(registers: Readonly<Record<string, HexField>>): Multihash {
  // Canonical CBOR sorts map keys, so this is independent of insertion order.
  return mhSha256(concatBytes(utf8("cool/contrast/registers/v1"), canonicalCbor(registers)));
}

/**
 * Which named registers differ between two identities — a mismatch that says
 * what. Symmetric: a register present on one side only counts as a difference,
 * which is what the identity comparison wants (the two must be the same set).
 */
export function registerDiff(
  a: Readonly<Record<string, string>>,
  b: Readonly<Record<string, string>>,
): string[] {
  const names = new Set([...Object.keys(a), ...Object.keys(b)]);
  return [...names].filter((name) => a[name] !== b[name]).sort();
}

/**
 * Which of the PINNED registers fail to match `actual`.
 *
 * Asymmetric on purpose. Pinning is usually partial: an operator pins `mrtd`
 * because that is the image they approved, and does not want to restate four
 * RTMRs and MRSEAM to say so. Registers the pin does not mention are not
 * checked; a pinned register missing from the record IS a mismatch, so a pin
 * cannot be satisfied by simply omitting the field.
 */
export function pinnedRegisterDiff(
  pinned: Readonly<Record<string, string>>,
  actual: Readonly<Record<string, string>>,
): string[] {
  return Object.keys(pinned)
    .filter((name) => pinned[name] !== actual[name])
    .sort();
}

/* ── the key binding ──────────────────────────────────────────────────── */

/** The fields the mesh key signs over. Canonicalised, so both sides agree. */
export interface BindingStatement {
  readonly key_id: string;
  readonly ed25519_pub: Base64Field;
  readonly ml_dsa_pub: Base64Field;
  readonly issued_at: string;
}

/**
 * The exact bytes the mesh certificate's private key signs.
 *
 * `issued_at` and `key_id` are inside the statement, not merely beside it, so a
 * binding cannot be lifted onto a different CooL key or silently re-dated.
 */
export function bindingMessage(statement: BindingStatement): Uint8Array {
  return concatBytes(utf8(BINDING_TAG), canonicalCbor(statement));
}

/** The commitment recorded in the receipt: a digest of the binding statement. */
export function bindingCommitment(statement: BindingStatement): Multihash {
  return mhSha256(bindingMessage(statement));
}

/** Build the statement for a CooL record key. */
export function bindingStatement(
  keyId: string,
  entry: DirectoryEntry,
  issuedAt: string,
): BindingStatement {
  return {
    key_id: keyId,
    ed25519_pub: entry.ed25519_pub,
    ml_dsa_pub: entry.ml_dsa_pub,
    issued_at: issuedAt,
  };
}
