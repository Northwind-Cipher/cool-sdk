/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * One attestation result shape for both platforms.
 *
 * The two trust paths stay separate: each platform's own verifier runs first,
 * against its own roots. Only the VERIFIED outcomes are normalised, into the
 * same four claims — platform attestation, workload measurement, runtime key
 * binding, freshness — using the platform vocabulary pass / fail / unknown /
 * not_applicable / not_checked.
 *
 * Mapping from the TDX receipt-v2 domains is conservative: `absent` and
 * `pending` become unknown, and `simulated` / `mock` become unknown with an
 * explicit reason. None of them can ever become pass.
 */
import type { DomainCheckV2, VerdictV2 } from "../phala/types";
import { check, overallOf, type Check, type OverallStatus } from "../platform/status";
import type { NitroAttestationReport, NitroCheck } from "./attestation";

export interface NormalizedAttestation {
  readonly schema: "cool.attestation-result.v1";
  readonly platform: "intel-tdx" | "aws-nitro";
  readonly overall_status: OverallStatus;
  readonly claims: {
    readonly platform_attestation: Check;
    readonly workload_measurement: Check;
    readonly key_binding: Check;
    readonly freshness: Check;
  };
  readonly reasons: readonly string[];
  /** The platform report this was derived from, by reference. */
  readonly source: string;
}

function fromTdx(c: DomainCheckV2, name: string): Check {
  switch (c.status) {
    case "pass": return check("pass", `${name}_pass`, c.detail);
    case "fail": return check("fail", `${name}_fail`, c.detail);
    case "simulated":
    case "mock": return check("unknown", "simulated_not_hardware", c.detail, { limitation: "a simulated quote is not evidence that hardware protected the run" });
    case "pending": return check("unknown", `${name}_pending`, c.detail);
    case "absent": return check("unknown", `${name}_absent`, c.detail);
  }
}

const fromNitro = (c: NitroCheck): Check => check(c.status, c.reason, c.detail, c.limitation ? { limitation: c.limitation } : {});

function combine(...checks: NitroCheck[]): Check {
  const fail = checks.find((c) => c.status === "fail");
  if (fail) return fromNitro(fail);
  const open = checks.find((c) => c.status === "unknown" || c.status === "not_checked");
  if (open) return fromNitro(open);
  return fromNitro(checks.find((c) => c.status === "pass") ?? checks[0]!);
}

function finish(platform: NormalizedAttestation["platform"], claims: NormalizedAttestation["claims"], source: string): NormalizedAttestation {
  const { overall, reasons } = overallOf(claims, Object.keys(claims));
  return { schema: "cool.attestation-result.v1", platform, overall_status: overall, claims, reasons, source };
}

/** Normalise a TDX receipt verdict. TDX has no separate freshness check on main. */
export function normalizeTdx(verdict: VerdictV2, source = "cool.receipt.v2 verdict"): NormalizedAttestation {
  return finish("intel-tdx", {
    platform_attestation: fromTdx(verdict.checks.attestation, "attestation"),
    workload_measurement: fromTdx(verdict.checks.enclave, "enclave"),
    key_binding: fromTdx(verdict.checks.enclave, "enclave"),
    freshness: check("not_checked", "no_freshness_check", "the TDX verifier on main does not check quote freshness"),
  }, source);
}

/** Normalise a Nitro attestation report. */
export function normalizeNitro(report: NitroAttestationReport): NormalizedAttestation {
  const c = report.checks;
  return finish("aws-nitro", {
    platform_attestation: combine(c.structure, c.trust_root, c.certificate_chain, c.cose_signature),
    workload_measurement: combine(c.debug_mode, c.pcr_policy, c.pcr8_signing),
    key_binding: combine(c.key_binding, c.public_key),
    freshness: fromNitro(c.freshness),
  }, `nitro report ${report.document_sha256}`);
}
