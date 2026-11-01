/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The TEE adapter interface: one contract, platform-specific semantics kept.
 *
 * Each adapter returns the platform's own claims untouched (no invented
 * universal "PCR" field), a normalized summary only where meanings are
 * comparable, the trust-chain result, the verifier name and version, the time
 * of validation, an outcome and its limitations. A new platform is a new
 * adapter; the evidence core and the envelope parser do not change.
 *
 * Support levels are stated honestly and match validation depth:
 *
 *   aws-nitro      implemented — offline verifier, pinned AWS root, real AWS fixture,
 *                  adversarial tests. No CooL workload has run in a real enclave.
 *   intel-tdx      implemented via the dstack path — recorded hardware validation
 *                  (artifacts/); quote chain checked through a configured verifier.
 *   phala-dstack   partial — runtime/deployment evidence and KMS-derived keys; the
 *                  underlying TDX quote is a separate, linked claim.
 *   amd-sev-snp    unsupported — no parser or VCEK chain validation yet.
 *   nvidia-cc      unsupported — GPU evidence is committed but not verified (NRAS not
 *                  integrated); never reported as verified.
 */
import { createHash } from "node:crypto";
import { verifyNitroAttestation, type VerifyNitroOptions } from "../nitro/attestation";
import { normalizeNitro, normalizeTdx, type NormalizedAttestation } from "../nitro/normalize";
import { verifyReceiptV2 } from "../phala/verify";
import type { ReceiptV2, VerifyOptionsV2 } from "../phala/types";
import type { Outcome } from "./outcome";

export type TeePlatform = "aws-nitro" | "intel-tdx" | "phala-dstack" | "amd-sev-snp" | "nvidia-cc";
export type SupportLevel = "implemented" | "partial" | "unsupported";

export interface AdapterResult {
  readonly platform: TeePlatform;
  readonly support: SupportLevel;
  readonly outcome: Outcome;
  readonly evidence_digest: string | null;
  /** The platform's own claims, as reported by its verifier. */
  readonly platform_claims: unknown;
  readonly normalized: NormalizedAttestation | null;
  readonly verifier: { readonly name: string; readonly version: string };
  readonly validated_at: string;
  readonly limitations: readonly string[];
}

export interface TeeAdapter<E = unknown, O = unknown> {
  readonly platform: TeePlatform;
  readonly support: SupportLevel;
  verify(evidence: E, options?: O): Promise<AdapterResult>;
}

const STALE_REASONS = new Set(["attestation_stale", "certificate_expired", "trust_bundle_stale"]);

/** invalid if anything genuinely fails; otherwise stale if only freshness fails; otherwise indeterminate. */
const outcomeOf = (n: NormalizedAttestation): Outcome => {
  if (n.overall_status === "pass") return "verified";
  const claims = Object.values(n.claims);
  if (claims.some((c) => c.status === "fail" && !STALE_REASONS.has(c.reason))) return "invalid";
  if (claims.some((c) => STALE_REASONS.has(c.reason))) return "stale";
  return "indeterminate";
};

export const nitroAdapter: TeeAdapter<Uint8Array, VerifyNitroOptions> = {
  platform: "aws-nitro",
  support: "implemented",
  async verify(document, options = {}) {
    const report = verifyNitroAttestation(document, options);
    const normalized = normalizeNitro(report);
    return {
      platform: "aws-nitro", support: "implemented", outcome: outcomeOf(normalized), evidence_digest: report.document_sha256,
      platform_claims: report, normalized, verifier: { name: "cool-nitro", version: report.parser.version }, validated_at: new Date(options.now ?? Date.now()).toISOString(),
      limitations: ["no revocation check (AWS publishes no CRL for this PKI)", "X.509 path checks are not full RFC 5280"],
    };
  },
};

export const tdxAdapter: TeeAdapter<ReceiptV2, VerifyOptionsV2> = {
  platform: "intel-tdx",
  support: "implemented",
  async verify(receipt, options = {}) {
    const verdict = await verifyReceiptV2(receipt, options);
    const normalized = normalizeTdx(verdict);
    return {
      platform: "intel-tdx", support: "implemented", outcome: outcomeOf(normalized),
      evidence_digest: createHash("sha256").update(JSON.stringify(receipt.attestation ?? null)).digest("hex"),
      platform_claims: { attestation: verdict.checks.attestation, enclave: verdict.checks.enclave }, normalized,
      verifier: { name: "cool-nwc/phala", version: "receipt.v2" }, validated_at: new Date().toISOString(),
      limitations: ["TCB status recorded as Unknown on this path", "quote freshness not checked", "quote chain depends on the configured QuoteVerifier"],
    };
  },
};

/** An adapter for a platform this verifier cannot check: always `unsupported`, never `verified`. */
export function unsupportedAdapter(platform: TeePlatform, why: string): TeeAdapter {
  return {
    platform,
    support: "unsupported",
    async verify() {
      return {
        platform, support: "unsupported", outcome: "unsupported", evidence_digest: null, platform_claims: null, normalized: null,
        verifier: { name: "none", version: "0" }, validated_at: new Date().toISOString(), limitations: [why],
      };
    },
  };
}

export const ADAPTERS: Readonly<Record<TeePlatform, TeeAdapter<never, never>>> = {
  "aws-nitro": nitroAdapter as TeeAdapter<never, never>,
  "intel-tdx": tdxAdapter as TeeAdapter<never, never>,
  "phala-dstack": { ...tdxAdapter, platform: "phala-dstack", support: "partial" } as TeeAdapter<never, never>,
  "amd-sev-snp": unsupportedAdapter("amd-sev-snp", "SEV-SNP report parsing and VCEK/VLEK chain validation are not implemented") as TeeAdapter<never, never>,
  "nvidia-cc": unsupportedAdapter("nvidia-cc", "NVIDIA GPU attestation is committed to but not verified (NRAS not integrated)") as TeeAdapter<never, never>,
};
