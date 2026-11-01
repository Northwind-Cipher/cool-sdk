/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The verifier's headline outcome — never a bare green tick.
 *
 *   verified       every required check passed
 *   invalid        something was checked and is wrong (tampered, untrusted, mismatched)
 *   unsupported    an algorithm, schema, platform or critical field this verifier does not handle
 *   stale          evidence that was valid is too old to rely on now (attestation, trust, checkpoint, collateral)
 *   incomplete     evidence is missing — gaps, unresolved references, no external confirmation
 *   indeterminate  the verifier could not decide (missing inputs, unavailable dependencies)
 *
 * Precedence when several apply: invalid > unsupported > stale > incomplete >
 * indeterminate > verified. The per-check detail is always kept alongside.
 */
import type { Check } from "./status";

export type Outcome = "verified" | "invalid" | "unsupported" | "stale" | "incomplete" | "indeterminate";

const STALE = new Set([
  "attestation_stale", "trust_snapshot_stale", "checkpoint_stale", "trust_bundle_stale", "certificate_expired",
  "collateral_stale", "decision_expired", "request_expired",
]);
const INCOMPLETE = new Set(["missing_evidence", "sequence_gap", "no_confirmation", "confirmation_unavailable", "incomplete_interval"]);
const UNSUPPORTED = new Set([
  "unsupported_algorithm", "unsupported_schema", "unsupported_platform", "unexpected_critical_field", "unsupported_version",
]);

export function classifyOutcome(checks: Readonly<Record<string, Check>>, required: readonly string[]): { readonly outcome: Outcome; readonly reasons: readonly string[] } {
  const found = { invalid: false, unsupported: false, stale: false, incomplete: false, indeterminate: false };
  const reasons: string[] = [];
  for (const name of required) {
    const c = checks[name];
    if (!c) { found.indeterminate = true; reasons.push(`${name}: missing`); continue; }
    if (c.status === "pass" || c.status === "not_applicable") continue;
    reasons.push(`${name}: ${c.reason}`);
    if (UNSUPPORTED.has(c.reason)) found.unsupported = true;
    else if (STALE.has(c.reason)) found.stale = true;
    else if (INCOMPLETE.has(c.reason)) found.incomplete = true;
    else if (c.status === "fail") found.invalid = true;
    else found.indeterminate = true;
  }
  const outcome: Outcome = found.invalid ? "invalid" : found.unsupported ? "unsupported" : found.stale ? "stale"
    : found.incomplete ? "incomplete" : found.indeterminate ? "indeterminate" : "verified";
  return { outcome, reasons };
}
