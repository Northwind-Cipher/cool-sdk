/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The one result vocabulary every platform module uses.
 *
 *   pass            the property was checked and holds
 *   fail            the property was checked and does not hold
 *   unknown         a check ran but could not decide (stale trust, missing input)
 *   not_applicable  the property does not apply to this evidence
 *   not_checked     nobody asked, or a prerequisite failed
 *
 * `unknown` and `not_checked` are never promoted to `pass`. A report's
 * overall status is `pass` only when every required check passed (or was
 * not_applicable); any failure makes it `fail`; anything else makes it
 * `unknown`.
 */
export type CheckStatus = "pass" | "fail" | "unknown" | "not_applicable" | "not_checked";
export type OverallStatus = "pass" | "fail" | "unknown";

export interface Check {
  readonly status: CheckStatus;
  /** Stable, machine-readable reason code. */
  readonly reason: string;
  readonly detail: string;
  /** Which piece of evidence the check looked at. */
  readonly evidence_ref?: string;
  /** Algorithm or rule version the check used. */
  readonly algorithm?: string;
  /** What a pass does NOT establish, when worth saying. */
  readonly limitation?: string;
}

export function check(
  status: CheckStatus,
  reason: string,
  detail: string,
  extra: Omit<Check, "status" | "reason" | "detail"> = {},
): Check {
  return { status, reason, detail, ...extra };
}

/** Fold required checks into an overall status plus the reasons it is not a pass. */
export function overallOf(
  checks: Readonly<Record<string, Check>>,
  required: readonly string[],
): { overall: OverallStatus; reasons: string[] } {
  let overall: OverallStatus = "pass";
  const reasons: string[] = [];
  for (const name of required) {
    const c = checks[name];
    if (!c) {
      overall = overall === "fail" ? "fail" : "unknown";
      reasons.push(`${name}: missing`);
      continue;
    }
    if (c.status === "pass" || c.status === "not_applicable") continue;
    reasons.push(`${name}: ${c.reason}`);
    if (c.status === "fail") overall = "fail";
    else if (overall === "pass") overall = "unknown";
  }
  return { overall, reasons };
}
