/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The shared policy engine: deterministic, versioned, and honest about
 * unknowns.
 *
 * A policy is data (`cool.policy.v1`): an ordered list of rules, each a
 * condition over named facts and a decision. Evaluation uses three-valued
 * logic — a fact that is missing or null is UNKNOWN, not false — so "we could
 * not tell" never quietly becomes "safe". Every rule whose condition is true
 * contributes its decision; every rule whose condition is unknown contributes
 * its `on_unknown` decision (default `defer`). The most restrictive
 * contribution wins:
 *
 *     deny > quarantine > require_approval > defer > audit_only > allow
 *
 * If nothing matched, the policy's `default` applies. The result is a
 * decision record naming the exact policy digest, the matched rules, reason
 * codes and a digest of the inputs — enough to replay the decision later.
 *
 * Fail-open vs fail-closed is not hardcoded: each policy chooses its own
 * default and on_unknown, so a production-deploy policy can default to deny
 * while a telemetry policy defaults to audit_only.
 *
 * Deterministic evaluation is open so anyone can REPLAY a recorded decision:
 * same policy digest + same facts ⇒ same decision. Managing policies (lifecycle,
 * approvals, overrides) is part of the commercial platform.
 *
 * Modes: `observe` records what WOULD happen (enforced: false); `enforce`
 * marks the decision for enforcement. Even then the engine enforces nothing
 * itself — that is the enforcement coordinator's job, against an external
 * system, with confirmation.
 */
import { canonicalCbor } from "../canonical";
import { mhSha256 } from "../multihash";
import type { Multihash } from "../types";

export type Decision = "allow" | "deny" | "require_approval" | "quarantine" | "defer" | "audit_only";
const SEVERITY: Record<Decision, number> = { allow: 0, audit_only: 1, defer: 2, require_approval: 3, quarantine: 4, deny: 5 };
const DECISIONS = Object.keys(SEVERITY) as Decision[];

export type Op = "eq" | "neq" | "in" | "exists" | "lt" | "lte" | "gt" | "gte" | "matches";
export type Condition =
  | { readonly all: readonly Condition[] }
  | { readonly any: readonly Condition[] }
  | { readonly not: Condition }
  | { readonly fact: string; readonly op: Op; readonly value?: unknown };

export interface PolicyRule {
  readonly id: string;
  readonly description?: string;
  readonly when: Condition;
  readonly decision: Decision;
  readonly reason: string;
  readonly on_unknown?: Decision;
}

export interface PolicyDocument {
  readonly schema: "cool.policy.v1";
  readonly id: string;
  readonly version: string;
  readonly description?: string;
  readonly mode: "observe" | "enforce";
  readonly default: Decision;
  readonly on_unknown?: Decision;
  readonly rules: readonly PolicyRule[];
}

export type Facts = Readonly<Record<string, unknown>>;

export interface MatchedRule {
  readonly id: string;
  readonly result: "true" | "unknown";
  readonly decision: Decision;
  readonly reason: string;
  readonly unknown_facts?: readonly string[];
}

export interface PolicyDecisionRecord {
  readonly schema: "cool.policy-decision.v1";
  readonly policy_id: string;
  readonly policy_version: string;
  readonly policy_digest: Multihash;
  readonly mode: "observe" | "enforce";
  readonly decision: Decision;
  /** True only in enforce mode. In observe mode the decision is advisory. */
  readonly enforced: boolean;
  readonly matched_rules: readonly MatchedRule[];
  readonly reason_codes: readonly string[];
  readonly input_digest: Multihash;
  readonly input_refs: readonly string[];
  readonly evaluated_at: string;
  readonly override?: { readonly actor: string; readonly reason: string; readonly approver?: string; readonly at: string; readonly original_decision: Decision };
}

type Tri = true | false | "unknown";

function evaluateCondition(c: Condition, facts: Facts, unknowns: Set<string>): Tri {
  if ("all" in c) {
    let sawUnknown = false;
    for (const sub of c.all) {
      const v = evaluateCondition(sub, facts, unknowns);
      if (v === false) return false;
      if (v === "unknown") sawUnknown = true;
    }
    return sawUnknown ? "unknown" : true;
  }
  if ("any" in c) {
    let sawUnknown = false;
    for (const sub of c.any) {
      const v = evaluateCondition(sub, facts, unknowns);
      if (v === true) return true;
      if (v === "unknown") sawUnknown = true;
    }
    return sawUnknown ? "unknown" : false;
  }
  if ("not" in c) {
    const v = evaluateCondition(c.not, facts, unknowns);
    return v === "unknown" ? "unknown" : !v;
  }
  const value = facts[c.fact];
  if (c.op === "exists") return value !== undefined && value !== null;
  if (value === undefined || value === null) {
    unknowns.add(c.fact);
    return "unknown";
  }
  switch (c.op) {
    case "eq": return value === c.value;
    case "neq": return value !== c.value;
    case "in": return Array.isArray(c.value) && c.value.includes(value);
    case "lt": return typeof value === "number" && typeof c.value === "number" && value < c.value;
    case "lte": return typeof value === "number" && typeof c.value === "number" && value <= c.value;
    case "gt": return typeof value === "number" && typeof c.value === "number" && value > c.value;
    case "gte": return typeof value === "number" && typeof c.value === "number" && value >= c.value;
    case "matches": return typeof value === "string" && typeof c.value === "string" && new RegExp(c.value).test(value);
  }
}

/** Structural validation. Returns problems; empty means valid. */
export function validatePolicy(p: PolicyDocument): string[] {
  const problems: string[] = [];
  if (p?.schema !== "cool.policy.v1") problems.push("schema must be cool.policy.v1");
  if (!p?.id || !p?.version) problems.push("id and version are required");
  if (!["observe", "enforce"].includes(p?.mode)) problems.push("mode must be observe or enforce");
  if (!DECISIONS.includes(p?.default)) problems.push(`default must be one of ${DECISIONS.join(", ")}`);
  if (p?.on_unknown && !DECISIONS.includes(p.on_unknown)) problems.push("on_unknown is not a decision");
  const ids = new Set<string>();
  const ops: Op[] = ["eq", "neq", "in", "exists", "lt", "lte", "gt", "gte", "matches"];
  const walk = (c: Condition, path: string): void => {
    if (!c || typeof c !== "object") { problems.push(`${path}: condition missing`); return; }
    if ("all" in c) c.all.forEach((s, i) => walk(s, `${path}.all[${i}]`));
    else if ("any" in c) c.any.forEach((s, i) => walk(s, `${path}.any[${i}]`));
    else if ("not" in c) walk(c.not, `${path}.not`);
    else if (typeof c.fact !== "string" || !ops.includes(c.op)) problems.push(`${path}: needs fact and a known op`);
    else if (c.op === "matches") { try { new RegExp(String(c.value)); } catch { problems.push(`${path}: invalid regex`); } }
  };
  for (const [i, rule] of (p?.rules ?? []).entries()) {
    if (!rule.id || ids.has(rule.id)) problems.push(`rules[${i}]: id missing or duplicated`);
    ids.add(rule.id);
    if (!DECISIONS.includes(rule.decision)) problems.push(`rules[${i}]: unknown decision ${String(rule.decision)}`);
    if (rule.on_unknown && !DECISIONS.includes(rule.on_unknown)) problems.push(`rules[${i}]: unknown on_unknown`);
    if (!rule.reason) problems.push(`rules[${i}]: reason code required`);
    walk(rule.when, `rules[${i}].when`);
  }
  return problems;
}

export function policyDigest(p: PolicyDocument): Multihash {
  return mhSha256(canonicalCbor(p));
}

/** Evaluate. Pure and deterministic: same policy, facts and time → same record. */
export function evaluatePolicy(
  p: PolicyDocument,
  facts: Facts,
  options: { readonly now?: Date; readonly inputRefs?: readonly string[] } = {},
): PolicyDecisionRecord {
  const problems = validatePolicy(p);
  if (problems.length) throw new Error(`invalid policy ${p?.id}@${p?.version}: ${problems.join("; ")}`);
  const matched: MatchedRule[] = [];
  for (const rule of p.rules) {
    const unknowns = new Set<string>();
    const v = evaluateCondition(rule.when, facts, unknowns);
    if (v === true) matched.push({ id: rule.id, result: "true", decision: rule.decision, reason: rule.reason });
    else if (v === "unknown") {
      matched.push({ id: rule.id, result: "unknown", decision: rule.on_unknown ?? p.on_unknown ?? "defer", reason: `${rule.reason}:unknown_input`, unknown_facts: [...unknowns].sort() });
    }
  }
  const decision = matched.length === 0 ? p.default
    : matched.reduce<Decision>((acc, m) => (SEVERITY[m.decision] > SEVERITY[acc] ? m.decision : acc), "allow");
  const reason_codes = matched.length === 0 ? ["no_rule_matched:default"] : matched.map((m) => `${m.id}:${m.reason}`);
  const sortedFacts = Object.fromEntries(Object.entries(facts).filter(([, v]) => v !== undefined).sort(([a], [b]) => a.localeCompare(b)));
  return {
    schema: "cool.policy-decision.v1",
    policy_id: p.id,
    policy_version: p.version,
    policy_digest: policyDigest(p),
    mode: p.mode,
    decision,
    enforced: p.mode === "enforce",
    matched_rules: matched,
    reason_codes,
    input_digest: mhSha256(canonicalCbor(sortedFacts)),
    input_refs: [...(options.inputRefs ?? [])],
    evaluated_at: (options.now ?? new Date()).toISOString(),
  };
}

/** Evaluate against many inputs with no side effects — the "simulate" lifecycle step. */
export function simulatePolicy(p: PolicyDocument, cases: ReadonlyArray<{ readonly name: string; readonly facts: Facts }>): Array<{ name: string; decision: Decision; reason_codes: readonly string[] }> {
  return cases.map((c) => {
    const r = evaluatePolicy({ ...p, mode: "observe" }, c.facts, { now: new Date(0) });
    return { name: c.name, decision: r.decision, reason_codes: r.reason_codes };
  });
}
