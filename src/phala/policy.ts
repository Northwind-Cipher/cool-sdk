/**
 * Governance, evaluated where the record is sealed.
 *
 * The approval was previously something the caller asserted — it arrived as an
 * argument and got signed, which proves somebody *said* two people approved, not
 * that a rule was applied. This module moves the decision inside the enclave:
 * rules are declared once, evaluated against the change, and the decision plus
 * the rule that produced it are sealed into the same signature as everything
 * else.
 *
 * That is the difference between a record that says "approved" and a record that
 * says "approved under POL-002, which requires two approvers from the owning
 * team, and here are the two". The second one survives an auditor asking how.
 *
 * Rules are plain data, not code, so they can be reviewed, diffed, version
 * controlled and — because a policy set hashes deterministically — committed to
 * inside the record. A change to the rules is itself a change worth sealing.
 */
import { canonicalCbor } from "../canonical";
import { mhSha256 } from "../multihash";
import type { Multihash } from "../types";
import type { ChangeApproval, ChangeKind } from "./types";

/** What a rule can decide. `escalate` means "a human must look". */
export type Decision = "auto-approved" | "approved" | "rejected" | "escalate";

/** The facts a rule is evaluated against. */
export interface PolicyInput {
  readonly kind: ChangeKind;
  readonly ref: string;
  readonly environment: string;
  readonly actor: { readonly id: string; readonly method: string };
  readonly approvers: readonly string[];
  /** Optional risk signals the caller can supply — e.g. from a scoring model. */
  readonly risk?: number;
  /** Free-form labels: `owner:payments`, `tier:high`, `pii:true`. */
  readonly labels?: readonly string[];
}

/** A condition. Every field present must hold. */
export interface PolicyMatch {
  readonly kinds?: readonly ChangeKind[];
  readonly environments?: readonly string[];
  /** Substring or `re:<pattern>` against the change ref. */
  readonly ref?: string;
  /** Minimum number of approvers for the rule to apply. */
  readonly minApprovers?: number;
  /**
   * Maximum number of approvers. The pair lets a rule set say "approved with
   * two, escalate with fewer" without the escalate rule also firing on the
   * approved case — which, under strictest-wins, would make approval
   * unreachable.
   */
  readonly maxApprovers?: number;
  /** Applies only when the caller's risk signal is at or above this. */
  readonly minRisk?: number;
  readonly labels?: readonly string[];
  /** Actor method, e.g. `oidc` for CI, `session` for a human. */
  readonly actorMethods?: readonly string[];
}

export interface PolicyRule {
  /** Stable identifier recorded in the receipt, e.g. `POL-002`. */
  readonly id: string;
  readonly title: string;
  readonly when: PolicyMatch;
  readonly decision: Decision;
  /** Regulatory obligations this rule exists to satisfy. */
  readonly obligations?: readonly string[];
  /** Why the rule exists — printed by `cool policy` and shown in the console. */
  readonly because?: string;
}

export interface PolicySet {
  readonly id: string;
  readonly rules: readonly PolicyRule[];
  /** Decision when nothing matches. Default `escalate` — silence is not consent. */
  readonly fallback?: Decision;
}

/** The outcome, which is what gets sealed. */
export interface PolicyOutcome {
  readonly decision: Decision;
  readonly rule: string | null;
  readonly title: string | null;
  readonly obligations: readonly string[];
  /** Commitment to the exact rule set used. Rules change; records should not. */
  readonly policy_hash: Multihash;
  /** Every rule that matched, worst decision first — the audit trail of the decision. */
  readonly considered: readonly { id: string; decision: Decision }[];
}

/** Severity order: the strictest matching rule wins, never the first one. */
const SEVERITY: Record<Decision, number> = {
  rejected: 3,
  escalate: 2,
  approved: 1,
  "auto-approved": 0,
};

function matches(rule: PolicyRule, input: PolicyInput): boolean {
  const m = rule.when;
  if (m.kinds && !m.kinds.includes(input.kind)) return false;
  if (m.environments && !m.environments.includes(input.environment)) return false;
  if (m.actorMethods && !m.actorMethods.includes(input.actor.method)) return false;
  if (m.ref) {
    if (m.ref.startsWith("re:")) {
      if (!new RegExp(m.ref.slice(3)).test(input.ref)) return false;
    } else if (!input.ref.includes(m.ref)) return false;
  }
  if (m.minApprovers !== undefined && input.approvers.length < m.minApprovers) return false;
  if (m.maxApprovers !== undefined && input.approvers.length > m.maxApprovers) return false;
  if (m.minRisk !== undefined && (input.risk ?? 0) < m.minRisk) return false;
  if (m.labels && !m.labels.every((label) => (input.labels ?? []).includes(label))) return false;
  return true;
}

/** Deterministic commitment to a rule set, so a record names the rules it met. */
export function policyHash(policy: PolicySet): Multihash {
  return mhSha256(canonicalCbor(policy as unknown as Record<string, unknown>));
}

/**
 * Evaluate a change against a policy set.
 *
 * Strictest-wins rather than first-match: a permissive rule written later can
 * never quietly override a restrictive one, which is the failure mode that makes
 * hand-ordered rule lists dangerous.
 */
export function evaluate(policy: PolicySet, input: PolicyInput): PolicyOutcome {
  const matched = policy.rules.filter((rule) => matches(rule, input));
  const considered = matched
    .map((rule) => ({ id: rule.id, decision: rule.decision }))
    .sort((a, b) => SEVERITY[b.decision] - SEVERITY[a.decision]);

  const hash = policyHash(policy);
  if (matched.length === 0) {
    return {
      decision: policy.fallback ?? "escalate",
      rule: null,
      title: null,
      obligations: [],
      policy_hash: hash,
      considered: [],
    };
  }

  const winner = matched.reduce((worst, rule) =>
    SEVERITY[rule.decision] > SEVERITY[worst.decision] ? rule : worst,
  );

  return {
    decision: winner.decision,
    rule: winner.id,
    title: winner.title,
    obligations: winner.obligations ?? [],
    policy_hash: hash,
    considered,
  };
}

/**
 * Fold an outcome into the approval block a record carries.
 *
 * `escalate` is recorded as `rejected` in the receipt schema — the record only
 * knows "this did not have authority to proceed"; the difference between "needs
 * a human" and "forbidden" is an operational one, kept in the outcome.
 */
export function approvalFrom(
  outcome: PolicyOutcome,
  approvers: readonly string[],
): ChangeApproval {
  return {
    policy_id: outcome.rule ?? "no-matching-rule",
    decision:
      outcome.decision === "escalate"
        ? "rejected"
        : (outcome.decision as "auto-approved" | "approved" | "rejected"),
    approvers: [...approvers],
  };
}

/**
 * A defensible starting set.
 *
 * Written to be read by a compliance officer rather than a programmer, and
 * chosen so the defaults fail safe: production prompt and model changes need two
 * humans, widening what an agent may do is never automatic, and anything not
 * covered escalates instead of sliding through.
 */
export const DEFAULT_POLICY: PolicySet = {
  id: "cool.default.v1",
  fallback: "escalate",
  rules: [
    {
      id: "POL-001",
      title: "Non-production changes are automatic",
      when: { environments: ["dev", "test", "staging"] },
      decision: "auto-approved",
      because: "Nothing outside production is customer-facing; friction here buys nothing.",
    },
    {
      id: "POL-002",
      title: "Production prompt and model changes need two approvers",
      when: { environments: ["prod"], kinds: ["prompt", "model", "policy"], minApprovers: 2 },
      decision: "approved",
      obligations: ["eu-ai-act-14"],
      because: "Article 14 requires oversight traceable to named people.",
    },
    {
      id: "POL-003",
      title: "Production changes without two approvers escalate",
      when: { environments: ["prod"], kinds: ["prompt", "model", "policy"], maxApprovers: 1 },
      decision: "escalate",
      obligations: ["eu-ai-act-14"],
      because: "A change nobody signed off is not a change that has been approved.",
    },
    {
      id: "POL-008",
      title: "Parameters and datasets need compliance sign-off in production",
      when: { environments: ["prod"], kinds: ["params", "dataset"], minApprovers: 1 },
      decision: "approved",
      obligations: ["eu-ai-act-15"],
      because: "These move accuracy, and Article 15 wants that provenance recorded.",
    },
    {
      id: "POL-031",
      title: "Widening agent permissions is never automatic",
      when: { kinds: ["agent-permission", "tool"] },
      decision: "escalate",
      obligations: ["eu-ai-act-14", "dpdp-8"],
      because: "What an agent may do is the blast radius of every other decision.",
    },
    {
      id: "POL-040",
      title: "High-risk changes always reach a human",
      when: { minRisk: 0.8 },
      decision: "escalate",
      because: "A model can score risk; it should not be the one to accept it.",
    },
  ],
};
