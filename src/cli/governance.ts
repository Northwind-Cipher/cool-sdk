/**
 * Policy, compliance and audit packs — the half of the product that is not
 * cryptography.
 *
 * These three commands answer the questions that actually get asked in the room:
 * what are the rules, are we covered, and can you hand me something I can check
 * myself. None of them assert anything: the policy is printed from the rule set
 * that will actually run, and coverage is counted from receipts on disk.
 */
import { writeFileSync, readFileSync } from "node:fs";
import {
  DEFAULT_POLICY,
  buildAuditPack,
  coverage,
  evaluate,
  verifyAuditPack,
} from "../phala/index";
import type { AuditPack, ChangeKind, PolicySet } from "../phala/index";
import { loadReceipts, type Workspace } from "./workspace";
import { Progress, bar, c, columns, fields, g, out, panel, pad } from "./tty";
import { paragraph } from "./help";

const flag = (args: string[], name: string): string | undefined => {
  const index = args.indexOf(`--${name}`);
  return index >= 0 ? args[index + 1] : undefined;
};

/** The rule set in force. One place, so the CLI cannot print a different one. */
export const ACTIVE_POLICY: PolicySet = DEFAULT_POLICY;

/* ── policy ───────────────────────────────────────────────────────────── */

export function policyCommand(args: string[]): number {
  if (args[0] === "test") {
    const kind = (args[1] ?? "prompt") as ChangeKind;
    const ref = args[2] ?? "example#system";
    const approvers = (flag(args, "approvers") ?? "").split(",").filter(Boolean);
    const outcome = evaluate(ACTIVE_POLICY, {
      kind,
      ref,
      environment: flag(args, "env") ?? "prod",
      actor: { id: "user:cli", method: "cli" },
      approvers,
      ...(flag(args, "risk") ? { risk: Number(flag(args, "risk")) } : {}),
      ...(flag(args, "label") ? { labels: [flag(args, "label")!] } : {}),
    });

    const tone =
      outcome.decision === "rejected" || outcome.decision === "escalate" ? c.yellow : c.green;
    panel(
      "policy test",
      [
        `${c.grey("change")}     ${kind} ${ref}`,
        `${c.grey("approvers")}  ${approvers.length > 0 ? approvers.join(", ") : c.faint("none")}`,
        "",
        `${c.grey("decision")}   ${c.bold(tone(outcome.decision))}`,
        `${c.grey("rule")}       ${outcome.rule ?? c.faint("nothing matched — fallback applied")}`,
        `${c.grey("title")}      ${outcome.title ?? ""}`,
      ],
      tone,
    );
    if (outcome.considered.length > 1) {
      out();
      out(`  ${c.faint("Also matched:")}`);
      for (const rule of outcome.considered.slice(1)) {
        out(`    ${c.faint(`${rule.id} → ${rule.decision}`)}`);
      }
    }
    out();
    out(
      `  ${c.faint(
        "The strictest matching rule wins, so a permissive rule added later cannot override a stricter one.",
      )}`,
    );
    out();
    return 0;
  }

  out();
  out(`  ${c.bold(ACTIVE_POLICY.id)}   ${c.faint(`${ACTIVE_POLICY.rules.length} rules`)}`);
  out();
  for (const rule of ACTIVE_POLICY.rules) {
    const tone =
      rule.decision === "rejected" || rule.decision === "escalate" ? c.yellow : c.green;
    out(`  ${c.bold(c.brand(rule.id))}  ${rule.title}`);
    out(`    ${c.grey("decision")}  ${tone(rule.decision)}`);
    const when: string[] = [];
    if (rule.when.environments) when.push(`env ∈ [${rule.when.environments.join(", ")}]`);
    if (rule.when.kinds) when.push(`kind ∈ [${rule.when.kinds.join(", ")}]`);
    if (rule.when.minApprovers !== undefined) when.push(`approvers ≥ ${rule.when.minApprovers}`);
    if (rule.when.minRisk !== undefined) when.push(`risk ≥ ${rule.when.minRisk}`);
    if (rule.when.ref) when.push(`ref ~ ${rule.when.ref}`);
    out(`    ${c.grey("when")}      ${when.join("  ·  ") || c.faint("always")}`);
    if (rule.obligations?.length) {
      out(`    ${c.grey("covers")}    ${rule.obligations.join(", ")}`);
    }
    if (rule.because) out(`    ${c.faint(rule.because)}`);
    out();
  }
  out(
    `  ${c.grey("fallback")}  ${c.yellow(ACTIVE_POLICY.fallback ?? "escalate")} ${c.faint(
      "— anything unmatched needs a human",
    )}`,
  );
  out();
  out(`  ${c.faint("Try one:")} ${c.brand("cool policy test agent-permission app#tools --env prod")}`);
  out();
  return 0;
}

/* ── compliance ───────────────────────────────────────────────────────── */

export function complianceCommand(workspace: Workspace | null, args: string[]): number {
  const receipts = loadReceipts(workspace?.root).map((entry) => entry.receipt);
  const rows = coverage(receipts);
  const shown = args.includes("--gaps") ? rows.filter((row) => !row.covered) : rows;

  if (receipts.length === 0) {
    out(`  ${c.faint("No evidence in this project yet, so nothing is covered.")}`);
    out(`  ${c.faint("Seal something first:")} ${c.brand("cool walkthrough")}`);
    out();
    return 0;
  }

  out();
  const width = Math.min(20, columns() - 62);
  for (const row of shown) {
    const mark = row.covered ? c.green(g.pass) : c.yellow(g.warn);
    out(`  ${mark} ${c.bold(pad(row.obligation.regime, 18))}${c.grey(row.obligation.clause)}`);
    out(`    ${c.faint(row.obligation.requirement)}`);
    out(
      `    ${bar(row.records, receipts.length, width)} ${pad(String(row.records), 4)}` +
        `${c.faint(`records · ${row.obligation.satisfiedBy}`)}`,
    );
    out();
  }

  const covered = rows.filter((row) => row.covered).length;
  out(
    `  ${covered} of ${rows.length} obligations have evidence behind them` +
      c.faint("  — counted from receipts, never asserted"),
  );
  out();
  return 0;
}

/* ── pack ─────────────────────────────────────────────────────────────── */

export async function packCommand(workspace: Workspace | null, args: string[]): Promise<number> {
  const sub = args[0] ?? "build";

  if (sub === "verify") {
    const path = args[1];
    if (!path) {
      out(`  ${c.red(g.fail)} usage: cool pack verify <file>`);
      return 1;
    }
    const pack = JSON.parse(readFileSync(path, "utf8")) as AuditPack;
    const progress = new Progress().start(`checking ${pack.records.length} record(s)`);
    const verdict = await verifyAuditPack(pack);
    if (verdict.ok) progress.succeed(`every record in ${path} verifies`);
    else progress.fail(`${verdict.failed} of ${verdict.total} records FAILED`);

    fields([
      ["subject", pack.subject],
      ["generated", pack.generated_at],
      ["records", `${verdict.verified} verified / ${verdict.total}`],
      ["witnesses", String(verdict.witnesses)],
      ["obligations", `${verdict.obligationsCovered} of ${verdict.obligationsTotal} covered`],
    ]);
    for (const failure of verdict.failures) {
      out(`  ${c.red(g.fail)} ${failure.record_id}: ${failure.reasons[0] ?? "rejected"}`);
    }
    out();
    out(
      `  ${c.faint(
        "The summary above was recomputed from the receipts, not read from the pack.",
      )}`,
    );
    out();
    return verdict.ok ? 0 : 1;
  }

  if (!workspace) {
    out(`  ${c.red(g.fail)} building a pack needs this project's evidence`);
    return 1;
  }
  const target = flag(args, "out") ?? "cool-audit-pack.json";
  const receipts = loadReceipts(workspace.root).map((entry) => entry.receipt);
  const progress = new Progress().start(`packing ${receipts.length} record(s)`);
  const pack = buildAuditPack(receipts, {
    subject: `${workspace.info.appName} — ${workspace.root}`,
    enclave: {
      vendor: workspace.info.vendor,
      mode: workspace.info.mode,
      app_id: workspace.info.appId,
      measurement: workspace.info.measurement,
    },
  });
  writeFileSync(target, `${JSON.stringify(pack, null, 2)}\n`);
  progress.succeed(`wrote ${c.bold(target)}`);

  fields([
    ["records", String(pack.records.length)],
    ["obligations", `${pack.obligations.filter((o) => o.covered).length} of ${pack.obligations.length} covered`],
    ["verifies with", "cool pack verify " + target],
  ]);
  out();
  paragraph(
    c.faint(
      "Self-contained: every receipt, the keys to check them, the enclave measurement and " +
        "the clause mapping. It verifies offline, by someone who has never met you.",
    ),
  );
  out();
  return 0;
}
