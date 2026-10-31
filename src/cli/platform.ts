/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Platform commands: verify a portable evidence bundle, evaluate a policy, and
 * run the supply-chain deployment-gate demo.
 *
 * Exit codes are a stable contract (docs/cli-exit-codes.md):
 *
 *   0   pass / allow / audit_only
 *   1   fail / deny / quarantine
 *   2   unknown, or a decision that needs a human (require_approval, defer)
 *   64  usage error
 *   65  input is not valid (schema, JSON)
 *   66  input could not be read
 */
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { generateKeypair } from "../keys";
import {
  CoolClient,
  LocalDirectoryTarget,
  PayloadRegistry,
  RELEASE_POLICY,
  TransparencyLog,
  TrustStore,
  buildProvenance,
  evaluatePolicy,
  exportBundle,
  validatePolicy,
  verifyBundle,
  type EvidenceBundle,
  type PolicyDocument,
  type TrustSnapshot,
} from "../platform/index";
import { c, g, out } from "./tty";

export const EXIT = { ok: 0, fail: 1, unknown: 2, usage: 64, dataErr: 65, noInput: 66 } as const;

const flag = (args: string[], name: string) => args.includes(name);
const option = (args: string[], name: string) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const positional = (args: string[]) => args.filter((a, i) => !a.startsWith("--") && !(i > 0 && args[i - 1]!.startsWith("--") && ["--trust", "--out"].includes(args[i - 1]!)));

function readJson<T>(path: string): { value?: T; code?: number; error?: string } {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    return { code: EXIT.noInput, error: `cannot read ${path}: ${(err as Error).message}` };
  }
  try {
    return { value: JSON.parse(text) as T };
  } catch (err) {
    return { code: EXIT.dataErr, error: `${path} is not JSON: ${(err as Error).message}` };
  }
}

const mark = (s: string) => (s === "pass" ? c.green(g.pass) : s === "fail" ? c.red(g.fail) : c.yellow(g.warn));

/** `cool bundle verify <file> [--trust snapshot.json] [--json]` */
export function bundleCommand(args: string[]): number {
  const [sub, file] = positional(args);
  if (sub !== "verify" || !file) {
    out(`  usage: ${c.brand("cool bundle verify <bundle.json> [--trust trust.json] [--json]")}`);
    return EXIT.usage;
  }
  const b = readJson<EvidenceBundle>(file);
  if (!b.value) return out(`  ${c.red(g.fail)} ${b.error}`), b.code!;
  let trust: TrustStore | undefined;
  const trustPath = option(args, "--trust");
  if (trustPath) {
    const t = readJson<TrustSnapshot>(trustPath);
    if (!t.value) return out(`  ${c.red(g.fail)} ${t.error}`), t.code!;
    try { trust = new TrustStore(t.value); } catch (err) { return out(`  ${c.red(g.fail)} ${(err as Error).message}`), EXIT.dataErr; }
  }
  let report;
  try {
    report = verifyBundle(b.value, { registry: PayloadRegistry.standard(), ...(trust ? { trust } : {}), purpose: (t) => (/^(build|artifact)\./.test(t) ? "builder" : "evidence") });
  } catch (err) {
    out(`  ${c.red(g.fail)} ${(err as Error).message}`);
    return EXIT.dataErr;
  }
  if (flag(args, "--json")) out(JSON.stringify(report, null, 2));
  else {
    out(`  ${c.bold(b.value.title)} ${c.faint(`(${b.value.envelopes.length} envelopes)`)}`);
    for (const [name, chk] of Object.entries(report.checks)) out(`    ${mark(chk.status)} ${name.padEnd(26)} ${c.grey(chk.detail)}`);
    out();
    for (const e of report.timeline.entries) out(`    ${c.faint(e.at || "—".padEnd(24))}  ${e.label.padEnd(15)} ${e.event_type.padEnd(22)} ${c.grey(e.summary)}`);
    out();
    out(`  ${mark(report.overall_status)} bundle ${report.overall_status}${report.reasons.length ? c.grey(` — ${report.reasons.join("; ")}`) : ""}`);
  }
  return report.overall_status === "pass" ? EXIT.ok : report.overall_status === "fail" ? EXIT.fail : EXIT.unknown;
}

/** `cool decide <policy.json> <facts.json> [--json]` */
export function decideCommand(args: string[]): number {
  const [policyPath, factsPath] = positional(args);
  if (!policyPath || !factsPath) {
    out(`  usage: ${c.brand("cool decide <policy.json> <facts.json> [--json]")}`);
    return EXIT.usage;
  }
  const p = readJson<PolicyDocument>(policyPath);
  if (!p.value) return out(`  ${c.red(g.fail)} ${p.error}`), p.code!;
  const f = readJson<Record<string, unknown>>(factsPath);
  if (!f.value) return out(`  ${c.red(g.fail)} ${f.error}`), f.code!;
  const problems = validatePolicy(p.value);
  if (problems.length) return out(`  ${c.red(g.fail)} invalid policy: ${problems.join("; ")}`), EXIT.dataErr;
  const r = evaluatePolicy(p.value, f.value);
  if (flag(args, "--json")) out(JSON.stringify(r, null, 2));
  else {
    out(`  ${c.bold(r.decision)} ${c.faint(`${r.policy_id}@${r.policy_version} · ${r.mode}${r.enforced ? "" : " (advisory)"}`)}`);
    for (const m of r.matched_rules) out(`    ${m.result === "true" ? c.cyan("matched") : c.yellow("unknown")} ${m.id} → ${m.decision} ${c.grey(m.reason)}${m.unknown_facts ? c.faint(` [${m.unknown_facts.join(", ")}]`) : ""}`);
  }
  return ["allow", "audit_only"].includes(r.decision) ? EXIT.ok : ["deny", "quarantine"].includes(r.decision) ? EXIT.fail : EXIT.unknown;
}

/**
 * `cool gate-demo [dir]` — the spec's first milestone, run locally:
 * build → provenance → verify → policy → deploy; tamper → refuse; export → verify.
 * Everything is real except the scale: a local directory stands in for a cluster.
 */
export async function gateDemoCommand(args: string[]): Promise<number> {
  const dir = resolve(positional(args)[0] ?? mkdtempSync(join(tmpdir(), "cool-gate-demo-")));
  mkdirSync(dir, { recursive: true });
  const step = (n: number, text: string) => out(`  ${c.brand(String(n).padStart(2))} ${text}`);
  const ok = (text: string) => out(`     ${c.green(g.pass)} ${c.grey(text)}`);
  const bad = (text: string) => out(`     ${c.red(g.fail)} ${c.grey(text)}`);
  const now = () => new Date();

  const builderKey = generateKeypair("demo-builder");
  const operatorKey = generateKeypair("demo-operator");
  const logKey = generateKeypair("demo-log");
  const snapshot: TrustSnapshot = {
    schema: "cool.trust-snapshot.v1", id: "gate-demo", as_of: now().toISOString(),
    keys: [
      { key_id: builderKey.keyId, entry: builderKey.directoryEntry, purposes: ["builder"], owner: "demo CI", valid_from: new Date(0).toISOString(), status: "active" },
      { key_id: operatorKey.keyId, entry: operatorKey.directoryEntry, purposes: ["evidence"], owner: "demo ops", valid_from: new Date(0).toISOString(), status: "active" },
      { key_id: logKey.keyId, entry: logKey.directoryEntry, purposes: ["log"], owner: "demo log", valid_from: new Date(0).toISOString(), status: "active" },
    ],
  };
  const trust = new TrustStore(snapshot);
  const log = new TransparencyLog("gate-demo-log", logKey);
  const builder = new CoolClient({ project: "demo", signer: builderKey, trust, log });
  const operator = new CoolClient({ project: "demo", signer: operatorKey, trust, log, policyMode: "enforce", enforcement: { enabled: true } });
  const target = new LocalDirectoryTarget(join(dir, "prod"));
  const artifactPath = join(dir, "service.tar");
  let expected = true;

  step(1, "build a benign artifact and record signed provenance");
  writeFileSync(artifactPath, "demo service v1\n");
  const prov = buildProvenance({ buildId: "build-1", builderId: builderKey.keyId, repository: "demo/service", commit: "0000000000000000000000000000000000000001", artifactPath, finishedAt: now().toISOString() });
  const build = builder.evidence.publish(builder.evidence.record(prov.build));
  const artifact = builder.evidence.publish(builder.evidence.record({ ...prov.artifact, provenance: { collection_method: "emitted", refs: [build.digest] } }));
  ok(`artifact ${prov.digest.slice(0, 26)}… · leaf ${artifact.checkpoint?.leaf_index} in the log`);

  const evidence = () => ({
    artifactPath, build, artifact,
    buildReport: operator.evidence.verify(build, { purpose: "builder" }),
    artifactReport: operator.evidence.verify(artifact, { purpose: "builder" }),
    trustedBuilders: [builderKey.keyId], allowedRepositories: ["demo/service"],
  });

  step(2, "verify provenance and gate the deployment");
  const first = await operator.supply_chain.gate({ evidence: evidence(), target, deploymentId: "deploy-1", environment: "prod", requestedBy: "user:demo", dryRun: false });
  if (first.enforcement.confirmed) ok(`${first.decision.decision} → deployed and confirmed by the target (${first.decision.reason_codes.join(", ")})`);
  else { bad(`expected a deployment: ${first.enforcement.detail}`); expected = false; }

  step(3, "tamper with the artifact and retry");
  writeFileSync(artifactPath, "demo service v1\n# injected\n");
  const second = await operator.supply_chain.gate({ evidence: evidence(), target, deploymentId: "deploy-2", environment: "prod", requestedBy: "user:demo", dryRun: false });
  if (second.decision.decision === "deny") ok(`deny → ${second.decision.reason_codes.join(", ")}; target untouched`);
  else { bad(`expected deny, got ${second.decision.decision}`); expected = false; }

  step(4, "export the evidence bundle and verify it independently");
  const records = [...first.records, ...second.records].map((r) => operator.evidence.publish(operator.evidence.record(r)));
  const bundle = exportBundle({ title: "gate demo", envelopes: [build, artifact, ...records], decisions: [first.decision, second.decision], trust, exporter: operatorKey });
  writeFileSync(join(dir, "bundle.json"), JSON.stringify(bundle, null, 2));
  writeFileSync(join(dir, "trust.json"), JSON.stringify(snapshot, null, 2));
  writeFileSync(join(dir, "policy.json"), JSON.stringify(RELEASE_POLICY, null, 2));
  const report = verifyBundle(JSON.parse(readFileSync(join(dir, "bundle.json"), "utf8")), { registry: PayloadRegistry.standard(), trust, purpose: (t) => (/^(build|artifact)\./.test(t) ? "builder" : "evidence") });
  if (report.overall_status === "pass") ok(`bundle verifies: ${report.envelopes.length} envelopes, ${report.timeline.links.length} links`);
  else { bad(`bundle ${report.overall_status}: ${report.reasons.join("; ")}`); expected = false; }

  out();
  out(`  ${c.faint("files")} ${dir}`);
  out(`  ${c.faint("check it yourself:")} ${c.brand(`cool bundle verify ${join(dir, "bundle.json")} --trust ${join(dir, "trust.json")}`)}`);
  out(`  ${c.faint("limits: a local directory stands in for a cluster; keys are generated for the demo and live only in this run.")}`);
  return expected ? EXIT.ok : EXIT.fail;
}
