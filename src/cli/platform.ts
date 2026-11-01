/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Platform command: verify a portable evidence bundle, offline. (Policy
 * evaluation and the deployment gate are commands of the commercial platform.)
 *
 * Exit codes are a stable contract (docs/cli-exit-codes.md):
 *
 *   0   pass
 *   1   fail
 *   2   unknown
 *   64  usage error
 *   65  input is not valid (schema, JSON)
 *   66  input could not be read
 */
import { readFileSync } from "node:fs";
import { PayloadRegistry, TrustStore, verifyBundle, type EvidenceBundle, type TrustSnapshot } from "../platform/index";
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
    for (const e of report.entries) out(`    ${c.faint(e.at.padEnd(24))}  ${mark(e.overall_status)} ${e.event_type.padEnd(24)} ${c.grey(e.digest.slice(0, 26))}…`);
    out();
    out(`  ${mark(report.overall_status)} bundle ${report.overall_status}${report.reasons.length ? c.grey(` — ${report.reasons.join("; ")}`) : ""}`);
  }
  return report.overall_status === "pass" ? EXIT.ok : report.overall_status === "fail" ? EXIT.fail : EXIT.unknown;
}
