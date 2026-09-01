/**
 * What `cool` can do, in one place.
 *
 * Every command is written so that it works identically whether it was typed at
 * the interactive prompt or passed as an argument — `cool verify x.json` and
 * `/verify x.json` run the same function. That keeps the tool honest: anything a
 * demo can do, a CI job can do too, and there is no interactive-only magic.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { domainOrder } from "../phala/index";
import type { ChangeKind, ReceiptV2, VerdictV2 } from "../phala/index";
import {
  analytics,
  loadReceipts,
  readReceipt,
  saveReceipt,
  verify,
  type Workspace,
} from "./workspace";
import { Progress, bar, c, columns, fields, g, out, panel, sparkline, status } from "./tty";
import { latestVersion, isNewer } from "./update";

/**
 * The version the CLI reports.
 *
 * Read from the package it was installed as, rather than typed here — a CLI
 * that lies about its own version is a support ticket that takes an hour to
 * diagnose. The literal below is only reached when running from source in this
 * repository, where there is no published package.json above the module.
 */
function resolveVersion(): string {
  try {
    const here = fileURLToPath(import.meta.url);
    const manifest = JSON.parse(
      readFileSync(join(dirname(here), "..", "..", "package.json"), "utf8"),
    ) as { name?: string; version?: string };
    if (manifest.name === "cool-nwc" && typeof manifest.version === "string") {
      return manifest.version;
    }
  } catch {
    // Running from source, or a packaging layout we do not recognise.
  }
  return "2.5.0-dev";
}

export const VERSION = resolveVersion();

/* ── help ─────────────────────────────────────────────────────────────── */

export function banner(workspace: Workspace | null): void {
  const mode = workspace?.info.mode ?? "unknown";
  const vendor = workspace?.info.vendor ?? "—";
  const tone = mode === "hardware" ? c.green : c.cyan;

  panel("CooL", [
    `${c.bold("evidence for AI, sealed in a TEE")}   ${c.faint(`v${VERSION}`)}`,
    "",
    `${c.grey("enclave")}   ${tone(`${vendor} · ${mode}`)}${
      mode === "simulated" ? c.faint("   (no hardware — every receipt says so)") : ""
    }`,
    `${c.grey("key")}       ${workspace?.cool.plane.keys.record.keyId ?? "—"}`,
    `${c.grey("channel")}   ${
      workspace?.cool.handshake.ok ? c.green("open") : c.red("closed")
    }   ${c.grey("receipts")}  ${loadReceipts(workspace?.root).length}`,
  ]);
  out();
  out(
    `  ${c.faint("type")} ${c.brand("/help")} ${c.faint("for commands,")} ${c.brand("/demo")} ${c.faint(
      "to watch the whole thing, ",
    )}${c.brand("/exit")} ${c.faint("to leave")}`,
  );
  out();
}

/* ── status ───────────────────────────────────────────────────────────── */

export function statusPanel(workspace: Workspace): void {
  const { info, cool } = workspace;
  const measurement = info.measurement;

  panel(
    "enclave",
    [
      `${c.grey("vendor")}       ${info.vendor}`,
      `${c.grey("mode")}         ${
        info.mode === "hardware" ? c.green(info.mode) : c.cyan(`${info.mode} — not hardware evidence`)
      }`,
      `${c.grey("app id")}       ${info.appId}`,
      `${c.grey("instance")}     ${info.instanceId}`,
      `${c.grey("mrtd")}         ${measurement.mrtd.slice(4, 44)}…`,
      `${c.grey("rtmr3")}        ${measurement.rtmr3.slice(4, 44)}…`,
      `${c.grey("signing key")}  ${cool.plane.keys.record.keyId} ${c.faint("(derived from the measurement)")}`,
      `${c.grey("log")}          ${cool.plane.logSize} entr${cool.plane.logSize === 1 ? "y" : "ies"}`,
    ],
    info.mode === "hardware" ? c.green : c.brand,
  );
  out();

  out(`  ${c.bold("RA-TLS handshake")}`);
  for (const step of cool.handshake.steps) {
    out(`  ${step.ok ? c.green(g.pass) : c.red(g.fail)} ${c.grey(step.label.padEnd(16))} ${step.detail}`);
  }
  out();
}

/* ── seal ─────────────────────────────────────────────────────────────── */

const KINDS: ChangeKind[] = [
  "prompt",
  "model",
  "params",
  "policy",
  "dataset",
  "agent-permission",
  "tool",
];

export async function seal(
  workspace: Workspace,
  args: string[],
): Promise<ReceiptV2 | null> {
  const kind = (args[0] ?? "prompt") as ChangeKind;
  if (!KINDS.includes(kind)) {
    out(`  ${c.red(g.fail)} unknown kind '${kind}'. One of: ${KINDS.join(", ")}`);
    return null;
  }
  const ref = args[1] ?? `${basename(workspace.root)}#system`;
  const after = args.slice(2).join(" ") || `updated at ${new Date().toISOString()}`;

  const progress = new Progress().start("capturing — async, out of band");
  const receipt = await workspace.cool.change({
    kind,
    ref,
    environment: process.env["COOL_ENV"] ?? "dev",
    after,
    actor: { id: `user:${process.env["USER"] ?? process.env["USERNAME"] ?? "local"}`, method: "cli" },
  });
  progress.update("sealing inside the enclave — hash, hybrid-sign, append");
  const path = saveReceipt(workspace.root, receipt);
  progress.succeed(`sealed ${c.bold(receipt.record.record_id)}`);

  fields([
    ["kind", `${kind} ${c.faint(ref)}`],
    ["binding", c.grey(receipt.binding_hash)],
    ["leaf", `${receipt.inclusion?.leaf_index} of ${receipt.inclusion?.tree_size}`],
    ["signature", `${receipt.record.signature.alg} ${c.faint(receipt.record.signature.key_id)}`],
    ["saved", c.grey(relative(workspace.root, path))],
  ]);
  out();
  return receipt;
}

/* ── verify ───────────────────────────────────────────────────────────── */

export function printVerdict(verdict: VerdictV2, subject: string): void {
  out(`  ${c.bold(subject)}`);
  for (const domain of domainOrder()) {
    const check = verdict.checks[domain];
    out(`    ${status(check.status).padEnd(22)} ${c.grey(domain.padEnd(12))} ${c.faint(check.detail)}`);
  }
  out(
    verdict.ok
      ? `  ${c.green(`${g.pass} receipt verifies`)}`
      : `  ${c.red(`${g.fail} receipt REJECTED`)}`,
  );
  for (const reason of verdict.reasons) out(`    ${c.red(reason)}`);
  out();
}

export async function verifyCommand(
  workspace: Workspace | null,
  args: string[],
): Promise<number> {
  const requireHardware = args.includes("--require-hardware");
  const targets = args.filter((arg) => !arg.startsWith("--"));
  const stored = loadReceipts(workspace?.root);

  let receipts: { label: string; receipt: ReceiptV2 }[];
  if (targets.length === 0 || targets[0] === "last") {
    const latest = stored.at(-1);
    if (!latest) {
      out(`  ${c.yellow(g.warn)} no receipts yet — try ${c.brand("/seal prompt app#system \"hello\"")}`);
      return 1;
    }
    receipts = [{ label: basename(latest.path), receipt: latest.receipt }];
  } else if (targets[0] === "all") {
    receipts = stored.map((entry) => ({ label: basename(entry.path), receipt: entry.receipt }));
  } else {
    receipts = targets.map((path) => ({ label: path, receipt: readReceipt(path) }));
  }

  let failures = 0;
  for (const { label, receipt } of receipts) {
    const progress = new Progress().start(`verifying ${label}`);
    const verdict = await verify(receipt, workspace, { requireHardware, pin: true });
    if (verdict.ok) progress.succeed(`${label}`);
    else progress.fail(`${label}`);
    printVerdict(verdict, label);
    if (!verdict.ok) failures++;
  }

  if (receipts.length > 1) {
    out(
      `  ${receipts.length - failures}/${receipts.length} verified${
        failures > 0 ? c.red(` · ${failures} rejected`) : ""
      }`,
    );
    out();
  }
  return failures === 0 ? 0 : 1;
}

/* ── stats ────────────────────────────────────────────────────────────── */

export async function stats(workspace: Workspace | null): Promise<void> {
  const stored = loadReceipts(workspace?.root);
  const progress = new Progress().start(`re-verifying ${stored.length} receipt(s)`);
  const a = await analytics(stored, workspace);
  progress.succeed(`analysed ${stored.length} receipt(s)`);

  if (a.total === 0) {
    out(`  ${c.faint("Nothing recorded in this project yet.")}`);
    out();
    return;
  }

  const width = Math.min(28, columns() - 34);
  const max = Math.max(...a.byKind.map(([, count]) => count), 1);

  panel("evidence", [
    `${c.grey("records")}      ${c.bold(String(a.total))}   ${c.faint(
      `${a.changes} change · ${a.evidence} evidence`,
    )}`,
    `${c.grey("verified")}     ${c.green(String(a.verified))}${
      a.failed > 0 ? c.red(`   ${a.failed} rejected`) : ""
    }`,
    `${c.grey("runtime")}      ${
      a.hardware > 0 ? c.green(`${a.hardware} hardware`) : ""
    }${a.simulated > 0 ? c.cyan(`${a.hardware > 0 ? " · " : ""}${a.simulated} simulated`) : ""}`,
    `${c.grey("log")}          tree size ${a.treeSize}`,
  ]);
  out();

  out(`  ${c.bold("by kind")}`);
  for (const [kind, count] of a.byKind) {
    out(`    ${c.grey(kind.padEnd(18))} ${bar(count, max, width)} ${String(count).padStart(3)}`);
  }
  out();

  out(`  ${c.bold("last 14 days")}   ${sparkline(a.perDay)}  ${c.faint(`${a.total} total`)}`);

  if (a.capture) {
    out();
    out(`  ${c.bold("capture cost")} ${c.faint("— measured on this machine, off the request path")}`);
    fields(
      [
        ["p50", `${a.capture.p50Ms.toFixed(4)} ms`],
        ["p99", `${a.capture.p99Ms.toFixed(4)} ms`],
        ["sent", String(a.capture.sent)],
        ["dropped", a.capture.dropped > 0 ? c.yellow(String(a.capture.dropped)) : "0"],
      ],
      "    ",
    );
  }
  out();
}

/* ── attest ───────────────────────────────────────────────────────────── */

export function attest(workspace: Workspace): void {
  const quote = workspace.cool.handshake.quote;
  const m = workspace.info.measurement;

  panel(
    "quote",
    [
      `${c.grey("format")}       ${quote.format}`,
      `${c.grey("root")}         ${
        quote.root === "cool-sim-root" ? c.cyan(`${quote.root} — NOT a vendor root`) : c.green(quote.root)
      }`,
      `${c.grey("tcb")}          ${quote.body.tcb_status}`,
      `${c.grey("report_data")}  ${quote.body.report_data}`,
      c.faint("   ↳ commits to the public half of the key that signs every record"),
    ],
    quote.root === "cool-sim-root" ? c.cyan : c.green,
  );
  out();
  out(`  ${c.bold("measurement registers")}`);
  for (const [name, value] of Object.entries(m)) {
    out(`    ${c.grey(name.toUpperCase().padEnd(6))} ${c.faint(value.slice(4))}`);
  }
  out();
  out(`  ${c.faint("MRTD is the image; RTMR3 moves when your application does.")}`);
  out();
}

/* ── export ───────────────────────────────────────────────────────────── */

export async function exportPack(workspace: Workspace, args: string[]): Promise<void> {
  const target = args[0] ?? "cool-audit-pack.json";
  const stored = loadReceipts(workspace.root);
  const progress = new Progress().start(`building an audit pack from ${stored.length} receipt(s)`);

  const records = [];
  for (const { receipt } of stored) {
    const verdict = await verify(receipt, workspace);
    records.push({
      record_id: receipt.record.record_id,
      schema: receipt.record.schema,
      sealed_at: receipt.record.time.issued_at,
      verdict: { ok: verdict.ok, checks: verdict.checks },
      receipt,
    });
  }

  writeFileSync(
    target,
    `${JSON.stringify(
      {
        schema: "cool.audit-pack.v1",
        generated_at: new Date().toISOString(),
        project: basename(workspace.root),
        enclave: {
          vendor: workspace.info.vendor,
          mode: workspace.info.mode,
          app_id: workspace.info.appId,
          measurement: workspace.info.measurement,
        },
        records,
        how_to_verify:
          "cool verify <any receipt in this pack> — offline, no account, no network unless a hardware quote is being chained to its vendor root.",
      },
      null,
      2,
    )}\n`,
  );
  progress.succeed(`wrote ${c.bold(target)} ${c.faint(`(${records.length} records)`)}`);
  out();
}

/* ── doctor ───────────────────────────────────────────────────────────── */

export async function doctor(workspace: Workspace | null): Promise<number> {
  const checks: [string, boolean, string][] = [];
  const node = Number(process.versions.node.split(".")[0] ?? 0);
  checks.push(["node ≥ 20", node >= 20, `v${process.versions.node}`]);

  // Asking the public registry, cached for a day, one-second timeout, silent on
  // failure. An out-of-date security tool is worth one line of output; phoning
  // home on every invocation is not.
  const latest = await latestVersion(workspace?.root);
  checks.push([
    "up to date",
    latest === null || !isNewer(latest, VERSION),
    latest === null
      ? `${VERSION} — registry not reachable, no check made`
      : isNewer(latest, VERSION)
        ? `${VERSION} installed, ${latest} available — npm i -g cool-nwc@latest`
        : `${VERSION} is current`,
  ]);
  checks.push([
    "web crypto",
    typeof globalThis.crypto?.getRandomValues === "function",
    "required for salts and keys",
  ]);

  const endpoint = process.env["DSTACK_ENDPOINT"];
  checks.push([
    "dstack endpoint",
    Boolean(endpoint),
    endpoint ?? "unset — running the simulator, receipts will say 'simulated'",
  ]);
  const verifierUrl = process.env["QUOTE_VERIFIER_URL"];
  checks.push([
    "quote verifier",
    Boolean(verifierUrl),
    verifierUrl ?? "unset — a hardware quote would be reported, not verified",
  ]);

  if (workspace) {
    checks.push([
      "evidence plane",
      workspace.cool.handshake.ok,
      workspace.cool.handshake.ok ? "RA-TLS channel open" : workspace.cool.handshake.reasons.join("; "),
    ]);
    const probe = await workspace.cool.change({
      kind: "policy",
      ref: "cool#doctor",
      environment: "dev",
      after: "doctor probe",
      actor: { id: "cool:doctor", method: "cli" },
    });
    const verdict = await verify(probe, workspace, { pin: true });
    checks.push(["seal + verify", verdict.ok, verdict.ok ? "round trip clean" : verdict.reasons[0] ?? ""]);
  }

  panel(
    "doctor",
    checks.map(
      ([label, ok, detail]) =>
        `${ok ? c.green(g.pass) : c.yellow(g.warn)} ${c.grey(label.padEnd(16))} ${c.faint(detail)}`,
    ),
    checks.every(([, ok]) => ok) ? c.green : c.yellow,
  );
  out();
  return checks.every(([, ok]) => ok) ? 0 : 1;
}
