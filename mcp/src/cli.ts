#!/usr/bin/env node
/**
 * CooL MCP server
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * mcp-server-cool — one binary, several entry points:
 *
 *   mcp-server-cool [serve] [--workspace DIR] [--export-jsonl FILE]   MCP server over stdio (default)
 *   mcp-server-cool proxy --workspace DIR --name NAME -- CMD ARGS...   record every call to another MCP server
 *   mcp-server-cool hook  [--workspace DIR] [--all]                    Claude Code PostToolUse hook (JSON on stdin)
 *   mcp-server-cool init    --workspace DIR                            create .cool/ and print the fingerprint
 *   mcp-server-cool record  --workspace DIR --tool NAME [--target T] [--outcome O]
 *   mcp-server-cool seal    --workspace DIR
 *   mcp-server-cool verify  BUNDLE_DIR [--fingerprint FP | --trust FILE | --workspace DIR] [--json]
 *   mcp-server-cool status  --workspace DIR
 *
 * Exit codes for verify: 0 VALID, 1 INVALID, 2 INDETERMINATE, 3 usage error.
 */
import { readFileSync } from "node:fs";
import { relative, isAbsolute, resolve } from "node:path";
import { openWorkspace, resolveWorkspaceRoot } from "./workspace.js";
import { recordReceipt, type Outcome } from "./receipts.js";
import { sealWorkspace } from "./seal.js";
import { verifyBundleDir, type VerifyResult } from "./verify.js";
import { serve, statusOf, VERSION } from "./server.js";
import { runProxy } from "./proxy.js";

interface Args { readonly cmd: string; readonly pos: string[]; readonly flags: Map<string, string | true>; readonly rest: string[] }

function parse(argv: string[]): Args {
  const dd = argv.indexOf("--");
  const head = dd >= 0 ? argv.slice(0, dd) : argv;
  const rest = dd >= 0 ? argv.slice(dd + 1) : [];
  const flags = new Map<string, string | true>(); const pos: string[] = [];
  for (let i = 0; i < head.length; i++) {
    const a = head[i]!;
    if (a.startsWith("--")) {
      const [k, v] = a.slice(2).split("=", 2) as [string, string | undefined];
      if (v !== undefined) flags.set(k, v);
      else if (head[i + 1] !== undefined && !head[i + 1]!.startsWith("--") && !["all", "json", "help", "version"].includes(k)) flags.set(k, head[++i]!);
      else flags.set(k, true);
    } else pos.push(a);
  }
  const cmds = ["serve", "proxy", "hook", "init", "record", "seal", "verify", "status", "help"];
  const cmd = pos[0] && cmds.includes(pos[0]) ? pos.shift()! : "serve";
  return { cmd, pos, flags, rest };
}

const str = (a: Args, k: string) => { const v = a.flags.get(k); return typeof v === "string" ? v : undefined; };
/**
 * The workspace named on the command line or in the environment. A relative value is an explicit
 * choice ("--workspace ."), so it is resolved against the current directory; a placeholder the MCP
 * client did not expand (a literal "${...}") is ignored with a warning rather than mis-resolved.
 */
function configuredWorkspace(a: Args, fallback?: string): string | undefined {
  for (const [name, v] of [["--workspace", str(a, "workspace")], ["COOL_WORKSPACE", process.env["COOL_WORKSPACE"]], ["CLAUDE_PROJECT_DIR", process.env["CLAUDE_PROJECT_DIR"]], ["hook cwd", fallback]] as const) {
    if (!v) continue;
    if (v.includes("${")) { process.stderr.write(`mcp-server-cool: ignoring ${name}="${v}" (the client did not expand the placeholder)
`); continue; }
    return resolve(v);
  }
  return undefined;
}
const wsOf = (a: Args, fallback?: string) => {
  const w = configuredWorkspace(a, fallback);
  return openWorkspace(resolveWorkspaceRoot(w ? { configured: w } : {}));
};
const out = (v: unknown): void => void process.stdout.write(`${typeof v === "string" ? v : JSON.stringify(v, null, 2)}\n`);

/** Files whose change matters for an audit trail: prompts, agent and policy configuration. */
export const SENSITIVE = [
  /(^|\/)CLAUDE\.md$/i, /(^|\/)AGENTS\.md$/i, /(^|\/)GEMINI\.md$/i, /(^|\/)\.cursorrules$/i, /(^|\/)\.windsurfrules$/i,
  /(^|\/)\.cursor\/rules\//i, /(^|\/)\.claude\//i, /(^|\/)\.github\/copilot-instructions\.md$/i,
  /(^|\/)(prompts?|agents?|policies|policy)\//i, /\.prompt(\.md)?$/i,
  /(^|\/)(\.mcp\.json|mcp\.json)$/i, /(^|\/)(model|models|llm)[-_.]?(config)?\.(json|ya?ml|toml)$/i,
  /\.rego$/i, /\.cedar$/i, /(^|\/)\.env(\..*)?$/i,
];

function printVerify(r: VerifyResult, json: boolean): void {
  if (json) { out(r); return; }
  const icon = { pass: "PASS", fail: "FAIL", unknown: "????", not_applicable: " -- " } as const;
  out(`\n  ${r.verdict}\n`);
  for (const c of r.checks) out(`  [${icon[c.status]}] ${c.name.padEnd(30)} ${c.reason}: ${c.detail}`);
  out(`\n  Receipts: ${r.receipts}`);
  out(`  Identity: ${r.declared.identity}`);
  out(`  Policy:   ${r.declared.policy}`);
  out(`  Coverage: ${r.coverage}`);
  out(`  Limits:\n${r.limitations.map((l) => `    - ${l}`).join("\n")}\n`);
}

async function hook(a: Args): Promise<number> {
  let input: { cwd?: string; session_id?: string; tool_name?: string; tool_input?: Record<string, unknown>; tool_response?: unknown; tool_use_id?: string };
  try { input = JSON.parse(readFileSync(0, "utf8") || "{}"); } catch (err) { process.stderr.write(`CooL hook: could not read hook input: ${(err as Error).message}\n`); return 1; }
  try {
    const ws = wsOf(a, input.cwd);
    const file = typeof input.tool_input?.["file_path"] === "string" ? input.tool_input["file_path"] as string : typeof input.tool_input?.["notebook_path"] === "string" ? input.tool_input["notebook_path"] as string : undefined;
    const rel = file ? (isAbsolute(file) ? relative(ws.root, file) : file).split("\\").join("/") : undefined;
    if (!a.flags.has("all") && (!rel || !SENSITIVE.some((re) => re.test(rel)))) return 0; // not in scope: silent by design
    const { receipt, warnings } = recordReceipt(ws, {
      capture: "hook", tool_name: input.tool_name ?? "unknown", change_kind: "file_edit",
      ...(rel ? { target_resource: rel } : {}),
      agent_id: "agent:claude-code",
      initiator_id: input.session_id ? `claude-code-session:${input.session_id}` : "unknown",
      ...(input.tool_use_id ? { correlation_id: input.tool_use_id } : {}),
      input: input.tool_input ?? {},
      ...(input.tool_response !== undefined ? { output: input.tool_response } : {}),
    });
    out({ systemMessage: `CooL recorded receipt ${receipt.sequence_number} for ${receipt.tool_name} ${rel ?? ""}`.trim() + (warnings.length ? ` (warnings: ${warnings.join("; ")})` : "") });
    return 0;
  } catch (err) {
    // Non-blocking but visible: Claude Code shows a non-zero, non-2 exit to the user.
    process.stderr.write(`CooL hook could NOT record this change: ${(err as Error).message}\n`);
    return 1;
  }
}

const HELP = `mcp-server-cool ${VERSION} — signed, verifiable receipts for AI agent actions

  mcp-server-cool [serve] --workspace DIR           run the MCP server over stdio
  mcp-server-cool proxy --workspace DIR --name N -- CMD ARGS   record every call to another MCP server
  mcp-server-cool hook [--workspace DIR] [--all]     Claude Code PostToolUse hook
  mcp-server-cool init|status|seal --workspace DIR
  mcp-server-cool record --workspace DIR --tool NAME [--target T] [--outcome success|failure|denied|error|unknown]
  mcp-server-cool verify BUNDLE_DIR [--fingerprint FP | --trust FILE | --workspace DIR] [--json]

verify exits 0 VALID, 1 INVALID, 2 INDETERMINATE. Docs: https://github.com/Northwind-Cipher/cool-sdk/blob/main/docs/mcp.md`;

export async function main(argv = process.argv.slice(2)): Promise<number> {
  const a = parse(argv);
  if (a.flags.has("version")) { out(VERSION); return 0; }
  if (a.flags.has("help") || a.cmd === "help") { out(HELP); return 0; }
  try {
    switch (a.cmd) {
      case "serve": {
        const w = configuredWorkspace(a);
        const e = str(a, "export-jsonl") ?? process.env["COOL_EXPORT_JSONL"];
        await serve({ ...(w ? { workspace: w } : {}), ...(e ? { exportJsonl: e } : {}), ...(str(a, "agent-id") ? { agentId: str(a, "agent-id")! } : {}) });
        return -1; // keep running
      }
      case "proxy": {
        const w = configuredWorkspace(a);
        if (!w || !a.rest.length) { process.stderr.write("usage: mcp-server-cool proxy --workspace DIR --name NAME -- COMMAND [ARGS...]\n"); return 3; }
        const e = str(a, "export-jsonl");
        await runProxy({ workspace: w, name: str(a, "name") ?? a.rest[0]!, command: a.rest[0]!, args: a.rest.slice(1), ...(str(a, "agent-id") ? { agentId: str(a, "agent-id")! } : {}), ...(str(a, "initiator") ? { initiatorId: str(a, "initiator")! } : {}), ...(e ? { exportJsonl: e } : {}) });
        return -1;
      }
      case "hook": return await hook(a);
      case "init": case "status": out(statusOf(wsOf(a))); return 0;
      case "record": {
        const tool = str(a, "tool");
        if (!tool) { process.stderr.write("record needs --tool NAME\n"); return 3; }
        const r = recordReceipt(wsOf(a), { capture: "cli", tool_name: tool, ...(str(a, "target") ? { target_resource: str(a, "target")! } : {}), ...(str(a, "outcome") ? { outcome: str(a, "outcome") as Outcome } : {}), ...(str(a, "initiator") ? { initiator_id: str(a, "initiator")! } : {}), ...(str(a, "agent-id") ? { agent_id: str(a, "agent-id")! } : {}), ...(str(a, "kind") ? { change_kind: str(a, "kind")! } : {}) });
        out(r.receipt); for (const w of r.warnings) process.stderr.write(`warning: ${w}\n`);
        return 0;
      }
      case "seal": out(sealWorkspace(wsOf(a))); return 0;
      case "verify": {
        const dir = a.pos[0];
        if (!dir) { process.stderr.write("usage: mcp-server-cool verify BUNDLE_DIR [--fingerprint FP | --trust FILE]\n"); return 3; }
        const r = verifyBundleDir(dir, str(a, "trust") ? { trustFile: str(a, "trust")! } : str(a, "fingerprint") ? { fingerprint: str(a, "fingerprint")! } : str(a, "workspace") ? { workspace: wsOf(a) } : {});
        printVerify(r, a.flags.has("json"));
        return r.verdict === "VALID" ? 0 : r.verdict === "INVALID" ? 1 : 2;
      }
    }
    return 3;
  } catch (err) {
    const e = err as Error & { code?: string };
    process.stderr.write(`mcp-server-cool: ${e.code ? `[${e.code}] ` : ""}${e.message}\n`);
    return 3;
  }
}

main().then((code) => { if (code >= 0) process.exitCode = code; }, (err) => { process.stderr.write(`${(err as Error).stack}\n`); process.exitCode = 3; });
