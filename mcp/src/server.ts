/**
 * CooL MCP server
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The MCP server: four tools over stdio, for any MCP client (Claude Code,
 * Claude Desktop, Cursor, Windsurf, VS Code, Codex CLI, Gemini CLI, ...).
 *
 *   cool_record_change   record one agent action as a signed receipt
 *   cool_seal_log        seal all receipts into a portable, verifiable bundle
 *   cool_verify_receipt  verify a bundle (offline) or one local receipt
 *   cool_status          what is recorded, what is wrong, the key fingerprint
 *
 * Every failure is returned as a visible tool error — never swallowed.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { existsSync, readdirSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { openWorkspace, resolveWorkspaceRoot, WorkspaceError, displayPath, type Workspace } from "./workspace.js";
import { loadReceipts, recordReceipt, receiptView } from "./receipts.js";
import { sealWorkspace } from "./seal.js";
import { looksLikePath, verifyBundleDir, verifyLocalReceipt } from "./verify.js";

export const VERSION = "0.1.0";

export interface ServerOptions {
  /** --workspace / COOL_WORKSPACE. */
  readonly workspace?: string;
  /** --export-jsonl: also append a flat JSON line per receipt (for a SIEM forwarder). */
  readonly exportJsonl?: string;
  readonly agentId?: string;
}

type ToolResult = { content: { type: "text"; text: string }[]; isError?: boolean };
const ok = (v: unknown): ToolResult => ({ content: [{ type: "text", text: typeof v === "string" ? v : JSON.stringify(v, null, 2) }] });
const fail = (err: unknown): ToolResult => {
  const e = err as Error & { code?: string };
  return { content: [{ type: "text", text: `CooL error${e.code ? ` [${e.code}]` : ""}: ${e.message}` }], isError: true };
};

const wsArg = { workspace_root: z.string().optional().describe("Absolute path of the project directory to record into. Optional when the server was started with --workspace or the client offers exactly one root.") };

export function latestBundle(ws: Workspace): string | undefined {
  if (!existsSync(ws.bundlesDir)) return undefined;
  const dirs = readdirSync(ws.bundlesDir).filter((d) => existsSync(join(ws.bundlesDir, d, "bundle.json"))).sort();
  return dirs.length ? join(ws.bundlesDir, dirs.at(-1)!) : undefined;
}

export function createServer(opts: ServerOptions = {}): McpServer {
  const server = new McpServer({ name: "cool", version: VERSION }, {
    instructions: "CooL records what AI agents do as signed, tamper-evident receipts in <project>/.cool/. Call cool_record_change after a meaningful change (file edit, config or prompt change, deployment, external call). Call cool_seal_log to produce a bundle someone else can verify offline, and cool_verify_receipt to check one. Inputs and outputs are stored only as keyed digests.",
  });
  const cache = new Map<string, Workspace>();

  async function workspace(param?: string): Promise<Workspace> {
    let roots: string[] | undefined;
    if (!param && !opts.workspace && server.server.getClientCapabilities()?.roots) {
      try { roots = (await server.server.listRoots()).roots.map((r) => r.uri).filter((u) => u.startsWith("file://")); } catch { roots = undefined; }
    }
    const root = resolveWorkspaceRoot({ ...(param ? { param } : {}), ...(opts.workspace ? { configured: opts.workspace } : {}), ...(roots ? { roots } : {}) });
    let ws = cache.get(root);
    if (!ws) { ws = openWorkspace(root); cache.set(root, ws); }
    return ws;
  }

  server.registerTool("cool_record_change", {
    title: "Record an agent action",
    description: "Record one action taken by an AI agent (a file change, tool call, deployment, external request) as a signed CooL receipt. Raw input and output are never stored, only keyed digests. Returns the receipt.",
    inputSchema: {
      ...wsArg,
      tool_name: z.string().min(1).describe("What was done, e.g. 'Edit', 'deploy', 'github.create_pr'"),
      target_resource: z.string().optional().describe("What it was done to, e.g. a file path relative to the workspace or a URL"),
      outcome: z.enum(["success", "failure", "denied", "error", "unknown"]).optional().describe("Default: success"),
      change_kind: z.string().optional().describe("e.g. 'file_edit', 'config_change', 'prompt_change', 'deploy'"),
      agent_id: z.string().optional().describe("Declared identity of the agent (not independently authenticated)"),
      initiator_id: z.string().optional().describe("Declared person or system that asked for this; recorded as 'unknown' if omitted"),
      authority_ref: z.string().optional().describe("Reference to the approval, ticket or grant that authorised it"),
      policy_version: z.string().optional().describe("Version of the policy in force (declared, not enforced by CooL)"),
      correlation_id: z.string().optional().describe("Links related receipts, e.g. a session or request id"),
      input: z.any().optional().describe("The action's input. Hashed, never stored."),
      output: z.any().optional().describe("The action's result. Hashed, never stored."),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  }, async (a) => {
    try {
      const ws = await workspace(a.workspace_root);
      const { receipt, warnings } = recordReceipt(ws, {
        tool_name: a.tool_name, capture: "mcp_tool",
        ...(a.target_resource ? { target_resource: a.target_resource } : {}),
        ...(a.outcome ? { outcome: a.outcome } : {}),
        ...(a.change_kind ? { change_kind: a.change_kind } : {}),
        agent_id: a.agent_id ?? opts.agentId ?? "agent:mcp-client",
        ...(a.initiator_id ? { initiator_id: a.initiator_id } : {}),
        ...(a.authority_ref ? { authority_ref: a.authority_ref } : {}),
        ...(a.policy_version ? { policy_version: a.policy_version } : {}),
        ...(a.correlation_id ? { correlation_id: a.correlation_id } : {}),
        ...(a.input !== undefined ? { input: a.input } : {}),
        ...(a.output !== undefined ? { output: a.output } : {}),
      }, opts.exportJsonl ? { exportJsonl: opts.exportJsonl } : {});
      return ok({ recorded: true, receipt, warnings });
    } catch (err) { return fail(err); }
  });

  server.registerTool("cool_seal_log", {
    title: "Seal the receipt log",
    description: "Seal every receipt recorded in this workspace into a Merkle tree and export a portable bundle (.cool/bundles/<time>/) that anyone can verify offline. Refuses a log with corrupt or duplicated entries. Returns the bundle path and the key fingerprint to share out of band.",
    inputSchema: { ...wsArg },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  }, async (a) => {
    try {
      const ws = await workspace(a.workspace_root);
      const r = sealWorkspace(ws);
      return ok({ ...r, bundle_dir: displayPath(ws, r.bundle_dir), next: `Share the bundle directory, and send the fingerprint separately. To verify: npx -y @northwindcipher/mcp-server-cool verify ${displayPath(ws, r.bundle_dir)} --fingerprint ${r.fingerprint}` });
    } catch (err) { return fail(err); }
  });

  server.registerTool("cool_verify_receipt", {
    title: "Verify receipts",
    description: "Verify a sealed bundle offline (signatures, Merkle proofs, sequence gaps, duplicates/replays, order) or a single receipt from the local log. Returns VALID, INVALID or INDETERMINATE with a reason for every check. With no target, verifies the latest bundle.",
    inputSchema: {
      ...wsArg,
      target: z.string().optional().describe("A bundle directory (absolute or relative to the workspace), or a receipt's event id or sequence number like '1763400000.3'. Default: the latest bundle."),
      fingerprint: z.string().optional().describe("The recorder's workspace fingerprint, obtained out of band. Without it (or trust_file), a bundle from elsewhere can be at best INDETERMINATE."),
      trust_file: z.string().optional().describe("Path to a cool.trust-snapshot.v1 file you trust"),
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async (a) => {
    try {
      const ws = await workspace(a.workspace_root);
      const target = a.target ?? latestBundle(ws);
      if (!target) throw new Error("nothing to verify: no bundle has been sealed yet (call cool_seal_log first) and no target was given");
      if (!a.target || looksLikePath(target)) {
        const dir = isAbsolute(target) ? target : resolve(ws.root, target);
        // Pinned keys: what the caller supplied; otherwise this workspace's own keys (valid only for its own bundles).
        return ok(verifyBundleDir(dir, a.trust_file ? { trustFile: a.trust_file } : a.fingerprint ? { fingerprint: a.fingerprint } : { workspace: ws }));
      }
      return ok(verifyLocalReceipt(ws, target));
    } catch (err) { return fail(err); }
  });

  server.registerTool("cool_status", {
    title: "CooL status",
    description: "Show what CooL has recorded in this workspace: receipt count, last receipt, any problems in the log (gaps, torn writes, duplicates), the latest bundle and the key fingerprint.",
    inputSchema: { ...wsArg },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async (a) => {
    try {
      const ws = await workspace(a.workspace_root);
      return ok(statusOf(ws));
    } catch (err) { return fail(err); }
  });

  return server;
}

export function statusOf(ws: Workspace) {
  const { receipts, problems } = loadReceipts(ws);
  const last = receipts.at(-1);
  const bundle = latestBundle(ws);
  return {
    workspace: ws.root, workspace_id: ws.id, epoch: ws.epoch, fingerprint: ws.fingerprint,
    receipts: receipts.length,
    last_receipt: last ? receiptView(ws, last) : null,
    problems,
    latest_bundle: bundle ? displayPath(ws, bundle) : null,
    log: displayPath(ws, ws.receiptsPath),
  };
}

export async function serve(opts: ServerOptions = {}): Promise<void> {
  if (opts.workspace) openWorkspace(resolveWorkspaceRoot({ configured: opts.workspace })); // fail fast, visibly, on a bad --workspace
  const server = createServer(opts);
  await server.connect(new StdioServerTransport());
  process.stderr.write(`cool MCP server ${VERSION} ready${opts.workspace ? ` (workspace ${opts.workspace})` : " (workspace from tool argument or client roots)"}\n`);
}

export { WorkspaceError };
export const isMain = (url: string) => process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(url);
