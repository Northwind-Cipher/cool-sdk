/**
 * CooL MCP server
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Proxy mode: sit between an MCP client and any downstream MCP server, and
 * record a receipt for every `tools/call` that passes through.
 *
 *   mcp-server-cool proxy --workspace /repo --name github -- npx -y @modelcontextprotocol/server-github
 *
 * This is the one capture mode that does not depend on the agent choosing to
 * record: every call through the proxy is recorded. Calls that do not go
 * through it (another server configured directly, a shell command) are not.
 *
 * If a receipt cannot be written the call still completes — stopping the
 * user's work would be worse — but the failure is made visible twice: on
 * stderr (client logs) and appended to the tool result the agent sees.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, type CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { recordReceipt } from "./receipts.js";
import { openWorkspace, resolveWorkspaceRoot } from "./workspace.js";
import { VERSION } from "./server.js";

export interface ProxyOptions {
  readonly workspace: string;
  readonly name: string;
  readonly command: string;
  readonly args: readonly string[];
  readonly agentId?: string;
  readonly initiatorId?: string;
  readonly exportJsonl?: string;
}

/** Build the proxy pieces without connecting stdio — used directly by tests. */
export async function createProxy(o: ProxyOptions, downstream?: Client) {
  const ws = openWorkspace(resolveWorkspaceRoot({ configured: o.workspace }));
  const client = downstream ?? new Client({ name: "cool-proxy", version: VERSION });
  if (!downstream) await client.connect(new StdioClientTransport({ command: o.command, args: [...o.args], stderr: "inherit" }));
  const server = new Server({ name: `cool-proxy:${o.name}`, version: VERSION }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async (req) => client.listTools(req.params));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const started = Date.now();
    let result: CallToolResult | undefined; let thrown: unknown;
    try { result = (await client.callTool(req.params)) as CallToolResult; } catch (err) { thrown = err; }
    const outcome = thrown ? "error" : result?.isError ? "failure" : "success";
    let warning: string | undefined;
    try {
      const r = recordReceipt(ws, {
        capture: "mcp_proxy", server: o.name, tool_name: `${o.name}.${req.params.name}`,
        outcome, input: req.params.arguments ?? {}, output: thrown ? { error: String((thrown as Error).message) } : result?.content ?? null,
        duration_ms: Date.now() - started,
        agent_id: o.agentId ?? "agent:mcp-client",
        ...(o.initiatorId ? { initiator_id: o.initiatorId } : {}),
      }, o.exportJsonl ? { exportJsonl: o.exportJsonl } : {});
      if (r.warnings.length) process.stderr.write(`cool-proxy: ${r.warnings.join("; ")}\n`);
    } catch (err) {
      warning = `CooL could not record this call: ${(err as Error).message}`;
      process.stderr.write(`cool-proxy WARNING: ${warning}\n`);
    }
    if (thrown) throw thrown;
    return warning ? { ...result!, content: [...(result!.content ?? []), { type: "text", text: `[${warning}]` }] } : result!;
  });
  return { server, client, ws };
}

export async function runProxy(o: ProxyOptions): Promise<void> {
  const { server, client } = await createProxy(o);
  await server.connect(new StdioServerTransport());
  const close = async () => { await client.close().catch(() => undefined); process.exit(0); };
  process.stdin.on("end", close);
  process.on("SIGTERM", close);
  process.stderr.write(`cool proxy for "${o.name}" ready (workspace ${o.workspace})\n`);
}
