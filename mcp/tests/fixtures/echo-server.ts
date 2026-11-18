/** A minimal downstream MCP server for proxy tests: one `echo` tool, one `boom` tool that errors. */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "echo", version: "1.0.0" });
server.registerTool("echo", { description: "echo text", inputSchema: { text: z.string() } }, async ({ text }) => ({ content: [{ type: "text", text: `echo: ${text}` }] }));
server.registerTool("boom", { description: "always fails", inputSchema: {} }, async () => ({ content: [{ type: "text", text: "boom" }], isError: true }));
await server.connect(new StdioServerTransport());
