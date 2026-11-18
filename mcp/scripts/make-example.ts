/** Regenerate examples/agent-receipt/ from a real recording in a throwaway workspace (example keys, not secret). */
import { mkdtempSync, writeFileSync, readFileSync, cpSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { openWorkspace, resolveWorkspaceRoot } from "../src/workspace.js";
import { recordReceipt } from "../src/receipts.js";
import { sealWorkspace } from "../src/seal.js";

const out = resolve(import.meta.dirname, "..", "..", "examples", "agent-receipt");
const ws = openWorkspace(resolveWorkspaceRoot({ configured: mkdtempSync(join(tmpdir(), "cool-example-")) }));
const { receipt, envelope } = recordReceipt(ws, { capture: "mcp_proxy", server: "github", tool_name: "github.create_pull_request", target_resource: "github.com/example-org/payments-api", agent_id: "agent:release-bot", initiator_id: "user:alice@example.com", authority_ref: "CHG-2026-0142", policy_version: "release-policy@7", correlation_id: "session-7f3a", change_kind: "tool_call", input: { title: "Bump rate limits", base: "main" }, output: { number: 318 }, duration_ms: 812 });
recordReceipt(ws, { capture: "hook", tool_name: "Edit", target_resource: "CLAUDE.md", agent_id: "agent:claude-code", initiator_id: "claude-code-session:5c1d", change_kind: "prompt_change", correlation_id: "toolu_01", input: { old_string: "...", new_string: "..." } });
writeFileSync(join(out, "receipt.json"), `${JSON.stringify(receipt, null, 2)}\n`);
writeFileSync(join(out, "envelope.json"), `${JSON.stringify(envelope, null, 2)}\n`);
const sealed = sealWorkspace(ws, { now: new Date() });
rmSync(join(out, "bundle"), { recursive: true, force: true });
cpSync(sealed.bundle_dir, join(out, "bundle"), { recursive: true });
writeFileSync(join(out, "FINGERPRINT.txt"), `${sealed.fingerprint}\n`);
console.log("wrote", out, JSON.parse(readFileSync(join(out, "bundle", "MANIFEST.json"), "utf8")).receipts, "receipts");
