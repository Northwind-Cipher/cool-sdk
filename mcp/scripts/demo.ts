/**
 * The 2–3 minute demo: capture → show receipt → seal → verify → tamper → show failure → show limits.
 *
 *   npm run demo                # runs straight through (~10 s)
 *   npm run demo -- --pace      # pauses between steps for a live presentation or recording
 *
 * Everything is real: a real MCP client talks to the real server over stdio, and a real
 * downstream MCP server sits behind the CooL proxy. Nothing leaves this machine.
 */
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { verifyBundleDir, type VerifyResult } from "../src/verify.js";

const pace = process.argv.includes("--pace");
const pkg = resolve(import.meta.dirname, "..");
const CLI = join(pkg, "src", "cli.ts");
const B = "\x1b[1m", D = "\x1b[2m", G = "\x1b[32m", R = "\x1b[31m", Y = "\x1b[33m", X = "\x1b[0m";
const say = (s = "") => console.log(s);
const step = async (n: number, title: string) => {
  if (pace) await new Promise((r) => setTimeout(r, 2500));
  say(`\n${B}${n}. ${title}${X}`);
};
const text = (r: any) => (r.content as { text: string }[]).map((c) => c.text).join("\n");
const colour = (v: string) => (v === "VALID" ? G : v === "INVALID" ? R : Y) + v + X;
const showVerdict = (r: VerifyResult, only?: "bad") => {
  say(`   verdict: ${B}${colour(r.verdict)}${X}`);
  for (const c of r.checks) if (!only || c.status !== "pass") say(`   ${c.status === "pass" ? `${G}✔${X}` : c.status === "fail" ? `${R}✘${X}` : `${Y}?${X}`} ${c.name}: ${D}${c.detail}${X}`);
};

const project = mkdtempSync(join(tmpdir(), "cool-demo-project-"));
say(`${B}CooL — verifiable receipts for AI agents${X}  ${D}(project: ${project})${X}`);

await step(1, "An agent works through CooL");
const client = new Client({ name: "demo-agent", version: "1" });
await client.connect(new StdioClientTransport({ command: process.execPath, args: ["--import", "tsx", CLI, "--workspace", project, "--agent-id", "agent:demo"], cwd: pkg, stderr: "ignore" }));
say(`   tools offered: ${(await client.listTools()).tools.map((t) => t.name).join(", ")}`);
await client.callTool({ name: "cool_record_change", arguments: { tool_name: "Edit", target_resource: "CLAUDE.md", change_kind: "prompt_change", initiator_id: "user:alice", input: { added: "Always deploy on Fridays" } } });
say("   ✎ recorded: Edit CLAUDE.md (prompt change, asked for by user:alice)");
await client.callTool({ name: "cool_record_change", arguments: { tool_name: "deploy", target_resource: "payments-api@prod", change_kind: "deploy", initiator_id: "user:alice", authority_ref: "CHG-2026-0142", policy_version: "release-policy@7", outcome: "success" } });
say("   🚀 recorded: deploy payments-api@prod under change CHG-2026-0142");

const proxied = new Client({ name: "demo-agent", version: "1" });
await proxied.connect(new StdioClientTransport({ command: process.execPath, args: ["--import", "tsx", CLI, "proxy", "--workspace", project, "--name", "tickets", "--", process.execPath, "--import", "tsx", join(pkg, "tests", "fixtures", "echo-server.ts")], cwd: pkg, stderr: "ignore" }));
await proxied.callTool({ name: "echo", arguments: { text: "close ticket OPS-77" } });
say("   🔁 recorded automatically by the proxy: tickets.echo (the agent did not have to ask)");
await proxied.close();

await step(2, "What a receipt looks like (no prompts or payloads, only keyed digests)");
const status = JSON.parse(text(await client.callTool({ name: "cool_status", arguments: {} })));
const r = status.last_receipt;
for (const k of ["sequence_number", "timestamp", "agent_id", "initiator_id", "tool_name", "outcome", "capture"]) say(`   ${k.padEnd(16)} ${r[k]}`);
say(`   ${"input_digest".padEnd(16)} ${String(r.payload.input_digest).slice(0, 34)}…  ${D}(raw input never stored)${X}`);
say(`   ${"signer".padEnd(16)} ${r.signer.algorithm}`);
say(`   receipts in log: ${status.receipts}`);

await step(3, "Seal: Merkle tree + signed tree head + manifest → a portable bundle");
const seal = JSON.parse(text(await client.callTool({ name: "cool_seal_log", arguments: {} })));
await client.close();
const bundle = join(project, seal.bundle_dir);
say(`   bundle:      ${seal.bundle_dir}  (${seal.receipts} receipts, tree size ${seal.tree_size})`);
say(`   fingerprint: ${B}${seal.fingerprint}${X}`);
say(`   ${D}→ send the bundle by any means; send the fingerprint by a separate channel${X}`);

await step(4, "Someone else verifies it — offline, with the fingerprint they were given");
showVerdict(verifyBundleDir(bundle, { fingerprint: seal.fingerprint }));

await step(5, "Tamper: change one receipt (deploy success → failure) and fix up the file hash");
const copy = join(mkdtempSync(join(tmpdir(), "cool-demo-tampered-")), "bundle");
cpSync(bundle, copy, { recursive: true });
const b = JSON.parse(readFileSync(join(copy, "bundle.json"), "utf8"));
const target = b.envelopes.find((e: any) => e.core.payload.tool === "deploy");
target.core.payload.outcome = "failure";
const out = `${JSON.stringify(b, null, 2)}\n`;
writeFileSync(join(copy, "bundle.json"), out);
const m = JSON.parse(readFileSync(join(copy, "MANIFEST.json"), "utf8"));
m.files["bundle.json"] = `sha256:${createHash("sha256").update(out).digest("hex")}`;
writeFileSync(join(copy, "MANIFEST.json"), JSON.stringify(m, null, 2));
say("   changed the deploy outcome from success to failure, re-hashed bundle.json in MANIFEST.json");

await step(6, "Verify the tampered bundle");
showVerdict(verifyBundleDir(copy, { fingerprint: seal.fingerprint }), "bad");
say(`\n   ${D}…and without the fingerprint, even the untouched bundle is only:${X}`);
const unpinned = verifyBundleDir(bundle);
say(`   verdict: ${B}${colour(unpinned.verdict)}${X}  ${D}(${unpinned.checks.find((c) => c.name === "trust_source")!.reason}: a bundle cannot vouch for its own keys)${X}`);

await step(7, "What this does NOT prove — stated in every result");
const v = verifyBundleDir(bundle, { fingerprint: seal.fingerprint });
say(`   • ${v.declared.identity}`);
say(`   • ${v.declared.policy}`);
for (const l of v.limitations) say(`   • ${l}`);
say(`\n${B}CooL makes changes to the record detectable. It does not make the record complete.${X}`);
