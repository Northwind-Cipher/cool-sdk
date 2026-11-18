/**
 * CooL MCP server
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The sprint's definition of done, as tests: workspace safety, receipts,
 * torn / interrupted capture, duplicates and gaps, every tamper fixture,
 * offline verification, the MCP tools over real stdio, the proxy and the hook.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir, tmpdir } from "node:os";
import { join, parse, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { spawn, spawnSync } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { openWorkspace, resolveWorkspaceRoot, WorkspaceError, type Workspace } from "../src/workspace.js";
import { loadReceipts, payloadDigest, recordReceipt } from "../src/receipts.js";
import { sealWorkspace } from "../src/seal.js";
import { verifyBundleDir, verifyLocalReceipt } from "../src/verify.js";

const here = resolve(import.meta.dirname);
const pkg = resolve(here, "..");
const CLI = join(pkg, "src", "cli.ts");
const TSX = ["--import", "tsx"];

const tmp = (p = "cool-mcp-") => mkdtempSync(join(tmpdir(), p));
function fresh(n = 3): { ws: Workspace; dir: string; bundle: string } {
  const dir = tmp();
  const ws = openWorkspace(resolveWorkspaceRoot({ configured: dir }));
  for (let i = 0; i < n; i++) recordReceipt(ws, { capture: "mcp_tool", tool_name: i % 2 ? "deploy" : "Edit", target_resource: `src/f${i}.ts`, initiator_id: "user:alice", input: { i }, output: { ok: true } });
  return { ws, dir, bundle: n ? sealWorkspace(ws).bundle_dir : "" };
}

/** Copy a bundle, mutate bundle.json, and (by default) re-hash it in MANIFEST.json so the DEEP checks must catch it. */
function tampered(bundle: string, mutate: (b: any) => void, o: { rehash?: boolean } = {}): string {
  const out = join(tmp("cool-tamper-"), "b");
  cpSync(bundle, out, { recursive: true });
  const b = JSON.parse(readFileSync(join(out, "bundle.json"), "utf8"));
  mutate(b);
  const text = `${JSON.stringify(b, null, 2)}\n`;
  writeFileSync(join(out, "bundle.json"), text);
  if (o.rehash !== false) {
    const m = JSON.parse(readFileSync(join(out, "MANIFEST.json"), "utf8"));
    m.files["bundle.json"] = `sha256:${createHash("sha256").update(text).digest("hex")}`;
    writeFileSync(join(out, "MANIFEST.json"), JSON.stringify(m, null, 2));
  }
  return out;
}
const failed = (r: ReturnType<typeof verifyBundleDir>) => r.checks.filter((c) => c.status === "fail").map((c) => c.reason);

// ── workspace ──────────────────────────────────────────────────────────────

test("workspace: must be explicit; never falls back to cwd", () => {
  assert.throws(() => resolveWorkspaceRoot({}), (e: WorkspaceError) => e.code === "workspace_required");
  assert.throws(() => resolveWorkspaceRoot({ roots: ["file:///a", "file:///b"] }), /2 roots/);
});

test("workspace: relative, missing, filesystem root and home directory are refused", () => {
  assert.throws(() => resolveWorkspaceRoot({ param: "relative/dir" }), (e: WorkspaceError) => e.code === "workspace_invalid");
  assert.throws(() => resolveWorkspaceRoot({ param: join(tmpdir(), "does-not-exist-cool") }), (e: WorkspaceError) => e.code === "workspace_invalid");
  assert.throws(() => resolveWorkspaceRoot({ param: parse(process.cwd()).root }), (e: WorkspaceError) => e.code === "workspace_unsafe");
  assert.throws(() => resolveWorkspaceRoot({ param: homedir() }), (e: WorkspaceError) => e.code === "workspace_unsafe");
});

test("workspace: a single file:// root is accepted; .cool is created with keys ignored by git", () => {
  const dir = tmp();
  const root = resolveWorkspaceRoot({ roots: [pathToFileURL(dir).href] });
  const ws = openWorkspace(root);
  assert.ok(existsSync(join(ws.mcpDir, "keys.json")));
  assert.match(readFileSync(join(ws.mcpDir, ".gitignore"), "utf8"), /keys\.json/);
  assert.equal(openWorkspace(root).fingerprint, ws.fingerprint, "keys persist across restarts");
  assert.ok(readdirSync(dir).every((f) => f === ".cool"), "nothing written outside .cool/");
  if (process.platform !== "win32") assert.equal(statSync(join(ws.mcpDir, "keys.json")).mode & 0o777, 0o600);
});

// ── receipts ───────────────────────────────────────────────────────────────

test("receipt: carries every spec field; raw input/output never stored, only keyed digests", () => {
  const { ws } = fresh(0);
  const secret = "sk-live-THIS-MUST-NOT-APPEAR";
  const { receipt } = recordReceipt(ws, { capture: "mcp_tool", tool_name: "http.post", target_resource: "https://api.example/x", authority_ref: "CHG-42", policy_version: "p@3", correlation_id: "sess-1", input: { token: secret }, output: "done" });
  for (const k of ["schema_version", "event_id", "timestamp", "time_source", "agent_id", "initiator_id", "authority_ref", "policy_version", "tool_name", "target_resource", "correlation_id", "sequence_number", "outcome", "payload", "signer", "evidence"]) assert.ok(k in receipt, k);
  assert.equal(receipt.initiator_id, "unknown", "an absent initiator is recorded explicitly as unknown");
  assert.equal(receipt.payload.raw_payload_stored, false);
  assert.equal(receipt.payload.input_digest, payloadDigest(ws, "input", { token: secret }));
  assert.equal(payloadDigest(ws, "input", { b: 1, a: 2 }), payloadDigest(ws, "input", { a: 2, b: 1 }), "key order does not matter");
  assert.ok(!readFileSync(ws.receiptsPath, "utf8").includes(secret));
  assert.equal(verifyLocalReceipt(ws, receipt.sequence_number).verdict, "VALID");
});

test("capture: a torn final line is reported, set aside, and capture continues", () => {
  const { ws } = fresh(2);
  appendFileSync(ws.receiptsPath, '{"format":"cool.envelope.v1","core":{"event_id":"x"'); // the process died mid-write
  const before = loadReceipts(ws);
  assert.equal(before.receipts.length, 2);
  assert.ok(before.problems.some((p) => p.kind === "torn_write"));
  assert.ok(sealWorkspace(ws).warnings.some((w) => w.startsWith("torn_write")), "sealing reports it and leaves it out");
  const r = recordReceipt(ws, { capture: "cli", tool_name: "after-crash" });
  assert.ok(r.warnings.some((w) => /moved to \.cool\/mcp\/torn-.*\.fragment/.test(w)), r.warnings.join(";"));
  assert.equal(r.receipt.sequence_number.split(".")[1], "2", "sequence continues from the last good receipt");
  assert.deepEqual(loadReceipts(ws).problems, []);
  assert.ok(readdirSync(ws.mcpDir).some((f) => f.endsWith(".fragment")));
  assert.equal(verifyBundleDir(sealWorkspace(ws).bundle_dir, { fingerprint: ws.fingerprint }).verdict, "VALID");
});

test("capture: a corrupt line in the middle stops recording and sealing, visibly", () => {
  const { ws } = fresh(2);
  const lines = readFileSync(ws.receiptsPath, "utf8").split("\n");
  writeFileSync(ws.receiptsPath, [lines[0], "not json", ...lines.slice(1)].join("\n"));
  assert.throws(() => recordReceipt(ws, { capture: "cli", tool_name: "x" }), /corrupt/);
  assert.throws(() => sealWorkspace(ws), /refusing to seal: corrupt_line/);
});

test("capture: a duplicated (replayed) line is refused at seal; a deleted line shows as a gap", () => {
  const { ws } = fresh(3);
  const lines = readFileSync(ws.receiptsPath, "utf8").trimEnd().split("\n");
  writeFileSync(ws.receiptsPath, `${[...lines, lines[1]].join("\n")}\n`);
  assert.throws(() => sealWorkspace(ws), /duplicate/);
  writeFileSync(ws.receiptsPath, `${[lines[0], lines[2]].join("\n")}\n`);
  assert.ok(loadReceipts(ws).problems.some((p) => p.kind === "sequence_gap" && p.detail.includes(".1 ")));
  const sealed = sealWorkspace(ws);
  const v = verifyBundleDir(sealed.bundle_dir, { fingerprint: ws.fingerprint });
  assert.equal(v.verdict, "INVALID");
  assert.ok(failed(v).includes("sequence_gap"));
});

test("capture: killing the recorder mid-stream never corrupts earlier receipts", async () => {
  const dir = tmp();
  const ws = openWorkspace(resolveWorkspaceRoot({ configured: dir }));
  const child = spawn(process.execPath, [...TSX, join(here, "fixtures", "record-loop.ts"), ws.root], { cwd: pkg, stdio: ["ignore", "pipe", "inherit"] });
  await new Promise<void>((res) => child.stdout.once("data", () => res()));
  await new Promise((r) => setTimeout(r, 400));
  child.kill("SIGKILL");
  await new Promise((r) => child.once("exit", r));
  const { receipts, problems } = loadReceipts(ws);
  assert.ok(receipts.length > 0, "some receipts were written");
  assert.deepEqual(problems.filter((p) => p.kind !== "torn_write").map((p) => p.kind), [], "at most the final line is torn");
  recordReceipt(ws, { capture: "cli", tool_name: "after-kill" }); // repairs a torn tail, if any
  assert.deepEqual(loadReceipts(ws).problems, []);
  const s = sealWorkspace(ws);
  assert.equal(verifyBundleDir(s.bundle_dir, { fingerprint: ws.fingerprint }).verdict, "VALID");
});

// ── seal + verify ──────────────────────────────────────────────────────────

test("seal: bundle has manifest with file hashes and no private keys", () => {
  const { ws, bundle } = fresh(3);
  const m = JSON.parse(readFileSync(join(bundle, "MANIFEST.json"), "utf8"));
  assert.equal(m.contains_private_keys, false);
  assert.equal(m.receipts, 3);
  assert.match(m.files["bundle.json"], /^sha256:/);
  const all = readdirSync(bundle).map((f) => readFileSync(join(bundle, f), "utf8")).join("\n");
  const keys = JSON.parse(readFileSync(join(ws.mcpDir, "keys.json"), "utf8"));
  for (const s of [keys.evidence_seed, keys.log_seed, keys.commit_key]) assert.ok(!all.includes(s), "no seed or HMAC key in the bundle");
});

test("verify: VALID only with independently pinned keys; INDETERMINATE without; INVALID with the wrong ones", () => {
  const { ws, bundle } = fresh(3);
  assert.equal(verifyBundleDir(bundle, { fingerprint: ws.fingerprint }).verdict, "VALID");
  assert.equal(verifyBundleDir(bundle, { workspace: ws }).verdict, "VALID");
  const unpinned = verifyBundleDir(bundle);
  assert.equal(unpinned.verdict, "INDETERMINATE");
  assert.equal(unpinned.checks.find((c) => c.name === "trust_source")?.reason, "self_asserted_trust");
  assert.equal(verifyBundleDir(bundle, { fingerprint: fresh(1).ws.fingerprint }).verdict, "INVALID");
  const tf = join(tmp(), "trust.json");
  writeFileSync(tf, readFileSync(join(bundle, "trust.json")));
  assert.equal(verifyBundleDir(bundle, { trustFile: tf }).verdict, "VALID");
  const v = verifyBundleDir(bundle, { fingerprint: ws.fingerprint });
  assert.match(v.declared.identity, /not independently authenticated/);
  assert.match(v.declared.policy, /does not prove the policy was enforced/);
  assert.match(v.coverage, /outside this boundary/);
  assert.ok(v.checks.every((c) => c.reason && c.detail), "every check has a reason");
});

test("tamper fixtures: changed bytes, deleted, reordered, duplicated, bad signature, missing proof → INVALID", () => {
  const { ws, bundle } = fresh(4);
  const pin = { fingerprint: ws.fingerprint };
  const cases: Record<string, [(b: any) => void, string]> = {
    "changed bytes": [(b) => { b.envelopes[1].core.payload.tool = "rm -rf"; }, "envelope_failed"],
    "deleted receipt": [(b) => { b.envelopes.splice(1, 1); }, "manifest_mismatch"],
    "reordered (proofs swapped)": [(b) => { const c = b.envelopes[0].checkpoint; b.envelopes[0].checkpoint = b.envelopes[2].checkpoint; b.envelopes[2].checkpoint = c; }, "envelope_failed"],
    "duplicated / replayed": [(b) => { b.envelopes.push(b.envelopes[0]); }, "duplicate_evidence"],
    "invalid signature": [(b) => { const s = b.envelopes[0].signatures[0]; s.ed25519 = s.ed25519.replace(/^(base64:)(.)/, (_: string, p: string, c: string) => p + (c === "A" ? "B" : "A")); }, "envelope_failed"],
    "missing proof": [(b) => { delete b.envelopes[3].checkpoint; }, "envelope_failed"],
  };
  for (const [name, [mutate, reason]] of Object.entries(cases)) {
    const r = verifyBundleDir(tampered(bundle, mutate), pin);
    assert.equal(r.verdict, "INVALID", name);
    assert.ok(failed(r).includes(reason), `${name}: expected ${reason}, got ${failed(r).join(",")}`);
  }
  // Without re-hashing, the file hash check catches any edit first.
  assert.ok(failed(verifyBundleDir(tampered(bundle, (b) => { b.title = "x"; }, { rehash: false }), pin)).includes("file_hash_mismatch"));
});

test("tamper fixtures: missing or corrupt components → INVALID with the reason", () => {
  const { ws, bundle } = fresh(2);
  for (const f of ["bundle.json", "MANIFEST.json", "trust.json"]) {
    const out = join(tmp(), "b"); cpSync(bundle, out, { recursive: true }); rmSync(join(out, f));
    const r = verifyBundleDir(out, { fingerprint: ws.fingerprint });
    assert.equal(r.verdict, "INVALID", f);
    assert.equal(r.checks[0]!.reason, "missing_component");
  }
  const out = join(tmp(), "b"); cpSync(bundle, out, { recursive: true }); writeFileSync(join(out, "bundle.json"), "{ not json");
  assert.equal(verifyBundleDir(out, { fingerprint: ws.fingerprint }).checks[0]!.reason, "corrupt_component");
});

test("verify: works with the network unavailable", async () => {
  const { ws, bundle } = fresh(2);
  const net = await import("node:net");
  const saved = { fetch: globalThis.fetch, connect: net.Socket.prototype.connect };
  const no = () => { throw new Error("network used during verification"); };
  globalThis.fetch = no as never; net.Socket.prototype.connect = no as never;
  try { assert.equal(verifyBundleDir(bundle, { fingerprint: ws.fingerprint }).verdict, "VALID"); }
  finally { globalThis.fetch = saved.fetch; net.Socket.prototype.connect = saved.connect; }
});

// ── over real stdio ────────────────────────────────────────────────────────

async function connect(args: string[], env: Record<string, string> = {}): Promise<Client> {
  const c = new Client({ name: "test", version: "1" });
  await c.connect(new StdioClientTransport({ command: process.execPath, args: [...TSX, CLI, ...args], cwd: pkg, env: { ...process.env, ...env } as Record<string, string>, stderr: "pipe" }));
  return c;
}
const text = (r: any) => (r.content as { text: string }[]).map((c) => c.text).join("\n");

test("MCP: an SDK client discovers and calls all four tools over stdio", async () => {
  const dir = tmp();
  const c = await connect(["--workspace", dir]);
  try {
    const tools = (await c.listTools()).tools.map((t) => t.name).sort();
    assert.deepEqual(tools, ["cool_record_change", "cool_seal_log", "cool_status", "cool_verify_receipt"]);
    const rec = await c.callTool({ name: "cool_record_change", arguments: { tool_name: "Edit", target_resource: "CLAUDE.md", change_kind: "prompt_change", input: { old: "a", new: "b" } } });
    assert.ok(!rec.isError, text(rec));
    assert.equal(JSON.parse(text(rec)).receipt.capture, "mcp_tool");
    const seal = await c.callTool({ name: "cool_seal_log", arguments: {} });
    assert.ok(!seal.isError, text(seal));
    const ver = await c.callTool({ name: "cool_verify_receipt", arguments: {} });
    assert.equal(JSON.parse(text(ver)).verdict, "VALID");
    const st = JSON.parse(text(await c.callTool({ name: "cool_status", arguments: {} })));
    assert.equal(st.receipts, 1);
    const outside = await c.callTool({ name: "cool_record_change", arguments: { workspace_root: "relative/path", tool_name: "x" } });
    assert.ok(outside.isError);
    assert.match(text(outside), /workspace_invalid/);
  } finally { await c.close(); }
});

test("MCP: with no workspace configured, a call fails visibly instead of guessing", async () => {
  const c = await connect([], { COOL_WORKSPACE: "", CLAUDE_PROJECT_DIR: "" });
  try {
    const r = await c.callTool({ name: "cool_record_change", arguments: { tool_name: "x" } });
    assert.ok(r.isError);
    assert.match(text(r), /workspace_required/);
  } finally { await c.close(); }
});

test("proxy: every downstream tool call is recorded; recording failures are shown, not swallowed", async () => {
  const dir = tmp();
  const c = await connect(["proxy", "--workspace", dir, "--name", "echo", "--", process.execPath, ...TSX, join(here, "fixtures", "echo-server.ts")]);
  try {
    assert.deepEqual((await c.listTools()).tools.map((t) => t.name).sort(), ["boom", "echo"]);
    assert.equal(text(await c.callTool({ name: "echo", arguments: { text: "hi" } })), "echo: hi");
    await c.callTool({ name: "boom", arguments: {} });
    const ws = openWorkspace(resolveWorkspaceRoot({ configured: dir }));
    const { receipts } = loadReceipts(ws);
    assert.deepEqual(receipts.map((r) => [(r.core.payload as any).tool, (r.core.payload as any).outcome, (r.core.payload as any).capture]), [["echo.echo", "success", "mcp_proxy"], ["echo.boom", "failure", "mcp_proxy"]]);
    appendFileSync(ws.receiptsPath, "garbage\n{}\n");
    const r = await c.callTool({ name: "echo", arguments: { text: "still works" } });
    assert.match(text(r), /echo: still works/);
    assert.match(text(r), /CooL could not record this call/);
  } finally { await c.close(); }
});

// ── Claude Code hook ───────────────────────────────────────────────────────

const hook = (input: object, args: string[] = [], env: Record<string, string> = {}) =>
  spawnSync(process.execPath, [...TSX, CLI, "hook", ...args], { cwd: pkg, input: JSON.stringify(input), encoding: "utf8", env: { ...process.env, CLAUDE_PROJECT_DIR: "", ...env } });

test("hook: records edits to sensitive files with a visible message; ignores the rest; fails visibly", () => {
  const dir = tmp();
  const base = { session_id: "s1", cwd: dir, hook_event_name: "PostToolUse", tool_name: "Edit", tool_use_id: "tu1" };
  const yes = hook({ ...base, tool_input: { file_path: join(dir, "CLAUDE.md"), old_string: "a", new_string: "b" } });
  assert.equal(yes.status, 0, yes.stderr);
  assert.match(JSON.parse(yes.stdout).systemMessage, /CooL recorded receipt .* Edit CLAUDE\.md/);
  const no = hook({ ...base, tool_input: { file_path: join(dir, "src", "app.ts") } });
  assert.equal(no.status, 0); assert.equal(no.stdout, "");
  const all = hook({ ...base, tool_input: { file_path: join(dir, "src", "app.ts") } }, ["--all"]);
  assert.match(all.stdout, /systemMessage/);
  const ws = openWorkspace(resolveWorkspaceRoot({ configured: dir }));
  assert.equal(loadReceipts(ws).receipts.length, 2);
  assert.equal((loadReceipts(ws).receipts[0]!.core.payload as any).initiator, "claude-code-session:s1");
  const bad = hook({ ...base, cwd: homedir(), tool_input: { file_path: join(homedir(), "CLAUDE.md") } });
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /could NOT record/);
  mkdirSync(join(dir, "x"), { recursive: true });
});

test("cli: verify exit codes are 0 VALID, 1 INVALID, 2 INDETERMINATE", () => {
  const { ws, bundle } = fresh(1);
  const run = (...a: string[]) => spawnSync(process.execPath, [...TSX, CLI, "verify", bundle, ...a], { cwd: pkg, encoding: "utf8" }).status;
  assert.equal(run("--fingerprint", ws.fingerprint), 0);
  assert.equal(run("--fingerprint", "sha256:00"), 1);
  assert.equal(run(), 2);
});

// ── schema + golden vector ─────────────────────────────────────────────────

test("schema: every receipt the server produces, and the published example, conform to cool.agent-receipt.v1", async () => {
  const { default: Ajv2020 } = await import("ajv/dist/2020.js") as any;
  const ajv = new Ajv2020({ strict: false });
  const validate = ajv.compile(JSON.parse(readFileSync(join(pkg, "..", "spec", "schemas", "cool.agent-receipt.v1.schema.json"), "utf8")));
  const example = JSON.parse(readFileSync(join(pkg, "..", "examples", "agent-receipt", "receipt.json"), "utf8"));
  assert.ok(validate(example), JSON.stringify(validate.errors));
  const { ws } = fresh(0);
  for (const outcome of ["success", "failure", "denied", "error", "unknown"] as const) {
    const { receipt } = recordReceipt(ws, { capture: "sdk", tool_name: "t", outcome });
    assert.ok(validate(receipt), JSON.stringify(validate.errors));
  }
  assert.ok(!validate({ ...example, payload: { ...example.payload, raw_payload_stored: true } }), "a receipt that stores raw payloads is not a v1 receipt");
  assert.ok(!validate({ ...example, surprise: 1 }), "unknown top-level fields are rejected (additive change = new minor schema)");
});

test("golden vector: the committed example bundle still verifies VALID with its published fingerprint", () => {
  const dir = join(pkg, "..", "examples", "agent-receipt");
  const fp = readFileSync(join(dir, "FINGERPRINT.txt"), "utf8").trim();
  const r = verifyBundleDir(join(dir, "bundle"), { fingerprint: fp });
  assert.equal(r.verdict, "VALID", r.summary);
  assert.equal(r.receipts, 2);
});

test("cli: an explicit relative --workspace resolves against the current directory; an unexpanded ${...} is ignored visibly", () => {
  const dir = tmp();
  const r = spawnSync(process.execPath, ["--import", import.meta.resolve("tsx"), CLI, "status", "--workspace", "."], { cwd: dir, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).workspace.toLowerCase(), resolveWorkspaceRoot({ configured: dir }).toLowerCase());
  const u = spawnSync(process.execPath, [...TSX, CLI, "status", "--workspace", "${workspaceFolder}"], { cwd: pkg, encoding: "utf8", env: { ...process.env, COOL_WORKSPACE: "", CLAUDE_PROJECT_DIR: "" } });
  assert.equal(u.status, 3);
  assert.match(u.stderr, /ignoring --workspace="\$\{workspaceFolder\}"/);
  assert.match(u.stderr, /workspace_required/);
});

test("export: --export-jsonl appends one flat SIEM line per receipt (no payloads); a failing export is a warning, not a lost receipt", () => {
  const { ws } = fresh(0);
  const file = join(tmp(), "siem.jsonl");
  recordReceipt(ws, { capture: "sdk", tool_name: "a", input: { secret: "zzz-not-exported" } }, { exportJsonl: file });
  recordReceipt(ws, { capture: "sdk", tool_name: "b" }, { exportJsonl: file });
  const lines = readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.deepEqual(lines.map((l) => [l.tool, l.source, l.sequence.split(".")[1]]), [["a", "cool", "0"], ["b", "cool", "1"]]);
  assert.ok(!readFileSync(file, "utf8").includes("zzz-not-exported"));
  const bad = recordReceipt(ws, { capture: "sdk", tool_name: "c" }, { exportJsonl: join(tmp(), "no-such-dir", "x.jsonl") });
  assert.ok(bad.warnings.some((w) => w.startsWith("export_failed")));
  assert.equal(loadReceipts(ws).receipts.length, 3, "the receipt itself was kept");
});

test("capture: three processes recording at once never reuse or skip a sequence number", async () => {
  const dir = tmp();
  const ws = openWorkspace(resolveWorkspaceRoot({ configured: dir }));
  const code = `const r = await import(${JSON.stringify(pathToFileURL(join(pkg, "src", "receipts.ts")).href)}); const w = (await import(${JSON.stringify(pathToFileURL(join(pkg, "src", "workspace.ts")).href)})).openWorkspace(${JSON.stringify(ws.root)}); for (let i = 0; i < 25; i++) r.recordReceipt(w, { capture: "cli", tool_name: "race" });`;
  const run = () => new Promise<void>((res, rej) => {
    const c = spawn(process.execPath, [...TSX, "--input-type=module", "-e", code], { cwd: pkg, stdio: ["ignore", "ignore", "inherit"] });
    c.once("exit", (status) => (status === 0 ? res() : rej(new Error(`exit ${status}`))));
  });
  await Promise.all([run(), run(), run()]);
  const { receipts, problems } = loadReceipts(ws);
  assert.equal(receipts.length, 75);
  assert.deepEqual(problems, [], "no gaps, duplicates or torn lines");
  assert.equal(verifyBundleDir(sealWorkspace(ws).bundle_dir, { fingerprint: ws.fingerprint }).verdict, "VALID");
});
