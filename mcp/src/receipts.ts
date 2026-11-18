/**
 * CooL MCP server
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Agent Execution Receipts.
 *
 * A receipt is a signed `cool.envelope.v1` of type `agent.execution`, appended
 * to `<workspace>/.cool/mcp/receipts.jsonl` (one envelope per line, O_APPEND,
 * fsync). It is numbered `[epoch].[n]` so a missing receipt shows as a gap.
 *
 * Privacy by default: inputs and outputs are NEVER stored. Only keyed digests
 * (HMAC-SHA-256 under the workspace's own key, over a canonical JSON form)
 * are, so a bundle recipient cannot test guesses of a payload, while the
 * workspace owner can later show that a given payload matches.
 *
 * Failure is never silent: a receipt that could not be written throws, and
 * the caller reports it. A torn last line (the process died mid-write) is
 * reported, excluded, and the sequence continues from the last good receipt.
 */
import { appendFileSync, closeSync, existsSync, fsyncSync, openSync, readFileSync, readSync, statSync, truncateSync, unlinkSync, writeFileSync, writeSync } from "node:fs";
import { join } from "node:path";
import { createHmac } from "node:crypto";
import { hostname } from "node:os";
import { createEnvelope, signEnvelope, PayloadRegistry, type SignedEnvelope } from "cool-nwc/platform";
import { displayPath, type Workspace } from "./workspace.js";

export const RECEIPT_SCHEMA = "cool.agent-receipt.v1";
export type Outcome = "success" | "failure" | "denied" | "error" | "unknown";
export type Capture = "mcp_tool" | "mcp_proxy" | "hook" | "sdk" | "cli";

export interface RecordInput {
  readonly tool_name: string;
  readonly target_resource?: string;
  readonly outcome?: Outcome;
  readonly agent_id?: string;
  readonly initiator_id?: string;
  readonly authority_ref?: string;
  readonly policy_version?: string;
  readonly correlation_id?: string;
  readonly change_kind?: string;
  /** Hashed, never stored. */
  readonly input?: unknown;
  /** Hashed, never stored. */
  readonly output?: unknown;
  readonly duration_ms?: number;
  readonly server?: string;
  readonly capture: Capture;
}

/** The receipt as people read it: the fields from the Agent Execution Receipt spec. */
export interface AgentReceipt {
  readonly schema_version: typeof RECEIPT_SCHEMA;
  readonly event_id: string;
  readonly timestamp: string;
  readonly time_source: string;
  readonly agent_id: string;
  readonly initiator_id: string;
  readonly authority_ref: string | null;
  readonly policy_version: string | null;
  readonly tool_name: string;
  readonly target_resource: string | null;
  readonly correlation_id: string | null;
  readonly sequence_number: string;
  readonly outcome: Outcome;
  readonly capture: Capture;
  readonly payload: { readonly input_digest: string | null; readonly output_digest: string | null; readonly digest_scheme: "hmac-sha-256"; readonly raw_payload_stored: false };
  readonly signer: { readonly key_id: string; readonly algorithm: "ml-dsa-65+ed25519"; readonly fingerprint: string };
  readonly evidence: { readonly envelope_digest: string; readonly log: string };
}

export interface LoadResult {
  readonly receipts: readonly SignedEnvelope[];
  readonly problems: readonly { readonly kind: "torn_write" | "corrupt_line" | "duplicate" | "sequence_gap" | "foreign_epoch"; readonly detail: string }[];
}

const registry = PayloadRegistry.standard();

/** Canonical JSON: sorted keys, no whitespace. Deterministic for equal values. */
export function canonicalJson(v: unknown): string {
  if (v === undefined) return "null";
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(",")}}`;
}

export function payloadDigest(ws: Workspace, kind: "input" | "output", value: unknown): string {
  return `mh:sha256:${createHmac("sha256", ws.commitKey).update(`cool.mcp.${kind}.v1\0`).update(canonicalJson(value)).digest("hex")}`;
}

/** Read every receipt, reporting (not hiding) anything wrong with the file. */
export function loadReceipts(ws: Workspace): LoadResult {
  if (!existsSync(ws.receiptsPath)) return { receipts: [], problems: [] };
  const text = readFileSync(ws.receiptsPath, "utf8");
  const lines = text.split("\n");
  const endsClean = text.endsWith("\n") || text.length === 0;
  const receipts: SignedEnvelope[] = [];
  const problems: { kind: LoadResult["problems"][number]["kind"]; detail: string }[] = [];
  const seen = new Set<string>();
  lines.forEach((line, i) => {
    if (!line.trim()) return;
    const last = i === lines.length - 1 || (i === lines.length - 2 && lines[lines.length - 1] === "");
    let env: SignedEnvelope;
    try { env = JSON.parse(line) as SignedEnvelope; } catch {
      problems.push(last && !endsClean ? { kind: "torn_write", detail: `line ${i + 1} is incomplete (the process stopped while writing it); it is excluded` } : { kind: "corrupt_line", detail: `line ${i + 1} is not valid JSON` });
      return;
    }
    const key = env.core?.event_id;
    if (!key || seen.has(key) || seen.has(env.digest)) { problems.push({ kind: "duplicate", detail: `line ${i + 1} repeats event ${key ?? "?"}` }); return; }
    seen.add(key); seen.add(env.digest);
    if (env.core.sequence && env.core.sequence.epoch !== ws.epoch) problems.push({ kind: "foreign_epoch", detail: `line ${i + 1} belongs to epoch ${env.core.sequence.epoch}, not this workspace's ${ws.epoch}` });
    receipts.push(env);
  });
  const set = new Set<number>();
  let max = -1;
  for (const r of receipts) { const n = r.core.sequence?.number; if (typeof n === "number") { set.add(n); if (n > max) max = n; } }
  for (let n = 0; n <= max; n++) if (!set.has(n)) problems.push({ kind: "sequence_gap", detail: `receipt ${ws.epoch}.${n} is missing from the log` });
  return { receipts, problems };
}

// ── appending: one writer at a time, without re-reading the whole log ─────────

/**
 * Cross-process lock (the MCP server, the proxy and the hook may share a workspace).
 * O_EXCL lock file holding the writer's pid; a lock whose writer is gone (or older than 30 s) is broken.
 */
function withLock<T>(ws: Workspace, fn: () => T): T {
  const lock = join(ws.mcpDir, "receipts.lock");
  const deadline = Date.now() + 15_000;
  const nap = new Int32Array(new SharedArrayBuffer(4));
  for (;;) {
    try { const fd = openSync(lock, "wx"); writeSync(fd, String(process.pid)); closeSync(fd); break; } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      try {
        const holder = Number(readFileSync(lock, "utf8"));
        if (Date.now() - statSync(lock).mtimeMs > 30_000 || (holder > 0 && !alive(holder))) { unlinkSync(lock); continue; }
      } catch { continue; }
      if (Date.now() > deadline) throw new Error(`timed out waiting for ${displayPath(ws, lock)}; if no CooL process is running, delete it`);
      Atomics.wait(nap, 0, 0, 5);
    }
  }
  try { return fn(); } finally { try { unlinkSync(lock); } catch { /* already gone */ } }
}

/** Is a process with this pid running on this machine? (The lock holder of a crashed writer is not.) */
function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (err) { return (err as NodeJS.ErrnoException).code === "EPERM"; }
}

interface Tail { size: number; next: number; ids: Set<string>; tail: string }
const tails = new Map<string, Tail>();
const TAIL = 256;

function readRange(path: string, start: number, end: number): string {
  const fd = openSync(path, "r");
  try {
    const buf = Buffer.alloc(end - start);
    let off = 0;
    while (off < buf.length) { const n = readSync(fd, buf, off, buf.length - off, start + off); if (!n) break; off += n; }
    return buf.subarray(0, off).toString("utf8");
  } finally { closeSync(fd); }
}

/** The next sequence number, reading only what was appended since we last looked; anything unusual → full check. */
function nextSequence(ws: Workspace, warnings: string[]): Tail {
  const size = existsSync(ws.receiptsPath) ? statSync(ws.receiptsPath).size : 0;
  const t = tails.get(ws.receiptsPath);
  if (t && size >= t.size && (t.size === 0 || readRange(ws.receiptsPath, Math.max(0, t.size - TAIL), t.size) === t.tail)) {
    if (size === t.size) return t;
    const added = readRange(ws.receiptsPath, t.size, size);
    if (added.endsWith("\n")) {
      let ok = true;
      const ids = new Set(t.ids); let next = t.next;
      for (const line of added.split("\n")) {
        if (!line) continue;
        try {
          const e = JSON.parse(line) as SignedEnvelope;
          if (ids.has(e.core.event_id) || ids.has(e.digest) || e.core.sequence?.epoch !== ws.epoch || e.core.sequence.number !== next) { ok = false; break; }
          ids.add(e.core.event_id); ids.add(e.digest); next++;
        } catch { ok = false; break; }
      }
      if (ok) { const u = { size, next, ids, tail: readRange(ws.receiptsPath, Math.max(0, size - TAIL), size) }; tails.set(ws.receiptsPath, u); return u; }
    }
  }
  // Full check: recovers a torn tail, refuses corruption.
  let { receipts, problems } = loadReceipts(ws);
  if (problems.some((p) => p.kind === "torn_write")) {
    // Crash recovery: keep the fragment for inspection, cut the log back to its last complete line.
    const text = readFileSync(ws.receiptsPath, "utf8");
    const keep = text.lastIndexOf("\n") + 1;
    const fragment = join(ws.mcpDir, `torn-${new Date().toISOString().replace(/[:.]/g, "-")}.fragment`);
    writeFileSync(fragment, text.slice(keep));
    truncateSync(ws.receiptsPath, Buffer.byteLength(text.slice(0, keep)));
    warnings.push(`torn_write: an incomplete receipt from an interrupted write was moved to ${displayPath(ws, fragment)}; capture continues`);
    ({ receipts, problems } = loadReceipts(ws));
  }
  warnings.push(...problems.map((p) => `${p.kind}: ${p.detail}`));
  if (problems.some((p) => p.kind === "corrupt_line")) throw new Error(`the receipt log is corrupt (${problems.filter((p) => p.kind === "corrupt_line").map((p) => p.detail).join("; ")}); refusing to append until it is inspected`);
  let next = 0; const ids = new Set<string>();
  for (const r of receipts) { ids.add(r.core.event_id); ids.add(r.digest); const n = r.core.sequence?.number; if (typeof n === "number" && n >= next) next = n + 1; }
  const s2 = existsSync(ws.receiptsPath) ? statSync(ws.receiptsPath).size : 0;
  const u = { size: s2, next, ids, tail: s2 ? readRange(ws.receiptsPath, Math.max(0, s2 - TAIL), s2) : "" };
  // A log with problems (gaps, duplicates) is re-checked in full every time, so the warnings keep showing.
  if (problems.length) tails.delete(ws.receiptsPath); else tails.set(ws.receiptsPath, u);
  return u;
}

export function receiptView(ws: Workspace, env: SignedEnvelope): AgentReceipt {
  const p = env.core.payload as Record<string, unknown>;
  const s = env.core.sequence;
  return {
    schema_version: RECEIPT_SCHEMA,
    event_id: env.core.event_id,
    timestamp: env.core.occurred_at,
    time_source: "the recording machine's clock (not independently trusted)",
    agent_id: env.core.actor.id,
    initiator_id: String(p["initiator"] ?? "unknown"),
    authority_ref: (p["authority_ref"] as string | undefined) ?? null,
    policy_version: (p["policy_version"] as string | undefined) ?? null,
    tool_name: String(p["tool"]),
    target_resource: (p["target"] as string | undefined) ?? null,
    correlation_id: (p["correlation_id"] as string | undefined) ?? null,
    sequence_number: s ? `${s.epoch}.${s.number}` : "unsequenced",
    outcome: p["outcome"] as Outcome,
    capture: p["capture"] as Capture,
    payload: { input_digest: (p["input_digest"] as string | undefined) ?? null, output_digest: (p["output_digest"] as string | undefined) ?? null, digest_scheme: "hmac-sha-256", raw_payload_stored: false },
    signer: { key_id: env.signatures[0]!.key_id, algorithm: "ml-dsa-65+ed25519", fingerprint: ws.fingerprint },
    evidence: { envelope_digest: env.digest, log: displayPath(ws, ws.receiptsPath) },
  };
}

/** Create, sign and durably append one receipt. Throws on any failure. */
export function recordReceipt(ws: Workspace, input: RecordInput, o: { readonly exportJsonl?: string } = {}): { readonly receipt: AgentReceipt; readonly envelope: SignedEnvelope; readonly warnings: readonly string[] } {
  if (!input.tool_name || typeof input.tool_name !== "string") throw new Error("tool_name is required");
  return withLock(ws, () => appendReceipt(ws, input, o));
}

function appendReceipt(ws: Workspace, input: RecordInput, o: { readonly exportJsonl?: string }): { readonly receipt: AgentReceipt; readonly envelope: SignedEnvelope; readonly warnings: readonly string[] } {
  const warnings: string[] = [];
  const state = nextSequence(ws, warnings);
  const next = state.next;
  const now = new Date().toISOString();
  const payload: Record<string, unknown> = {
    tool: input.tool_name,
    outcome: input.outcome ?? "success",
    capture: input.capture,
    initiator: input.initiator_id ?? "unknown",
    digest_scheme: "hmac-sha-256",
    ...(input.target_resource ? { target: input.target_resource } : {}),
    ...(input.authority_ref ? { authority_ref: input.authority_ref } : {}),
    ...(input.policy_version ? { policy_version: input.policy_version } : {}),
    ...(input.correlation_id ? { correlation_id: input.correlation_id } : {}),
    ...(input.change_kind ? { change_kind: input.change_kind } : {}),
    ...(input.server ? { server: input.server } : {}),
    ...(input.input !== undefined ? { input_digest: payloadDigest(ws, "input", input.input) } : {}),
    ...(input.output !== undefined ? { output_digest: payloadDigest(ws, "output", input.output) } : {}),
    ...(Number.isSafeInteger(input.duration_ms) ? { duration_ms: input.duration_ms } : {}),
  };
  const env = signEnvelope(createEnvelope({
    event_type: "agent.execution",
    occurred_at: now,
    observed_at: now,
    source: { system: "mcp-server-cool", instance: hostname() },
    actor: { id: input.agent_id ?? "agent:unspecified", type: "workload" },
    action: input.change_kind ?? "tool_call",
    resource: { type: "tool", ref: input.tool_name },
    payload,
    sequence: { epoch: ws.epoch, number: next },
  }, registry), ws.key);

  const line = Buffer.from(`${JSON.stringify(env)}\n`, "utf8");
  const fd = openSync(ws.receiptsPath, "a", 0o644);
  try {
    writeSync(fd, line);
    fsyncSync(fd);
  } finally { closeSync(fd); }
  if (tails.get(ws.receiptsPath) === state) {
    state.size += line.length; state.next = next + 1; state.ids.add(env.core.event_id); state.ids.add(env.digest);
    state.tail = readRange(ws.receiptsPath, Math.max(0, state.size - TAIL), state.size);
  }

  const receipt = receiptView(ws, env);
  if (o.exportJsonl) {
    // At-least-once, local append: a SIEM forwarder tails this file. A failure here is reported, the receipt is already safe.
    try {
      appendFileSync(o.exportJsonl, `${JSON.stringify({ time: receipt.timestamp, source: "cool", workspace: ws.id, event_id: receipt.event_id, sequence: receipt.sequence_number, tool: receipt.tool_name, target: receipt.target_resource, outcome: receipt.outcome, agent: receipt.agent_id, initiator: receipt.initiator_id, capture: receipt.capture, envelope_digest: receipt.evidence.envelope_digest, signer: receipt.signer.key_id })}\n`);
    } catch (err) { warnings.push(`export_failed: could not append to ${o.exportJsonl}: ${(err as Error).message}`); }
  }
  return { receipt, envelope: env, warnings };
}
