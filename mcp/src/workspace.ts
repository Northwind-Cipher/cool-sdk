/**
 * CooL MCP server
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The workspace: the one project directory this server is allowed to write
 * into. Every receipt, key and bundle lives under `<workspace>/.cool/`.
 *
 * Resolution order — the first that is set wins, and there is NO silent
 * fallback to the process's working directory (an MCP client such as Claude
 * Desktop starts servers in its own app directory, which is never what you
 * want):
 *   1. the tool call's `workspace_root` argument
 *   2. `--workspace <dir>` on the command line, or COOL_WORKSPACE
 *   3. the client's MCP roots, when it offers exactly one file:// root
 *
 * A workspace must be an existing absolute directory. The filesystem root and
 * the user's home directory are refused (too broad to be a project), and
 * `.cool` must not be a link that leads outside the workspace.
 */
import { existsSync, lstatSync, mkdirSync, realpathSync, statSync, writeFileSync, readFileSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import { randomBytes, createHash } from "node:crypto";
import { generateKeypair, type KeyPair } from "cool-nwc";

export class WorkspaceError extends Error {
  constructor(readonly code: "workspace_required" | "workspace_invalid" | "workspace_unsafe", message: string) {
    super(message);
    this.name = "WorkspaceError";
  }
}

export interface Workspace {
  readonly root: string;
  readonly coolDir: string;
  readonly mcpDir: string;
  readonly receiptsPath: string;
  readonly bundlesDir: string;
  readonly checkpointsPath: string;
  /** Signs receipts and exported bundles. */
  readonly key: KeyPair;
  /** Signs the workspace transparency log's tree heads. */
  readonly logKey: KeyPair;
  /** HMAC key for payload digests: recipients of a bundle cannot test guesses of a payload without it. */
  readonly commitKey: Buffer;
  /** One epoch per workspace: sequence numbers continue across server restarts. */
  readonly epoch: number;
  readonly id: string;
  /** SHA-256 fingerprint of the receipt and log public keys: pin this to verify elsewhere. */
  readonly fingerprint: string;
}

interface KeyFile { readonly version: 1; readonly created_at: string; readonly workspace_id: string; readonly epoch: number; readonly evidence_seed: string; readonly log_seed: string; readonly commit_key: string }

/** Resolve and validate a workspace root. Throws WorkspaceError; never guesses. */
export function resolveWorkspaceRoot(candidates: { readonly param?: string; readonly configured?: string; readonly roots?: readonly string[] }): string {
  const raw = candidates.param ?? candidates.configured ?? (candidates.roots?.length === 1 ? candidates.roots[0] : undefined);
  if (!raw) {
    const hint = candidates.roots && candidates.roots.length > 1 ? ` The client offers ${candidates.roots.length} roots; pass workspace_root to choose one.` : "";
    throw new WorkspaceError("workspace_required", `No workspace chosen. Pass workspace_root, start the server with --workspace <project dir>, or set COOL_WORKSPACE.${hint}`);
  }
  const path = raw.startsWith("file://") ? decodeURIComponent(new URL(raw).pathname).replace(/^\/([A-Za-z]:)/, "$1") : raw;
  if (!isAbsolute(path)) throw new WorkspaceError("workspace_invalid", `workspace_root must be an absolute path, got "${raw}"`);
  if (!existsSync(path) || !statSync(path).isDirectory()) throw new WorkspaceError("workspace_invalid", `workspace_root "${path}" is not an existing directory`);
  const real = realpathSync(path);
  if (parse(real).root === real) throw new WorkspaceError("workspace_unsafe", `refusing the filesystem root "${real}" as a workspace`);
  if (sameDir(real, homedir())) throw new WorkspaceError("workspace_unsafe", "refusing the home directory itself as a workspace; choose a project directory");
  return real;
}

const sameDir = (a: string, b: string) => {
  try { return relative(realpathSync(a), realpathSync(b)) === ""; } catch { return false; }
};

/** Ensure `inner` stays inside `root` after resolving links. */
export function assertInside(root: string, inner: string): void {
  const r = relative(root, existsSync(inner) ? realpathSync(inner) : resolve(inner));
  if (r === "" || (!r.startsWith("..") && !isAbsolute(r))) return;
  throw new WorkspaceError("workspace_unsafe", `"${inner}" resolves outside the workspace`);
}

/** Open (and on first use, initialise) the workspace's `.cool/` directory. */
export function openWorkspace(root: string): Workspace {
  const coolDir = join(root, ".cool");
  if (existsSync(coolDir) && lstatSync(coolDir).isSymbolicLink()) assertInside(root, coolDir);
  const mcpDir = join(coolDir, "mcp");
  const bundlesDir = join(coolDir, "bundles");
  for (const d of [coolDir, mcpDir, bundlesDir]) {
    mkdirSync(d, { recursive: true });
    assertInside(root, d);
  }
  // Keys never leave this directory and must never be committed.
  const ignore = join(mcpDir, ".gitignore");
  if (!existsSync(ignore)) writeFileSync(ignore, "# CooL: private signing keys — never commit\nkeys.json\n");
  const keyPath = join(mcpDir, "keys.json");
  let k: KeyFile;
  if (existsSync(keyPath)) k = JSON.parse(readFileSync(keyPath, "utf8")) as KeyFile;
  else {
    k = { version: 1, created_at: new Date().toISOString(), workspace_id: `ws_${randomBytes(8).toString("hex")}`, epoch: Math.floor(Date.now() / 1000), evidence_seed: randomBytes(32).toString("hex"), log_seed: randomBytes(32).toString("hex"), commit_key: randomBytes(32).toString("hex") };
    writeFileSync(keyPath, JSON.stringify(k, null, 2), { mode: 0o600 });
    try { chmodSync(keyPath, 0o600); } catch { /* best effort on platforms without POSIX modes */ }
  }
  const key = generateKeypair(`cool-mcp-${k.workspace_id}`, { seed: Uint8Array.from(Buffer.from(k.evidence_seed, "hex")) });
  const logKey = generateKeypair(`cool-mcp-log-${k.workspace_id}`, { seed: Uint8Array.from(Buffer.from(k.log_seed, "hex")) });
  return {
    root, coolDir, mcpDir, bundlesDir,
    receiptsPath: join(mcpDir, "receipts.jsonl"),
    checkpointsPath: join(mcpDir, "checkpoints.jsonl"),
    key, logKey,
    commitKey: Buffer.from(k.commit_key, "hex"),
    epoch: k.epoch,
    id: k.workspace_id,
    fingerprint: keyFingerprint(key.directoryEntry, logKey.directoryEntry),
  };
}

/**
 * sha256 over the public halves of the receipt key AND the log key, so pinning
 * one fingerprint pins both: who signed the receipts and who signed the tree head.
 */
export function keyFingerprint(evidence: KeyPair["directoryEntry"], log: KeyPair["directoryEntry"]): string {
  return `sha256:${createHash("sha256").update(["cool.mcp.fingerprint.v1", evidence.ml_dsa_pub, evidence.ed25519_pub, log.ml_dsa_pub, log.ed25519_pub].join("\n")).digest("hex")}`;
}

export const displayPath = (ws: Workspace, p: string) => relative(ws.root, p).split(sep).join("/");
