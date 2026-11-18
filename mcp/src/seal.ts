/**
 * CooL MCP server
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Sealing: put every receipt into an RFC 6962 Merkle log, sign the tree head,
 * and export a portable bundle another person can verify offline.
 *
 *   .cool/bundles/<UTC time>/
 *     bundle.json     cool.bundle.v1: receipts + inclusion proofs + signed manifest
 *     trust.json      PUBLIC keys only (receipt key, log key) — never a private key
 *     MANIFEST.json   file hashes, versions, tree head, key fingerprint, coverage
 *     VERIFY.txt      how to verify it, in plain words
 *
 * Sealing refuses a log with corrupt or duplicated lines instead of sealing
 * around them. A torn final line is reported and left out.
 */
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { TransparencyLog, TrustStore, exportBundle, type SignedEnvelope, type TrustSnapshot } from "cool-nwc/platform";
import { loadReceipts } from "./receipts.js";
import { displayPath, type Workspace } from "./workspace.js";

export const BUNDLE_MANIFEST_SCHEMA = "cool.mcp-bundle-manifest.v1";

export function captureScope(ws: Workspace, receipts: readonly SignedEnvelope[]): string {
  let lo = Infinity, hi = -Infinity;
  for (const r of receipts) { const n = r.core.sequence?.number; if (typeof n === "number") { lo = Math.min(lo, n); hi = Math.max(hi, n); } }
  const range = hi >= 0 ? `${ws.epoch}.${lo}–${ws.epoch}.${hi}` : "none";
  return `This bundle covers only actions recorded through CooL for workspace ${ws.id} (receipts ${range}): MCP tool calls made through the CooL proxy, explicit cool_record_change calls, and configured hooks. Actions taken any other way (other tools, direct API calls, or while CooL was not running) are outside this boundary and cannot be shown to have happened or not. Timestamps come from the recording machine's clock.`;
}

export function trustFor(ws: Workspace): TrustSnapshot {
  const now = new Date().toISOString();
  return {
    schema: "cool.trust-snapshot.v1",
    id: `cool-mcp-${ws.id}`,
    as_of: now,
    keys: [
      { key_id: ws.key.keyId, entry: ws.key.directoryEntry, purposes: ["evidence"], owner: `CooL MCP workspace ${ws.id}`, valid_from: "2020-01-01T00:00:00Z", status: "active" },
      { key_id: ws.logKey.keyId, entry: ws.logKey.directoryEntry, purposes: ["log"], owner: `CooL MCP workspace ${ws.id} (log)`, valid_from: "2020-01-01T00:00:00Z", status: "active" },
    ],
  } as unknown as TrustSnapshot;
}

export interface SealResult {
  readonly bundle_dir: string;
  readonly receipts: number;
  readonly tree_size: number;
  readonly root_hash: string | null;
  readonly fingerprint: string;
  readonly warnings: readonly string[];
  readonly coverage: string;
}

const sha256File = (data: string) => `sha256:${createHash("sha256").update(data).digest("hex")}`;

export function sealWorkspace(ws: Workspace, o: { readonly now?: Date } = {}): SealResult {
  const { receipts, problems } = loadReceipts(ws);
  const blocking = problems.filter((p) => p.kind === "corrupt_line" || p.kind === "duplicate" || p.kind === "foreign_epoch");
  if (blocking.length) throw new Error(`refusing to seal: ${blocking.map((p) => `${p.kind}: ${p.detail}`).join("; ")}`);
  if (!receipts.length) throw new Error("nothing to seal: no receipts have been recorded in this workspace yet");

  const log = new TransparencyLog(`cool-mcp/${ws.id}`, ws.logKey, () => o.now ?? new Date());
  for (const r of receipts) log.add(r);
  // Every receipt carries an inclusion proof against the same, final tree head (signed once).
  const proofs = log.checkpoints(receipts.map((r) => r.digest));
  const sealed = receipts.map((r, i) => ({ ...r, checkpoint: proofs[i]! }));
  const head = sealed.at(-1)!.checkpoint.sth;
  const trust = trustFor(ws);
  const bundle = exportBundle({ title: `CooL MCP evidence, workspace ${ws.id}`, envelopes: sealed, trust: new TrustStore(trust), exporter: ws.key, ...(o.now ? { now: o.now } : {}) });

  const stamp = (o.now ?? new Date()).toISOString().replace(/[:.]/g, "-");
  const dir = join(ws.bundlesDir, stamp);
  mkdirSync(dir, { recursive: true });
  const files: Record<string, string> = {
    "bundle.json": `${JSON.stringify(bundle, null, 2)}\n`,
    "trust.json": `${JSON.stringify(trust, null, 2)}\n`,
  };
  const coverage = captureScope(ws, receipts);
  const manifest = {
    schema: BUNDLE_MANIFEST_SCHEMA,
    bundle_version: "cool.bundle.v1",
    receipt_schema: "cool.agent-receipt.v1 (agent.execution.v1 envelopes)",
    created_at: (o.now ?? new Date()).toISOString(),
    workspace: ws.id,
    receipts: receipts.length,
    tree: { log_id: head.log_id, size: head.tree_size, root_hash: head.root_hash },
    key_fingerprint: ws.fingerprint,
    files: Object.fromEntries(Object.entries(files).map(([n, d]) => [n, sha256File(d)])),
    coverage,
    contains_private_keys: false,
  };
  files["MANIFEST.json"] = `${JSON.stringify(manifest, null, 2)}\n`;
  files["VERIFY.txt"] = [
    "How to verify this CooL evidence bundle (works offline, no account needed):",
    "",
    "  npx -y @northwindcipher/mcp-server-cool verify . --fingerprint " + ws.fingerprint,
    "",
    "Get the fingerprint from the person who recorded the evidence through a separate channel",
    "(a call, a signed email). Without it, the result is at best INDETERMINATE: the bundle's own",
    "key list proves nothing about who should be trusted.",
    "",
    "Coverage: " + coverage,
    "",
  ].join("\n");
  for (const [n, d] of Object.entries(files)) writeFileSync(join(dir, n), d);
  appendFileSync(ws.checkpointsPath, `${JSON.stringify(head)}\n`);

  return {
    bundle_dir: dir,
    receipts: receipts.length,
    tree_size: head.tree_size,
    root_hash: head.root_hash,
    fingerprint: ws.fingerprint,
    warnings: problems.map((p) => `${p.kind}: ${p.detail}`),
    coverage,
  };
}

export const describeBundleDir = (ws: Workspace, dir: string) => displayPath(ws, dir);
