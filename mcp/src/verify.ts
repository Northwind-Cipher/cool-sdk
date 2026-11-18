/**
 * CooL MCP server
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Offline verification of a sealed bundle directory, or of one receipt.
 *
 * Three verdicts, never a bare tick:
 *   VALID          every check passed AND the signing keys were pinned independently
 *                  (a fingerprint obtained out of band, a trust file, or the local workspace)
 *   INVALID        something was checked and is wrong: altered, missing, reordered,
 *                  replayed, or signed by the wrong key
 *   INDETERMINATE  nothing is wrong that we can see, but something could not be decided:
 *                  usually that nobody independently told us which key to trust
 *
 * No network is used: everything is recomputed from the bytes in the directory.
 * Who the agent and initiator were, and what policy applied, are reported as
 * DECLARED by the recorder — CooL proves the record was not changed, not that
 * the declarations were true.
 */
import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { isAbsolute, join, resolve } from "node:path";
import { PayloadRegistry, TrustStore, verifyBundle, verifyEnvelope, type SignedEnvelope, type TrustSnapshot } from "cool-nwc/platform";
import { keyFingerprint, type Workspace } from "./workspace.js";
import { loadReceipts, receiptView, type AgentReceipt } from "./receipts.js";
import { trustFor } from "./seal.js";

export type Verdict = "VALID" | "INVALID" | "INDETERMINATE";
export interface VerifyCheck { readonly name: string; readonly status: "pass" | "fail" | "unknown" | "not_applicable"; readonly reason: string; readonly detail: string }
export interface VerifyResult {
  readonly verdict: Verdict;
  readonly summary: string;
  readonly checks: readonly VerifyCheck[];
  readonly receipts: number;
  readonly declared: { readonly identity: string; readonly policy: string };
  readonly coverage: string;
  readonly limitations: readonly string[];
}

const registry = PayloadRegistry.standard();
const sha256 = (data: Buffer | string) => `sha256:${createHash("sha256").update(data).digest("hex")}`;

const DECLARED = {
  identity: "agent_id and initiator_id are declared by the recorder; they are not independently authenticated.",
  policy: "authority_ref and policy_version are declared references; CooL does not prove the policy was enforced.",
};
const LIMITS = [
  "Only actions that passed through CooL are covered; anything done another way is outside the record.",
  "Timestamps come from the recording machine's clock.",
  "A dropped FINAL receipt cannot be detected from the bundle alone; compare the tree size with a checkpoint you hold.",
  "The workspace keys live on the recording machine; anyone with that machine's files can sign new receipts.",
];

function verdictOf(checks: readonly VerifyCheck[]): Verdict {
  if (checks.some((c) => c.status === "fail")) return "INVALID";
  if (checks.some((c) => c.status === "unknown")) return "INDETERMINATE";
  return "VALID";
}

function summaryOf(v: Verdict, checks: readonly VerifyCheck[], n: number): string {
  if (v === "VALID") return `VALID: ${n} receipt(s); signatures, Merkle proofs, sequence, duplicates and order all check out against the pinned keys.`;
  const bad = checks.filter((c) => c.status === (v === "INVALID" ? "fail" : "unknown"));
  return `${v}: ${bad.map((c) => `${c.name} (${c.reason}) — ${c.detail}`).join("; ")}`;
}

export interface VerifyBundleOptions {
  /** A cool.trust-snapshot.v1 file you trust (obtained independently of the bundle). */
  readonly trustFile?: string;
  /** The workspace fingerprint, obtained out of band: pins the bundle's own trust.json. */
  readonly fingerprint?: string;
  /** Verify against this local workspace's keys (only meaningful on the recording machine). */
  readonly workspace?: Workspace;
  readonly now?: Date;
}

/** Verify a sealed bundle directory (or a path to its bundle.json). Never throws for bad evidence. */
export function verifyBundleDir(path: string, o: VerifyBundleOptions = {}): VerifyResult {
  const dir = path.endsWith(".json") ? resolve(path, "..") : resolve(path);
  const checks: VerifyCheck[] = [];
  const add = (name: string, status: VerifyCheck["status"], reason: string, detail: string) => checks.push({ name, status, reason, detail });
  const read = (f: string): Buffer | undefined => (existsSync(join(dir, f)) ? readFileSync(join(dir, f)) : undefined);
  const done = (n = 0, coverage = "unknown: the bundle could not be read"): VerifyResult => {
    const v = verdictOf(checks);
    return { verdict: v, summary: summaryOf(v, checks, n), checks, receipts: n, declared: DECLARED, coverage, limitations: LIMITS };
  };

  // 1. Components present and parseable.
  const raw = { bundle: read("bundle.json"), manifest: read("MANIFEST.json"), trust: read("trust.json") };
  const missing = Object.entries({ "bundle.json": raw.bundle, "MANIFEST.json": raw.manifest, "trust.json": raw.trust }).filter(([, b]) => !b).map(([n]) => n);
  if (missing.length) { add("components_present", "fail", "missing_component", `missing from ${dir}: ${missing.join(", ")}`); return done(); }
  let bundle: Parameters<typeof verifyBundle>[0]; let manifest: Record<string, unknown>; let bundled: TrustSnapshot;
  try {
    bundle = JSON.parse(raw.bundle!.toString("utf8"));
    manifest = JSON.parse(raw.manifest!.toString("utf8"));
    bundled = JSON.parse(raw.trust!.toString("utf8"));
  } catch (err) { add("components_present", "fail", "corrupt_component", `a component is not valid JSON: ${(err as Error).message}`); return done(); }
  add("components_present", "pass", "components_present", "bundle.json, MANIFEST.json and trust.json present and parseable");
  const coverage = typeof manifest["coverage"] === "string" ? manifest["coverage"] as string : "not stated in the manifest";

  // 2. File hashes in the manifest.
  const listed = (manifest["files"] ?? {}) as Record<string, string>;
  const wrong = Object.entries(listed).filter(([f, h]) => { const b = read(f); return !b || sha256(b) !== h; }).map(([f]) => f);
  if (!listed["bundle.json"] || !listed["trust.json"]) add("file_hashes", "fail", "manifest_incomplete", "MANIFEST.json does not list bundle.json and trust.json");
  else if (wrong.length) add("file_hashes", "fail", "file_hash_mismatch", `changed since sealing: ${wrong.join(", ")}`);
  else add("file_hashes", "pass", "file_hashes_match", `${Object.keys(listed).length} file(s) match MANIFEST.json`);
  if (JSON.stringify(bundled).includes("seed") || /secret|private/i.test(Object.keys(bundled.keys?.[0] ?? {}).join(","))) add("no_private_keys", "fail", "private_key_present", "trust.json appears to contain private key material");

  // 3. Which keys to trust — the question a bundle cannot answer about itself.
  let trust: TrustStore | undefined;
  const fp = (s: TrustSnapshot) => {
    const ev = s.keys.find((k) => k.purposes.includes("evidence")); const lg = s.keys.find((k) => k.purposes.includes("log"));
    return ev && lg ? keyFingerprint(ev.entry, lg.entry) : undefined;
  };
  if (o.trustFile) {
    try {
      trust = new TrustStore(JSON.parse(readFileSync(o.trustFile, "utf8")) as TrustSnapshot);
      add("trust_source", "pass", "verifier_trust_file", `keys taken from your trust file ${o.trustFile}`);
    } catch (err) { add("trust_source", "unknown", "trust_file_unreadable", `could not read trust file: ${(err as Error).message}`); }
  } else if (o.fingerprint) {
    const got = fp(bundled);
    if (got && got === o.fingerprint.trim()) { trust = new TrustStore(bundled); add("trust_source", "pass", "fingerprint_pinned", `bundle keys match the fingerprint you supplied (${got.slice(0, 23)}…)`); }
    else add("trust_source", "fail", "fingerprint_mismatch", `the bundle's keys have fingerprint ${got ?? "(none)"}, not the ${o.fingerprint} you expected — these receipts were not signed by that workspace`);
  } else if (o.workspace) {
    trust = new TrustStore(trustFor(o.workspace));
    add("trust_source", "pass", "local_workspace", `keys pinned from the local workspace ${o.workspace.id} (meaningful only on the recording machine)`);
  } else {
    add("trust_source", "unknown", "self_asserted_trust", "no fingerprint or trust file supplied: the bundle's own key list proves nothing about whom to trust. Re-run with --fingerprint <value from the recorder>.");
  }

  // 4. Recompute everything: signatures, inclusion proofs, sequence, duplicates, order.
  let report: ReturnType<typeof verifyBundle>;
  try {
    report = verifyBundle(bundle, { registry, ...(trust ? { trust } : {}), requireCheckpoint: true, ...(o.now ? { now: o.now.getTime() } : {}) });
  } catch (err) { add("bundle_format", "fail", "unsupported_bundle", (err as Error).message); return done(0, coverage); }
  const map: Record<string, string> = {
    manifest_valid: "bundle_manifest", exporter_signature_valid: "exporter_signature", envelopes_valid: "receipt_signatures_and_proofs",
    evidence_complete: "references_resolved", sequence_complete: "sequence_complete", duplicates_absent: "no_duplicates_or_replays", order_consistent: "log_order",
  };
  for (const [k, name] of Object.entries(map)) {
    const c = (report.checks as Record<string, { status: string; reason: string; detail: string }>)[k]!;
    // Without pinned trust, a per-receipt "unknown" just restates the trust question already reported.
    const status = (c.status === "not_checked" ? "unknown" : c.status) as VerifyCheck["status"];
    add(name, status, c.reason, k === "envelopes_valid" && status !== "pass" ? `${c.detail}: ${[...new Set(report.envelopes.flatMap((e) => e.reasons))].slice(0, 4).join("; ")}` : c.detail);
  }
  if (trust) {
    // The exporter must be the pinned receipt key: otherwise anyone could re-wrap (and prune) trusted receipts.
    const ev = trust.snapshot().keys.find((k) => k.purposes.includes("evidence"));
    const same = ev && ev.entry.ml_dsa_pub === bundle.exporter_key.ml_dsa_pub && ev.entry.ed25519_pub === bundle.exporter_key.ed25519_pub;
    if (same) add("exporter_trusted", "pass", "exporter_is_pinned_key", "the bundle was exported by the pinned workspace key");
    else add("exporter_trusted", "fail", "exporter_untrusted", `the bundle was exported by ${bundle.exporter_key.key_id}, which is not the pinned workspace key`);
  }
  const envs = bundle.envelopes as readonly SignedEnvelope[];
  const foreign = envs.filter((e) => e.core.event_type !== "agent.execution");
  if (foreign.length) add("receipt_type", "fail", "unexpected_event_type", `${foreign.length} envelope(s) are not agent.execution receipts`);
  const roots = new Set(envs.map((e) => e.checkpoint?.sth.root_hash));
  const tree = manifest["tree"] as { root_hash?: string; size?: number } | undefined;
  if (roots.size !== 1 || !tree || ![...roots].includes(tree.root_hash as never)) add("tree_head", "fail", "tree_head_mismatch", "receipts do not all prove inclusion in the tree head named by MANIFEST.json");
  else add("tree_head", "pass", "single_tree_head", `all ${envs.length} receipt(s) included in tree of size ${tree.size}, root ${String(tree.root_hash).slice(0, 18)}…`);
  return done(envs.length, coverage);
}

/** Verify one receipt from the local log, by event id or sequence number ("<epoch>.<n>"). */
export function verifyLocalReceipt(ws: Workspace, id: string): VerifyResult & { readonly receipt?: AgentReceipt } {
  const { receipts, problems } = loadReceipts(ws);
  const env = receipts.find((r) => r.core.event_id === id || (r.core.sequence && `${r.core.sequence.epoch}.${r.core.sequence.number}` === id));
  const checks: VerifyCheck[] = [];
  if (!env) {
    checks.push({ name: "receipt_found", status: "unknown", reason: "receipt_not_found", detail: `no receipt ${id} in ${ws.receiptsPath}` });
    return { verdict: "INDETERMINATE", summary: `INDETERMINATE: receipt ${id} not found`, checks, receipts: 0, declared: DECLARED, coverage: "single receipt", limitations: LIMITS };
  }
  const r = verifyEnvelope(env, { registry, trust: new TrustStore(trustFor(ws)) });
  for (const k of ["digest_valid", "signature_valid", "signer_trusted", "payload_valid"] as const) {
    const c = (r.checks as unknown as Record<string, { status: string; reason: string; detail: string } | undefined>)[k];
    if (c) checks.push({ name: k, status: (c.status === "not_checked" ? "unknown" : c.status) as VerifyCheck["status"], reason: c.reason, detail: c.detail });
  }
  for (const p of problems.filter((x) => x.kind !== "torn_write")) checks.push({ name: "log_integrity", status: "fail", reason: p.kind, detail: p.detail });
  checks.push({ name: "sealed", status: "not_applicable", reason: "local_check", detail: "single-receipt check against the local workspace key; seal and verify the bundle for Merkle proofs and an offline-portable result" });
  const v = verdictOf(checks);
  return { verdict: v, summary: summaryOf(v, checks, 1), checks, receipts: 1, declared: DECLARED, coverage: "a single receipt, verified on the recording machine", limitations: LIMITS, receipt: receiptView(ws, env) };
}

export const looksLikePath = (s: string) => isAbsolute(s) || s.includes("/") || s.includes("\\") || s.endsWith(".json") || s.startsWith(".");
