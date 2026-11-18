/** Measure record / seal / verify on this machine. `npm run bench` — numbers go in docs, never guessed. */
import { mkdtempSync, statSync } from "node:fs";
import { tmpdir, cpus } from "node:os";
import { join } from "node:path";
import { openWorkspace, resolveWorkspaceRoot } from "../src/workspace.js";
import { recordReceipt } from "../src/receipts.js";
import { sealWorkspace } from "../src/seal.js";
import { verifyBundleDir } from "../src/verify.js";

const q = (xs: number[], p: number) => { const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(p * s.length))]!; };
const rows: string[] = [];
for (const n of [10, 100, 1000]) {
  const ws = openWorkspace(resolveWorkspaceRoot({ configured: mkdtempSync(join(tmpdir(), "cool-bench-")) }));
  const rec: number[] = [];
  for (let i = 0; i < n; i++) {
    const t = performance.now();
    recordReceipt(ws, { capture: "sdk", tool_name: "Edit", target_resource: `src/f${i}.ts`, input: { i, text: "x".repeat(500) }, output: { ok: true } });
    rec.push(performance.now() - t);
  }
  let t = performance.now(); const s = sealWorkspace(ws); const seal = performance.now() - t;
  t = performance.now(); const v = verifyBundleDir(s.bundle_dir, { fingerprint: ws.fingerprint }); const ver = performance.now() - t;
  if (v.verdict !== "VALID") throw new Error(v.summary);
  const size = statSync(join(s.bundle_dir, "bundle.json")).size;
  rows.push(`| ${n} | ${q(rec, 0.5).toFixed(1)} | ${q(rec, 0.95).toFixed(1)} | ${seal.toFixed(0)} | ${ver.toFixed(0)} | ${(ver / n).toFixed(1)} | ${(size / 1024).toFixed(0)} KiB |`);
}
console.log(`Node ${process.version}, ${process.platform}/${process.arch}, ${cpus()[0]?.model}, ${cpus().length} threads\n`);
console.log("| receipts | record p50 (ms) | record p95 (ms) | seal (ms) | verify bundle (ms) | verify per receipt (ms) | bundle.json |");
console.log("|---:|---:|---:|---:|---:|---:|---:|");
for (const r of rows) console.log(r);
