/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Labels are enforced, not just written down.
 *
 *  - docs/capabilities.md is exactly what the registry generates
 *  - every TEE adapter's `support` equals its capability label
 *  - capabilities whose label depends on a validation artifact cannot claim
 *    "implemented" unless a passing, non-synthetic artifact is committed
 *  - statements known to be stale cannot reappear in README or docs
 */
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { ADAPTERS, CAPABILITIES, capabilitiesMarkdown, capability } from "../src/platform/index";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

test("capabilities: every id is unique and every label is one of the five", () => {
  const ids = CAPABILITIES.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const c of CAPABILITIES) assert.ok(["implemented", "experimental", "partial", "planned", "unsupported"].includes(c.label), c.id);
});

test("capabilities: docs/capabilities.md is generated from the registry (run `npm run docs:capabilities`)", () => {
  assert.equal(readFileSync(join(ROOT, "docs/capabilities.md"), "utf8"), capabilitiesMarkdown());
});

test("capabilities: TEE adapters report exactly the registry's labels", () => {
  const map: Record<string, string> = { "aws-nitro": "nitro-verifier", "intel-tdx": "tdx", "phala-dstack": "dstack-kms", "amd-sev-snp": "sev-snp", "nvidia-cc": "nvidia-cc" };
  for (const [platform, id] of Object.entries(map)) assert.equal(ADAPTERS[platform as keyof typeof ADAPTERS].support, capability(id).label, platform);
});

const passingArtifacts = (dir: string, ok: (a: Record<string, unknown>) => boolean) => {
  const d = join(ROOT, dir);
  if (!existsSync(d)) return 0;
  return readdirSync(d).filter((f) => f.endsWith(".json")).map((f) => JSON.parse(readFileSync(join(d, f), "utf8")) as Record<string, unknown>).filter(ok).length;
};

test("capabilities: hardware and cloud labels follow committed validation artifacts", () => {
  const nitro = passingArtifacts("artifacts/nitro-validation", (a) => a["passed"] === true && a["synthetic"] === false);
  assert.equal(capability("nitro-runtime").label, nitro > 0 ? "implemented" : "experimental", "nitro-runtime is implemented iff a real-hardware artifact passed");
  for (const p of ["aws", "gcp"] as const) {
    const n = passingArtifacts("artifacts/kms-validation", (a) => a["provider"] === p && a["overall_status"] === "pass");
    assert.equal(capability(`kms-${p}`).label, n > 0 ? "implemented" : "experimental", `kms-${p}`);
  }
  assert.equal(capability("external-review").label, existsSync(join(ROOT, "docs/security-review/external")) ? "implemented" : "planned");
});

test("capabilities: stale statements do not reappear in README or docs", () => {
  const STALE: Array<[RegExp, string]> = [
    [/SEV-SNP\*{0,2}\s*\|\s*\*{0,2}unsupported/i, "SEV-SNP is implemented"],
    [/NVIDIA[^|\n]*\|\s*\*{0,2}unsupported/i, "NVIDIA CC is experimental"],
    [/RFC 3161[^.\n]*(not implemented|planned)/i, "RFC 3161 is implemented"],
    [/KMS\/HSM adapters? (ships?|are) \*{0,2}planned/i, "KMS adapters exist (experimental)"],
    [/no managed KMS\/HSM adapter ships/i, "KMS adapters exist (experimental)"],
    [/Distributed nonce store[^|\n]*\|\s*planned/i, "Redis store is implemented"],
    [/helper absent/i, "the NSM helper exists"],
    [/in-enclave runtime is \[?not built/i, "the enclave kit is built (experimental)"],
    [/(running|runs|ran) (on|in(side)?) (a )?real (AWS )?Nitro enclave/i, "no real-hardware run is recorded yet"],
    [/independent(ly)? (security )?(review|audit)(ed)? (has been|was) (completed|done|performed)/i, "no external review has happened"],
  ];
  const files = ["README.md", "SECURITY.md", "GOVERNANCE.md", ...readdirSync(join(ROOT, "docs")).filter((f) => f.endsWith(".md")).map((f) => `docs/${f}`), "examples/nitro-enclave/README.md"];
  const hits: string[] = [];
  for (const f of files) {
    if (!existsSync(join(ROOT, f))) continue;
    const text = readFileSync(join(ROOT, f), "utf8");
    for (const [re, truth] of STALE) {
      const m = text.match(re);
      // Negations ("Do not describe CooL as running on a real Nitro enclave until…") are allowed.
      if (m && !/do not|until|not yet|never/i.test(text.slice(Math.max(0, m.index! - 80), m.index! + m[0].length + 80))) hits.push(`${f}: "${m[0]}" (${truth})`);
    }
  }
  assert.deepEqual(hits, []);
});
