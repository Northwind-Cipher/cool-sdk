// CooL
// Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0
//
// Runs on the PARENT EC2 instance. Challenges the enclave with a fresh nonce,
// verifies its attestation against the pinned AWS root and the PCRs that
// nitro-cli reported at build time, seals receipts, verifies them, and writes a
// validation artifact. Exit 0 only if everything passed.
//
//   node host/collect.mjs build/pcrs.json [out-dir] [count]
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { collectFromEnclave } from "cool-nwc/nitro";

const [pcrsPath = "build/pcrs.json", outDir = "artifacts", count = "5"] = process.argv.slice(2);
const pcrs = JSON.parse(readFileSync(pcrsPath, "utf8"));
const policy = {
  id: "cool-nitro-validation",
  version: pcrs.version ?? "1",
  source: `nitro-cli build-enclave measurements (${pcrsPath})`,
  pcrs: { 0: pcrs.PCR0, 1: pcrs.PCR1, 2: pcrs.PCR2 },
  pcr8: pcrs.PCR8 ?? "not_applicable",
};

const env = (k) => process.env[k] ?? "unknown";
const artifact = await collectFromEnclave({
  port: Number(process.env.COOL_ENCLAVE_PORT ?? 5005),
  policy,
  count: Number(count),
  environment: {
    instance_type: env("COOL_INSTANCE_TYPE"),
    region: env("COOL_REGION"),
    nitro_cli: env("COOL_NITRO_CLI_VERSION"),
    eif_sha256: env("COOL_EIF_SHA256"),
    commit: env("COOL_COMMIT"),
  },
});

mkdirSync(outDir, { recursive: true });
const file = join(outDir, `nitro-validation-${artifact.recorded_at.replace(/[:.]/g, "-")}.json`);
writeFileSync(file, `${JSON.stringify(artifact, null, 2)}\n`);
console.log(`attestation: ${artifact.attestation.overall_status}  (synthetic: ${artifact.synthetic})`);
for (const [i, r] of artifact.receipts.entries()) console.log(`receipt ${i}: ${r.overall_status} / ${r.outcome}`);
console.log(`${artifact.passed ? "PASSED" : "FAILED"} — artifact: ${file}`);
if (!artifact.passed) for (const r of artifact.attestation.reasons) console.log(`  reason: ${r}`);
process.exit(artifact.passed && !artifact.synthetic ? 0 : 1);
