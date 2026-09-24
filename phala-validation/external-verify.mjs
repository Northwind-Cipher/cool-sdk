/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * External verification: runs OUTSIDE the Phala CVM, on the operator's own
 * machine, against a receipt pulled over HTTPS from the deployed workload.
 * Proves the receipt is independently checkable without trusting the
 * container that produced it.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { verifyReceiptV2, remoteQuoteVerifier } from "../dist/phala/index.js";

const receiptPath = process.argv[2];
const outPath = process.argv[3];
if (!receiptPath) {
  console.error("usage: node external-verify.mjs <receipt.json> [out.json]");
  process.exit(1);
}

const receipt = JSON.parse(readFileSync(receiptPath, "utf8"));

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

const verifier = remoteQuoteVerifier({
  endpoint: "https://cloud-api.phala.com/api/v1/attestations/verify",
  root: "intel-dcap",
  name: "phala-cloud-attestation-api",
  encode: (rawQuoteBase64) => {
    const bytes = Uint8Array.from(atob(rawQuoteBase64), (c) => c.charCodeAt(0));
    return { hex: bytesToHex(bytes) };
  },
  decode: (response) => {
    const r = response ?? {};
    const verified = r?.quote?.verified === true;
    return { ok: verified, detail: verified ? "verified by Phala Cloud attestation API (real Intel DCAP check)" : `Phala Cloud attestation API returned: ${JSON.stringify(r)}` };
  },
});

const verdict = await verifyReceiptV2(receipt, { requireHardware: true, quoteVerifier: verifier });

console.log(JSON.stringify(verdict, null, 2));
if (outPath) writeFileSync(outPath, JSON.stringify(verdict, null, 2));

process.exit(verdict.ok ? 0 : 1);
