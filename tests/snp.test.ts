/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * AMD SEV-SNP against GENUINE evidence: a Milan attestation report and its
 * VCEK (virtee/sev test data, Apache-2.0), chaining to AMD's real ARK-Milan
 * pinned in src/snp/roots.ts. Then every way it should fail.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { X509Certificate, createHash, randomBytes } from "node:crypto";
import { AMD_SNP_ROOTS, decodeTcb, parseSnpReport, verifySnpReport } from "../src/snp/index";
import { ADAPTERS } from "../src/platform/index";

const f = JSON.parse(readFileSync(new URL("./fixtures/snp-milan-virtee.json", import.meta.url), "utf8"));
const report = () => Uint8Array.from(Buffer.from(f.report_hex, "hex"));
const vcek = Uint8Array.from(Buffer.from(f.vcek_der_b64, "base64"));
const AT = Date.parse("2026-11-02T12:00:00Z");
const base = { certificate: vcek, expectedMeasurement: f.measurement as string, now: AT };

test("snp: pinned AMD roots are the published ones", () => {
  assert.equal(AMD_SNP_ROOTS.Milan.arkSha256, "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd");
  assert.equal(AMD_SNP_ROOTS.Genoa.arkSha256, "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1");
  assert.equal(AMD_SNP_ROOTS.Turin.arkSha256, "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a");
  assert.equal(createHash("sha256").update(vcek).digest("hex"), f.vcek_sha256);
});

test("snp: a GENUINE Milan report verifies — chain, signature, TCB and chip binding, policy, measurement", () => {
  const r = verifySnpReport(report(), base);
  assert.equal(r.outcome, "verified", JSON.stringify(r.reasons));
  assert.equal(r.product, "Milan");
  assert.match(r.checks.chain.detail, /VCEK → ASK-Milan → ARK-Milan/);
  assert.equal(r.checks.signature.reason, "signature_valid");
  assert.equal(r.checks.tcb_binding.reason, "tcb_bound");
  assert.deepEqual(r.tcb, { bootloader: 3, tee: 0, snp: 8, microcode: 115 });
  assert.equal(r.report?.policy.debug, false);
});

test("snp: adapter reports implemented and the same verdict", async () => {
  const a = await ADAPTERS["amd-sev-snp"].verify(report() as never, base as never);
  assert.equal(a.support, "implemented");
  assert.equal(a.outcome, "verified");
  assert.match(a.evidence_digest ?? "", /^mh:sha256:[0-9a-f]{64}$/);
});

test("snp: any change inside the signed region breaks the signature", () => {
  for (const offset of [0x08 /* policy: e.g. set DEBUG */, 0x50 /* report_data */, 0x90 /* measurement */, 0x180 /* reported_tcb */, 0x1a0 /* chip_id */, 0x29f]) {
    const b = report();
    b[offset] = b[offset]! ^ (0x01);
    const r = verifySnpReport(b, base);
    assert.equal(r.checks.signature.reason, "signature_invalid", `offset 0x${offset.toString(16)}`);
    assert.equal(r.outcome, "invalid");
  }
  const sig = report();
  sig[0x2a0] = sig[0x2a0]! ^ (0x80);
  assert.equal(verifySnpReport(sig, base).checks.signature.reason, "signature_invalid");
  for (const offset of [0x2a0 + 50, 0x2e8 + 60, 0x400]) {
    const pad = report();
    pad[offset] = 1;
    assert.equal(verifySnpReport(pad, base).checks.structure.reason, "malformed", `unsigned byte 0x${offset.toString(16)} must be zero`);
  }
});

test("snp: policy failures — wrong measurement pin, report_data, TCB minimum, VMPL, revoked VCEK", () => {
  assert.equal(verifySnpReport(report(), { ...base, expectedMeasurement: "00".repeat(48) }).checks.measurement.reason, "measurement_mismatch");
  assert.equal(verifySnpReport(report(), { ...base, expectedReportData: "11".repeat(64) }).checks.report_data.reason, "report_data_mismatch");
  assert.equal(verifySnpReport(report(), { ...base, expectedReportData: f.report_data }).checks.report_data.reason, "report_data_matches");
  const low = verifySnpReport(report(), { ...base, minimumTcb: { snp: 9 } });
  assert.equal(low.checks.tcb_minimum.reason, "tcb_below_minimum");
  assert.equal(low.outcome, "invalid");
  assert.equal(verifySnpReport(report(), { ...base, minimumTcb: { snp: 8, microcode: 115 } }).checks.tcb_minimum.reason, "tcb_meets_minimum");
  assert.equal(verifySnpReport(report(), { ...base, expectedVmpl: 1 }).checks.vmpl.reason, "vmpl_mismatch");
  const serial = new X509Certificate(vcek).serialNumber;
  assert.equal(verifySnpReport(report(), { ...base, revokedSerials: [serial] }).checks.chain.reason, "certificate_revoked");
});

test("snp: no measurement pin → indeterminate, never verified", () => {
  const r = verifySnpReport(report(), { certificate: vcek, now: AT });
  assert.equal(r.outcome, "indeterminate");
  assert.equal(r.checks.measurement.reason, "no_measurement_policy");
});

test("snp: an expired VCEK is stale; a certificate for another chip or product is rejected", () => {
  assert.equal(verifySnpReport(report(), { ...base, now: Date.parse("2031-01-01T00:00:00Z") }).outcome, "stale");
  const turin = Uint8Array.from(Buffer.from(f.other_vcek_turin_der_b64, "base64"));
  const r = verifySnpReport(report(), { ...base, certificate: turin });
  assert.equal(r.outcome, "invalid");
  assert.notEqual(r.checks.signature.reason, "signature_valid");
  // A Milan VCEK presented as Genoa fails the pinned chain.
  assert.equal(verifySnpReport(report(), { ...base, product: "Genoa" }).checks.chain.reason, "untrusted_root");
});

test("snp: malformed input never throws", () => {
  assert.equal(verifySnpReport(report().subarray(0, 1000), base).checks.structure.reason, "malformed");
  assert.equal(verifySnpReport(report(), { ...base, certificate: Uint8Array.of(1, 2, 3) }).checks.chain.reason, "malformed");
  const v = report(); v[0] = 9;
  assert.equal(verifySnpReport(v, base).checks.structure.reason, "unsupported_version");
  assert.equal(verifySnpReport(v, base).outcome, "invalid");
  for (let i = 0; i < 300; i++) {
    const b = report();
    for (let k = 0; k < 1 + (i % 8); k++) b[randomBytes(2).readUInt16BE() % b.length] = randomBytes(1)[0]!;
    const changed = Buffer.compare(Buffer.from(b), Buffer.from(report())) !== 0;
    const r = verifySnpReport(b, base);
    if (changed) assert.notEqual(r.outcome, "verified", `fuzz ${i}: an altered report must never verify`);
  }
});

test("snp: TCB decoding differs for Turin", () => {
  assert.deepEqual(decodeTcb("0102030400000005", "Turin"), { fmc: 1, bootloader: 2, tee: 3, snp: 4, microcode: 5 });
  assert.deepEqual(decodeTcb("0300000000000873", "Milan"), { bootloader: 3, tee: 0, snp: 8, microcode: 115 });
  assert.equal(parseSnpReport(report()).signing_key, "vcek");
});
