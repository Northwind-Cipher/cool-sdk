/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * NVIDIA NRAS results.
 *
 * GENUINE: NRAS's published JWKS (snapshot 2026-11-02) — every signing key in
 * it must chain to the pinned NRAS intermediates.
 * SYNTHETIC: the attestation tokens. No confidential-computing GPU was
 * available, so tokens in NRAS's exact shape are signed on a synthetic P-384
 * PKI and the verifier is pointed at that PKI explicitly. The adapter is
 * therefore labelled `experimental` until a real result is recorded.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { X509Certificate, createHash, sign as cryptoSign, type KeyObject } from "node:crypto";
import { NRAS_ANCHORS, NRAS_ISSUER, cpuBindingNonce, verifyNrasResult, type Jwks } from "../src/nvidia/index";
import { ADAPTERS } from "../src/platform/index";
import { syntheticNitroPki } from "./support/synthetic-pki";

const real = JSON.parse(readFileSync(new URL("./fixtures/nras-jwks-2026-11-02.json", import.meta.url), "utf8"));

test("nvidia: every key in NVIDIA's real NRAS JWKS snapshot chains to a pinned NRAS intermediate", () => {
  const anchors = NRAS_ANCHORS.map((a) => new X509Certificate(a.der));
  const seen = new Set<string>();
  for (const k of real.jwks.keys) {
    const leaf = new X509Certificate(Buffer.from(k.x5c[0], "base64"));
    const issuer = anchors.find((a) => leaf.checkIssued(a) && leaf.verify(a.publicKey));
    assert.ok(issuer, `${k.kid} does not chain to a pinned anchor`);
    seen.add(issuer.subject);
    assert.match(leaf.subject, /NVIDIA Attestation Service/);
  }
  assert.equal(seen.size, 2, "both pinned intermediates are in use");
});

/* ── synthetic NRAS-shaped tokens ─────────────────────────────────────── */

const pki = syntheticNitroPki();
const KID = "synthetic-nras-kid";
const jwks: Jwks = {
  keys: [{ kid: KID, kty: "EC", crv: "P-384", ...(new X509Certificate(pki.leaf).publicKey.export({ format: "jwk" }) as { x: string; y: string }), x5c: [Buffer.from(pki.leaf).toString("base64"), Buffer.from(pki.intermediate).toString("base64")] }],
};
const anchors = [{ name: "SYNTHETIC NRAS intermediate", sha256: createHash("sha256").update(pki.intermediate).digest("hex"), der: pki.intermediate }];
const NOW = Date.parse("2026-11-02T12:00:00Z");
const s = (n: number) => Math.floor(n / 1000);
const b64url = (b: Buffer | string) => Buffer.from(b).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");

function jwt(payload: Record<string, unknown>, o: { key?: KeyObject; alg?: string; kid?: string } = {}): string {
  const head = b64url(JSON.stringify({ alg: o.alg ?? "ES384", kid: o.kid ?? KID, typ: "JWT" }));
  const body = b64url(JSON.stringify(payload));
  const sig = cryptoSign("sha384", Buffer.from(`${head}.${body}`), { key: o.key ?? pki.leafKey, dsaEncoding: "ieee-p1363" });
  return `${head}.${body}.${b64url(sig)}`;
}

const NONCE = "a1".repeat(32);
function result(o: { nonce?: string; overall?: unknown; gpu?: Record<string, unknown>; exp?: number; submodDigest?: string; omitSubmod?: boolean } = {}) {
  const times = { iat: s(NOW - 60_000), nbf: s(NOW - 120_000), exp: s(o.exp ?? NOW + 3_600_000) };
  const gpu = jwt({ iss: NRAS_ISSUER, ...times, eat_nonce: o.nonce ?? NONCE, measres: "success", hwmodel: "GH100 A01 GSP BROM", ueid: "478176379286082186618948445787393647364802107249", "x-nvidia-gpu-arch-check": true, "x-nvidia-gpu-attestation-report-signature-verified": true, "x-nvidia-gpu-attestation-report-nonce-match": true, "x-nvidia-gpu-driver-version": "550.90.07", "x-nvidia-gpu-vbios-version": "96.00.9F.00.01", dbgstat: "disabled", secboot: true, ...o.gpu });
  const overall = jwt({ iss: NRAS_ISSUER, ...times, eat_nonce: o.nonce ?? NONCE, "x-nvidia-overall-att-result": o.overall ?? true, "x-nvidia-ver": "2.0", submods: o.omitSubmod ? {} : { "GPU-0": ["DIGEST", ["SHA256", o.submodDigest ?? createHash("sha256").update(gpu).digest("hex")]] } });
  return [["JWT", overall], { "GPU-0": gpu }];
}
const opts = { jwks, anchors, expectedNonce: NONCE, now: NOW };

test("nvidia: an NRAS-shaped result verifies — chain, ES384 signatures, freshness, nonce, overall result, submods, GPU claims", () => {
  const r = verifyNrasResult(result(), opts);
  assert.equal(r.outcome, "verified", JSON.stringify(r.reasons));
  assert.equal(r.gpus[0]?.hwmodel, "GH100 A01 GSP BROM");
  assert.match(r.checks.submods.detail, /detached token/);
});

test("nvidia: the default anchors are NVIDIA's — a synthetic signer is untrusted without an explicit anchor", () => {
  const r = verifyNrasResult(result(), { jwks, expectedNonce: NONCE, now: NOW });
  assert.equal(r.checks.key_chain.reason, "untrusted_root");
  assert.equal(r.outcome, "invalid");
});

test("nvidia: tampering, wrong nonce, failed appraisal, unbound GPU token, expiry and algorithm all fail", () => {
  const good = result() as [[string, string], Record<string, string>];
  const [h, p, sg] = good[0][1].split(".");
  const forged = JSON.parse(Buffer.from(p!, "base64url").toString());
  forged["x-nvidia-overall-att-result"] = true; forged.eat_nonce = "ff";
  const tampered = [["JWT", `${h}.${b64url(JSON.stringify(forged))}.${sg}`], good[1]];
  assert.equal(verifyNrasResult(tampered, opts).checks.signatures.reason, "signature_invalid");

  assert.equal(verifyNrasResult(result({ nonce: "00" }), opts).checks.nonce.reason, "nonce_mismatch");
  assert.equal(verifyNrasResult(result({ overall: false }), opts).checks.overall_result.reason, "attestation_failed");
  assert.equal(verifyNrasResult(result({ gpu: { measres: "fail" } }), opts).checks.gpu_claims.reason, "gpu_appraisal_failed");
  assert.equal(verifyNrasResult(result({ gpu: { dbgstat: "enabled" } }), opts).outcome, "invalid");
  assert.equal(verifyNrasResult(result({ submodDigest: "00".repeat(32) }), opts).checks.submods.reason, "submod_unbound");
  assert.equal(verifyNrasResult(result({ omitSubmod: true }), opts).checks.submods.reason, "submod_unbound");
  const stale = verifyNrasResult(result({ exp: NOW - 3_600_000 }), opts);
  assert.equal(stale.outcome, "stale");
  const hs = [["JWT", jwt({ iss: NRAS_ISSUER }, { alg: "HS256" })], { "GPU-0": result()[1]!["GPU-0" as never] }];
  const hsr = verifyNrasResult(hs, opts);
  assert.equal(hsr.checks.format.reason, "unsupported_algorithm", "HS256 (or any non-ES384) is refused");
  assert.notEqual(hsr.outcome, "verified");
  assert.equal(verifyNrasResult(result(), { ...opts, jwks: { keys: [] } }).checks.format.reason, "unknown_key");
});

test("nvidia: without a nonce the result is indeterminate (replay cannot be excluded)", () => {
  assert.equal(verifyNrasResult(result(), { jwks, anchors, now: NOW }).outcome, "indeterminate");
});

test("nvidia: CPU binding — the NRAS nonce must derive from the CPU TEE report's REPORT_DATA", () => {
  const reportData = new Uint8Array(64).fill(7);
  const nonce = cpuBindingNonce(reportData);
  assert.equal(verifyNrasResult(result({ nonce }), { ...opts, expectedNonce: nonce, cpuReportData: reportData }).checks.cpu_binding.reason, "cpu_bound");
  assert.equal(verifyNrasResult(result(), { ...opts, cpuReportData: reportData }).checks.cpu_binding.reason, "cpu_binding_mismatch");
});

test("nvidia: malformed input never throws; the adapter is labelled experimental", async () => {
  for (const bad of [null, "x", [], [["JWT", "a.b"]], [["JWT", "e30.e30.AA"], {}], { a: 1 }]) assert.equal(verifyNrasResult(bad, opts).outcome, "invalid");
  const a = await ADAPTERS["nvidia-cc"].verify(result() as never, opts as never);
  assert.equal(a.support, "experimental");
  assert.equal(a.outcome, "verified");
  assert.ok(a.limitations.some((l) => /real confidential-computing GPU/.test(l)));
});

test("nvidia: a token dated in the future is rejected, not treated as fresh", () => {
  const r = verifyNrasResult(result(), { ...opts, now: NOW - 3_600_000 });
  assert.equal(r.checks.freshness.reason, "issued_in_future");
  assert.equal(r.outcome, "invalid");
});
