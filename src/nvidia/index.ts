/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * `cool-nwc/nvidia` — offline verification of NVIDIA Confidential Computing
 * attestation RESULTS issued by the NVIDIA Remote Attestation Service (NRAS).
 *
 * What this is, precisely: NRAS appraises a GPU's SPDM evidence (device
 * certificate chain, signed measurements, RIMs, OCSP) and returns Entity
 * Attestation Tokens signed with ES384. This module verifies those tokens
 * offline, against a JWKS snapshot you archived with the evidence and the
 * pinned NRAS intermediates (./anchors). It does NOT re-appraise the raw GPU
 * evidence itself — that is NVIDIA's verdict, attributed to NVIDIA's key.
 *
 * NRAS response shape (nvtrust unified EAT): [["JWT", <overall token>], { "GPU-0": <detached token>, … }]
 *
 * Checks:
 *   format          the unified-EAT array shape; alg ES384; a kid present in the JWKS
 *   key_chain       x5c leaf ← a PINNED NRAS intermediate; leaf valid at the token's iat;
 *                   leaf public key = the JWK's x/y
 *   signatures      every token (overall and each GPU) verifies
 *   freshness       now ≤ exp (+ skew) on every token          → `stale` otherwise
 *   nonce           eat_nonce = your nonce, on every token      (required for `verified`)
 *   overall_result  x-nvidia-overall-att-result === true
 *   submods         each GPU token is bound into the overall token's submods digest
 *   gpu_claims      measres = "success" and NVIDIA's appraisal flags true on every GPU
 *   cpu_binding     the nonce equals the CooL binding nonce for a CPU TEE report, when given
 */
import { X509Certificate, createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { check, type Check } from "../platform/status";
import { classifyOutcome, type Outcome } from "../platform/outcome";
import { NRAS_ANCHORS, type NrasAnchor } from "./anchors";

export { NRAS_ANCHORS } from "./anchors";
export type { NrasAnchor } from "./anchors";

export const NRAS_ISSUER = "https://nras.attestation.nvidia.com";

export interface Jwk { readonly kid: string; readonly kty: string; readonly crv?: string; readonly x?: string; readonly y?: string; readonly x5c?: readonly string[] }
export interface Jwks { readonly keys: readonly Jwk[] }

export interface NvidiaChecks {
  readonly format: Check;
  readonly key_chain: Check;
  readonly signatures: Check;
  readonly freshness: Check;
  readonly nonce: Check;
  readonly overall_result: Check;
  readonly submods: Check;
  readonly gpu_claims: Check;
  readonly cpu_binding: Check;
}

export interface NvidiaVerification {
  readonly outcome: Outcome;
  readonly checks: NvidiaChecks;
  readonly reasons: readonly string[];
  readonly gpus: readonly { readonly id: string; readonly hwmodel?: string; readonly driver_version?: string; readonly vbios_version?: string; readonly ueid?: string }[];
  readonly issued_at?: string;
  readonly limitations: readonly string[];
}

export interface VerifyNvidiaOptions {
  /** The JWKS snapshot fetched when the result was obtained (archive it with the evidence). */
  readonly jwks: Jwks;
  /** Hex nonce you sent to NRAS. Without it the outcome is at best `indeterminate`. */
  readonly expectedNonce?: string;
  readonly anchors?: readonly NrasAnchor[];
  readonly issuer?: string;
  readonly expectedGpuCount?: number;
  /** When set, the nonce must equal {@link cpuBindingNonce}(this) — ties the GPU result to a CPU TEE report. */
  readonly cpuReportData?: Uint8Array;
  readonly now?: number;
  readonly clockSkewMs?: number;
}

const LIMITS = [
  "the GPU's raw SPDM evidence is appraised by NVIDIA's NRAS, not re-appraised here; CooL verifies NRAS's signed verdict",
  "NRAS signing keys are anchored at pinned NVIDIA intermediates; the CA 001 root is not published at a documented location",
  "OCSP status is as NRAS reported it at appraisal time",
];

/**
 * The CooL convention for binding GPU attestation to a CPU TEE: the nonce sent
 * to NRAS is SHA-256("cool.gpu-binding.v1\0" ‖ REPORT_DATA of the CPU report).
 * A verifier holding both reports checks they name each other.
 */
export function cpuBindingNonce(cpuReportData: Uint8Array): string {
  return createHash("sha256").update(Buffer.concat([Buffer.from("cool.gpu-binding.v1\0"), Buffer.from(cpuReportData)])).digest("hex");
}

const b64url = (s: string) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");

interface Jwt { readonly raw: string; readonly header: Record<string, unknown>; readonly payload: Record<string, unknown>; readonly payloadBytes: Buffer; readonly signingInput: Buffer; readonly signature: Buffer }

function parseJwt(raw: unknown): Jwt {
  if (typeof raw !== "string") throw new Error("token is not a string");
  const parts = raw.split(".");
  if (parts.length !== 3) throw new Error("token is not a compact JWS");
  const header = JSON.parse(b64url(parts[0]!).toString("utf8")) as Record<string, unknown>;
  const payloadBytes = b64url(parts[1]!);
  const payload = JSON.parse(payloadBytes.toString("utf8")) as Record<string, unknown>;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("token payload is not an object");
  return { raw, header, payload, payloadBytes, signingInput: Buffer.from(`${parts[0]}.${parts[1]}`), signature: b64url(parts[2]!) };
}

const NOT = (why: string) => check("not_checked", "prerequisite_failed", why);
const sha256hex = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

/** Verify an NRAS attestation result offline. Never throws on malformed input. */
export function verifyNrasResult(result: unknown, o: VerifyNvidiaOptions): NvidiaVerification {
  const now = o.now ?? Date.now();
  const skew = o.clockSkewMs ?? 60_000;
  let overall: Jwt;
  const gpuTokens: Array<[string, Jwt]> = [];
  try {
    const arr = typeof result === "string" ? JSON.parse(result) : result;
    if (!Array.isArray(arr) || !Array.isArray(arr[0]) || arr[0][0] !== "JWT") throw new Error('expected [["JWT", token], {…}]');
    overall = parseJwt(arr[0][1]);
    const detached = arr[1] && typeof arr[1] === "object" ? (arr[1] as Record<string, unknown>) : {};
    for (const [id, t] of Object.entries(detached)) gpuTokens.push([id, parseJwt(t)]);
    if (gpuTokens.length === 0) throw new Error("no per-GPU detached tokens");
  } catch (err) {
    const c = check("fail", "malformed", `not an NRAS unified EAT result: ${(err as Error).message}`);
    return done({ format: c, key_chain: NOT("format"), signatures: NOT("format"), freshness: NOT("format"), nonce: NOT("format"), overall_result: NOT("format"), submods: NOT("format"), gpu_claims: NOT("format"), cpu_binding: NOT("format") }, []);
  }
  const all: Array<[string, Jwt]> = [["overall", overall], ...gpuTokens];

  /* format + key chain + signatures */
  const anchors = (o.anchors ?? NRAS_ANCHORS).map((a) => ({ name: a.name, cert: new X509Certificate(a.der), fp: a.sha256 }));
  const formatProblems: string[] = [];
  const chainProblems: string[] = [];
  const sigProblems: string[] = [];
  const anchorNames = new Set<string>();
  for (const [id, t] of all) {
    if (t.header["alg"] !== "ES384") { formatProblems.push(`${id}: alg ${String(t.header["alg"])} (expected ES384)`); continue; }
    const kid = t.header["kid"];
    const jwk = o.jwks.keys.find((k) => k.kid === kid);
    if (!jwk) { formatProblems.push(`${id}: kid ${String(kid)} is not in the JWKS snapshot`); continue; }
    if (!jwk.x5c?.length) { chainProblems.push(`${id}: JWK has no x5c chain`); continue; }
    let leaf: X509Certificate;
    try { leaf = new X509Certificate(Buffer.from(jwk.x5c[0]!, "base64")); } catch { chainProblems.push(`${id}: x5c leaf does not parse`); continue; }
    const supplied = jwk.x5c.slice(1).map((c) => { try { return new X509Certificate(Buffer.from(c, "base64")); } catch { return undefined; } }).filter((c): c is X509Certificate => !!c);
    const issuer = [...anchors.map((a) => a.cert), ...supplied].find((c) => leaf.checkIssued(c) && leaf.verify(c.publicKey));
    const anchor = issuer && anchors.find((a) => a.cert.fingerprint256 === issuer.fingerprint256);
    const iat = typeof t.payload["iat"] === "number" ? (t.payload["iat"] as number) * 1000 : now;
    if (!issuer) chainProblems.push(`${id}: signing certificate is not issued by its x5c intermediate`);
    else if (!anchor) chainProblems.push(`${id}: intermediate "${issuer.subject.split("\n").find((l) => l.startsWith("CN="))?.slice(3)}" is not a pinned NRAS anchor`);
    else if (iat < Date.parse(leaf.validFrom) - skew || iat > Date.parse(leaf.validTo) + skew) chainProblems.push(`${id}: token issued outside the signing certificate's validity`);
    else anchorNames.add(anchor.name);
    // The JWK key must be the certificate key.
    const certJwk = leaf.publicKey.export({ format: "jwk" }) as { x?: string; y?: string; crv?: string };
    if (jwk.x && (certJwk.x !== jwk.x || certJwk.y !== jwk.y)) { chainProblems.push(`${id}: JWK x/y differ from the x5c certificate key`); continue; }
    let ok = false;
    try { ok = cryptoVerify("sha384", t.signingInput, { key: createPublicKey(leaf.publicKey.export({ type: "spki", format: "pem" })), dsaEncoding: "ieee-p1363" }, t.signature); } catch { ok = false; }
    if (!ok) sigProblems.push(`${id}: ES384 signature invalid`);
  }
  const format = formatProblems.length ? check("fail", formatProblems.some((p) => p.includes("alg")) ? "unsupported_algorithm" : "unknown_key", formatProblems.join("; ")) : check("pass", "well_formed", `overall + ${gpuTokens.length} GPU token(s), ES384`);
  const key_chain = formatProblems.length ? NOT("format") : chainProblems.length ? check("fail", chainProblems.some((p) => p.includes("pinned")) ? "untrusted_root" : "chain_invalid", chainProblems.join("; ")) : check("pass", "chain_valid", `signing certificates chain to ${[...anchorNames].join(", ")}`);
  const signatures = formatProblems.length || chainProblems.length ? NOT("key chain") : sigProblems.length ? check("fail", "signature_invalid", sigProblems.join("; ")) : check("pass", "signature_valid", `${all.length} token(s) verify`);

  /* freshness */
  const expired = all.filter(([, t]) => typeof t.payload["exp"] !== "number" || now > (t.payload["exp"] as number) * 1000 + skew).map(([id]) => id);
  const future = all.filter(([, t]) => typeof t.payload["iat"] === "number" && (t.payload["iat"] as number) * 1000 > now + skew).map(([id]) => id);
  const freshness = future.length ? check("fail", "issued_in_future", `iat is in the future: ${future.join(", ")}`)
    : expired.length ? check("unknown", "attestation_stale", `expired or no exp: ${expired.join(", ")}`) : check("pass", "fresh", "every token is within its validity window");

  /* nonce */
  const nonces = all.map(([id, t]) => [id, String(t.payload["eat_nonce"] ?? "")] as const);
  const nonce = o.expectedNonce === undefined
    ? check("unknown", "no_nonce_policy", "no expected nonce supplied: replay of an old result cannot be excluded")
    : nonces.every(([, n]) => n.toLowerCase() === o.expectedNonce!.toLowerCase()) ? check("pass", "nonce_matches", o.expectedNonce) : check("fail", "nonce_mismatch", nonces.filter(([, n]) => n.toLowerCase() !== o.expectedNonce!.toLowerCase()).map(([id, n]) => `${id}: ${n || "(none)"}`).join("; "));

  /* overall result + issuer */
  const iss = o.issuer ?? NRAS_ISSUER;
  const overall_result = overall.payload["iss"] !== iss
    ? check("fail", "wrong_issuer", `iss ${String(overall.payload["iss"])} ≠ ${iss}`)
    : overall.payload["x-nvidia-overall-att-result"] === true ? check("pass", "attestation_passed", "x-nvidia-overall-att-result = true") : check("fail", "attestation_failed", `x-nvidia-overall-att-result = ${JSON.stringify(overall.payload["x-nvidia-overall-att-result"])}`);

  /* submods */
  const submods = overall.payload["submods"] as Record<string, unknown> | undefined;
  const subProblems: string[] = [];
  let method = "";
  for (const [id, t] of gpuTokens) {
    const entry = submods?.[id] as unknown;
    const digest = Array.isArray(entry) && entry[0] === "DIGEST" && Array.isArray(entry[1]) && entry[1][0] === "SHA256" ? String(entry[1][1]).toLowerCase() : undefined;
    if (!digest) { subProblems.push(`${id}: no SHA256 DIGEST entry in submods`); continue; }
    if (digest === sha256hex(t.raw)) method ||= "SHA-256 of the detached token";
    else if (digest === sha256hex(t.payloadBytes)) method ||= "SHA-256 of the detached claims";
    else subProblems.push(`${id}: submods digest does not match the detached token`);
  }
  if (o.expectedGpuCount !== undefined && gpuTokens.length !== o.expectedGpuCount) subProblems.push(`expected ${o.expectedGpuCount} GPU(s), got ${gpuTokens.length}`);
  const submodsCheck = subProblems.length ? check("fail", "submod_unbound", subProblems.join("; ")) : check("pass", "submods_bound", `every GPU token is bound into the overall token (${method})`);

  /* GPU claims */
  const gpuProblems: string[] = [];
  const REQUIRED_TRUE = ["x-nvidia-gpu-arch-check", "x-nvidia-gpu-attestation-report-signature-verified", "x-nvidia-gpu-attestation-report-nonce-match"];
  for (const [id, t] of gpuTokens) {
    if (t.payload["measres"] !== "success") gpuProblems.push(`${id}: measres ${JSON.stringify(t.payload["measres"])}`);
    for (const c of REQUIRED_TRUE) if (c in t.payload && t.payload[c] !== true) gpuProblems.push(`${id}: ${c} = ${JSON.stringify(t.payload[c])}`);
    if ("dbgstat" in t.payload && t.payload["dbgstat"] !== "disabled") gpuProblems.push(`${id}: dbgstat ${JSON.stringify(t.payload["dbgstat"])}`);
    if ("secboot" in t.payload && t.payload["secboot"] !== true) gpuProblems.push(`${id}: secboot ${JSON.stringify(t.payload["secboot"])}`);
  }
  const gpu_claims = gpuProblems.length ? check("fail", "gpu_appraisal_failed", gpuProblems.join("; ")) : check("pass", "gpu_appraisal_passed", `${gpuTokens.length} GPU(s): measurements match NVIDIA's reference values`);

  const cpu_binding = o.cpuReportData === undefined
    ? check("not_applicable", "no_cpu_report", "not bound to a CPU TEE report")
    : o.expectedNonce !== undefined && o.expectedNonce.toLowerCase() === cpuBindingNonce(o.cpuReportData) ? check("pass", "cpu_bound", "the NRAS nonce is the CooL binding nonce of the CPU report") : check("fail", "cpu_binding_mismatch", "the NRAS nonce does not derive from the CPU report's REPORT_DATA");

  const gpus = gpuTokens.map(([id, t]) => ({
    id,
    ...(typeof t.payload["hwmodel"] === "string" ? { hwmodel: t.payload["hwmodel"] as string } : {}),
    ...(typeof t.payload["x-nvidia-gpu-driver-version"] === "string" ? { driver_version: t.payload["x-nvidia-gpu-driver-version"] as string } : {}),
    ...(typeof t.payload["x-nvidia-gpu-vbios-version"] === "string" ? { vbios_version: t.payload["x-nvidia-gpu-vbios-version"] as string } : {}),
    ...(typeof t.payload["ueid"] === "string" ? { ueid: t.payload["ueid"] as string } : {}),
  }));
  const iat = typeof overall.payload["iat"] === "number" ? new Date((overall.payload["iat"] as number) * 1000).toISOString() : undefined;
  return done({ format, key_chain, signatures, freshness, nonce, overall_result, submods: submodsCheck, gpu_claims, cpu_binding }, gpus, iat);
}

function done(checks: NvidiaChecks, gpus: NvidiaVerification["gpus"], issued_at?: string): NvidiaVerification {
  const { outcome, reasons } = classifyOutcome(checks as unknown as Record<string, Check>, Object.keys(checks));
  return { outcome, checks, reasons, gpus, ...(issued_at ? { issued_at } : {}), limitations: LIMITS };
}
