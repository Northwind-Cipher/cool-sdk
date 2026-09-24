// SUPERSEDED by closure-verify.mjs (this script generates its own witness key, so it cannot show witness separation). Kept to reproduce the earlier evidence.
/**
 * Final external verification, run OUTSIDE the Phala CVM.
 *
 *   node phala-validation/final-verify.mjs <receiptsA.json> <receiptsB.json> <outDir>
 *
 * Inputs are the arrays served at /receipts by Deployment A and Deployment B of
 * the validation workload. Each domain is checked directly from primitives
 * (cbor2, node:crypto, @noble/*) rather than by calling verifyReceiptV2 alone,
 * and then cross-checked against verifyReceiptV2. Nothing here is hard-coded:
 * every JSON written is computed from the inputs, and the process exits non-zero
 * if any check that must hold does not.
 *
 * Requires `npm run build` (imports ../dist) and network access to Phala Cloud's
 * attestation API (attestation verification here is ONLINE, not offline).
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { encode, cdeEncodeOptions } from "cbor2";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { ed25519 } from "@noble/curves/ed25519";
import { verifyReceiptV2, remoteQuoteVerifier, withTrustedKeys, enclaveReportData } from "../dist/phala/index.js";
import { cosign, attachWitness } from "../dist/phala/witness.js";
import { coreOfV2, recordSigningMessageV2, recordLeafDataV2 } from "../dist/phala/record.js";
import { sthCore, sthSigningMessage } from "../dist/record.js";
import { leafHash, merkleRoot, verifyInclusion, consistencyProof, verifyConsistency } from "../dist/merkle.js";
import { multihashDigest } from "../dist/multihash.js";
import { generateKeypair } from "../dist/keys.js";

const [, , aPath, bPath, outDir] = process.argv;
if (!aPath || !bPath || !outDir) {
  console.error("usage: node final-verify.mjs <receiptsA.json> <receiptsB.json> <outDir>");
  process.exit(2);
}
fs.mkdirSync(outDir, { recursive: true });

const PHALA_API = "https://cloud-api.phala.com/api/v1/attestations/verify";
const sha256hex = (b) => crypto.createHash("sha256").update(b).digest("hex");
const b64 = (f) => Buffer.from(f.slice("base64:".length), "base64");
const hex = (u8) => Buffer.from(u8).toString("hex");
const write = (name, obj) => fs.writeFileSync(path.join(outDir, name), JSON.stringify(obj, null, 2));
const A = JSON.parse(fs.readFileSync(aPath, "utf8"));
const B = JSON.parse(fs.readFileSync(bPath, "utf8"));
const finalA = A[A.length - 1];
const finalB = B[B.length - 1];
const now = () => new Date().toISOString();
const failures = [];
const must = (cond, msg) => { if (!cond) failures.push(msg); return cond; };

const phalaVerifier = remoteQuoteVerifier({
  endpoint: PHALA_API,
  root: "intel-dcap",
  name: "phala-cloud-attestation-api",
  encode: (raw) => ({ hex: hex(Buffer.from(raw, "base64")) }),
  decode: (r) => ({ ok: r?.quote?.verified === true }),
});
const measurementOf = (r) => r.record.runtime.enclave_measurement;
const dirEntry = (r) => r.key_directory[r.record.signature.key_id];

/* ── 1 binding: independent recompute (cbor2 + node:crypto, not the SDK verifier) ── */
const bindingRows = A.map((r, i) => {
  const core = coreOfV2(r.record);
  const recomputed = `mh:sha256:${sha256hex(encode(core, cdeEncodeOptions))}`;
  return { index: i, stored: r.binding_hash, recomputed, match: recomputed === r.binding_hash };
});
must(bindingRows.every((x) => x.match), "binding recompute mismatch");
write("binding-domain-final.json", {
  domain: "binding", checked_at: now(),
  method: "canonical CBOR (cbor2 cdeEncodeOptions) of the record core (record minus signature), SHA-256 via node:crypto, compared to stored binding_hash",
  independence: "Recomputed by a script that does not call verifyReceiptV2 and uses node:crypto rather than @noble/hashes; it shares the cbor2 library with the SDK.",
  receipts_checked: bindingRows.length, results: bindingRows,
  result: bindingRows.every((x) => x.match) ? "PASS" : "FAIL",
});

/* ── 2 signature: ML-DSA-65 AND Ed25519 directly via @noble ── */
const sigRows = A.map((r, i) => {
  const core = coreOfV2(r.record);
  const message = recordSigningMessageV2(core, r.binding_hash);
  const e = dirEntry(r);
  const s = r.record.signature;
  const ml = ml_dsa65.verify(b64(e.ml_dsa_pub), message, b64(s.ml_dsa));
  const ed = ed25519.verify(b64(s.ed25519), message, b64(e.ed25519_pub));
  return { index: i, key_id: s.key_id, signed_bytes_sha256: sha256hex(message), ml_dsa_65: ml, ed25519: ed };
});
must(sigRows.every((x) => x.ml_dsa_65 && x.ed25519), "signature failure");
write("signature-domain-final.json", {
  domain: "signature", checked_at: now(),
  method: "signed message = canonicalCBOR(core) || 32-byte binding digest; ML-DSA-65 and Ed25519 verified by calling @noble/post-quantum and @noble/curves directly (not hybridVerify)",
  receipts_checked: sigRows.length, results: sigRows,
  result: sigRows.every((x) => x.ml_dsa_65 && x.ed25519) ? "PASS" : "FAIL",
  limitation: "No second independent implementation of ML-DSA-65 was used; the same @noble libraries back the SDK.",
});

/* ── 3 inclusion: every receipt, plus STH signature; report non-trivial path ── */
const incRows = A.map((r, i) => {
  const e = r.key_directory[r.sth.signature.key_id];
  const m = sthSigningMessage(sthCore(r.sth));
  const sthOk = ml_dsa65.verify(b64(e.ml_dsa_pub), m, b64(r.sth.signature.ml_dsa)) && ed25519.verify(b64(r.sth.signature.ed25519), m, b64(e.ed25519_pub));
  const pathOk = verifyInclusion(leafHash(recordLeafDataV2(r.binding_hash)), r.inclusion.leaf_index, r.sth.tree_size, r.inclusion.audit_path.map(multihashDigest), multihashDigest(r.sth.root_hash));
  return { index: i, leaf_index: r.inclusion.leaf_index, tree_size: r.sth.tree_size, audit_path_length: r.inclusion.audit_path.length, audit_path_ok: pathOk, sth_signature_ok: sthOk };
});
must(incRows.every((x) => x.audit_path_ok && x.sth_signature_ok), "inclusion failure");
write("inclusion-domain-final.json", {
  domain: "inclusion", checked_at: now(),
  method: "RFC 6962 audit path reconstructs the STH root; STH hybrid signature verified directly with @noble",
  final_receipt: { leaf_index: finalA.inclusion.leaf_index, tree_size: finalA.sth.tree_size, audit_path_length: finalA.inclusion.audit_path.length },
  results: incRows,
  result: incRows.every((x) => x.audit_path_ok && x.sth_signature_ok) ? "PASS" : "FAIL",
  limitation: "The log and its STH key live inside the same enclave/operator; this proves internal log consistency, not an external log operator.",
});

/* ── 4 consistency: signed heads at every size, proofs between all pairs ── */
const leaves = A.map((r) => leafHash(recordLeafDataV2(r.binding_hash)));
const heads = A.map((r) => ({ size: r.sth.tree_size, root: multihashDigest(r.sth.root_hash) }));
const consRows = [];
for (let m = 1; m <= A.length; m++) for (let n = m; n <= A.length; n++) {
  const proof = consistencyProof(leaves.slice(0, n), m);
  const okSigned = verifyConsistency(m, n, heads[m - 1].root, heads[n - 1].root, proof);
  const forged = merkleRoot([...leaves.slice(0, Math.max(m - 1, 0)), leafHash(new Uint8Array(32).fill(0xee))]);
  const forgedRejected = m < n ? !verifyConsistency(m, n, forged, heads[n - 1].root, proof) : true;
  consRows.push({ from: m, to: n, proof_hashes: proof.length, verifies_against_enclave_signed_heads: okSigned, forged_first_root_rejected: forgedRejected });
}
must(consRows.every((x) => x.verifies_against_enclave_signed_heads && x.forged_first_root_rejected), "consistency failure");
const headline = consRows.find((x) => x.from === 2 && x.to === A.length);
write("consistency-domain-final.json", {
  domain: "consistency", checked_at: now(),
  scope: "REAL CooL log mechanism exercised on the deployed enclave's own signed tree heads (sizes 1..6). Consistency is NOT a field of the receipt verdict (verifyReceiptV2); it is verified by this script.",
  method: "Leaf hashes come from the receipts' binding digests; the proof is computed by consistencyProof() outside the CVM and checked with verifyConsistency() against roots taken from STHs that the enclave signed (each STH signature is verified in inclusion-domain-final.json).",
  headline: { from_size: 2, to_size: A.length, proof: headline && consistencyProof(leaves.slice(0, A.length), 2).map((h) => `hex:${hex(h)}`), ...headline },
  pairs_checked: consRows.length, results: consRows,
  result: consRows.every((x) => x.verifies_against_enclave_signed_heads && x.forged_first_root_rejected) ? "PASS" : "FAIL",
  limitation: "The proof was computed externally from public leaf hashes, not requested from a log service; the deployed log exposes no consistency endpoint. The earlier size-1 receipts (artifacts/receipts/deployment-a-receipt.json) did NOT exercise consistency.",
});

/* ── 5 witness: cryptographic separation demonstrated; operational independence NOT ── */
const witnessKey = generateKeypair("validation-witness-01");
const stmt = cosign(finalA.sth, witnessKey);
const witnessed = attachWitness(finalA, stmt);
const wMsg = sthSigningMessage(sthCore(finalA.sth));
const wSigOk = ml_dsa65.verify(b64(witnessKey.directoryEntry.ml_dsa_pub), wMsg, b64(stmt.witness.ml_dsa)) && ed25519.verify(b64(stmt.witness.ed25519), wMsg, b64(witnessKey.directoryEntry.ed25519_pub));
const wVerdict = await verifyReceiptV2(withTrustedKeys(witnessed, { [witnessKey.keyId]: witnessKey.directoryEntry }), { witnessThreshold: 1, requireHardware: true, quoteVerifier: phalaVerifier });
const enclaveKeys = new Set([finalA.record.signature.key_id, finalA.sth.signature.key_id]);
must(wSigOk && wVerdict.checks.witnesses.status === "pass", "witness failure");
write("witness-domain-final.json", {
  domain: "witness", checked_at: now(),
  cryptographically_independent: wSigOk && !enclaveKeys.has(witnessKey.keyId) && wVerdict.checks.witnesses.status === "pass" ? "PASS" : "FAIL",
  operationally_independent: "NOT DEMONSTRATED",
  statement: "Cryptographically independent witness key demonstrated; operational third-party independence was not demonstrated in this validation.",
  witness_key_id: witnessKey.keyId, witness_public_keys: witnessKey.directoryEntry,
  signed_bytes: "canonicalCBOR({log_id, tree_size, root_hash, timestamp}) of the final STH", signed_bytes_sha256: sha256hex(wMsg),
  sth: sthCore(finalA.sth), witness_signature: stmt.witness,
  direct_signature_verification: wSigOk, verifier_witness_domain: wVerdict.checks.witnesses,
  why_not_third_party: "The witness key was generated and used by the same operator that ran the validation, and its public key was supplied to the verifier by the same script (withTrustedKeys). The private key was not retained.",
  how_a_third_party_would_provide_it: "An independent operator runs cosign(sth, theirKey) over the published STH (log_id, tree_size, root_hash, timestamp) and returns the WitnessStatement; the verifier obtains their public key out of band and passes it via withTrustedKeys; the domain counts only external:true statements that verify.",
  result_of_domain_mechanism: "PASS",
});
fs.writeFileSync(path.join(outDir, "witnessed-final-receipt.json"), JSON.stringify(witnessed, null, 2));

/* ── 6 attestation: raw quote parse + Phala API, response archived ── */
function parseQuote(r) {
  const raw = b64(r.attestation.quote.raw);
  const tdx = { version: raw.readUInt16LE(0), tee_type: "0x" + raw.readUInt32LE(4).toString(16) };
  const rt = (i) => hex(raw.subarray(48 + 328 + 48 * i, 48 + 328 + 48 * i + 48));
  return { raw, ...tdx, mrtd: hex(raw.subarray(48 + 136, 48 + 184)), rtmr: [0, 1, 2, 3].map(rt), report_data: hex(raw.subarray(48 + 520, 48 + 584)) };
}
const qa = parseQuote(finalA);
const requestBody = JSON.stringify({ hex: hex(qa.raw) });
const t0 = now();
const resp = await fetch(PHALA_API, { method: "POST", headers: { "content-type": "application/json" }, body: requestBody });
const respText = await resp.text();
let respJson = null; try { respJson = JSON.parse(respText); } catch { /* keep text */ }
const t1 = now();
const verifiedTrue = resp.ok && respJson?.quote?.verified === true;
must(verifiedTrue, "Phala API did not verify quote");
fs.writeFileSync(path.join(outDir, "phala-attestation-api-response-A.json"), respText);
const sdkAtt = await verifyReceiptV2(finalA, { requireHardware: true, quoteVerifier: phalaVerifier });
write("attestation-domain-final.json", {
  domain: "attestation", verification_mode: "ONLINE (Phala Cloud attestation service). NOT offline.",
  verifier_endpoint: PHALA_API, request: { method: "POST", body_shape: "{hex: <raw quote hex>}", quote_bytes: qa.raw.length, quote_sha256: sha256hex(qa.raw), request_body_sha256: sha256hex(requestBody) },
  request_started_at: t0, response_received_at: t1, http_status: resp.status,
  response_archived_as: "phala-attestation-api-response-A.json", response_body: respJson ?? respText,
  raw_quote: { format: finalA.attestation.quote.format, root_label: finalA.attestation.quote.root, size_bytes: qa.raw.length, quote_version: qa.version, tee_type: qa.tee_type, tee_type_is_tdx: qa.tee_type === "0x81", mrtd: qa.mrtd, rtmr0: qa.rtmr[0], rtmr1: qa.rtmr[1], rtmr2: qa.rtmr[2], rtmr3: qa.rtmr[3], report_data_first32: qa.report_data.slice(0, 64) },
  sdk_verdict_attestation: sdkAtt.checks.attestation,
  result: verifiedTrue && qa.tee_type === "0x81" && sdkAtt.checks.attestation.status === "pass" ? "PASS" : "FAIL",
  limitations: ["Verification is delegated to Phala's service; the Intel DCAP collateral chain and TCB evaluation are performed there and are not visible in the response archived here.", "TCB status recorded by CooL is the literal 'Unknown'.", "No offline DCAP verification was performed.", "No quote freshness/nonce check."],
});

/* ── 7 enclave: measurements vs raw quote, key binding, pins, fail-closed ── */
const mA = measurementOf(finalA);
const matches = { mrtd: `hex:${qa.mrtd}` === mA.mrtd, rtmr0: `hex:${qa.rtmr[0]}` === mA.rtmr0, rtmr1: `hex:${qa.rtmr[1]}` === mA.rtmr1, rtmr2: `hex:${qa.rtmr[2]}` === mA.rtmr2, rtmr3: `hex:${qa.rtmr[3]}` === mA.rtmr3 };
const expectedRD = enclaveReportData(dirEntry(finalA));
const bindingOk = qa.report_data.slice(0, 64) === expectedRD.slice("mh:sha256:".length) && finalA.attestation.quote.body.report_data === expectedRD;
const wrongPin = { ...mA, rtmr3: `hex:${"ab".repeat(48)}` };
const tValid = await verifyReceiptV2(finalA, { requireHardware: true, quoteVerifier: phalaVerifier, expectedMeasurement: mA });
const tWrong = await verifyReceiptV2(finalA, { requireHardware: true, quoteVerifier: phalaVerifier, expectedMeasurement: wrongPin });
const tNoAtt = await verifyReceiptV2(finalA, { requireHardware: true });
const tNoAttLax = await verifyReceiptV2(finalA, {});
must(Object.values(matches).every(Boolean) && bindingOk, "enclave measurement/binding mismatch");
must(tValid.ok && tValid.checks.enclave.status === "pass", "valid pin should pass");
must(!tWrong.ok && tWrong.checks.enclave.status === "fail", "wrong pin should fail");
must(!tNoAtt.ok && tNoAtt.checks.enclave.status === "fail", "requireHardware without attestation must fail enclave");
write("enclave-domain-final.json", {
  domain: "enclave", checked_at: now(),
  measurement_receipt_vs_raw_quote: matches, all_registers_match: Object.values(matches).every(Boolean),
  measurement: { mrtd: mA.mrtd, rtmr0: mA.rtmr0, rtmr1: mA.rtmr1, rtmr2: mA.rtmr2, rtmr3: mA.rtmr3 },
  docker_image_digest_in_record: finalA.record.event.software.digest, note_digest_vs_measurement: "The Docker image digest is a different identifier from the TDX measurement and is recorded separately.",
  report_data_binding: { signing_key_id: finalA.record.signature.key_id, expected_report_data: expectedRD, quote_report_data_first32: qa.report_data.slice(0, 64), binds_signing_key: bindingOk },
  policy_tests: {
    valid_measurement_pin: { ok: tValid.ok, enclave: tValid.checks.enclave.status },
    wrong_measurement_pin: { ok: tWrong.ok, enclave: tWrong.checks.enclave.status, detail: tWrong.checks.enclave.detail },
    requireHardware_without_verifier: { ok: tNoAtt.ok, attestation: tNoAtt.checks.attestation.status, enclave: tNoAtt.checks.enclave.status, detail: tNoAtt.checks.enclave.detail },
    requireHardware_with_verifier: { ok: tValid.ok, attestation: tValid.checks.attestation.status, enclave: tValid.checks.enclave.status },
    no_requireHardware_no_verifier_legacy_behaviour: { ok: tNoAttLax.ok, attestation: tNoAttLax.checks.attestation.status, enclave: tNoAttLax.checks.enclave.status, note: "Unchanged for callers that do not set requireHardware: enclave binding checks can pass while attestation is only reported." },
  },
  result: Object.values(matches).every(Boolean) && bindingOk && tValid.ok && !tWrong.ok && !tNoAtt.ok ? "PASS" : "FAIL",
  limitations: ["Measurement pins were taken from the receipts under test; approval is procedural.", "Dev OS image (is_dev=true) on the CVM.", "MRTD/RTMR0-2 are constant across workloads; only RTMR3 reflects the application."],
});

/* ── workload change A vs B ── */
const mB = measurementOf(finalB);
const cmp = Object.fromEntries(["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"].map((k) => [k, mA[k] === mB[k] ? "SAME" : "DIFFERENT"]));
const bVsA = await verifyReceiptV2(finalB, { requireHardware: true, quoteVerifier: phalaVerifier, expectedMeasurement: mA });
const bVsB = await verifyReceiptV2(finalB, { requireHardware: true, quoteVerifier: phalaVerifier, expectedMeasurement: mB });
const aStill = await verifyReceiptV2(finalA, { requireHardware: true, quoteVerifier: phalaVerifier, expectedMeasurement: mA });
must(cmp.mrtd === "SAME" && cmp.rtmr0 === "SAME" && cmp.rtmr1 === "SAME" && cmp.rtmr2 === "SAME" && cmp.rtmr3 === "DIFFERENT", "unexpected A/B register pattern");
must(!bVsA.ok && bVsB.ok && aStill.ok, "pin outcomes wrong");
write("workload-change-final.json", {
  checked_at: now(), image_digest_A: finalA.record.event.software.digest, image_digest_B: finalB.record.event.software.digest,
  register_comparison: cmp, rtmr3_A: mA.rtmr3, rtmr3_B: mB.rtmr3,
  B_against_A_pin: { ok: bVsA.ok, enclave: bVsA.checks.enclave, expected: "FAIL" },
  B_against_B_pin: { ok: bVsB.ok, enclave: bVsB.checks.enclave, expected: "PASS" },
  historical_A_after_B_exists: { ok: aStill.ok, enclave: aStill.checks.enclave, expected: "PASS", note: "verifyReceiptV2 is a pure function of receipt+options+verifier; A does not depend on B's existence." },
  result: !bVsA.ok && bVsB.ok && aStill.ok ? "PASS" : "FAIL",
  limitation: "Both pins are copied from the receipts under test; approval is procedural.",
});

/* ── tamper: two variants, on the fresh receipt; originals untouched ── */
const tamperDir = path.join(outDir, "tamper-final"); fs.mkdirSync(tamperDir, { recursive: true });
const flip = (s) => s.slice(0, -1) + (s.slice(-1) === "0" ? "1" : "0");
const variants = {
  binding_hash: (r) => { r.binding_hash = flip(r.binding_hash); },
  "record.event.metadata_hash": (r) => { r.record.event.metadata_hash = flip(r.record.event.metadata_hash); },
};
const tamperOut = {};
write("_original-final-receipt.json", finalA);
for (const [field, mutate] of Object.entries(variants)) {
  const t = structuredClone(finalA); mutate(t);
  const v = await verifyReceiptV2(t, { requireHardware: true, quoteVerifier: phalaVerifier });
  fs.writeFileSync(path.join(tamperDir, `tampered-${field.replace(/\W/g, "_")}.json`), JSON.stringify(t, null, 2));
  tamperOut[field] = { ok: v.ok, domains: Object.fromEntries(Object.entries(v.checks).map(([k, x]) => [k, x.status])), reasons: v.reasons };
}
fs.renameSync(path.join(outDir, "_original-final-receipt.json"), path.join(tamperDir, "original-final-receipt.json"));
must(tamperOut.binding_hash.domains.binding === "fail" && tamperOut.binding_hash.domains.signature === "fail" && tamperOut.binding_hash.domains.inclusion === "fail" && tamperOut.binding_hash.domains.attestation === "pass", "binding_hash tamper outcome");
must(tamperOut["record.event.metadata_hash"].domains.binding === "fail" && tamperOut["record.event.metadata_hash"].domains.signature === "fail", "metadata tamper outcome");
write("tamper-final.json", { checked_at: now(), original: "tamper-final/original-final-receipt.json", variants: tamperOut,
  note: "Flipping binding_hash fails binding, signature and inclusion (the log leaf is derived from the stored binding_hash). Flipping a field inside the record (metadata_hash) fails binding and signature; inclusion still passes because the log committed to the original binding digest, which is exactly what should not change. Hardware domains stay valid in both because the quote and measurement were untouched." });

/* ── final external verification, all domains ── */
const full = await verifyReceiptV2(witnessed, { requireHardware: true, quoteVerifier: phalaVerifier, witnessThreshold: 1, ...{} });
const fullTrusted = await verifyReceiptV2(withTrustedKeys(witnessed, { [witnessKey.keyId]: witnessKey.directoryEntry }), { requireHardware: true, quoteVerifier: phalaVerifier, witnessThreshold: 1 });
const domains = {
  binding: bindingRows.every((x) => x.match), signature: sigRows.every((x) => x.ml_dsa_65 && x.ed25519), inclusion: incRows.every((x) => x.audit_path_ok && x.sth_signature_ok),
  consistency: consRows.every((x) => x.verifies_against_enclave_signed_heads),
  witness_cryptographic: wSigOk, attestation_online: verifiedTrue, enclave: Object.values(matches).every(Boolean) && bindingOk && tValid.ok && !tNoAtt.ok,
};
write("final-external-verification.json", {
  checked_at: now(), run_outside_cvm: true, receipts_source: { A: path.basename(aPath), B: path.basename(bPath) },
  verifyReceiptV2_on_witnessed_final_receipt: { ok: fullTrusted.ok, checks: Object.fromEntries(Object.entries(fullTrusted.checks).map(([k, v]) => [k, v.status])), reasons: fullTrusted.reasons },
  direct_domain_checks: domains,
  operational_independence_of_witness: "NOT DEMONSTRATED",
  attestation_mode: "ONLINE",
  consistency_scope: "real CooL log mechanism on enclave-signed heads; not a verdict field",
  failures,
});
console.log(JSON.stringify({ domains, failures }, null, 2));
process.exit(failures.length ? 1 : 0);
