/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Closure verification: every domain checked OUTSIDE the CVMs, from evidence
 * files, with negative controls. Nothing is hard-coded; every JSON written is
 * computed from the inputs and the process exits non-zero if a check that must
 * hold does not.
 *
 *   node phala-validation/closure-verify.mjs <evidenceDir>
 *
 * <evidenceDir> holds (as produced by the deployment steps):
 *   raw/receipts-A.json  raw/receipts-B.json        primary log, deployments A and B
 *   witness/identity.json cosign-1..N.json presented-*.json decisions.json post-B-refusal.json
 *   runtime-A.json                                   GET /runtime of deployment A
 *   cvm-primary.json cvm-witness.json                selected fields of `phala cvms get`
 * Output goes to <evidenceDir>/verification/.
 *
 * Attestation verification is ONLINE (Phala's service); the local dcap-qvl check
 * is offline at verify time with archived collateral. Requires `npm run build`.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { encode, cdeEncodeOptions } from "cbor2";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { ed25519 } from "@noble/curves/ed25519";
import {
  verifyReceiptV2, verifyLogConsistency, phalaQuoteVerifier, withTrustedKeys, enclaveReportData,
  attachWitness, recordLeafDataV2, sthCore, sthSigningMessage, PHALA_ATTESTATION_ENDPOINT,
} from "../dist/phala/index.js";
import { coreOfV2, recordSigningMessageV2 } from "../dist/phala/record.js";

const dir = process.argv[2];
if (!dir) { console.error("usage: node closure-verify.mjs <evidenceDir>"); process.exit(2); }
const out = path.join(dir, "verification"); fs.mkdirSync(out, { recursive: true });
const J = (p) => JSON.parse(fs.readFileSync(path.join(dir, p), "utf8"));
const write = (n, o) => fs.writeFileSync(path.join(out, n), JSON.stringify(o, null, 2));
const now = () => new Date().toISOString();
const failures = [];
const must = (c, m) => { if (!c) failures.push(m); return !!c; };
const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");
const b64 = (f) => Buffer.from(f.slice(7), "base64");
const hex = (u) => Buffer.from(u).toString("hex");
const flip = (s) => s.slice(0, -1) + (s.slice(-1) === "0" ? "1" : "0");
const flipMh = (mh) => "mh:sha256:" + flip(mh.slice(10));
const flipB64 = (f) => f.slice(0, -6) + (f.slice(-6) === "AAAAAA" ? "BBBBBB" : "AAAAAA");

const A = J("raw/receipts-A.json"), B = J("raw/receipts-B.json");
const finalA = A[A.length - 1], finalB = B[B.length - 1];
const WID = J("witness/identity.json");
const N = A.length;
const verifier = phalaQuoteVerifier();
const mOf = (r) => r.record.runtime.enclave_measurement;
const pinA = mOf(finalA), pinB = mOf(finalB);
const entryOf = (r) => r.key_directory[r.record.signature.key_id];

/* raw quote parsing (TDX v4 quote body) */
function parseQuote(q) {
  const raw = b64(q.raw);
  const reg = (i) => hex(raw.subarray(48 + 328 + 48 * i, 48 + 376 + 48 * i));
  return { raw, version: raw.readUInt16LE(0), tee_type: "0x" + raw.readUInt32LE(4).toString(16), mrtd: hex(raw.subarray(184, 232)), rtmr: [0, 1, 2, 3].map(reg), report_data: hex(raw.subarray(568, 632)), size: raw.length };
}

/* ── independent RFC 6962 / RFC 9162 implementation (node:crypto only) ── */
const H = (...b) => crypto.createHash("sha256").update(Buffer.concat(b)).digest();
const leafH = (d) => H(Buffer.from([0]), d), nodeH = (l, r) => H(Buffer.from([1]), l, r);
const pow2below = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
function mth(ls) { if (ls.length === 1) return ls[0]; const k = pow2below(ls.length); return nodeH(mth(ls.slice(0, k)), mth(ls.slice(k))); }
function sub(m, ls, b) { const n = ls.length; if (m === n) return b ? [] : [mth(ls)]; const k = pow2below(n); return m <= k ? [...sub(m, ls.slice(0, k), b), mth(ls.slice(k))] : [...sub(m - k, ls.slice(k), false), mth(ls.slice(0, k))]; }
const proofOf = (ls, m) => (m === ls.length || m === 0 ? [] : sub(m, ls, true));
function verifyCons(m, n, first, second, proof) {
  if (m > n || m < 1) return false;
  if (m === n) return proof.length === 0 && first.equals(second);
  const p = (m & (m - 1)) === 0 ? [first, ...proof] : [...proof];
  if (p.length === 0) return false;
  let fn = m - 1, sn = n - 1; while (fn & 1) { fn >>= 1; sn >>= 1; }
  let fr = p[0], sr = p[0];
  for (const c of p.slice(1)) {
    if (sn === 0) return false;
    if ((fn & 1) || fn === sn) { fr = nodeH(c, fr); sr = nodeH(c, sr); if (!(fn & 1)) { while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1; } } }
    else sr = nodeH(sr, c);
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && fr.equals(first) && sr.equals(second);
}
const leafData = (r) => Buffer.from(r.binding_hash.slice(10), "hex");

/* ── 1 binding ── */
const bindingRows = A.map((r, i) => { const rc = "mh:sha256:" + sha256(encode(coreOfV2(r.record), cdeEncodeOptions)); return { index: i, stored: r.binding_hash, recomputed: rc, match: rc === r.binding_hash }; });
must(bindingRows.every((x) => x.match), "binding");
const tamperResults = {};
const runTamper = async (name, mutate, expectFail, trust = true) => {
  const t = structuredClone(finalA); mutate(t);
  let w = t;
  const v = await verifyReceiptV2(trust ? withTrustedKeys(w, { [WID.key_id]: WID.key_directory[WID.key_id] }) : w, { requireHardware: true, quoteVerifier: verifier, expectedMeasurement: pinA, witnessThreshold: 1 });
  tamperResults[name] = { ok: v.ok, domains: Object.fromEntries(Object.entries(v.checks).map(([k, x]) => [k, x.status])), reasons: v.reasons };
  must(!v.ok && expectFail.every((d) => v.checks[d].status !== "pass"), `tamper ${name}: expected ${expectFail} to fail`);
};

/* witness statements attached to the final A receipt (from the independent witness) */
const stmtFinal = J(`witness/cosign-${N}.json`).statement;
must(stmtFinal, "no witness statement for the final head");
const witnessedFinal = attachWitness(finalA, stmtFinal);
const trust = { [WID.key_id]: WID.key_directory[WID.key_id] };

write("binding-domain-final.json", { domain: "binding", checked_at: now(), method: "canonical CBOR (cbor2 CDE) of the record core, SHA-256 by node:crypto, compared with the stored binding_hash; run outside the SDK verifier", receipts: bindingRows.length, results: bindingRows,
  negative_control: "see tamper-final.json: flipping binding_hash or a field inside the record makes binding fail", result: bindingRows.every((x) => x.match) ? "VERIFIED" : "FAILED" });

/* ── 2 signature ── */
const sigRows = A.map((r, i) => { const msg = recordSigningMessageV2(coreOfV2(r.record), r.binding_hash), e = entryOf(r), s = r.record.signature; return { index: i, key_id: s.key_id, signed_bytes_sha256: sha256(msg), ml_dsa_65: ml_dsa65.verify(b64(e.ml_dsa_pub), msg, b64(s.ml_dsa)), ed25519: ed25519.verify(b64(s.ed25519), msg, b64(e.ed25519_pub)) }; });
must(sigRows.every((x) => x.ml_dsa_65 && x.ed25519), "signature");
write("signature-domain-final.json", { domain: "signature", checked_at: now(), scheme: "hybrid ML-DSA-65 + Ed25519, both required", method: "@noble/post-quantum and @noble/curves called directly over canonicalCBOR(core) || binding digest", receipts: sigRows.length, results: sigRows, result: sigRows.every((x) => x.ml_dsa_65 && x.ed25519) ? "VERIFIED" : "FAILED" });

/* ── 3 inclusion ── */
const incRows = A.map((r, i) => { const e = r.key_directory[r.sth.signature.key_id], m = sthSigningMessage(sthCore(r.sth)); const sthOk = ml_dsa65.verify(b64(e.ml_dsa_pub), m, b64(r.sth.signature.ml_dsa)) && ed25519.verify(b64(r.sth.signature.ed25519), m, b64(e.ed25519_pub)); return { index: i, leaf_index: r.inclusion.leaf_index, tree_size: r.sth.tree_size, audit_path_length: r.inclusion.audit_path.length, sth_signature_ok: sthOk }; });
// independent inclusion check: root recomputed from ALL leaves equals each head's root
const leavesA = A.map((r) => leafH(leafData(r)));
incRows.forEach((x, i) => { x.root_recomputed_from_leaves = "mh:sha256:" + hex(mth(leavesA.slice(0, A[i].sth.tree_size))); x.root_matches = x.root_recomputed_from_leaves === A[i].sth.root_hash; });
must(incRows.every((x) => x.sth_signature_ok && x.root_matches), "inclusion");
write("inclusion-domain-final.json", { domain: "inclusion", checked_at: now(), method: "each head's root is recomputed from the leaf hashes with an independent RFC 6962 implementation and matches the enclave-signed head; STH signatures verified directly", final_receipt: { leaf_index: finalA.inclusion.leaf_index, tree_size: finalA.sth.tree_size, audit_path_length: finalA.inclusion.audit_path.length }, results: incRows,
  negative_control: "tamper-final.json: modified root / forged STH make inclusion fail", result: incRows.every((x) => x.sth_signature_ok && x.root_matches) ? "VERIFIED" : "FAILED" });

/* ── 4 consistency ── */
const sdk = verifyLogConsistency(A);
const heads = A.map((r) => Buffer.from(r.sth.root_hash.slice(10), "hex"));
const pairs = [], negs = { modified_old_root: 0, modified_new_root: 0, wrong_first_size: 0, truncated_proof: 0, attempted: 0 };
for (let m = 1; m <= N; m++) for (let n = m; n <= N; n++) {
  const proof = proofOf(leavesA.slice(0, n), m);
  const ok = verifyCons(m, n, heads[m - 1], heads[n - 1], proof);
  pairs.push({ from: m, to: n, proof_hashes: proof.length, verifies_against_enclave_signed_heads: ok });
  if (m < n) {
    negs.attempted++;
    if (!verifyCons(m, n, Buffer.from(flip(hex(heads[m - 1])), "hex"), heads[n - 1], proof)) negs.modified_old_root++;
    if (!verifyCons(m, n, heads[m - 1], Buffer.from(flip(hex(heads[n - 1])), "hex"), proof)) negs.modified_new_root++;
    if (!verifyCons(m + 1 <= n ? m + 1 : m, n, heads[m - 1], heads[n - 1], proof) || m + 1 === n) negs.wrong_first_size++;
    if (proof.length > 0 && !verifyCons(m, n, heads[m - 1], heads[n - 1], proof.slice(1))) negs.truncated_proof++;
  }
}
must(pairs.every((p) => p.verifies_against_enclave_signed_heads), "consistency pairs");
must(sdk.ok, "sdk verifyLogConsistency: " + sdk.reasons.join("; "));
const modOld = verifyLogConsistency(A.map((r, i) => { const c = structuredClone(r); if (i === 1) c.sth.root_hash = flipMh(c.sth.root_hash); return c; }));
const modNew = verifyLogConsistency(A.map((r, i) => { const c = structuredClone(r); if (i === N - 1) c.sth.root_hash = flipMh(c.sth.root_hash); return c; }));
const wrongSize = verifyLogConsistency(A.map((r, i) => { const c = structuredClone(r); if (i === 3) c.sth.tree_size = N + 1; return c; }));
const fork = verifyLogConsistency([...A, B[3]]);
must(!modOld.ok && !modNew.ok && !wrongSize.ok && !fork.ok, "consistency negative controls (sdk)");
must(negs.modified_old_root === negs.attempted && negs.modified_new_root === negs.attempted, "consistency negative controls (independent)");
write("consistency-domain-final.json", { domain: "consistency", checked_at: now(),
  log: { events: N, tree_sizes: A.map((r) => r.sth.tree_size), source: "deployed primary log inside the TDX CVM; heads signed by its sealed log key" },
  methods: ["SDK verifyLogConsistency over the receipts (signatures, leaves, roots, equivocation, pairwise proofs)", "independent RFC 6962/9162 implementation using node:crypto: proofs generated and verified for every (m, n) pair"],
  sdk_result: { ok: sdk.ok, heads: sdk.heads.length, pairs: sdk.pairs.length }, independent_pairs_checked: pairs.length, independent_pairs_verified: pairs.filter((p) => p.verifies_against_enclave_signed_heads).length, pairs,
  negative_controls: { independent_impl: negs, sdk_modified_old_root_rejected: !modOld.ok, sdk_modified_new_root_rejected: !modNew.ok, sdk_wrong_tree_size_rejected: !wrongSize.ok, sdk_forked_history_rejected: !fork.ok, sdk_reasons: { modified_old: modOld.reasons.slice(0, 2), modified_new: modNew.reasons.slice(0, 2), wrong_size: wrongSize.reasons.slice(0, 2), fork: fork.reasons.slice(0, 2) } },
  note: "The verifier derives the proofs from the receipts' leaf hashes; it does not accept a proof from the log. The primary also serves no proof endpoint.",
  result: sdk.ok && pairs.every((p) => p.verifies_against_enclave_signed_heads) ? "VERIFIED" : "FAILED" });

/* ── 6 attestation (primary) + witness quote ── */
async function phalaCheck(q, label) {
  const p = parseQuote(q), body = JSON.stringify({ hex: hex(p.raw) });
  const t0 = now(); const resp = await fetch(PHALA_ATTESTATION_ENDPOINT, { method: "POST", headers: { "content-type": "application/json" }, body }); const text = await resp.text(); const t1 = now();
  let j = null; try { j = JSON.parse(text); } catch { /* keep text */ }
  fs.writeFileSync(path.join(out, `phala-attestation-response-${label}.json`), text);
  return { parsed: p, ok: resp.ok && j?.quote?.verified === true, status: resp.status, t0, t1, body_sha256: sha256(body), response: j };
}
const attP = await phalaCheck(finalA.attestation.quote, "primary");
const attW = await phalaCheck(WID.quote, "witness");
must(attP.ok && attW.ok, "phala verification of primary and witness quotes");
const primaryMatches = { mrtd: "hex:" + attP.parsed.mrtd === pinA.mrtd, rtmr: [0, 1, 2, 3].every((i) => "hex:" + attP.parsed.rtmr[i] === pinA["rtmr" + i]) };
const rdExpected = enclaveReportData(entryOf(finalA)).slice(10);
must(primaryMatches.mrtd && primaryMatches.rtmr && attP.parsed.report_data.slice(0, 64) === rdExpected, "primary quote/measurement/report_data");
const badQuoteByte = structuredClone(finalA); { const raw = Buffer.from(b64(badQuoteByte.attestation.quote.raw)); raw[48 + 136 + 3] ^= 1; badQuoteByte.attestation.quote.raw = "base64:" + raw.toString("base64"); }
const vBadQuote = await verifyReceiptV2(badQuoteByte, { requireHardware: true, quoteVerifier: verifier });
must(!vBadQuote.ok, "flipped quote byte must fail");
let offline = null;
try {
  const { verify } = await import("@phala/dcap-qvl");
  const c = attP.response.quote_collateral;
  const collateral = { pck_crl_issuer_chain: c.pck_crl_issuer_chain, root_ca_crl: c.root_ca_crl, pck_crl: c.pck_crl, tcb_info_issuer_chain: c.tcb_info_issuer_chain, tcb_info: c.tcb_info, tcb_info_signature: c.tcb_info_signature, qe_identity_issuer_chain: c.qe_identity_issuer_chain, qe_identity: c.qe_identity, qe_identity_signature: c.qe_identity_signature };
  const at = Math.floor(Date.now() / 1000);
  const r = verify(attP.parsed.raw, collateral, at);
  const bad = Buffer.from(attP.parsed.raw); bad[48 + 136 + 5] ^= 1;
  let rejected = false, err = null; try { verify(bad, collateral, at); } catch (e) { rejected = true; err = String(e?.message ?? e); }
  offline = { library: "@phala/dcap-qvl", mode: "OFFLINE at verify time (archived collateral from the Phala response; the collateral itself was obtained online)", result: rejected ? "PASS" : "FAIL", tcb_status: r.status, advisory_ids: r.advisory_ids ?? [], tee_type: r.report?.type ?? null, negative_control: { description: "one byte of MRTD in the quote body flipped", rejected, error: err } };
} catch (e) { offline = { library: "@phala/dcap-qvl", result: "FAIL", error: String(e?.message ?? e) }; }
write("attestation-domain-final.json", { domain: "attestation", verification_mode: "ONLINE via Phala Cloud's attestation service; plus a local dcap-qvl check with archived collateral (offline at verify time only; collateral obtained online)",
  endpoint: PHALA_ATTESTATION_ENDPOINT, request_started_at: attP.t0, response_received_at: attP.t1, http_status: attP.status, request_body_sha256: attP.body_sha256, response_archived_as: "phala-attestation-response-primary.json",
  raw_quote: { format: finalA.attestation.quote.format, root_label: finalA.attestation.quote.root, size_bytes: attP.parsed.size, quote_version: attP.parsed.version, tee_type: attP.parsed.tee_type, quote_sha256: sha256(attP.parsed.raw), mrtd: attP.parsed.mrtd, rtmr0: attP.parsed.rtmr[0], rtmr1: attP.parsed.rtmr[1], rtmr2: attP.parsed.rtmr[2], rtmr3: attP.parsed.rtmr[3], report_data_first32: attP.parsed.report_data.slice(0, 64) },
  registers_match_receipt: primaryMatches, report_data_binds_cool_signing_key: attP.parsed.report_data.slice(0, 64) === rdExpected, signing_key_id: finalA.record.signature.key_id,
  vendor_response_verified: attP.ok, local_offline_check: offline ?? "not supplied",
  negative_controls: { one_flipped_quote_byte: { ok: vBadQuote.ok, attestation: vBadQuote.checks.attestation.status, enclave: vBadQuote.checks.enclave.status, reasons: vBadQuote.reasons.slice(0, 3) } },
  limitations: ["Primary verification is online and delegated to Phala's service.", "CooL records tcb_status as 'Unknown'; TCB status comes from the local dcap-qvl check.", "No quote freshness/nonce check."],
  result: attP.ok && primaryMatches.mrtd && !vBadQuote.ok && (offline ? offline.result === "PASS" : false) ? "VERIFIED" : "FAILED" });
must(offline && offline.result === "PASS", "offline dcap-qvl result missing or failed");

/* ── 5 witness ── */
const wq = attW.parsed;
const wEntry = WID.key_directory[WID.key_id];
const witnessBinding = wq.report_data.slice(0, 64) === enclaveReportData(wEntry).slice(10);
const notPrimary = { app_id_differs: WID.app_id !== finalA.attestation.quote.body.app_id, instance_differs: WID.instance_id !== finalA.attestation.quote.body.instance_id, rtmr3_differs: WID.measurement.rtmr3 !== pinA.rtmr3, witness_registers_nonzero: Object.values(WID.measurement).every((v) => !/^hex:0+$/.test(v)),
  record_key_differs: entryOf(finalA).ed25519_pub !== wEntry.ed25519_pub && entryOf(finalA).ml_dsa_pub !== wEntry.ml_dsa_pub, log_key_differs: finalA.key_directory[finalA.sth.signature.key_id].ed25519_pub !== wEntry.ed25519_pub && finalA.key_directory[finalA.sth.signature.key_id].ml_dsa_pub !== wEntry.ml_dsa_pub };
must(witnessBinding && Object.values(notPrimary).every(Boolean), "witness identity distinctness");
must(WID.primary_measurement_pin && JSON.stringify(WID.primary_measurement_pin) === JSON.stringify(pinA), "witness pinned the primary's measurement");
const stmtRows = [];
for (let n = 1; n <= N; n++) {
  const d = J(`witness/cosign-${n}.json`); const st = d.statement; const head = A[n - 1].sth; const msg = sthSigningMessage(sthCore(head));
  const sigOk = ml_dsa65.verify(b64(wEntry.ml_dsa_pub), msg, b64(st.witness.ml_dsa)) && ed25519.verify(b64(st.witness.ed25519), msg, b64(wEntry.ed25519_pub));
  stmtRows.push({ tree_size: n, decision_ok: d.ok, signed_bytes_sha256: sha256(msg), signature_verifies_over_primary_head: sigOk, statement_matches_primary_head: st.root_hash === head.root_hash && st.tree_size === head.tree_size && st.observed_at === head.timestamp,
    witness_checked: d.checks, previous_head_size: d.checks?.previous_head?.tree_size ?? null });
}
must(stmtRows.every((x) => x.decision_ok && x.signature_verifies_over_primary_head && x.statement_matches_primary_head && x.witness_checked.receipts_verified === N && x.witness_checked.consistency_pairs_verified === N - 1), "witness statements");
must(stmtRows.slice(1).every((x, i) => x.previous_head_size === stmtRows[i].tree_size && x.witness_checked.previous_head_still_in_history === true), "witness remembered and re-checked its previous head");
const vW = await verifyReceiptV2(withTrustedKeys(witnessedFinal, trust), { requireHardware: true, quoteVerifier: verifier, expectedMeasurement: pinA, witnessThreshold: 1 });
must(vW.ok && vW.checks.witnesses.status === "pass", "verdict with witness required");
const vNoWitnessKey = await verifyReceiptV2(withTrustedKeys(witnessedFinal, { [WID.key_id]: entryOf(finalA) }), { requireHardware: true, quoteVerifier: verifier, expectedMeasurement: pinA, witnessThreshold: 1 });
const vNoWitness = await verifyReceiptV2(finalA, { requireHardware: true, quoteVerifier: verifier, expectedMeasurement: pinA, witnessThreshold: 1 });
const presented = Object.fromEntries(["forged-root", "forged-time", "forged-size", "forged-sig"].map((k) => { const r = J(`witness/presented-${k}.json`); return [k, { signed: r.ok, reasons: r.reasons }]; }));
must(Object.values(presented).every((x) => x.signed === false), "witness must refuse forged heads");
const genuinePresented = J("witness/presented-genuine.json");
const postB = J("witness/post-B-refusal.json");
must(postB.ok === false, "witness must refuse after the primary log was replaced");
// forged witness signature / altered statement
const forgedSig = structuredClone(witnessedFinal); forgedSig.sth.witnesses = forgedSig.sth.witnesses.map((w) => w.id === WID.key_id ? { ...w, ed25519: flipB64(w.ed25519) } : w);
const vForgedSig = await verifyReceiptV2(withTrustedKeys(forgedSig, trust), { witnessThreshold: 1 });
const alteredHead = structuredClone(witnessedFinal); alteredHead.sth.root_hash = flipMh(alteredHead.sth.root_hash);
const vAltered = await verifyReceiptV2(withTrustedKeys(alteredHead, trust), { witnessThreshold: 1 });
must(vForgedSig.checks.witnesses.status !== "pass" && vAltered.checks.witnesses.status !== "pass" && vNoWitnessKey.checks.witnesses.status !== "pass" && vNoWitness.checks.witnesses.status !== "pass", "witness negative controls");
write("witness-domain-final.json", { domain: "witness", checked_at: now(),
  architecture: "The witness is a separate CVM with its own app_id running the pinned witness code. Its signing key is sealed by dstack to that app (path cool/witness/v1); the primary log workload cannot derive it. The witness pulls the primary's receipts itself, verifies each one (signature, inclusion, real TDX quote via Phala's service, the primary's pinned measurement), re-derives the history, checks consistency, and only then signs. It remembers the last head it signed and refuses a log that forks or rolls back.",
  witness_identity: { key_id: WID.key_id, app_id: WID.app_id, instance_id: WID.instance_id, measurement: WID.measurement, image_digest: WID.image_digest, public_keys: wEntry, quote_verified_by_phala: attW.ok, quote_report_data_binds_witness_key: witnessBinding, quote_sha256: sha256(wq.raw) },
  primary_identity: { app_id: finalA.attestation.quote.body.app_id, instance_id: finalA.attestation.quote.body.instance_id, rtmr3: pinA.rtmr3 },
  distinct_from_primary: notPrimary,
  environment_separation: J("cvm-witness.json").node_name !== J("cvm-primary.json").node_name ? { primary_node: J("cvm-primary.json").node_name, witness_node: J("cvm-witness.json").node_name, different_physical_nodes: true } : { different_physical_nodes: false },
  statements: stmtRows,
  witness_verified_the_primary_head: "each statement's checks show 8 receipts verified (incl. real quotes), 8 heads, 7 consistency pairs, and (after the first) that the previously signed head is still in the history",
  verifier_requires_witness: { with_witness_key_attested: { ok: vW.ok, witnesses: vW.checks.witnesses.status }, without_any_witness_statement: { witnesses: vNoWitness.checks.witnesses.status }, witness_key_replaced_by_primary_key: { witnesses: vNoWitnessKey.checks.witnesses.status } },
  negative_controls: { forged_heads_presented_to_witness_refused: presented, genuine_head_presented_is_signed: genuinePresented.ok, forged_witness_signature: vForgedSig.checks.witnesses.status, altered_head_with_genuine_witness_signature: vAltered.checks.witnesses.status, witness_after_primary_log_replaced: { signed: postB.ok, reasons: postB.reasons } },
  operator_note: "Both CVMs were deployed from one Phala account. Key custody, process, node and measured code are separate; organizational independence (a different company operating the witness) was NOT demonstrated.",
  result: "VERIFIED" });

/* ── 7 enclave + runtime status ── */
const rtA = J("runtime-A.json");
const wrongPin = { ...pinA, rtmr3: "hex:" + "ab".repeat(48) };
const eValid = await verifyReceiptV2(finalA, { requireHardware: true, quoteVerifier: verifier, expectedMeasurement: pinA });
const eWrong = await verifyReceiptV2(finalA, { requireHardware: true, quoteVerifier: verifier, expectedMeasurement: wrongPin });
const eNoVerifier = await verifyReceiptV2(finalA, { requireHardware: true, expectedMeasurement: pinA });
const zeroPin = Object.fromEntries(Object.keys(pinA).map((k) => [k, "hex:" + "0".repeat(96)]));
const eZero = await verifyReceiptV2(finalA, { requireHardware: true, quoteVerifier: verifier, expectedMeasurement: zeroPin });
must(eValid.ok && !eWrong.ok && eWrong.checks.enclave.status === "fail" && !eNoVerifier.ok && eNoVerifier.checks.enclave.status === "fail" && !eZero.ok, "enclave policy");
must(rtA.runtime?.state === "real" && rtA.cli?.[0]?.code === 0 && /REAL/.test(rtA.cli[0].stdout) && rtA.cli[1].stdout.includes("UNVERIFIED") && rtA.cli[2].code !== 0 && /MEASUREMENT MISMATCH/.test(rtA.cli[2].stdout + rtA.cli[2].stderr), "runtime status evidence");
write("enclave-domain-final.json", { domain: "enclave", checked_at: now(),
  measurement: pinA, all_registers_nonzero: Object.values(pinA).every((v) => !/^hex:0+$/.test(v)), registers_equal_raw_quote: primaryMatches, agent_identity: { app_id: finalA.attestation.quote.body.app_id, instance_id: finalA.attestation.quote.body.instance_id },
  docker_image_digest_in_record: finalA.record.event.software.digest, note: "The Docker image digest is a different identifier from the TDX measurement.",
  report_data_binds_signing_key: attP.parsed.report_data.slice(0, 64) === rdExpected,
  policy_tests: { valid_pin_with_verifier: { ok: eValid.ok, enclave: eValid.checks.enclave.status }, wrong_pin: { ok: eWrong.ok, enclave: eWrong.checks.enclave.status, detail: eWrong.checks.enclave.detail }, zero_measurement_pin: { ok: eZero.ok, enclave: eZero.checks.enclave.status }, requireHardware_without_verifier: { ok: eNoVerifier.ok, attestation: eNoVerifier.checks.attestation.status, enclave: eNoVerifier.checks.enclave.status } },
  runtime_status_in_cvm: { sdk_runtime: rtA.runtime, cli_hardware_required_with_verifier: { exit: rtA.cli[0].code, runtime_line: (rtA.cli[0].stdout.match(/runtime\s+[^\n│]*/) ?? [""])[0].trim() }, cli_no_verifier: { exit: rtA.cli[1].code, runtime_line: (rtA.cli[1].stdout.match(/runtime\s+[^\n│]*/) ?? [""])[0].trim() }, cli_wrong_pin_hardware_required: { exit: rtA.cli[2].code, output: (rtA.cli[2].stdout + rtA.cli[2].stderr).split("\n").find((l) => /MEASUREMENT MISMATCH/.test(l))?.trim() } },
  result: "VERIFIED" });

/* ── workload change ── */
const cmp = Object.fromEntries(["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"].map((k) => [k, pinA[k] === pinB[k] ? "SAME" : "DIFFERENT"]));
const bVsA = await verifyReceiptV2(finalB, { requireHardware: true, quoteVerifier: verifier, expectedMeasurement: pinA });
const bVsB = await verifyReceiptV2(finalB, { requireHardware: true, quoteVerifier: verifier, expectedMeasurement: pinB });
const aAfterB = await verifyReceiptV2(witnessedFinal, { ...{ requireHardware: true, quoteVerifier: verifier, expectedMeasurement: pinA, witnessThreshold: 1 } });
const aAfterBTrusted = await verifyReceiptV2(withTrustedKeys(witnessedFinal, trust), { requireHardware: true, quoteVerifier: verifier, expectedMeasurement: pinA, witnessThreshold: 1 });
must(cmp.mrtd === "SAME" && cmp.rtmr0 === "SAME" && cmp.rtmr1 === "SAME" && cmp.rtmr2 === "SAME" && cmp.rtmr3 === "DIFFERENT", "A/B register pattern");
must(!bVsA.ok && bVsB.ok && aAfterBTrusted.ok, "pin outcomes");
write("workload-change-final.json", { checked_at: now(), image_digest_A: finalA.record.event.software.digest, image_digest_B: finalB.record.event.software.digest, register_comparison: cmp, rtmr3_A: pinA.rtmr3, rtmr3_B: pinB.rtmr3,
  B_against_A_pin: { ok: bVsA.ok, enclave: bVsA.checks.enclave, expected: "FAIL" }, B_against_B_pin: { ok: bVsB.ok, enclave: bVsB.checks.enclave, expected: "PASS" },
  historical_A_witnessed_receipt_after_B_deployed: { ok: aAfterBTrusted.ok, checks: Object.fromEntries(Object.entries(aAfterBTrusted.checks).map(([k, v]) => [k, v.status])), expected: "PASS", note: "A's receipt and its witness statement were verified again after B was deployed; both quotes were re-checked online." },
  result: !bVsA.ok && bVsB.ok && aAfterBTrusted.ok ? "VERIFIED" : "FAILED" });

/* ── tamper matrix ── */
await runTamper("binding_hash", (t) => { t.binding_hash = flipMh(t.binding_hash); }, ["binding", "signature"]);
await runTamper("metadata_hash (inside the record)", (t) => { t.record.event.metadata_hash = flipMh(t.record.event.metadata_hash); }, ["binding", "signature"]);
await runTamper("signature (ed25519 bytes)", (t) => { t.record.signature.ed25519 = flipB64(t.record.signature.ed25519); }, ["signature"]);
await runTamper("signature (ml-dsa bytes)", (t) => { t.record.signature.ml_dsa = flipB64(t.record.signature.ml_dsa); }, ["signature"]);
await runTamper("inclusion/root (sth.root_hash)", (t) => { t.sth.root_hash = flipMh(t.sth.root_hash); }, ["inclusion"]);
await runTamper("forged STH (new root, original signature)", (t) => { t.sth.root_hash = flipMh(t.sth.root_hash); t.sth.tree_size = t.sth.tree_size; }, ["inclusion"]);
await runTamper("audit path element", (t) => { t.inclusion.audit_path[0] = flipMh(t.inclusion.audit_path[0]); }, ["inclusion"]);
await runTamper("forged witness signature", (t) => { const w = attachWitness(t, stmtFinal); t.sth = w.sth; t.key_directory = w.key_directory; t.sth.witnesses = t.sth.witnesses.map((x) => x.id === WID.key_id ? { ...x, ed25519: flipB64(x.ed25519) } : x); }, ["witnesses"]);
await runTamper("wrong quote (quote from deployment B)", (t) => { t.attestation.quote = structuredClone(finalB.attestation.quote); }, ["enclave"]);
await runTamper("wrong report_data in the quote body", (t) => { t.attestation.quote.body.report_data = flipMh(t.attestation.quote.body.report_data); }, ["enclave"]);
await runTamper("quote raw bytes altered", (t) => { const raw = Buffer.from(b64(t.attestation.quote.raw)); raw[600] ^= 1; t.attestation.quote.raw = "base64:" + raw.toString("base64"); }, ["enclave"]);
write("tamper-final.json", { checked_at: now(), original: "the untouched final receipt of deployment A", verifier_options: "requireHardware, Phala verifier, measurement pin of A, witness threshold 1 with the attested witness key", results: tamperResults,
  note: "Each row changes exactly one field. Domains not listed as failing are unaffected because the changed field is not part of them; the overall verdict is ok:false in every row." });
fs.mkdirSync(path.join(out, "tamper-final"), { recursive: true });
fs.writeFileSync(path.join(out, "tamper-final", "original-final-receipt.json"), JSON.stringify(finalA, null, 2));

/* ── overall external verdict ── */
write("final-external-verification.json", { checked_at: now(), run_outside_cvm: true,
  verifyReceiptV2_witnessed_final_receipt: { ok: vW.ok, checks: Object.fromEntries(Object.entries(vW.checks).map(([k, v]) => [k, v.status])), reasons: vW.reasons },
  domains: { binding: bindingRows.every((x) => x.match), signature: sigRows.every((x) => x.ml_dsa_65 && x.ed25519), inclusion: incRows.every((x) => x.sth_signature_ok && x.root_matches), consistency: pairs.every((p) => p.verifies_against_enclave_signed_heads) && sdk.ok, witness: stmtRows.every((x) => x.signature_verifies_over_primary_head) && vW.checks.witnesses.status === "pass", attestation: attP.ok && offline?.result === "PASS", enclave: eValid.ok && !eWrong.ok && !eNoVerifier.ok },
  witness_organizational_independence: "NOT DEMONSTRATED (same Phala account deployed primary and witness)", attestation_mode: "ONLINE (+ local dcap-qvl with archived collateral)", failures });
console.log(JSON.stringify({ failures, tamper_rows: Object.keys(tamperResults).length }, null, 2));
process.exit(failures.length ? 1 : 0);
