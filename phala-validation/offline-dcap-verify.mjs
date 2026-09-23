/**
 * Local (no network at verify time) Intel DCAP verification of a receipt's raw
 * TDX quote, using the pure-JS @phala/dcap-qvl library and the Intel collateral
 * that Phala Cloud's attestation API returned and that final-verify.mjs archived.
 *
 *   npm i --no-save @phala/dcap-qvl
 *   node phala-validation/offline-dcap-verify.mjs <receiptsA.json> <phala-response.json> <out.json>
 *
 * What this is: the quote signature, the PCK certificate chain up to Intel's
 * root CA (embedded in the library), the CRLs, the TCB info and the QE identity
 * are all checked locally against the archived collateral.
 * What this is NOT: independent of Phala. The library is Phala-authored, and the
 * collateral was obtained online through Phala's service. It removes the need to
 * trust the API's boolean at verify time; it does not remove Phala/Intel from
 * the trust base. Collateral freshness is evaluated against the time passed in.
 */
import fs from "node:fs";
import { verify } from "@phala/dcap-qvl";

const [, , receiptsPath, respPath, outPath] = process.argv;
const receipts = JSON.parse(fs.readFileSync(receiptsPath, "utf8"));
const resp = JSON.parse(fs.readFileSync(respPath, "utf8"));
const quote = Buffer.from(receipts[receipts.length - 1].attestation.quote.raw.slice("base64:".length), "base64");
const c = resp.quote_collateral;
const collateral = {
  pck_crl_issuer_chain: c.pck_crl_issuer_chain, root_ca_crl: c.root_ca_crl, pck_crl: c.pck_crl,
  tcb_info_issuer_chain: c.tcb_info_issuer_chain, tcb_info: c.tcb_info, tcb_info_signature: c.tcb_info_signature,
  qe_identity_issuer_chain: c.qe_identity_issuer_chain, qe_identity: c.qe_identity, qe_identity_signature: c.qe_identity_signature,
};
const now = Math.floor(Date.now() / 1000);
let out;
try {
  const r = verify(quote, collateral, now);
  out = {
    mode: "OFFLINE at verify time (archived collateral); collateral was obtained online via Phala's API",
    library: "@phala/dcap-qvl", checked_at_unix: now, result: "PASS",
    tcb_status: r.status, advisory_ids: r.advisory_ids ?? [],
    report_summary: { tee_type: r.report?.type ?? null },
  };
} catch (e) {
  out = { mode: "OFFLINE at verify time", library: "@phala/dcap-qvl", checked_at_unix: now, result: "FAIL", error: String(e?.message ?? e) };
}
// Negative control: a quote with one byte of the TD report body flipped must NOT verify.
const bad = Buffer.from(quote); bad[48 + 136 + 5] ^= 0x01;
let controlRejected = false, controlError = null;
try { verify(bad, collateral, now); } catch (e) { controlRejected = true; controlError = String(e?.message ?? e); }
out.negative_control = { description: "one byte of MRTD in the quote body flipped", rejected: controlRejected, error: controlError };
if (!controlRejected) out.result = "FAIL";
if (outPath) fs.writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log(JSON.stringify(out, null, 2));
process.exit(out.result === "PASS" ? 0 : 1);
