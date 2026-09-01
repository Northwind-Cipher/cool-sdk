/**
 * The v2 verifier — the whole product, from the buyer's side.
 *
 * Everything else CooL builds exists so that this function can be run by someone
 * who trusts neither CooL nor Phala nor the customer: an auditor, a regulator, a
 * counterparty, the customer's own client. It takes bytes and returns a verdict,
 * with no network access required for any domain except chaining a hardware
 * quote to its vendor root.
 *
 * Seven domains, and the honesty rules that govern them:
 *
 *   binding     — recompute the commitment over the core. Maths. Pass or fail.
 *   signature   — BOTH ML-DSA-65 and Ed25519 over core‖binding. Maths.
 *   inclusion   — RFC 6962 audit path to a validly signed STH. Maths.
 *   witnesses   — only `external: true` co-signatures count. A CooL
 *                 self-signature is shown and never counted.
 *   attestation — the quote's chain to a vendor root. `pass` ONLY with a real
 *                 verifier and a real root; `simulated` for the simulator;
 *                 `absent` when a hardware quote is present but unverifiable
 *                 here. Never optimistic.
 *   enclave     — the binding between the quote and this record: the quote
 *                 digest is inside the signed core, the measurement matches, and
 *                 `report_data` commits to the very key that signed. This is the
 *                 domain v1 could not have, and the one that makes a quote mean
 *                 something about THIS record rather than about some record.
 *   anchor      — absent. Not implemented. Never a pass.
 */
import type { DirectoryEntry, KeyDirectory } from "../types";
import { multihashDigest } from "../multihash";
import { hybridVerify } from "../sign";
import { leafHash, verifyInclusion } from "../merkle";
import { sthCore, sthSigningMessage } from "../record";
import {
  bindingHashV2,
  coreOfV2,
  recordLeafDataV2,
  recordSigningMessageV2,
  recordSubjectLabel,
} from "./record";
import {
  checkQuoteStructure,
  enclaveReportData,
  measurementDiff,
  measurementEquals,
  quoteDigest,
  simulatedQuoteVerifier,
} from "./quote";
import type { QuoteVerifier } from "./quote";
import { base64ToBytes, bytesToHex, parseProof, verifyAnchor } from "./anchor";
import type { BlockHeaderSource, Timestamp as AnchorTimestamp } from "./anchor";
import { validateReceiptV2Shape } from "./structure";
import type {
  DomainCheckV2,
  Measurement,
  ReceiptV2,
  VerdictChecksV2,
  VerdictSubjectV2,
  VerdictV2,
  VerifyOptionsV2,
} from "./types";

const ANCHOR_ABSENT = "NONE — this head was never submitted to a public chain";

/** Verifier options, plus the optional root-of-trust checker. */
export type VerifyArgsV2 = VerifyOptionsV2 & {
  /**
   * Chains a hardware quote to Intel/AMD/NVIDIA. Omit it and a hardware quote
   * is reported as present-but-unverified rather than assumed good.
   */
  readonly quoteVerifier?: QuoteVerifier;
  /**
   * Reads a Bitcoin block header's merkle root. Omit it and an anchor is
   * reported as pending rather than passing — a timestamp nobody checked
   * against the chain is not an anchor.
   */
  readonly blockHeaders?: BlockHeaderSource;
};

function fail(detail: string): DomainCheckV2 {
  return { status: "fail", detail };
}

/** Verify a `cool.receipt.v2`. Never throws; problems surface as failed domains. */
export async function verifyReceiptV2(
  receipt: unknown,
  options: VerifyArgsV2 = {},
): Promise<VerdictV2> {
  const shape = validateReceiptV2Shape(receipt);
  if (!shape.receipt) {
    const bad = fail("receipt failed cool.receipt.v2 structural validation");
    const absent: DomainCheckV2 = { status: "absent", detail: "not evaluated — receipt malformed" };
    return {
      ok: false,
      schema: "cool.receipt.v2",
      subject: null,
      checks: {
        binding: bad,
        signature: bad,
        inclusion: absent,
        witnesses: absent,
        attestation: absent,
        enclave: absent,
        anchor: absent,
      },
      reasons: shape.errors,
    };
  }

  const r = shape.receipt;
  const reasons: string[] = [];
  const core = coreOfV2(r.record);

  const subject: VerdictSubjectV2 = {
    kind: r.record.schema === "cool.change.v2" ? "change" : "evidence",
    subject: recordSubjectLabel(core),
    issued_at: r.record.time.issued_at,
    record_id: r.record.record_id,
    key_id: r.record.signature.key_id,
    tee: `${r.record.runtime.tee_vendor} · ${r.record.runtime.mode}`,
  };

  /* ── binding ── */
  const recomputed = bindingHashV2(core);
  const bindingOk = recomputed === r.binding_hash;
  const binding: DomainCheckV2 = bindingOk
    ? { status: "pass", detail: "recomputed from record, matches" }
    : fail(`FAILED — recomputed ${recomputed} ≠ stored ${r.binding_hash}`);
  if (!bindingOk) reasons.push("binding: recomputed binding_hash does not match the receipt");

  /* ── signature ── */
  const keyId = r.record.signature.key_id;
  const signingEntry: DirectoryEntry | undefined = r.key_directory[keyId];
  let signature: DomainCheckV2;
  if (!signingEntry) {
    signature = fail(`FAILED — no public key for key_id '${keyId}' in key_directory`);
    reasons.push(`signature: key_directory has no entry for '${keyId}'`);
  } else {
    const result = hybridVerify(
      recordSigningMessageV2(core, r.binding_hash),
      r.record.signature,
      signingEntry,
    );
    if (result.ok) {
      signature = { status: "pass", detail: `ML-DSA-65 + Ed25519 valid (key ${keyId})` };
    } else {
      const both = !result.mlDsaOk && !result.ed25519Ok;
      const which = both ? "ML-DSA-65 and Ed25519" : !result.mlDsaOk ? "ML-DSA-65" : "Ed25519";
      signature = fail(`FAILED — ${which} ${both ? "do" : "does"} not verify over core‖binding_hash`);
      reasons.push(`signature: ${which} did not verify (record altered or wrong key)`);
    }
  }

  /* ── inclusion ── */
  const inclusion = verifyInclusionDomain(r, reasons);

  /* ── witnesses ── */
  const witnesses = verifyWitnessesDomain(r, options.witnessThreshold ?? 0);

  /* ── attestation ── */
  const attestation = await verifyAttestationDomain(r, options, reasons);

  /* ── enclave binding ── */
  const enclave = verifyEnclaveDomain(r, signingEntry, options, reasons, attestation.status);

  /* ── anchor ── */
  const anchor = await verifyAnchorDomain(r, options, reasons);

  const checks: VerdictChecksV2 = {
    binding,
    signature,
    inclusion,
    witnesses,
    attestation,
    enclave,
    anchor,
  };

  const inclusionAcceptable = inclusion.status === "pass" || inclusion.status === "absent";
  let ok =
    binding.status === "pass" &&
    signature.status === "pass" &&
    inclusionAcceptable &&
    enclave.status !== "fail" &&
    attestation.status !== "fail";

  if (options.requireHardware && attestation.status !== "pass") {
    ok = false;
    reasons.push(
      "policy: requireHardware is set and this receipt is not backed by a verified hardware quote",
    );
  }

  return { ok, schema: "cool.receipt.v2", subject, checks, reasons };
}

/* ── domains ──────────────────────────────────────────────────────────── */

/**
 * The anchor domain: did this tree head exist at a point in time nobody can
 * move?
 *
 * Four outcomes, and the distinctions between them are the whole point:
 *
 *   absent   no anchor was ever submitted
 *   pending  submitted, or committed to a block nobody checked here
 *   pass     the recomputed commitment equals a real block's merkle root
 *   fail     it does not, or the proof is about a different head
 *
 * `pending` is not a soft pass. It is the honest state of a Bitcoin timestamp
 * for the hour between submission and aggregation, and the honest state of any
 * proof verified without a block header source.
 */
async function verifyAnchorDomain(
  r: ReceiptV2,
  options: VerifyArgsV2,
  reasons: string[],
): Promise<DomainCheckV2> {
  if (!r.anchor) return { status: "absent", detail: ANCHOR_ABSENT };
  const anchor = r.anchor;

  if (!r.sth) {
    reasons.push("anchor: an anchor is attached but the receipt carries no tree head");
    return fail("FAILED — anchor present without an STH to anchor");
  }
  if (anchor.target !== r.sth.root_hash) {
    reasons.push("anchor: the proof is about a different tree head than this receipt's");
    return fail(`FAILED — anchor targets ${anchor.target}, receipt head is ${r.sth.root_hash}`);
  }
  if (anchor.tree_size !== r.sth.tree_size) {
    reasons.push("anchor: the proof's tree size does not match the receipt's");
    return fail(`FAILED — anchor at size ${anchor.tree_size}, receipt at ${r.sth.tree_size}`);
  }

  let digest: Uint8Array;
  let timestamp: AnchorTimestamp;
  try {
    digest = multihashDigest(anchor.target);
    const parsed = parseProof(base64ToBytes(anchor.proof));
    if (bytesToHex(parsed.digest) !== bytesToHex(digest)) {
      reasons.push("anchor: the proof file is about a different digest than it claims");
      return fail("FAILED — the .ots proof does not cover this tree head");
    }
    timestamp = parsed.timestamp;
  } catch (error) {
    reasons.push(`anchor: the proof could not be parsed (${(error as Error).message})`);
    return fail(`FAILED — unreadable proof: ${(error as Error).message}`);
  }

  const check = await verifyAnchor(digest, timestamp, options.blockHeaders);
  switch (check.status) {
    case "confirmed":
      return { status: "pass", detail: check.detail };
    case "fail":
      reasons.push(`anchor: ${check.detail}`);
      return fail(`FAILED — ${check.detail}`);
    default:
      return { status: "pending", detail: check.detail };
  }
}

function verifyInclusionDomain(r: ReceiptV2, reasons: string[]): DomainCheckV2 {
  if (!r.inclusion || !r.sth) {
    return { status: "absent", detail: "absent (no transparency-log proof in this receipt)" };
  }
  const inc = r.inclusion;
  const sth = r.sth;

  if (inc.tree_size !== sth.tree_size) {
    reasons.push("inclusion: inclusion.tree_size does not match sth.tree_size");
    return fail(`FAILED — inclusion tree_size ${inc.tree_size} ≠ STH tree_size ${sth.tree_size}`);
  }
  if (inc.leaf_index < 0 || inc.leaf_index >= sth.tree_size) {
    reasons.push("inclusion: leaf_index out of range for tree_size");
    return fail(`FAILED — leaf_index ${inc.leaf_index} out of range for tree(${sth.tree_size})`);
  }

  try {
    const rootOk = verifyInclusion(
      leafHash(recordLeafDataV2(r.binding_hash)),
      inc.leaf_index,
      sth.tree_size,
      inc.audit_path.map(multihashDigest),
      multihashDigest(sth.root_hash),
    );
    if (!rootOk) {
      reasons.push("inclusion: audit path does not reconstruct the STH root");
      return fail("FAILED — audit path does not reconstruct STH root");
    }
  } catch {
    reasons.push("inclusion: malformed audit path or root hash");
    return fail("FAILED — malformed audit path or STH root hash");
  }

  const sthEntry = r.key_directory[sth.signature.key_id];
  if (!sthEntry) {
    reasons.push(`inclusion: key_directory has no entry for STH key '${sth.signature.key_id}'`);
    return fail(`FAILED — no public key for STH key_id '${sth.signature.key_id}'`);
  }
  if (!hybridVerify(sthSigningMessage(sthCore(sth)), sth.signature, sthEntry).ok) {
    reasons.push("inclusion: STH signature does not verify");
    return fail("FAILED — STH signature invalid");
  }

  return {
    status: "pass",
    detail: `leaf ${inc.leaf_index} ∈ tree(${sth.tree_size}); STH signature valid`,
  };
}

function verifyWitnessesDomain(r: ReceiptV2, threshold: number): DomainCheckV2 {
  if (!r.sth) return { status: "absent", detail: "no STH (transparency-log proof absent)" };
  const message = sthSigningMessage(sthCore(r.sth));
  let external = 0;
  let self = 0;

  for (const w of r.sth.witnesses) {
    if (!w.external) {
      self++;
      continue;
    }
    const entry = r.key_directory[w.id];
    if (!entry) continue;
    const ok = hybridVerify(
      message,
      { alg: w.alg, key_id: w.id, ml_dsa: w.ml_dsa, ed25519: w.ed25519 },
      entry,
    ).ok;
    if (ok) external++;
  }

  const note = self > 0 ? ` (${self} self-signature${self === 1 ? "" : "s"}, not counted)` : "";
  return external >= Math.max(threshold, 1)
    ? { status: "pass", detail: `${external} independent${note}` }
    : { status: "absent", detail: `${external} independent${note}` };
}

async function verifyAttestationDomain(
  r: ReceiptV2,
  options: VerifyArgsV2,
  reasons: string[],
): Promise<DomainCheckV2> {
  const quote = r.attestation.quote;
  if (!quote) {
    return { status: "mock", detail: "MOCK — no attestation quote in this receipt" };
  }

  const structural = checkQuoteStructure(quote);
  if (structural) {
    reasons.push(`attestation: ${structural.detail}`);
    return structural;
  }

  const simulated = quote.root === "cool-sim-root";
  const verifier: QuoteVerifier | null =
    options.quoteVerifier ?? (simulated ? simulatedQuoteVerifier(r.key_directory) : null);

  if (!verifier) {
    return {
      status: "absent",
      detail: `quote present (root ${quote.root}, TCB ${quote.body.tcb_status}) — no verifier configured, so it is REPORTED, not verified`,
    };
  }

  const verification = await verifier.verify(quote);
  if (!verification.ok) {
    reasons.push(`attestation: ${verification.detail}`);
    return fail(`FAILED — ${verification.detail}`);
  }
  if (simulated || verification.root === "cool-sim-root") {
    return {
      status: "simulated",
      detail: `${verification.detail} — this is NOT evidence that any hardware protected the run`,
    };
  }
  return {
    status: "pass",
    detail: `verified against ${verification.root} · TCB ${verification.tcb_status}`,
  };
}

function verifyEnclaveDomain(
  r: ReceiptV2,
  signingEntry: DirectoryEntry | undefined,
  options: VerifyArgsV2,
  reasons: string[],
  attestationStatus: DomainCheckV2["status"],
): DomainCheckV2 {
  const runtime = r.record.runtime;
  const quote = r.attestation.quote;

  if (!quote || !runtime.tee_quote) {
    return { status: "absent", detail: "no quote to bind — record was not produced in a TEE" };
  }

  // 1. The quote is inside the signature: its digest is a field of the signed core.
  const digest = quoteDigest(quote);
  if (digest !== runtime.tee_quote) {
    reasons.push("enclave: the attached quote is not the one the record signed over");
    return fail(
      "FAILED — quote digest ≠ runtime.tee_quote; the quote was swapped after signing",
    );
  }

  // 2. The record's measurement is the quote's measurement.
  if (!runtime.enclave_measurement) {
    reasons.push("enclave: record carries a quote digest but no measurement");
    return fail("FAILED — runtime.tee_quote present with no enclave_measurement");
  }
  if (!measurementEquals(runtime.enclave_measurement, quote.body.measurement)) {
    const diff = measurementDiff(runtime.enclave_measurement, quote.body.measurement);
    reasons.push("enclave: record measurement differs from the quoted measurement");
    return fail(`FAILED — record and quote disagree on ${diff.join(", ")}`);
  }

  // 3. The quote's report_data commits to the key that signed the record.
  if (!signingEntry) {
    return fail("FAILED — cannot check key binding without the signing key");
  }
  const expectedReportData = enclaveReportData(signingEntry);
  if (quote.body.report_data !== expectedReportData) {
    reasons.push("enclave: quote report_data does not commit to the signing key");
    return fail("FAILED — the quote attests a DIFFERENT key than the one that signed this record");
  }

  // 4. The measurement is the one the reader pinned (if they pinned one).
  const pin: Measurement | null =
    options.expectedMeasurement ?? r.attestation.expected_measurement ?? null;
  let pinNote = "no measurement pinned by the verifier";
  if (pin) {
    if (!measurementEquals(pin, quote.body.measurement)) {
      const diff = measurementDiff(pin, quote.body.measurement);
      reasons.push("enclave: measurement does not match the pinned image");
      return fail(
        `FAILED — running image differs from the approved one in ${diff.join(", ")}`,
      );
    }
    pinNote = `matches the pinned image ${pin.mrtd.slice(4, 16)}…`;
  }

  const detail = `quote is inside the signature; measurement ${quote.body.measurement.mrtd.slice(4, 16)}… holds the signing key; ${pinNote}`;
  return attestationStatus === "simulated"
    ? { status: "simulated", detail: `${detail} — but the quote itself is simulated` }
    : { status: "pass", detail };
}

/** Convenience: the seven domains in display order. */
export function domainOrder(): (keyof VerdictChecksV2)[] {
  return ["binding", "signature", "inclusion", "witnesses", "attestation", "enclave", "anchor"];
}

/** Merge a verifier's own trusted key directory over a receipt's embedded one. */
export function withTrustedKeys(receipt: ReceiptV2, trusted: KeyDirectory): ReceiptV2 {
  return { ...receipt, key_directory: { ...receipt.key_directory, ...trusted } };
}
