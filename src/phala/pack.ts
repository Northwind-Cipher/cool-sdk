/**
 * The audit pack — one file you can hand to someone who does not trust you.
 *
 * An auditor's real complaint about evidence systems is not cryptographic, it is
 * logistical: they get a spreadsheet, a screenshot and a promise, then spend two
 * weeks reconciling them. A pack is the opposite shape — every receipt, the keys
 * needed to check them, the measurement the deployment pinned, and the clause
 * mapping, in a single self-contained document that verifies offline.
 *
 * `verifyAuditPack` deliberately re-derives everything rather than trusting the
 * pack's own summary. A pack that lies about its contents fails on the first
 * receipt, which is the only sane behaviour for a document whose entire purpose
 * is being checked by a stranger.
 */
import type { KeyDirectory } from "../types";
import { verifyReceiptV2 } from "./verify";
import type { VerifyArgsV2 } from "./verify";
import { coverage } from "./compliance";
import { countWitnesses } from "./witness";
import type { Measurement, ReceiptV2, VerdictV2 } from "./types";

export interface AuditPackEntry {
  readonly record_id: string;
  readonly schema: string;
  readonly sealed_at: string;
  readonly receipt: ReceiptV2;
}

export interface AuditPack {
  readonly schema: "cool.audit-pack.v2";
  readonly generated_at: string;
  readonly subject: string;
  readonly enclave: {
    readonly vendor: string;
    readonly mode: string;
    readonly app_id: string;
    readonly measurement: Measurement | null;
  } | null;
  readonly records: readonly AuditPackEntry[];
  readonly obligations: readonly {
    id: string;
    regime: string;
    clause: string;
    requirement: string;
    satisfied_by: string;
    records: number;
    covered: boolean;
  }[];
  /** Keys a verifier may want that are not inside individual receipts. */
  readonly trusted_keys: KeyDirectory;
  readonly how_to_verify: string;
}

export interface BuildPackOptions {
  readonly subject: string;
  readonly generatedAt?: string;
  readonly enclave?: AuditPack["enclave"];
  readonly trustedKeys?: KeyDirectory;
}

export function buildAuditPack(
  receipts: readonly ReceiptV2[],
  options: BuildPackOptions,
): AuditPack {
  return {
    schema: "cool.audit-pack.v2",
    generated_at: options.generatedAt ?? new Date().toISOString(),
    subject: options.subject,
    enclave: options.enclave ?? null,
    records: receipts.map((receipt) => ({
      record_id: receipt.record.record_id,
      schema: receipt.record.schema,
      sealed_at: receipt.record.time.issued_at,
      receipt,
    })),
    obligations: coverage(receipts).map((row) => ({
      id: row.obligation.id,
      regime: row.obligation.regime,
      clause: row.obligation.clause,
      requirement: row.obligation.requirement,
      satisfied_by: row.obligation.satisfiedBy,
      records: row.records,
      covered: row.covered,
    })),
    trusted_keys: options.trustedKeys ?? {},
    how_to_verify:
      "npx cool-nwc verify <any receipt in this pack> — or `cool pack verify <this file>`. " +
      "Everything is checked offline: commitments, both signatures, Merkle inclusion, " +
      "and the binding between the enclave quote and the signing key.",
  };
}

export interface PackVerdict {
  readonly ok: boolean;
  readonly total: number;
  readonly verified: number;
  readonly failed: number;
  /** Records that did not verify, with the reason. */
  readonly failures: readonly { record_id: string; reasons: readonly string[] }[];
  /** Independent witness co-signatures found across the pack. */
  readonly witnesses: number;
  /** Per-record verdicts, in pack order. */
  readonly verdicts: readonly VerdictV2[];
  readonly obligationsCovered: number;
  readonly obligationsTotal: number;
}

/**
 * Verify every receipt in a pack.
 *
 * The summary inside the pack is ignored on purpose — this recomputes it. A pack
 * is only worth what an independent check of it says.
 */
export async function verifyAuditPack(
  pack: AuditPack,
  options: VerifyArgsV2 = {},
): Promise<PackVerdict> {
  const verdicts: VerdictV2[] = [];
  const failures: { record_id: string; reasons: string[] }[] = [];
  let witnesses = 0;

  for (const entry of pack.records) {
    const verdict = await verifyReceiptV2(entry.receipt, options);
    verdicts.push(verdict);
    if (!verdict.ok) {
      failures.push({ record_id: entry.record_id, reasons: [...verdict.reasons] });
    }
    witnesses += countWitnesses(entry.receipt).external;
  }

  const recomputed = coverage(pack.records.map((entry) => entry.receipt));
  return {
    ok: failures.length === 0 && pack.records.length > 0,
    total: pack.records.length,
    verified: verdicts.filter((v) => v.ok).length,
    failed: failures.length,
    failures,
    witnesses,
    verdicts,
    obligationsCovered: recomputed.filter((row) => row.covered).length,
    obligationsTotal: recomputed.length,
  };
}
