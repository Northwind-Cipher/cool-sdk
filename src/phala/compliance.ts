/**
 * Obligations, and whether the evidence actually covers them.
 *
 * The catalogue below is the part of CooL that a compliance officer reads and a
 * founder over-claims. So the rule here is strict: coverage is **computed from
 * receipts**, never asserted. If an obligation has no records behind it, it
 * reports zero and says what would satisfy it. A dashboard that shows green for
 * a control nobody exercised is worse than no dashboard, because it is the exact
 * thing an auditor is trained to disbelieve.
 *
 * Each obligation names the receipt field that satisfies it, so the mapping can
 * be argued with rather than taken on faith — which is what you want in the room
 * where it gets argued with.
 */
import type { ReceiptV2 } from "./types";

export interface Obligation {
  readonly id: string;
  readonly regime: string;
  readonly clause: string;
  readonly requirement: string;
  /** The receipt field or property that satisfies it. */
  readonly satisfiedBy: string;
  /** Which records count. Deliberately explicit rather than clever. */
  readonly counts: (receipt: ReceiptV2) => boolean;
}

const isEvidence = (r: ReceiptV2) => r.record.schema === "cool.evidence.v1";
const isChange = (r: ReceiptV2) => r.record.schema === "cool.change.v2";

export const OBLIGATIONS: readonly Obligation[] = [
  {
    id: "eu-ai-act-12",
    regime: "EU AI Act",
    clause: "Article 12 — record-keeping",
    requirement:
      "High-risk systems automatically record events over their lifetime, to a standard that permits traceability.",
    satisfiedBy: "every evidence record, sealed at the time of the event",
    counts: isEvidence,
  },
  {
    id: "eu-ai-act-14",
    regime: "EU AI Act",
    clause: "Article 14 — human oversight",
    requirement: "Oversight measures are documented and traceable to a named person.",
    satisfiedBy: "change.approval.approvers, inside the signature",
    counts: (r) =>
      isChange(r) &&
      r.record.schema === "cool.change.v2" &&
      (r.record.change.approval?.approvers.length ?? 0) > 0,
  },
  {
    id: "eu-ai-act-15",
    regime: "EU AI Act",
    clause: "Article 15 — accuracy and robustness",
    requirement: "Changes affecting accuracy are recorded with their provenance.",
    satisfiedBy: "change records of kind model, params or dataset",
    counts: (r) =>
      r.record.schema === "cool.change.v2" &&
      ["model", "params", "dataset"].includes(r.record.change.kind),
  },
  {
    id: "dpdp-8",
    regime: "DPDP Rules 2025",
    clause: "Section 8 — reasonable security safeguards",
    requirement: "Personal data is protected during processing, with retained evidence of controls.",
    satisfiedBy: "the TEE measurement inside the signed core; no plaintext in any record",
    counts: (r) => r.record.runtime.tee_quote !== null,
  },
  {
    id: "iso-42001-9",
    regime: "ISO/IEC 42001",
    clause: "Clause 9 — performance evaluation",
    requirement: "The AI management system is monitored, measured and evaluated with retained records.",
    satisfiedBy: "transparency-log inclusion proofs across the estate",
    counts: (r) => r.inclusion !== null,
  },
  {
    id: "rbi-dlg",
    regime: "RBI Digital Lending",
    clause: "Model governance",
    requirement: "The model version behind a credit decision is auditable after the fact.",
    satisfiedBy: "software identity and metadata committed per evidence record",
    counts: isEvidence,
  },
  {
    id: "soc2-cc7",
    regime: "SOC 2",
    clause: "CC7.2 — monitoring",
    requirement: "Changes to the system are logged and reviewed for anomalies.",
    satisfiedBy: "change records with a policy decision attached",
    counts: (r) => r.record.schema === "cool.change.v2" && r.record.change.approval !== null,
  },
];

export interface Coverage {
  readonly obligation: Obligation;
  readonly records: number;
  /** Records covering this obligation, as a share of all records. */
  readonly share: number;
  /** True only when at least one record actually satisfies the mapping. */
  readonly covered: boolean;
}

/** Compute coverage from a set of receipts. Nothing here is a stored value. */
export function coverage(receipts: readonly ReceiptV2[]): Coverage[] {
  return OBLIGATIONS.map((obligation) => {
    const records = receipts.filter((receipt) => {
      try {
        return obligation.counts(receipt);
      } catch {
        return false;
      }
    }).length;
    return {
      obligation,
      records,
      share: receipts.length === 0 ? 0 : records / receipts.length,
      covered: records > 0,
    };
  });
}

/** Obligations with nothing behind them — the list worth acting on. */
export function gaps(receipts: readonly ReceiptV2[]): Coverage[] {
  return coverage(receipts).filter((row) => !row.covered);
}
