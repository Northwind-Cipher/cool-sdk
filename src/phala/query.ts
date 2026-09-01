/**
 * Asking questions of a pile of receipts.
 *
 * Evidence nobody can search is evidence nobody uses. The questions that come up
 * in practice are narrow and repetitive — "every prompt change to the refund
 * agent in production last month", "everything this model touched", "which
 * changes went out without a human" — so this is a filter, a sort and a group,
 * not a query language.
 *
 * It works on receipts alone, which means the same function serves the CLI, the
 * console and an auditor holding nothing but a directory of JSON files.
 */
import type { ChangeKind, ReceiptV2 } from "./types";

export interface Query {
  /** `evidence`, `change`, or both when omitted. */
  readonly kind?: "evidence" | "change";
  readonly changeKinds?: readonly ChangeKind[];
  /** Substring match against the change ref or the evidence event type. */
  readonly subject?: string;
  readonly environment?: string;
  /** Actor id substring — `ci:`, `user:`, a specific person. */
  readonly actor?: string;
  readonly decision?: "auto-approved" | "approved" | "rejected" | "waived";
  /** ISO timestamps, inclusive. */
  readonly since?: string;
  readonly until?: string;
  /** Only records produced on real hardware, or only simulated ones. */
  readonly runtime?: "hardware" | "simulated" | "mock";
  readonly limit?: number;
}

/** What a record is *about*, for display and for `subject` matching. */
export function subjectOf(receipt: ReceiptV2): string {
  return receipt.record.schema === "cool.evidence.v1"
    ? receipt.record.event.type
    : receipt.record.change.ref;
}

export function actorOf(receipt: ReceiptV2): string | null {
  return receipt.record.schema === "cool.change.v2" ? receipt.record.change.actor.id : null;
}

export function environmentOf(receipt: ReceiptV2): string | null {
  return receipt.record.schema === "cool.change.v2" ? receipt.record.change.environment : null;
}

const matches = (receipt: ReceiptV2, q: Query): boolean => {
  const record = receipt.record;
  const isChange = record.schema === "cool.change.v2";

  if (q.kind === "evidence" && isChange) return false;
  if (q.kind === "change" && !isChange) return false;
  if (q.changeKinds && (!isChange || !q.changeKinds.includes(record.change.kind))) return false;
  if (q.environment && environmentOf(receipt) !== q.environment) return false;
  if (q.runtime && record.runtime.mode !== q.runtime) return false;

  if (q.subject && !subjectOf(receipt).toLowerCase().includes(q.subject.toLowerCase())) {
    return false;
  }
  if (q.actor) {
    const actor = actorOf(receipt);
    if (!actor || !actor.toLowerCase().includes(q.actor.toLowerCase())) return false;
  }
  if (q.decision) {
    if (!isChange || record.change.approval?.decision !== q.decision) return false;
  }
  if (q.since && record.time.issued_at < q.since) return false;
  if (q.until && record.time.issued_at > q.until) return false;
  return true;
};

/** Filter and sort. Newest first, because that is what anyone wants first. */
export function query(receipts: readonly ReceiptV2[], q: Query = {}): ReceiptV2[] {
  const found = receipts
    .filter((receipt) => matches(receipt, q))
    .sort((a, b) => b.record.time.issued_at.localeCompare(a.record.time.issued_at));
  return q.limit ? found.slice(0, q.limit) : found;
}

/** Count by an arbitrary key — the shape every summary panel needs. */
export function groupBy(
  receipts: readonly ReceiptV2[],
  key: (receipt: ReceiptV2) => string,
): [string, number][] {
  const counts = new Map<string, number>();
  for (const receipt of receipts) {
    const bucket = key(receipt);
    counts.set(bucket, (counts.get(bucket) ?? 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

export interface Summary {
  readonly total: number;
  readonly evidence: number;
  readonly changes: number;
  readonly byKind: [string, number][];
  readonly byEnvironment: [string, number][];
  readonly byActor: [string, number][];
  readonly needingReview: number;
  readonly hardware: number;
  readonly simulated: number;
  readonly earliest: string | null;
  readonly latest: string | null;
}

/** Everything a dashboard header needs, from receipts alone. */
export function summarise(receipts: readonly ReceiptV2[]): Summary {
  const changes = receipts.filter((r) => r.record.schema === "cool.change.v2");
  const times = receipts.map((r) => r.record.time.issued_at).sort();
  return {
    total: receipts.length,
    evidence: receipts.length - changes.length,
    changes: changes.length,
    byKind: groupBy(receipts, (r) =>
      r.record.schema === "cool.change.v2" ? r.record.change.kind : r.record.event.type,
    ),
    byEnvironment: groupBy(changes, (r) => environmentOf(r) ?? "—"),
    byActor: groupBy(changes, (r) => actorOf(r) ?? "—"),
    needingReview: changes.filter(
      (r) => r.record.schema === "cool.change.v2" && r.record.change.approval?.decision === "rejected",
    ).length,
    hardware: receipts.filter((r) => r.record.runtime.mode === "hardware").length,
    simulated: receipts.filter((r) => r.record.runtime.mode === "simulated").length,
    earliest: times[0] ?? null,
    latest: times.at(-1) ?? null,
  };
}
