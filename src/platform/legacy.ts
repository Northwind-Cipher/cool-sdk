/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Legacy compatibility: carry a `cool.receipt.v2` inside `cool.envelope.v1`
 * without changing what it means.
 *
 * The envelope commits to the receipt's digest; the receipt itself is kept
 * byte-for-byte (as an attachment or alongside) and is still verified by the
 * original verifier, `verifyReceiptV2`. The wrapper adds an envelope-level
 * signature and transparency; it never re-interprets the receipt's fields.
 */
import { canonicalCbor } from "../canonical";
import { mhSha256 } from "../multihash";
import { verifyReceiptV2 } from "../phala/verify";
import type { ReceiptV2 } from "../phala/types";
import type { VerdictV2 } from "../phala/types";
import { check, type Check } from "./status";
import type { EnvelopeInput, SignedEnvelope } from "./envelope";

/** The digest the wrapper commits to: canonical CBOR of the receipt as JSON data. */
export const legacyReceiptDigest = (receipt: ReceiptV2) => mhSha256(canonicalCbor(JSON.parse(JSON.stringify(receipt))));

/** Envelope input that wraps a legacy receipt. Sign it with any evidence key. */
export function wrapLegacyReceipt(receipt: ReceiptV2, o: { readonly source: string; readonly actor: string; readonly observed_at?: string }): EnvelopeInput {
  return {
    event_type: "legacy.receipt",
    occurred_at: receipt.record.time.issued_at,
    ...(o.observed_at ? { observed_at: o.observed_at } : {}),
    source: { system: o.source, event_id: receipt.record.record_id },
    actor: { id: o.actor, type: "service" },
    action: "wrap",
    resource: { type: "receipt", ref: receipt.record.record_id },
    provenance: { collection_method: "imported" },
    payload: { legacy_schema: "cool.receipt.v2", record_id: receipt.record.record_id, receipt_digest: legacyReceiptDigest(receipt) },
  };
}

/** Check a wrapper against the receipt it claims to carry, then verify the receipt as v2. */
export async function verifyWrappedLegacy(env: SignedEnvelope, receipt: ReceiptV2): Promise<{ readonly binding: Check; readonly legacy: VerdictV2 }> {
  const p = env.core.payload;
  const binding = env.core.event_type !== "legacy.receipt" ? check("fail", "not_a_wrapper", `event type is ${env.core.event_type}`)
    : p["receipt_digest"] !== legacyReceiptDigest(receipt) || p["record_id"] !== receipt.record.record_id
      ? check("fail", "legacy_mismatch", "the envelope does not wrap this receipt")
      : check("pass", "legacy_bound", `wraps ${receipt.record.record_id} (cool.receipt.v2) unchanged`);
  return { binding, legacy: await verifyReceiptV2(receipt) };
}
