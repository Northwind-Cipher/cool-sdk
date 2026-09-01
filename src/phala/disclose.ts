/**
 * Selective disclosure — showing one field without showing the record.
 *
 * A receipt commits to prompts, outputs and diffs as salted hashes, which is
 * what lets it be published at all. The obvious question follows immediately:
 * when a regulator asks *what the prompt actually said*, how do you answer
 * without handing over everything?
 *
 * The salt is the answer, and it is already in the receipt. Reveal the plaintext
 * plus its salt for one field, and anyone can recompute `mh(salt ‖ value)` and
 * compare it to the sealed commitment. One field opens; the rest stay closed;
 * nobody has to trust the person doing the revealing.
 *
 * Two properties worth being precise about:
 *
 *   • This proves the value was committed. It does not prove the value was
 *     *used* — that is what the rest of the record is for.
 *   • Once disclosed, a field is disclosed forever. Salts are per-field and
 *     per-record, so disclosing one prompt tells you nothing about any other
 *     record, but it does permanently open that one.
 */
import type { HexField, Multihash } from "../types";
import { saltedCommit } from "../hash";
import type { ReceiptV2 } from "./types";

/** Which committed field is being opened. */
export type DisclosableField =
  | "input"
  | "output"
  | "state"
  | "metadata"
  | "change.before"
  | "change.after";

/** A disclosure: the plaintext, its salt, and what it claims to open. */
export interface Disclosure {
  readonly schema: "cool.disclosure.v1";
  readonly record_id: string;
  readonly binding_hash: Multihash;
  readonly field: DisclosableField;
  readonly value: string;
  readonly salt: HexField;
  /** The commitment as it appears in the receipt, copied for convenience. */
  readonly commitment: Multihash;
}

/** The result of checking one. */
export interface DisclosureVerdict {
  readonly ok: boolean;
  readonly field: DisclosableField;
  readonly detail: string;
}

function fieldOf(
  receipt: ReceiptV2,
  field: DisclosableField,
): { commitment: Multihash; salt: HexField } | null {
  const record = receipt.record;
  if (record.schema === "cool.evidence.v1") {
    const c = record.event.commitments;
    if (field === "input" && c.input && c.input_salt) {
      return { commitment: c.input, salt: c.input_salt };
    }
    if (field === "output" && c.output && c.output_salt) {
      return { commitment: c.output, salt: c.output_salt };
    }
    if (field === "state" && c.state && c.state_salt) {
      return { commitment: c.state, salt: c.state_salt };
    }
    if (field === "metadata") {
      return { commitment: record.event.metadata_hash, salt: record.event.metadata_salt };
    }
    return null;
  }
  if (field === "change.after") {
    return { commitment: record.change.after_hash, salt: record.change.after_salt };
  }
  if (field === "change.before") {
    if (!record.change.before_hash || !record.change.before_salt) return null;
    return { commitment: record.change.before_hash, salt: record.change.before_salt };
  }
  return null;
}

/**
 * Build a disclosure for one field.
 *
 * Refuses to produce one whose commitment does not match the value handed in —
 * a disclosure that fails verification is worse than none, because it looks like
 * evidence of tampering when it is really a typo at the desk.
 */
export function disclose(
  receipt: ReceiptV2,
  field: DisclosableField,
  value: string,
): Disclosure {
  const found = fieldOf(receipt, field);
  if (!found) {
    throw new Error(`this record has no '${field}' field to disclose`);
  }
  const recomputed = saltedCommit(found.salt, value);
  if (recomputed !== found.commitment) {
    throw new Error(
      `the value supplied does not match the sealed commitment for '${field}' — ` +
        "either it is not the original text, or this is the wrong record",
    );
  }
  return {
    schema: "cool.disclosure.v1",
    record_id: receipt.record.record_id,
    binding_hash: receipt.binding_hash,
    field,
    value,
    salt: found.salt,
    commitment: found.commitment,
  };
}

/**
 * Check a disclosure against the receipt it claims to open.
 *
 * Pure arithmetic, offline, and independent of whether the receipt itself
 * verifies — check both, in that order, before believing anything.
 */
export function verifyDisclosure(
  receipt: ReceiptV2,
  disclosure: Disclosure,
): DisclosureVerdict {
  if (disclosure.record_id !== receipt.record.record_id) {
    return {
      ok: false,
      field: disclosure.field,
      detail: `disclosure is for record ${disclosure.record_id}, not ${receipt.record.record_id}`,
    };
  }
  if (disclosure.binding_hash !== receipt.binding_hash) {
    return {
      ok: false,
      field: disclosure.field,
      detail: "disclosure names a different binding hash — it belongs to another version of this record",
    };
  }
  const found = fieldOf(receipt, disclosure.field);
  if (!found) {
    return { ok: false, field: disclosure.field, detail: `record has no '${disclosure.field}'` };
  }
  if (found.salt !== disclosure.salt) {
    return { ok: false, field: disclosure.field, detail: "salt does not match the receipt" };
  }
  const recomputed = saltedCommit(disclosure.salt, disclosure.value);
  if (recomputed !== found.commitment) {
    return {
      ok: false,
      field: disclosure.field,
      detail: `FAILED — mh(salt ‖ value) = ${recomputed} ≠ ${found.commitment}`,
    };
  }
  return {
    ok: true,
    field: disclosure.field,
    detail: `the disclosed text is exactly what was committed as ${disclosure.field}`,
  };
}

/** Which fields this receipt could open, for a UI or a `--help` listing. */
export function disclosableFields(receipt: ReceiptV2): DisclosableField[] {
  if (receipt.record.schema === "cool.evidence.v1") {
    const c = receipt.record.event.commitments;
    const fields: DisclosableField[] = ["metadata"];
    if (c.input) fields.push("input");
    if (c.output) fields.push("output");
    if (c.state) fields.push("state");
    return fields;
  }
  return receipt.record.change.before_hash ? ["change.before", "change.after"] : ["change.after"];
}
