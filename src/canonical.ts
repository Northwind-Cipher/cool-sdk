/**
 * Deterministic canonicalization for CooL. Vendored verbatim from `cool-sdk`.
 *
 * What this proves: that the same logical value always encodes to the SAME
 * bytes (RFC 8949 §4.2 Core Deterministic Encoding / CDE), which is what makes
 * hashes and signatures reproducible and comparable across implementations.
 * What this does NOT prove: anything about the meaning, truth, or provenance
 * of the value being encoded.
 */
import { encode, cdeEncodeOptions } from "cbor2";

/**
 * Encode a JSON-like value to canonical (CDE) CBOR bytes.
 * Deterministic: identical input values always yield identical bytes.
 */
export function canonicalCbor(value: unknown): Uint8Array {
  return encode(value, cdeEncodeOptions);
}

/**
 * Human-facing JSON projection of a value (stable 2-space indentation).
 * For display only — NEVER hash or sign this; hashing uses {@link canonicalCbor}.
 */
export function jsonProjection(value: unknown): string {
  return JSON.stringify(value, null, 2);
}
