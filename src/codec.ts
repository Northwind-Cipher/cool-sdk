/**
 * Byte/string codecs for CooL's wire encodings.
 *
 * Vendored from `cool-sdk` (github.com/KenidoesCode/cool-sdk, Apache-2.0) with
 * ONE change: the upstream file encodes via Node's `Buffer`, which does not
 * exist in a browser. Every function below is a byte-for-byte equivalent built
 * on `btoa`/`atob` and manual hex, so the receipts this app produces are
 * identical to the ones the published SDK and CLI produce.
 *
 * What this proves: nothing on its own — these are deterministic, reversible
 * encodings (hex, base64) and the prefixed string forms used in receipts
 * (`hex:...`, `base64:...`).
 * What this does NOT prove: that the bytes are authentic, fresh, or meaningful.
 * Integrity comes from the hash/signature layers, not from encoding.
 */

const HEX_FIELD_PREFIX = "hex:";
const B64_FIELD_PREFIX = "base64:";

/** Lowercase hex of the given bytes. */
export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}

/** Bytes from lowercase/uppercase hex. Throws on non-hex input. */
export function fromHex(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new TypeError(`invalid hex string`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Standard base64 of the given bytes.
 * Chunked because `String.fromCharCode(...bytes)` blows the argument limit on
 * an ML-DSA-65 signature (~3.3 KB) on some engines.
 */
export function toBase64(bytes: Uint8Array): string {
  const CHUNK = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

/** Bytes from base64. */
export function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** UTF-8 encode a string to bytes. */
export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** Concatenate byte arrays into one. */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/** Encode bytes as the receipt `hex:<hex>` field form. */
export function toHexField(bytes: Uint8Array): `hex:${string}` {
  return `hex:${toHex(bytes)}`;
}

/** Decode a `hex:<hex>` field to bytes. Throws if the prefix is missing. */
export function fromHexField(field: string): Uint8Array {
  if (!field.startsWith(HEX_FIELD_PREFIX)) {
    throw new TypeError(`expected '${HEX_FIELD_PREFIX}' prefix`);
  }
  return fromHex(field.slice(HEX_FIELD_PREFIX.length));
}

/** Encode bytes as the receipt `base64:<b64>` field form. */
export function toBase64Field(bytes: Uint8Array): `base64:${string}` {
  return `base64:${toBase64(bytes)}`;
}

/** Decode a `base64:<b64>` field to bytes. Throws if the prefix is missing. */
export function fromBase64Field(field: string): Uint8Array {
  if (!field.startsWith(B64_FIELD_PREFIX)) {
    throw new TypeError(`expected '${B64_FIELD_PREFIX}' prefix`);
  }
  return fromBase64(field.slice(B64_FIELD_PREFIX.length));
}

/** Constant-time equality for two byte arrays of equal length. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
