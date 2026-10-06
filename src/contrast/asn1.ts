/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * A strict, minimal DER reader.
 *
 * CooL needs to read X.509 certificates because that is the shape Contrast
 * expresses attestation in: the Coordinator verifies a workload's SNP/TDX report
 * and then issues a mesh certificate carrying the report's claims as extensions.
 * To check that credential offline — in a browser, in CI, in an auditor's
 * sandbox — the verifier has to parse DER itself.
 *
 * Why hand-written rather than a dependency: the SDK ships five runtime
 * dependencies and each one is a supply-chain claim we have to stand behind. A
 * reader this small is cheaper to audit than to justify. It is deliberately
 * strict — indefinite lengths, non-minimal lengths and trailing garbage are all
 * rejected rather than tolerated, because a lenient parser in front of a
 * signature check is how certificate confusion bugs happen.
 *
 * What this proves: nothing. DER is an encoding. Authenticity comes from the
 * signature checks in `./x509.ts` that run over the bytes this reader delimits.
 */

/** DER universal tag numbers this reader knows by name. */
export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
} as const;

/** One parsed TLV. `raw` spans the identifier octet through the last content octet. */
export interface DerNode {
  /** The full identifier octet, e.g. `0x30` for SEQUENCE, `0xa3` for `[3]`. */
  readonly tag: number;
  /** True for constructed encodings (bit 6 of the identifier octet). */
  readonly constructed: boolean;
  /** Content octets only. */
  readonly contents: Uint8Array;
  /** Identifier + length + content octets — what a signature covers. */
  readonly raw: Uint8Array;
  /** Offset just past this node, for sequential reads. */
  readonly next: number;
}

/** Thrown on any malformed or non-canonical encoding. */
export class DerError extends Error {
  constructor(message: string) {
    super(`DER: ${message}`);
    this.name = "DerError";
  }
}

/**
 * Read one TLV at `offset`.
 *
 * Rejects indefinite-length form (not valid DER), multi-byte tags, and
 * non-minimal length encodings — all of which are the raw material for parser
 * differentials between two implementations reading the same certificate.
 */
export function readNode(bytes: Uint8Array, offset = 0): DerNode {
  if (offset >= bytes.length) throw new DerError("read past end of input");
  const tag = bytes[offset]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError("multi-byte tags are not supported");

  let cursor = offset + 1;
  if (cursor >= bytes.length) throw new DerError("truncated length");
  const first = bytes[cursor]!;
  cursor++;

  let length: number;
  if (first < 0x80) {
    length = first;
  } else if (first === 0x80) {
    throw new DerError("indefinite length is not valid DER");
  } else {
    const count = first & 0x7f;
    if (count > 4) throw new DerError("length exceeds 4 octets");
    if (cursor + count > bytes.length) throw new DerError("truncated long-form length");
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[cursor + i]!;
    cursor += count;
    if (length < 0x80) throw new DerError("non-minimal long-form length");
    // A length that would have fit in fewer octets is also non-minimal.
    if (count > 1 && bytes[cursor - count] === 0x00) throw new DerError("leading zero in length");
  }

  const end = cursor + length;
  if (end > bytes.length) throw new DerError(`content runs ${end - bytes.length} bytes past end`);

  return {
    tag,
    constructed: (tag & 0x20) !== 0,
    contents: bytes.subarray(cursor, end),
    raw: bytes.subarray(offset, end),
    next: end,
  };
}

/** Read one TLV and require it to be the whole input. */
export function readOnly(bytes: Uint8Array): DerNode {
  const node = readNode(bytes, 0);
  if (node.next !== bytes.length) {
    throw new DerError(`${bytes.length - node.next} trailing byte(s) after top-level value`);
  }
  return node;
}

/** Split a constructed node into its immediate children. */
export function childrenOf(node: DerNode): DerNode[] {
  if (!node.constructed) throw new DerError(`tag 0x${node.tag.toString(16)} is not constructed`);
  const out: DerNode[] = [];
  let offset = 0;
  while (offset < node.contents.length) {
    const child = readNode(node.contents, offset);
    out.push(child);
    offset = child.next;
  }
  return out;
}

/** Assert a node's tag, with a message naming where it was expected. */
export function expectTag(node: DerNode, tag: number, where: string): DerNode {
  if (node.tag !== tag) {
    throw new DerError(
      `${where}: expected tag 0x${tag.toString(16)}, found 0x${node.tag.toString(16)}`,
    );
  }
  return node;
}

/** Decode an OBJECT IDENTIFIER's contents to dotted-decimal form. */
export function oidToString(contents: Uint8Array): string {
  if (contents.length === 0) throw new DerError("empty OBJECT IDENTIFIER");
  const parts: number[] = [];
  const first = contents[0]!;
  parts.push(Math.min(Math.floor(first / 40), 2));
  parts.push(parts[0] === 2 ? first - 80 : first % 40);

  let value = 0;
  let started = false;
  for (let i = 1; i < contents.length; i++) {
    const byte = contents[i]!;
    // Arc components above 2^31 do not occur in certificate OIDs; a bound here
    // keeps a hostile encoding from silently wrapping to a different OID.
    if (value > 0x7fffff) throw new DerError("OBJECT IDENTIFIER arc too large");
    value = value * 128 + (byte & 0x7f);
    started = true;
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
      started = false;
    }
  }
  if (started) throw new DerError("OBJECT IDENTIFIER ends mid-arc");
  return parts.join(".");
}

/**
 * Unwrap a BIT STRING to its payload, requiring zero unused bits.
 *
 * Every BIT STRING in a certificate CooL reads — the signature value, the
 * subject public key — is byte-aligned, so a non-zero unused-bit count means
 * the input is not what we think it is.
 */
export function bitStringBytes(node: DerNode): Uint8Array {
  expectTag(node, TAG.BIT_STRING, "BIT STRING");
  if (node.contents.length === 0) throw new DerError("empty BIT STRING");
  if (node.contents[0] !== 0x00) throw new DerError("BIT STRING has unused bits");
  return node.contents.subarray(1);
}

/**
 * Unwrap the doubly-wrapped payload of a Contrast attestation extension.
 *
 * Contrast builds these with Go's `asn1.Marshal([]byte)` and hands the result to
 * `pkix.Extension.Value`, so the extension's `extnValue` OCTET STRING contains a
 * second OCTET STRING holding the claim bytes. Verified against certificates
 * issued by Contrast's own `internal/ca`.
 */
export function innerOctetString(extnValue: Uint8Array): Uint8Array {
  const node = readOnly(extnValue);
  expectTag(node, TAG.OCTET_STRING, "extension payload");
  return node.contents;
}

/** Read an INTEGER's contents as a bigint (two's complement, as DER encodes it). */
export function integerValue(node: DerNode): bigint {
  expectTag(node, TAG.INTEGER, "INTEGER");
  if (node.contents.length === 0) throw new DerError("empty INTEGER");
  let value = 0n;
  for (const byte of node.contents) value = (value << 8n) | BigInt(byte);
  if ((node.contents[0]! & 0x80) !== 0) {
    // Negative: subtract 2^bits. Certificate serial numbers are the only place
    // this can legitimately happen, and they are opaque identifiers to us.
    value -= 1n << BigInt(8 * node.contents.length);
  }
  return value;
}

/**
 * Unwrap the payload of a Contrast attestation extension that Go encoded as an
 * INTEGER (`extension.NewBigIntExtension`), returning it as a bigint.
 */
export function innerInteger(extnValue: Uint8Array): bigint {
  return integerValue(readOnly(extnValue));
}
