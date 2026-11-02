/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * A strict, minimal DER reader and writer — just what RFC 3161 timestamps,
 * AMD SEV-SNP certificate extensions and KMS public keys need.
 *
 * Strict means: definite lengths only, minimal length encoding, no trailing
 * bytes where a single element is expected, and a hard depth/size limit. Every
 * malformed input throws a {@link DerError}; callers turn that into a failed
 * check, never an uncaught exception. Fuzzed in tests/der-fuzz.test.ts.
 */

export class DerError extends Error {
  constructor(message: string) { super(message); this.name = "DerError"; }
}

export interface DerNode {
  /** The full identifier octet (class | constructed | number), single-byte tags only. */
  readonly tag: number;
  /** Header + content. */
  readonly raw: Uint8Array;
  readonly content: Uint8Array;
  readonly constructed: boolean;
  /** Children, for constructed nodes. */
  readonly children: readonly DerNode[];
}

const MAX_DEPTH = 32;

function readOne(buf: Uint8Array, offset: number, depth: number): { node: DerNode; next: number } {
  if (depth > MAX_DEPTH) throw new DerError("DER nesting too deep");
  if (offset + 2 > buf.length) throw new DerError("truncated DER header");
  const tag = buf[offset]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError("multi-byte DER tags are not supported");
  let len = buf[offset + 1]!;
  let p = offset + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0) throw new DerError("indefinite length is not DER");
    if (n > 4) throw new DerError("DER length too large");
    if (p + n > buf.length) throw new DerError("truncated DER length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p + i]!;
    if (buf[p] === 0 || len < 0x80) throw new DerError("non-minimal DER length");
    p += n;
  }
  const end = p + len;
  if (end > buf.length) throw new DerError("DER content runs past the end of the input");
  const content = buf.subarray(p, end);
  const constructed = (tag & 0x20) !== 0;
  const children: DerNode[] = [];
  if (constructed) {
    let q = 0;
    while (q < content.length) {
      const r = readOne(content, q, depth + 1);
      children.push(r.node);
      q = r.next;
    }
  }
  return { node: { tag, raw: buf.subarray(offset, end), content, constructed, children }, next: end };
}

/** Parse exactly one DER element; trailing bytes are an error. */
export function parseDer(buf: Uint8Array): DerNode {
  const { node, next } = readOne(buf, 0, 0);
  if (next !== buf.length) throw new DerError("trailing bytes after the DER element");
  return node;
}

export const TAG = {
  BOOLEAN: 0x01, INTEGER: 0x02, BIT_STRING: 0x03, OCTET_STRING: 0x04, NULL: 0x05, OID: 0x06,
  UTF8: 0x0c, PRINTABLE: 0x13, IA5: 0x16, UTC_TIME: 0x17, GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30, SET: 0x31,
} as const;

/** Assert a tag and return the node. */
export function expectTag(n: DerNode | undefined, tag: number, what: string): DerNode {
  if (!n) throw new DerError(`missing ${what}`);
  if (n.tag !== tag) throw new DerError(`${what}: expected tag 0x${tag.toString(16)}, got 0x${n.tag.toString(16)}`);
  return n;
}

export function child(n: DerNode, i: number, what: string): DerNode {
  const c = n.children[i];
  if (!c) throw new DerError(`missing ${what}`);
  return c;
}

export function decodeOid(n: DerNode): string {
  expectTag(n, TAG.OID, "OID");
  const b = n.content;
  if (b.length === 0) throw new DerError("empty OID");
  const arcs: number[] = [];
  let v = 0;
  for (let i = 0; i < b.length; i++) {
    if (v === 0 && b[i] === 0x80) throw new DerError("non-minimal OID arc");
    v = v * 128 + (b[i]! & 0x7f);
    if (v > Number.MAX_SAFE_INTEGER / 128) throw new DerError("OID arc too large");
    if (!(b[i]! & 0x80)) {
      if (arcs.length === 0) arcs.push(v < 80 ? Math.floor(v / 40) : 2, v < 80 ? v % 40 : v - 80);
      else arcs.push(v);
      v = 0;
    } else if (i === b.length - 1) throw new DerError("truncated OID");
  }
  return arcs.join(".");
}

/** Unsigned big-endian integer bytes (leading sign byte stripped). */
export function integerBytes(n: DerNode): Uint8Array {
  expectTag(n, TAG.INTEGER, "INTEGER");
  const b = n.content;
  if (b.length === 0) throw new DerError("empty INTEGER");
  if (b.length > 1 && ((b[0] === 0 && !(b[1]! & 0x80)) || (b[0] === 0xff && b[1]! & 0x80))) throw new DerError("non-minimal INTEGER");
  return b[0] === 0 && b.length > 1 ? b.subarray(1) : b;
}

export function integerValue(n: DerNode): number {
  const b = integerBytes(n);
  if (n.content[0]! & 0x80) throw new DerError("negative INTEGER");
  if (b.length > 6) throw new DerError("INTEGER too large for a number");
  let v = 0;
  for (const x of b) v = v * 256 + x;
  return v;
}

export function bitStringBytes(n: DerNode): Uint8Array {
  expectTag(n, TAG.BIT_STRING, "BIT STRING");
  if (n.content.length === 0 || n.content[0]! > 7) throw new DerError("bad BIT STRING");
  return n.content.subarray(1);
}

/** GeneralizedTime (YYYYMMDDHHMMSS[.fff]Z) or UTCTime → epoch ms. */
export function decodeTime(n: DerNode): number {
  const s = new TextDecoder().decode(n.content);
  let m: RegExpMatchArray | null;
  if (n.tag === TAG.GENERALIZED_TIME) {
    m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,9}))?Z$/);
    if (!m) throw new DerError(`bad GeneralizedTime ${s}`);
    const ms = m[7] ? Number(`0.${m[7]}`) * 1000 : 0;
    return Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!) + Math.floor(ms);
  }
  if (n.tag === TAG.UTC_TIME) {
    m = s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
    if (!m) throw new DerError(`bad UTCTime ${s}`);
    const yy = +m[1]!;
    return Date.UTC(yy < 50 ? 2000 + yy : 1900 + yy, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!);
  }
  throw new DerError("expected a time");
}

/* ── writer ───────────────────────────────────────────────────────────── */

export function tlv(tag: number, content: Uint8Array): Uint8Array {
  const n = content.length;
  let head: number[];
  if (n < 0x80) head = [tag, n];
  else {
    const bytes: number[] = [];
    for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
    head = [tag, 0x80 | bytes.length, ...bytes];
  }
  const out = new Uint8Array(head.length + n);
  out.set(head, 0);
  out.set(content, head.length);
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export const derSeq = (...parts: Uint8Array[]) => tlv(TAG.SEQUENCE, concat(...parts));
export const derSet = (...parts: Uint8Array[]) => tlv(TAG.SET, concat(...parts));
export const derOctets = (b: Uint8Array) => tlv(TAG.OCTET_STRING, b);
export const derNull = () => tlv(TAG.NULL, new Uint8Array(0));
export const derBool = (v: boolean) => tlv(TAG.BOOLEAN, Uint8Array.of(v ? 0xff : 0));

export function derInteger(b: Uint8Array | number): Uint8Array {
  let bytes: Uint8Array;
  if (typeof b === "number") {
    const a: number[] = [];
    for (let v = b; v > 0; v = Math.floor(v / 256)) a.unshift(v & 0xff);
    bytes = Uint8Array.from(a.length ? a : [0]);
  } else bytes = b;
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  const t = bytes.subarray(i);
  return tlv(TAG.INTEGER, t[0]! & 0x80 ? concat(Uint8Array.of(0), t) : t);
}

export function derOid(dotted: string): Uint8Array {
  const arcs = dotted.split(".").map(Number);
  const out = [40 * arcs[0]! + arcs[1]!];
  for (const arc of arcs.slice(2)) {
    const chunk = [arc & 0x7f];
    for (let v = Math.floor(arc / 128); v > 0; v = Math.floor(v / 128)) chunk.unshift((v & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return tlv(TAG.OID, Uint8Array.from(out));
}

export function derGeneralizedTime(ms: number): Uint8Array {
  const d = new Date(ms);
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  const s = `${p(d.getUTCFullYear(), 4)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(TAG.GENERALIZED_TIME, new TextEncoder().encode(s));
}

/** Find an X.509 v3 extension's extnValue (the OCTET STRING contents) by OID, from a certificate's DER. */
export function certificateExtensions(certDer: Uint8Array): Map<string, { critical: boolean; value: Uint8Array }> {
  const cert = parseDer(certDer);
  const tbs = child(cert, 0, "tbsCertificate");
  const out = new Map<string, { critical: boolean; value: Uint8Array }>();
  const extWrap = tbs.children.find((c) => c.tag === 0xa3);
  if (!extWrap) return out;
  const exts = expectTag(child(extWrap, 0, "extensions"), TAG.SEQUENCE, "extensions");
  for (const e of exts.children) {
    const id = decodeOid(child(e, 0, "extnID"));
    const critical = e.children.length === 3 && e.children[1]!.tag === TAG.BOOLEAN && e.children[1]!.content[0] !== 0;
    const value = expectTag(e.children[e.children.length - 1], TAG.OCTET_STRING, "extnValue").content;
    out.set(id, { critical, value });
  }
  return out;
}
