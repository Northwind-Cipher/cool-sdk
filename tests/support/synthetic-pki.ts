/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * A synthetic, Nitro-shaped test PKI, built fresh in memory on every run.
 *
 * root CA → intermediate CA → leaf, all P-384 / ecdsa-with-SHA384, so the
 * Nitro verifier's positive path can be exercised with PCRs and keys the tests
 * control. NOT AWS: the verifier only trusts this root when a test passes it
 * explicitly as a trust bundle.
 *
 * Built here rather than committed because the repository's security policy
 * forbids committing key material (`.github/workflows/security.yml`). Nothing
 * here touches disk; the keys exist only for the life of the test process.
 *
 * The DER encoder is the minimum X.509 v3 needs: names with one CN, UTCTime
 * validity, basicConstraints and keyUsage. node:crypto parses the result, which
 * is the check that it is well-formed.
 */
import { X509Certificate, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";

const tlv = (tag: number, content: Uint8Array): Uint8Array => {
  const n = content.length;
  const len = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
  return Uint8Array.from([tag, ...len, ...content]);
};
const cat = (...parts: Uint8Array[]): Uint8Array => Uint8Array.from(parts.flatMap((p) => [...p]));
const seq = (...parts: Uint8Array[]) => tlv(0x30, cat(...parts));
const set = (...parts: Uint8Array[]) => tlv(0x31, cat(...parts));
const bool = (v: boolean) => tlv(0x01, Uint8Array.from([v ? 0xff : 0x00]));
const octets = (b: Uint8Array) => tlv(0x04, b);
const bits = (unused: number, b: Uint8Array) => tlv(0x03, cat(Uint8Array.from([unused]), b));
const utf8 = (s: string) => tlv(0x0c, new TextEncoder().encode(s));
const explicit = (n: number, inner: Uint8Array) => tlv(0xa0 + n, inner);

function integer(b: Uint8Array): Uint8Array {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  const trimmed = b.subarray(i);
  return tlv(0x02, trimmed[0]! & 0x80 ? cat(Uint8Array.from([0]), trimmed) : trimmed);
}

function oid(dotted: string): Uint8Array {
  const arcs = dotted.split(".").map(Number);
  const out = [40 * arcs[0]! + arcs[1]!];
  for (const arc of arcs.slice(2)) {
    const chunk = [arc & 0x7f];
    for (let v = arc >> 7; v > 0; v >>= 7) chunk.unshift((v & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return tlv(0x06, Uint8Array.from(out));
}

function utcTime(date: Date): Uint8Array {
  const p = (n: number) => String(n).padStart(2, "0");
  const s = `${p(date.getUTCFullYear() % 100)}${p(date.getUTCMonth() + 1)}${p(date.getUTCDate())}` +
    `${p(date.getUTCHours())}${p(date.getUTCMinutes())}${p(date.getUTCSeconds())}Z`;
  return tlv(0x17, new TextEncoder().encode(s));
}

const ECDSA_SHA384 = seq(oid("1.2.840.10045.4.3.3"));
const name = (cn: string) => seq(set(seq(oid("2.5.4.3"), utf8(cn))));

function certificate(opts: {
  subject: string;
  issuer: string;
  subjectKey: KeyObject;
  issuerKey: KeyObject;
  ca: boolean;
  notBefore: Date;
  notAfter: Date;
}): Uint8Array {
  const basicConstraints = seq(oid("2.5.29.19"), bool(true), octets(opts.ca ? seq(bool(true)) : seq()));
  // keyCertSign + cRLSign for CAs; digitalSignature for the leaf.
  const keyUsage = seq(oid("2.5.29.15"), bool(true), octets(opts.ca ? bits(1, Uint8Array.from([0x06])) : bits(7, Uint8Array.from([0x80]))));
  const tbs = seq(
    explicit(0, integer(Uint8Array.from([2]))),
    integer(randomBytes(16)),
    ECDSA_SHA384,
    name(opts.issuer),
    seq(utcTime(opts.notBefore), utcTime(opts.notAfter)),
    name(opts.subject),
    new Uint8Array(opts.subjectKey.export({ type: "spki", format: "der" })),
    explicit(3, seq(basicConstraints, keyUsage)),
  );
  const signature = sign("sha384", tbs, opts.issuerKey);
  return seq(tbs, ECDSA_SHA384, bits(0, new Uint8Array(signature)));
}

export interface SyntheticPki {
  readonly root: Uint8Array;
  readonly intermediate: Uint8Array;
  readonly leaf: Uint8Array;
  /** Signs synthetic attestation documents. In memory only. */
  readonly leafKey: KeyObject;
}

/** Build root → intermediate → leaf, valid 2026-01-01 to 2046-01-01. */
export function syntheticNitroPki(): SyntheticPki {
  const ec = () => generateKeyPairSync("ec", { namedCurve: "secp384r1" });
  const [root, inter, leaf] = [ec(), ec(), ec()];
  const notBefore = new Date(Date.UTC(2026, 0, 1));
  const notAfter = new Date(Date.UTC(2046, 0, 1));
  const out: SyntheticPki = {
    root: certificate({ subject: "synthetic.nitro-root", issuer: "synthetic.nitro-root", subjectKey: root.publicKey, issuerKey: root.privateKey, ca: true, notBefore, notAfter }),
    intermediate: certificate({ subject: "synthetic.nitro-intermediate", issuer: "synthetic.nitro-root", subjectKey: inter.publicKey, issuerKey: root.privateKey, ca: true, notBefore, notAfter }),
    leaf: certificate({ subject: "synthetic.nitro-enclave", issuer: "synthetic.nitro-intermediate", subjectKey: leaf.publicKey, issuerKey: inter.privateKey, ca: false, notBefore, notAfter }),
    leafKey: leaf.privateKey,
  };
  // Parse everything once, so a malformed certificate fails here, loudly,
  // rather than as a confusing verifier result in some later test.
  for (const der of [out.root, out.intermediate, out.leaf]) new X509Certificate(der);
  return out;
}
