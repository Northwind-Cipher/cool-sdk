/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * RFC 3161 against a GENUINE DigiCert timestamp token (obtained with
 * `openssl ts -query`, verified with `openssl ts -verify`), then every way it
 * should fail. No network: the fixture is the TSA's real reply.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { X509Certificate, createHash, randomBytes } from "node:crypto";
import { createTimestampRequest, requestTimestamp, verifyTimestampToken } from "../src/platform/timestamp";
import { parseDer, decodeOid, integerBytes } from "../src/platform/der";
import { AMD_SNP_ROOTS } from "../src/snp/index";

const f = JSON.parse(readFileSync(new URL("./fixtures/rfc3161-digicert.json", import.meta.url), "utf8"));
const token = () => Uint8Array.from(Buffer.from(f.token_b64, "base64"));
const digest = Uint8Array.from(Buffer.from(f.digest_sha256, "hex"));
const anchor = { name: f.root.name as string, der: Uint8Array.from(Buffer.from(f.root.der_b64, "base64")) };
const opts = { digest, trustAnchors: [anchor], nonce: f.nonce as string };

test("rfc3161: the fixture digest is the SHA-256 of the stamped data, and the root is DigiCert Trusted Root G4", () => {
  assert.equal(createHash("sha256").update(f.data_utf8).digest("hex"), f.digest_sha256);
  assert.equal(createHash("sha256").update(anchor.der).digest("hex"), "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988");
});

test("rfc3161: a GENUINE DigiCert token verifies — imprint, nonce, signed attributes, RSA signature, TSA EKU, chain to the pinned root", () => {
  const r = verifyTimestampToken(token(), opts);
  assert.equal(r.outcome, "verified", JSON.stringify(r.reasons));
  assert.equal(r.gen_time, "2026-11-02T16:07:28.000Z");
  assert.equal(r.serial, f.serial);
  assert.equal(r.anchor, "DigiCert Trusted Root G4");
  assert.match(r.checks.chain.detail, /Timestamp Responder .* → .* → DigiCert Trusted Root G4/);
  assert.ok(r.limitations.some((l) => /revocation/.test(l)), "revocation is stated as unchecked");
});

test("rfc3161: a different digest, nonce or anchor fails", () => {
  const other = Uint8Array.from(digest); other[0] = other[0]! ^ (1);
  assert.equal(verifyTimestampToken(token(), { ...opts, digest: other }).checks.imprint.reason, "imprint_mismatch");
  assert.equal(verifyTimestampToken(token(), { ...opts, nonce: "01" }).checks.nonce.reason, "nonce_mismatch");
  const wrongAnchor = verifyTimestampToken(token(), { ...opts, trustAnchors: [{ name: "ARK-Milan", der: AMD_SNP_ROOTS.Milan.ark }] });
  assert.equal(wrongAnchor.checks.chain.reason, "untrusted_root");
  assert.equal(wrongAnchor.outcome, "invalid");
  const none = verifyTimestampToken(token(), { ...opts, trustAnchors: [] });
  assert.equal(none.outcome, "indeterminate", "no anchor: the signature cannot be attributed, so not verified");
});

test("rfc3161: altering the TSTInfo (e.g. genTime) breaks messageDigest; altering the signature breaks it", () => {
  const t = token();
  const at = Buffer.from(t).indexOf(Buffer.from("20261102160728"));
  assert.ok(at > 0);
  t[at + 3] = "7".charCodeAt(0); // 2026 → 2027
  const r = verifyTimestampToken(t, opts);
  assert.equal(r.checks.signed_attrs.reason, "message_digest_mismatch");
  assert.equal(r.outcome, "invalid");

  const s = token();
  s[s.length - 10] = s[s.length - 10]! ^ (0xff); // inside the RSA signature (last element of SignerInfo)
  assert.equal(verifyTimestampToken(s, opts).checks.signature.reason, "signature_invalid");
});

test("rfc3161: every byte that is signed, compared or used in the chain is authenticated (exhaustive single-bit flips)", () => {
  // CMS leaves two things unauthenticated by design: PKIStatus (0 granted / 1 grantedWithMods
  // are both acceptance) and certificates carried but not used — here DigiCert's copy of its
  // root, which the verifier replaces with the PINNED anchor. Everything else must fail.
  const t = token();
  const root = parseDer(t);
  const certs = root.children[1]!.children[1]!.children[0]!.children[3]!;
  // DigiCert ships its own (cross-signed) "Trusted Root G4"; the chain ends at the pinned anchor instead, so this copy is never used.
  const unusedRoot = certs.children.find((c) => /CN=DigiCert Trusted Root G4/.test(new X509Certificate(c.raw).subject))!;
  const start = unusedRoot.raw.byteOffset - t.byteOffset;
  const carrierOnly = (i: number) => i === 8 || (i >= start && i < start + unusedRoot.raw.length);
  const leaked: number[] = [];
  for (let i = 0; i < t.length; i++) {
    if (carrierOnly(i)) continue;
    const b = token(); b[i] = b[i]! ^ (0x01);
    if (verifyTimestampToken(b, opts).outcome === "verified") leaked.push(i);
  }
  assert.deepEqual(leaked, [], `bytes that changed without failing verification: ${leaked.slice(0, 20).join(",")}`);
});

test("rfc3161: garbage and random corruption never throw", () => {
  assert.equal(verifyTimestampToken(Uint8Array.of(0x30, 0x03, 1, 2), opts).outcome, "invalid");
  assert.equal(verifyTimestampToken(new Uint8Array(0), opts).checks.status.reason, "malformed");
  for (let i = 0; i < 400; i++) {
    const b = token();
    for (let k = 0; k < 1 + (i % 4); k++) b[randomBytes(2).readUInt16BE() % b.length] = b[randomBytes(2).readUInt16BE() % b.length]! ^ (1 + (randomBytes(1)[0]! % 255));
    assert.doesNotThrow(() => verifyTimestampToken(b, opts), `fuzz ${i}`);
  }
});

test("rfc3161: requests are well-formed DER with SHA-256, a nonce and certReq", async () => {
  const req = createTimestampRequest(digest, { nonce: Uint8Array.of(0x9a, 1, 2, 3) });
  const n = parseDer(req.der);
  assert.equal(n.children.length, 4);
  assert.equal(decodeOid(n.children[1]!.children[0]!.children[0]!), "2.16.840.1.101.3.4.2.1");
  assert.equal(Buffer.from(integerBytes(n.children[2]!)).toString("hex"), "9a010203");
  assert.equal(req.nonce, "9a010203");
  assert.throws(() => createTimestampRequest(new Uint8Array(20)));
  // requestTimestamp is the only networked call; with an injected fetch nothing leaves the process.
  let sent: Uint8Array | undefined;
  const fakeFetch = (async (_u: string, init: { body: Uint8Array }) => { sent = new Uint8Array(init.body); return new Response(Buffer.from(f.token_b64, "base64"), { status: 200 }); }) as unknown as typeof fetch;
  const out = await requestTimestamp("https://tsa.example", digest, { fetch: fakeFetch });
  assert.ok(sent && sent.length > 40);
  assert.equal(verifyTimestampToken(out.token, { digest, trustAnchors: [anchor] }).outcome, "verified");
});

test("rfc3161: oversized input is refused before parsing", () => {
  const r = verifyTimestampToken(new Uint8Array(70_000), opts);
  assert.equal(r.outcome, "invalid");
  assert.match(r.checks.status.detail, /limit/);
});
