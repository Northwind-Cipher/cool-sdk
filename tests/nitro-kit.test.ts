/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The Nitro deployment kit end to end over real TCP sockets (what socat
 * bridges to vsock in an enclave), with a SYNTHETIC NSM. The artifact says
 * `synthetic: true` — only a run on real hardware against the pinned AWS root
 * can produce `synthetic: false`.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { connect } from "node:net";
import { serveEnclave, collectFromEnclave, trustBundleFromDer, encodeFrame, FrameDecoder, FrameType, type NsmSource } from "../src/nitro/index";
import { syntheticAttestation, syntheticNitroPki, pcrHex } from "./support/synthetic-pki";

const PKI = syntheticNitroPki();
const BUNDLE = trustBundleFromDer("synthetic-test-pki", "per-run", "tests/support/synthetic-pki.ts", [{ name: "synthetic.nitro-root", der: PKI.root }]);
const POLICY = { id: "cool-validation-enclave", version: "1", source: "nitro-cli build-enclave measurements", pcrs: { 0: pcrHex("10"), 1: pcrHex("11"), 2: pcrHex("12") }, pcr8: "not_applicable" as const };
const nsm: NsmSource = { attest: async (req) => syntheticAttestation(PKI, { ...req, timestamp: Date.now() - 1_000 }) };

test("nitro kit: enclave server + host collector produce a passing validation artifact (synthetic NSM)", async () => {
  const server = await serveEnclave({ nsm, port: 0 });
  try {
    const a = await collectFromEnclave({ port: server.port, policy: POLICY, trustBundle: BUNDLE, count: 4, environment: { instance_type: "test" } });
    assert.equal(a.passed, true, JSON.stringify(a.attestation.reasons) + JSON.stringify(a.receipts.map((r) => r.reasons)));
    assert.equal(a.synthetic, true, "not the AWS root → labelled synthetic");
    assert.equal(a.receipts.length, 4);
    assert.ok(a.receipts.every((r) => r.overall_status === "pass" && r.envelope.attestation?.platform === "aws-nitro"));
    assert.deepEqual(a.receipts.map((r) => r.envelope.core.sequence?.number), [0, 1, 2, 3]);
    assert.equal(a.attestation.checks["freshness"]?.status, "pass");
  } finally { await server.close(); }
});

test("nitro kit: a PCR policy that does not match → passed false, and no receipt is trusted", async () => {
  const server = await serveEnclave({ nsm, port: 0 });
  try {
    const a = await collectFromEnclave({ port: server.port, policy: { ...POLICY, pcrs: { 0: pcrHex("aa"), 1: pcrHex("11"), 2: pcrHex("12") } }, trustBundle: BUNDLE });
    assert.equal(a.passed, false);
    assert.equal(a.receipts.length, 0);
    assert.notEqual(a.attestation.overall_status, "pass");
  } finally { await server.close(); }
});

test("nitro kit: against the pinned AWS root a synthetic enclave fails — the kit cannot fake a real run", async () => {
  const server = await serveEnclave({ nsm, port: 0 });
  try {
    const a = await collectFromEnclave({ port: server.port, policy: POLICY });
    assert.equal(a.synthetic, false);
    assert.equal(a.passed, false, "synthetic attestation must not pass against AWS_NitroEnclaves_Root-G1");
  } finally { await server.close(); }
});

test("nitro kit: one key per enclave instance — a second hello is refused", async () => {
  const server = await serveEnclave({ nsm, port: 0 });
  try {
    await collectFromEnclave({ port: server.port, policy: POLICY, trustBundle: BUNDLE, count: 1 });
    const sock = connect({ port: server.port });
    await new Promise<void>((r) => sock.once("connect", () => r()));
    const reply = await new Promise<{ type: number; body: { message?: string } }>((resolve) => {
      const d = new FrameDecoder();
      sock.on("data", (c: Buffer) => { const f = d.push(new Uint8Array(c))[0]; if (f) resolve({ type: f.type, body: JSON.parse(Buffer.from(f.payload).toString()) }); });
      sock.write(encodeFrame(FrameType.hello, new TextEncoder().encode(JSON.stringify({ nonce: Buffer.alloc(32, 1).toString("base64") }))));
    });
    sock.destroy();
    assert.equal(reply.type, FrameType.error);
    assert.match(reply.body.message ?? "", /already has a key/);
  } finally { await server.close(); }
});
