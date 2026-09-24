/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Bitcoin anchoring.
 *
 * The format tests use a fixed proof rather than the network, so they fail when
 * the serialiser drifts rather than when a calendar is down. The one test that
 * exercises the calendar wire contract runs against local calendar servers, so
 * the suite is deterministic and never depends on the network.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import {
  anchorHead,
  attachAnchor,
  base64ToBytes,
  bytesToBase64,
  parseProof,
  reachable,
  serialiseProof,
  submitToCalendars,
  verifyAnchor,
  verifyReceiptV2,
} from "../src/phala/index";
import type { AnchorProof, ReceiptV2 } from "../src/phala/index";
import { CoolTee } from "../src/phala/index";

/**
 * A real proof of a real head, submitted to the four public calendars and then
 * checked byte-for-byte against the reference `ots` serialiser. Frozen here so
 * the format is pinned: if a change makes us write different bytes, this test
 * says so, rather than a stranger's verifier saying so months later.
 */
const FIXTURE_DIGEST = "22205a586b7629a83519d5ff8c4d50ff3b858a7922cf8c34f757dc91e375ae11";
const FIXTURE_PROOF = readFileSync(
  join(import.meta.dirname, "fixtures", "head.ots.base64"),
  "utf8",
).trim();

test("a proof round-trips byte for byte", () => {
  const bytes = base64ToBytes(FIXTURE_PROOF);
  const parsed = parseProof(bytes);
  assert.equal(
    bytesToBase64(serialiseProof(parsed.digest, parsed.timestamp)),
    FIXTURE_PROOF,
    "serialisation drifted — proofs would no longer match what `ots` writes",
  );
});

test("the proof commits to the digest it claims, and the chain is recomputed", () => {
  const parsed = parseProof(base64ToBytes(FIXTURE_PROOF));
  assert.equal(
    Buffer.from(parsed.digest).toString("hex"),
    FIXTURE_DIGEST,
    "the proof is about the head we think it is",
  );
  // Every intermediate message is derived by applying the ops, never read from
  // the file — so a tampered proof cannot parse into something self-consistent.
  const found = reachable(parsed.timestamp);
  assert.ok(found.length > 0);
  assert.ok(found.every((entry) => entry.commitment.length > 0));
});

test("a truncated or corrupt proof is refused, not half-read", () => {
  const bytes = base64ToBytes(FIXTURE_PROOF);
  assert.throws(() => parseProof(bytes.subarray(0, bytes.length - 10)), /ended mid|unknown/i);
  const wrongMagic = Uint8Array.from(bytes);
  wrongMagic[3] = 0x00;
  assert.throws(() => parseProof(wrongMagic), /OpenTimestamps/);
});

test("a pending proof is pending, never a pass", async () => {
  const parsed = parseProof(base64ToBytes(FIXTURE_PROOF));
  const check = await verifyAnchor(parsed.digest, parsed.timestamp);
  assert.equal(check.status, "submitted");
  assert.equal(check.heights.length, 0);
  assert.ok(check.calendars.length > 0);
});

test("a proof about a different head is refused", async () => {
  const parsed = parseProof(base64ToBytes(FIXTURE_PROOF));
  const other = new Uint8Array(createHash("sha256").update("some other head").digest());
  const check = await verifyAnchor(other, parsed.timestamp);
  assert.equal(check.status, "fail");
  assert.match(check.detail, /different digest/);
});

test("a Bitcoin attestation only passes against a matching block header", async () => {
  // Build a proof whose commitment is a known value, then answer the header
  // lookup with that value reversed — the byte order a block explorer shows.
  const digest = new Uint8Array(createHash("sha256").update("head").digest());
  const timestamp = {
    msg: digest,
    attestations: [{ kind: "bitcoin" as const, height: 800_000 }],
    ops: [],
  };
  const displayed = Buffer.from(Uint8Array.from(digest).reverse()).toString("hex");

  const good = await verifyAnchor(digest, timestamp, async () => displayed);
  assert.equal(good.status, "confirmed");
  assert.deepEqual(good.heights, [800_000]);

  const bad = await verifyAnchor(digest, timestamp, async () => "00".repeat(32));
  assert.equal(bad.status, "fail", "a block with a different merkle root must not pass");

  const missing = await verifyAnchor(digest, timestamp, async () => null);
  assert.equal(missing.status, "pending", "an unreadable header is pending, never a pass");
});

test("an anchor cannot be attached to a receipt it does not cover", async () => {
  const cool = await CoolTee.connect({ capture: { flushMs: 1 } });
  const receipt = (await cool.change({
    kind: "prompt",
    ref: "anchor#test",
    environment: "test",
    after: "anchor me",
    actor: { id: "test", method: "cli" },
  })) as ReceiptV2;
  await cool.close();

  const wrong: AnchorProof = {
    kind: "opentimestamps",
    chain: "bitcoin",
    target: `mh:sha256:${"11".repeat(32)}` as AnchorProof["target"],
    tree_size: receipt.sth!.tree_size,
    proof: FIXTURE_PROOF,
    calendars: ["https://alice.btc.calendar.opentimestamps.org"],
    submitted_at: new Date().toISOString(),
    heights: [],
  };
  assert.throws(() => attachAnchor(receipt, wrong), /refusing to attach/);

  const rightHead: AnchorProof = { ...wrong, target: receipt.sth!.root_hash };
  const anchored = attachAnchor(receipt, rightHead);
  assert.equal(anchored.anchor?.target, receipt.sth!.root_hash);

  // The proof file is for a different digest than the head it now claims, and
  // the verifier catches that even though the metadata lines up.
  const verdict = await verifyReceiptV2(anchored);
  assert.equal(verdict.checks.anchor.status, "fail");
  assert.match(verdict.checks.anchor.detail, /does not cover this tree head/);
});

test("a receipt with no anchor says so plainly", async () => {
  const cool = await CoolTee.connect({ capture: { flushMs: 1 } });
  const receipt = await cool.change({
    kind: "prompt",
    ref: "anchor#none",
    environment: "test",
    after: "unanchored",
    actor: { id: "test", method: "cli" },
  });
  await cool.close();

  const verdict = await verifyReceiptV2(receipt);
  assert.equal(verdict.checks.anchor.status, "absent");
  assert.match(verdict.checks.anchor.detail, /never submitted/);
  assert.equal(verdict.ok, true, "an unanchored receipt is still a valid receipt");
});

/**
 * A local stand-in for an OpenTimestamps calendar, implementing the wire
 * contract `submit()` speaks: `POST /digest` with the raw 32-byte digest and
 * `Accept: application/vnd.opentimestamps.v1`, answered with a serialised
 * timestamp tree (here: a single "pending" attestation naming the calendar, which
 * is what a real calendar returns before Bitcoin aggregation). The reply is built
 * with the same serialiser the fixture round-trip test pins byte-for-byte.
 */
async function startCalendar(behaviour: "accept" | "refuse"): Promise<{ url: string; requests: { digest: string; accept: string | undefined; type: string | undefined }[]; close(): Promise<void> }> {
  const requests: { digest: string; accept: string | undefined; type: string | undefined }[] = [];
  let self = "";
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      requests.push({ digest: body.toString("hex"), accept: req.headers["accept"], type: req.headers["content-type"] });
      if (behaviour === "refuse" || req.method !== "POST" || req.url !== "/digest" || body.length !== 32) {
        res.writeHead(behaviour === "refuse" ? 503 : 400).end();
        return;
      }
      const digest = new Uint8Array(body);
      const stamp = { msg: digest, attestations: [{ kind: "pending" as const, uri: self }], ops: [] };
      // serialiseProof = 31-byte magic + version(1) + hash-op(1) + 32-byte digest + timestamp tree.
      const reply = serialiseProof(digest, stamp).subarray(31 + 1 + 1 + 32);
      res.writeHead(200, { "content-type": "application/vnd.opentimestamps.v1" }).end(Buffer.from(reply));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  self = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { url: self, requests, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}

test("calendars accept a head: submission, refusal handling and the resulting proof (local calendars, real wire contract)", async () => {
  const good1 = await startCalendar("accept");
  const good2 = await startCalendar("accept");
  const down = await startCalendar("refuse");
  try {
    const digest = new Uint8Array(
      createHash("sha256").update(`cool test ${process.hrtime.bigint()}`).digest(),
    );
    const calendars = [good1.url, good2.url, down.url];
    const result = await submitToCalendars(digest, { calendars });
    assert.equal(result.accepted.length, 2, "two independent calendars answered");
    assert.equal(result.refused.length, 1, "the failing calendar is recorded, not thrown");
    assert.match(result.refused[0]!.reason, /HTTP 503/);
    for (const cal of [good1, good2]) {
      assert.equal(cal.requests[0]?.digest, Buffer.from(digest).toString("hex"), "the calendar received exactly the digest");
      assert.equal(cal.requests[0]?.accept, "application/vnd.opentimestamps.v1");
    }

    const proof = await anchorHead(`mh:sha256:${Buffer.from(digest).toString("hex")}`, 1, { calendars });
    assert.equal(proof.chain, "bitcoin");
    assert.equal(proof.heights.length, 0, "nothing is confirmed the second it is submitted");
    assert.deepEqual([...proof.calendars].sort(), [good1.url, good2.url].sort());
    const parsed = parseProof(base64ToBytes(proof.proof));
    assert.equal(Buffer.from(parsed.digest).toString("hex"), Buffer.from(digest).toString("hex"));
    const check = await verifyAnchor(parsed.digest, parsed.timestamp);
    assert.equal(check.status, "submitted", "pending is never reported as confirmed");
    assert.deepEqual([...check.calendars].sort(), [good1.url, good2.url].sort());

    // Every calendar down: submission fails loudly rather than yielding an empty proof.
    await assert.rejects(() => submitToCalendars(digest, { calendars: [down.url] }), /no calendar accepted/);
  } finally {
    await Promise.all([good1.close(), good2.close(), down.close()]);
  }
});
