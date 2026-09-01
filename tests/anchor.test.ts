/**
 * Bitcoin anchoring.
 *
 * The format tests use a fixed proof rather than the network, so they fail when
 * the serialiser drifts rather than when a calendar is down. The one test that
 * does talk to the calendars is opt-in — `COOL_TEST_NETWORK=1` — because a test
 * suite that fails on a train is a test suite people stop running.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
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

test(
  "the public calendars accept a real head",
  { skip: process.env["COOL_TEST_NETWORK"] !== "1" },
  async () => {
    const digest = new Uint8Array(
      createHash("sha256").update(`cool test ${process.hrtime.bigint()}`).digest(),
    );
    const result = await submitToCalendars(digest);
    assert.ok(result.accepted.length >= 2, "at least two independent calendars answered");

    const proof = await anchorHead(`mh:sha256:${Buffer.from(digest).toString("hex")}`, 1);
    assert.equal(proof.chain, "bitcoin");
    assert.equal(proof.heights.length, 0, "nothing is confirmed the second it is submitted");
    assert.doesNotThrow(() => parseProof(base64ToBytes(proof.proof)));
  },
);
