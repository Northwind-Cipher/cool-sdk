/**
 * The capture queue — the promises the SDK makes to the application it lives in.
 *
 * Every assertion here is a promise made on the marketing page, turned into a
 * test that would fail if we broke it:
 *
 *   • `capture()` never throws, whatever the sink does;
 *   • it never blocks, so its cost is bounded and measured;
 *   • it never grows without bound — the oldest events go first, and the loss is
 *     counted rather than silent;
 *   • retries happen, and then it gives up rather than queuing forever;
 *   • `close()` drains what it can.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { CaptureQueue } from "../src/phala/index";

/** A timer that fires immediately, so the tests are deterministic and fast. */
const instant = (fn: () => void): unknown => {
  setTimeout(fn, 0);
  return 0;
};

test("capture() never throws, even when the sink always fails", async () => {
  const dropped: string[] = [];
  const queue = new CaptureQueue<string>({
    send: () => Promise.reject(new Error("evidence plane unreachable")),
    maxRetries: 1,
    flushMs: 0,
    setTimer: instant,
    onDrop: (event, reason) => dropped.push(`${event}:${reason}`),
  });

  assert.doesNotThrow(() => queue.capture("a"));
  await queue.close();

  assert.equal(queue.stats().sent, 0);
  assert.equal(queue.stats().dropped, 1);
  assert.equal(queue.stats().failures, 2, "one attempt plus one retry");
  assert.match(dropped[0] ?? "", /unreachable/);
  assert.match(queue.stats().lastError ?? "", /unreachable/);
});

test("a full queue drops the OLDEST events and counts them", async () => {
  const sent: string[][] = [];
  const dropped: string[] = [];
  const queue = new CaptureQueue<string>({
    send: async (batch) => {
      sent.push([...batch]);
    },
    maxQueue: 3,
    batchSize: 10,
    flushMs: 1000, // never fires during the test; we flush by hand
    setTimer: () => 0,
    onDrop: (event) => dropped.push(event),
  });

  for (const event of ["1", "2", "3", "4", "5"]) queue.capture(event);
  assert.deepEqual(dropped, ["1", "2"], "the newest events describe the situation you are in");

  await queue.flush();
  assert.deepEqual(sent, [["3", "4", "5"]]);
  assert.equal(queue.stats().highWater, 3);
  assert.equal(queue.stats().dropped, 2);
});

test("a flaky sink is retried, then succeeds", async () => {
  let attempts = 0;
  const queue = new CaptureQueue<string>({
    send: async () => {
      attempts++;
      if (attempts < 3) throw new Error("temporary");
    },
    maxRetries: 3,
    flushMs: 0,
    setTimer: instant,
  });

  queue.capture("x");
  await queue.close();

  assert.equal(attempts, 3);
  assert.equal(queue.stats().sent, 1);
  assert.equal(queue.stats().dropped, 0);
  assert.equal(queue.stats().failures, 2);
});

test("batches respect batchSize and preserve order", async () => {
  const batches: string[][] = [];
  const queue = new CaptureQueue<string>({
    send: async (batch) => {
      batches.push([...batch]);
    },
    batchSize: 2,
    flushMs: 1000,
    setTimer: () => 0,
  });

  for (const event of ["a", "b", "c", "d", "e"]) queue.capture(event);
  await queue.flush();

  assert.deepEqual(batches, [["a", "b"], ["c", "d"], ["e"]]);
  assert.equal(queue.stats().batches, 3);
  assert.equal(queue.stats().sent, 5);
});

test("the cost of capture is measured, not asserted", async () => {
  const queue = new CaptureQueue<number>({
    send: async () => {},
    flushMs: 1000,
    setTimer: () => 0,
  });

  for (let i = 0; i < 200; i++) queue.capture(i);
  const stats = queue.stats();

  assert.ok(stats.p50Ms >= 0);
  assert.ok(stats.p99Ms >= stats.p50Ms);
  // A generous ceiling: the claim is "off the request path", and anything near a
  // millisecond per enqueue would mean the queue is doing work it should not.
  assert.ok(stats.p99Ms < 5, `p99 was ${stats.p99Ms}ms`);
  await queue.flush();
});

test("a closed queue accepts nothing further", async () => {
  const queue = new CaptureQueue<string>({
    send: async () => {},
    flushMs: 0,
    setTimer: instant,
  });
  queue.capture("before");
  await queue.close();
  queue.capture("after");
  await queue.flush();
  assert.equal(queue.stats().sent, 1);
  assert.equal(queue.stats().queued, 0);
});
