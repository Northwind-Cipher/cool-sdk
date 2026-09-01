/**
 * The capture queue: out-of-band, bounded, and fail-open by construction.
 *
 * This is the piece that decides whether CooL is adoptable. An evidence system
 * that adds latency to a request gets removed the first time a page loads slowly;
 * one that can block a request when the evidence plane is down gets removed
 * during the first incident. So `capture()` does exactly three things — stamp,
 * push, return — and every hard part (batching, retry, backpressure, transport
 * failure) happens on a timer behind it.
 *
 * The guarantees, stated as the things this class refuses to do:
 *
 *   • It never awaits on the caller's path. `capture()` is synchronous and
 *     returns after an array push.
 *   • It never throws into the caller. A dead sink, a closed RA-TLS channel and
 *     a serialization bug all become counters, not exceptions.
 *   • It never grows without bound. Past `maxQueue` the OLDEST events are
 *     dropped and counted — a memory leak in an evidence agent would take the
 *     application down with it, which is the failure mode this exists to avoid.
 *
 * What it costs is honestly reported rather than asserted: {@link CaptureQueue.stats}
 * carries the measured enqueue cost, and dropped events are a first-class number
 * on the dashboard. Silent loss would make the whole record untrustworthy.
 */

/** Counters and measured cost. Everything here is meant to be surfaced. */
export interface CaptureStats {
  /** Currently waiting to be sent. */
  readonly queued: number;
  /** Successfully handed to the sink. */
  readonly sent: number;
  /** Dropped: queue overflow, or retries exhausted. */
  readonly dropped: number;
  /** Sink rejections (each one may still be retried). */
  readonly failures: number;
  readonly batches: number;
  /** Deepest the queue ever got — the number that sizes a production deployment. */
  readonly highWater: number;
  /** Median enqueue cost in milliseconds, as measured on this machine. */
  readonly p50Ms: number;
  /** 99th-percentile enqueue cost in milliseconds. */
  readonly p99Ms: number;
  readonly lastError: string | null;
}

/** Options for {@link CaptureQueue}. */
export interface CaptureOptions<T> {
  /** Where batches go — normally an {@link import("./ratls").AttestedChannel}. */
  readonly send: (batch: readonly T[]) => Promise<void>;
  /** Maximum events held in memory. Default 2048. */
  readonly maxQueue?: number;
  /** Flush interval in milliseconds. Default 200. */
  readonly flushMs?: number;
  /** Maximum events per batch. Default 32. */
  readonly batchSize?: number;
  /** Retries per batch before the events are dropped. Default 2. */
  readonly maxRetries?: number;
  /** Called for every dropped event, so loss is observable rather than silent. */
  readonly onDrop?: (event: T, reason: string) => void;
  /** Called after each successful batch — used by the console's live feed. */
  readonly onSent?: (batch: readonly T[]) => void;
  /** Injectable timer, for tests and for the deterministic demo runner. */
  readonly setTimer?: (fn: () => void, ms: number) => unknown;
  readonly clearTimer?: (handle: unknown) => void;
  /** Injectable monotonic clock in milliseconds. Default `performance.now`. */
  readonly now?: () => number;
}

const DEFAULT_SAMPLES = 512;

export class CaptureQueue<T> {
  private readonly queue: T[] = [];
  private readonly samples: number[] = [];
  private readonly options: Required<
    Pick<CaptureOptions<T>, "send" | "maxQueue" | "flushMs" | "batchSize" | "maxRetries">
  >;
  private readonly onDrop: ((event: T, reason: string) => void) | undefined;
  private readonly onSent: ((batch: readonly T[]) => void) | undefined;
  private readonly setTimer: (fn: () => void, ms: number) => unknown;
  private readonly clearTimer: (handle: unknown) => void;
  private readonly now: () => number;

  private timer: unknown = null;
  private inFlight: Promise<void> | null = null;
  private closed = false;

  private sent = 0;
  private dropped = 0;
  private failures = 0;
  private batches = 0;
  private highWater = 0;
  private lastError: string | null = null;

  constructor(options: CaptureOptions<T>) {
    this.options = {
      send: options.send,
      maxQueue: options.maxQueue ?? 2048,
      flushMs: options.flushMs ?? 200,
      batchSize: options.batchSize ?? 32,
      maxRetries: options.maxRetries ?? 2,
    };
    this.onDrop = options.onDrop;
    this.onSent = options.onSent;
    this.setTimer =
      options.setTimer ?? ((fn, ms) => globalThis.setTimeout(fn, ms) as unknown);
    this.clearTimer =
      options.clearTimer ?? ((handle) => globalThis.clearTimeout(handle as never));
    this.now =
      options.now ??
      (typeof performance !== "undefined" ? () => performance.now() : () => Date.now());
  }

  /**
   * Enqueue an event. Synchronous, non-throwing, O(1).
   *
   * This is the ONLY method on the customer's hot path, and the measured cost of
   * this call is what ends up in `p99Ms`.
   */
  capture(event: T): void {
    if (this.closed) return;
    const started = this.now();
    try {
      if (this.queue.length >= this.options.maxQueue) {
        // Drop the OLDEST: during a transport outage the newest events describe
        // the situation you are actually in, and an unbounded queue would take
        // the host application down alongside the evidence plane.
        const evicted = this.queue.shift();
        this.dropped++;
        if (evicted !== undefined) this.onDrop?.(evicted, "queue overflow");
      }
      this.queue.push(event);
      if (this.queue.length > this.highWater) this.highWater = this.queue.length;
      this.schedule();
    } catch (error) {
      // Even the enqueue path refuses to propagate. An evidence agent must not
      // be able to fail a customer's request.
      this.failures++;
      this.lastError = (error as Error).message;
    } finally {
      this.record(this.now() - started);
    }
  }

  private record(ms: number): void {
    this.samples.push(ms);
    if (this.samples.length > DEFAULT_SAMPLES) this.samples.shift();
  }

  private schedule(): void {
    if (this.timer !== null || this.closed) return;
    this.timer = this.setTimer(() => {
      this.timer = null;
      void this.flush();
    }, this.options.flushMs);
  }

  /**
   * Drain the queue. Safe to call at any time; concurrent calls share the same
   * in-flight drain rather than racing it.
   */
  flush(): Promise<void> {
    if (this.inFlight) return this.inFlight;
    this.inFlight = this.drain().finally(() => {
      this.inFlight = null;
    });
    return this.inFlight;
  }

  private async drain(): Promise<void> {
    while (this.queue.length > 0) {
      const batch = this.queue.splice(0, this.options.batchSize);
      let attempt = 0;
      for (;;) {
        try {
          await this.options.send(batch);
          this.sent += batch.length;
          this.batches++;
          this.onSent?.(batch);
          break;
        } catch (error) {
          this.failures++;
          this.lastError = (error as Error).message;
          if (attempt >= this.options.maxRetries) {
            this.dropped += batch.length;
            for (const event of batch) this.onDrop?.(event, this.lastError ?? "send failed");
            break;
          }
          attempt++;
          await new Promise<void>((resolve) => {
            this.setTimer(resolve, this.options.flushMs * attempt);
          });
        }
      }
    }
  }

  /** Stop accepting events and flush whatever is already queued. */
  async close(): Promise<void> {
    this.closed = true;
    if (this.timer !== null) {
      this.clearTimer(this.timer);
      this.timer = null;
    }
    await this.flush();
  }

  stats(): CaptureStats {
    const sorted = [...this.samples].sort((a, b) => a - b);
    const at = (q: number): number => {
      if (sorted.length === 0) return 0;
      const index = Math.min(sorted.length - 1, Math.floor(q * sorted.length));
      return sorted[index] ?? 0;
    };
    return {
      queued: this.queue.length,
      sent: this.sent,
      dropped: this.dropped,
      failures: this.failures,
      batches: this.batches,
      highWater: this.highWater,
      p50Ms: at(0.5),
      p99Ms: at(0.99),
      lastError: this.lastError,
    };
  }
}
