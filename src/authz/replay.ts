/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Replay resistance: a nonce is consumed at most once, at the enforcement
 * boundary, atomically.
 *
 *   consumed     first use — the action may proceed
 *   replayed     already used (or racing a concurrent use that won)
 *   unavailable  the store could not answer — the caller must NOT permit
 *
 * Timestamps alone do not stop replay; expiry bounds how long a nonce must be
 * remembered. Idempotent retries are handled above this layer by returning the
 * recorded result for the same request id, never by consuming twice.
 */
import { mkdirSync, openSync, closeSync, writeSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";

export type ConsumeResult = "consumed" | "replayed" | "unavailable";

export interface NonceStore {
  consume(scope: string, nonce: string, requestId: string): Promise<ConsumeResult>;
}

/** In-process store. Atomic because JavaScript runs each consume to completion. */
export class MemoryNonceStore implements NonceStore {
  readonly #used = new Map<string, string>();

  async consume(scope: string, nonce: string, requestId: string): Promise<ConsumeResult> {
    const k = `${scope}\0${nonce}`;
    if (this.#used.has(k)) return "replayed";
    this.#used.set(k, requestId);
    return "consumed";
  }
}

/**
 * Cross-process store on a local filesystem: one file per nonce, created with
 * O_EXCL (`wx`) so exactly one process can win. Any error other than "already
 * exists" is `unavailable`, never a silent permit.
 */
export class FileNonceStore implements NonceStore {
  constructor(readonly dir: string) {
    mkdirSync(dir, { recursive: true });
  }

  async consume(scope: string, nonce: string, requestId: string): Promise<ConsumeResult> {
    const name = createHash("sha256").update(`${scope}\0${nonce}`).digest("hex");
    try {
      const fd = openSync(join(this.dir, name), "wx");
      writeSync(fd, requestId);
      closeSync(fd);
      return "consumed";
    } catch (err) {
      return (err as NodeJS.ErrnoException).code === "EEXIST" ? "replayed" : "unavailable";
    }
  }
}
