/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Publishing envelopes to an append-only RFC 6962 log, and fetching
 * checkpoints for them.
 *
 * The log stores only each envelope's 32-byte digest — never the payload — so
 * it can be operated, mirrored or witnessed without seeing customer data. A
 * checkpoint is a signed tree head plus the audit path for one leaf. Witness
 * co-signatures are added to a head with the existing `cosign`; the envelope
 * verifier counts only witnesses the verifier trusts.
 *
 * This is the in-process reference log (MemoryLog). A durable, networked log
 * service is not part of this package.
 */
import { MemoryLog } from "../log-memory";
import { cosign } from "../phala/witness";
import type { KeyPair, STH } from "../types";
import { envelopeLeaf, withCheckpoint, type Checkpoint, type SignedEnvelope } from "./envelope";

export class TransparencyLog {
  readonly #log: MemoryLog;
  readonly #index = new Map<string, number>();
  readonly #clock: () => Date;

  constructor(logId: string, logKey: KeyPair, clock: () => Date = () => new Date()) {
    this.#log = new MemoryLog(logId, logKey);
    this.#clock = clock;
  }

  get size(): number {
    return this.#log.size;
  }

  /** Append an envelope (idempotent by digest) and return it with a checkpoint. */
  publish(env: SignedEnvelope): SignedEnvelope {
    let index = this.#index.get(env.digest);
    if (index === undefined) {
      index = this.#log.append(envelopeLeaf(env)).leafIndex;
      this.#index.set(env.digest, index);
    }
    return withCheckpoint(env, this.checkpoint(env.digest)!);
  }

  /** A fresh checkpoint for a published digest, at the current tree head. */
  checkpoint(digest: string, witnesses: readonly KeyPair[] = []): Checkpoint | null {
    const index = this.#index.get(digest);
    if (index === undefined) return null;
    let sth: STH = this.#log.buildSTH(this.#clock().toISOString());
    for (const w of witnesses) sth = { ...sth, witnesses: [...sth.witnesses, cosign(sth, w).witness] };
    return { sth, leaf_index: index, audit_path: this.#log.inclusionAuditPath(index) };
  }
}
