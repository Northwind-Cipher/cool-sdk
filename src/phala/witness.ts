/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Witnesses — the one domain that has always reported `absent`.
 *
 * A log signed only by its operator proves that the operator has not
 * contradicted themselves. It cannot prove they never showed a different tree to
 * somebody else, because the same key can sign two trees. The standard answer is
 * an independent party who signs the tree heads they saw: once a witness has
 * co-signed size 40, the operator cannot later produce a size-40 tree with
 * different contents without the witness's signature failing.
 *
 * So this module is small and its consequences are not. It provides:
 *
 *   • `cosign` — a third party signs a tree head they have observed;
 *   • `attachWitness` — fold that co-signature into the STH a receipt carries;
 *   • `verifyWitnesses` — count only signatures that verify AND are external.
 *
 * The honesty rule that has been in the verifier since v1 stays exactly as it
 * was: a CooL self-signature is displayed and never counted. What changes is
 * that `pass` is now reachable by doing the real thing rather than unreachable
 * by construction.
 */
import type { DirectoryEntry, KeyDirectory, KeyPair, STH, Witness as WitnessSig } from "../types";
import { hybridSign, hybridVerify } from "../sign";
import { sthCore, sthSigningMessage } from "../record";
import type { ReceiptV2 } from "./types";
import { verifyLogConsistency } from "./consistency";

/** What a witness publishes about a tree head it has seen. */
export interface WitnessStatement {
  readonly witness_id: string;
  readonly log_id: string;
  readonly tree_size: number;
  readonly root_hash: string;
  readonly observed_at: string;
  readonly witness: WitnessSig;
  /** The witness's public keys, so a verifier needs nothing else. */
  readonly directory_entry: DirectoryEntry;
}

/**
 * Co-sign a tree head as an independent observer.
 *
 * The signature covers exactly the bytes the log's own signature covers, so a
 * witness never has to trust the operator's rendering of the tree — only the
 * (log_id, size, root, timestamp) it was shown.
 */
export function cosign(sth: STH, key: KeyPair): WitnessStatement {
  const signature = hybridSign(sthSigningMessage(sthCore(sth)), key);
  return {
    witness_id: key.keyId,
    log_id: sth.log_id,
    tree_size: sth.tree_size,
    root_hash: sth.root_hash,
    // The tree head's own timestamp, not the wall clock: this statement is
    // about a specific head, and that head is identified by its timestamp too.
    observed_at: sth.timestamp,
    witness: {
      id: key.keyId,
      external: true,
      alg: signature.alg,
      ml_dsa: signature.ml_dsa,
      ed25519: signature.ed25519,
    },
    directory_entry: key.directoryEntry,
  };
}

/**
 * Attach a witness statement to a receipt.
 *
 * Rejects a statement for a different tree — attaching one would produce a
 * receipt whose witness signature fails, which reads as an attack rather than
 * as the mistake it is.
 */
export function attachWitness(receipt: ReceiptV2, statement: WitnessStatement): ReceiptV2 {
  if (!receipt.sth) {
    throw new Error("this receipt carries no tree head to witness");
  }
  // The timestamp is inside the bytes the witness signed, so a statement made
  // against a different tree head — even one with the same size and root — would
  // attach cleanly and then fail to verify, which reads as an attack rather than
  // as the mistake it is.
  if (
    statement.log_id !== receipt.sth.log_id ||
    statement.tree_size !== receipt.sth.tree_size ||
    statement.root_hash !== receipt.sth.root_hash ||
    statement.observed_at !== receipt.sth.timestamp
  ) {
    throw new Error(
      `witness statement is for ${statement.log_id}@${statement.tree_size}, ` +
        `this receipt carries ${receipt.sth.log_id}@${receipt.sth.tree_size}`,
    );
  }

  const already = receipt.sth.witnesses.some((w) => w.id === statement.witness_id);
  const witnesses = already
    ? receipt.sth.witnesses
    : [...receipt.sth.witnesses, statement.witness];

  const directory: KeyDirectory = {
    ...receipt.key_directory,
    [statement.witness_id]: statement.directory_entry,
  };

  return { ...receipt, sth: { ...receipt.sth, witnesses }, key_directory: directory };
}

/** How many independent witnesses actually verify on this receipt. */
export function countWitnesses(receipt: ReceiptV2): {
  external: number;
  self: number;
  invalid: number;
} {
  if (!receipt.sth) return { external: 0, self: 0, invalid: 0 };
  const message = sthSigningMessage(sthCore(receipt.sth));
  let external = 0;
  let self = 0;
  let invalid = 0;

  for (const w of receipt.sth.witnesses) {
    if (!w.external) {
      self++;
      continue;
    }
    const entry = receipt.key_directory[w.id];
    const ok =
      entry !== undefined &&
      hybridVerify(message, { alg: w.alg, key_id: w.id, ml_dsa: w.ml_dsa, ed25519: w.ed25519 }, entry)
        .ok;
    if (ok) external++;
    else invalid++;
  }
  return { external, self, invalid };
}

/* ── an observing witness ─────────────────────────────────────────────── */

/** What a witness checked before it agreed to sign. */
export interface WitnessChecks {
  readonly receipts_verified: number;
  readonly heads_verified: number;
  readonly consistency_pairs_verified: number;
  readonly previous_head: { readonly tree_size: number; readonly root_hash: string } | null;
  readonly previous_head_still_in_history: boolean | null;
}

export interface WitnessDecision {
  readonly ok: boolean;
  readonly statement: WitnessStatement | null;
  readonly reasons: readonly string[];
  readonly checks: WitnessChecks | null;
}

export interface WitnessOptions {
  /**
   * Check one receipt the way this witness's operator requires (for hardware
   * logs: a verified quote and a pinned measurement). A receipt that fails is
   * never counted, and nothing is signed.
   */
  readonly verifyReceipt: (receipt: ReceiptV2) => Promise<{ ok: boolean; reasons: readonly string[] }>;
  /** Trusted keys for tree-head signatures; override what the receipts carry. */
  readonly trustedKeys?: KeyDirectory;
}

/**
 * A witness that OBSERVES a log before it signs.
 *
 * It never signs a head it was handed. It is given the receipts, verifies each
 * one, re-derives the whole history, checks every signed head and every
 * consistency step, and — the property that makes a witness worth having —
 * remembers the last head it signed, refusing any later head whose history does
 * not contain it. A log that forks or rolls back after being witnessed cannot
 * obtain a new signature.
 *
 * Its key is generated or sealed by whoever runs the witness, not by the log.
 */
export class Witness {
  private last: { tree_size: number; root_hash: string } | null = null;

  constructor(
    private readonly key: KeyPair,
    private readonly options: WitnessOptions,
  ) {}

  get keyId(): string {
    return this.key.keyId;
  }

  get directoryEntry(): DirectoryEntry {
    return this.key.directoryEntry;
  }

  get lastWitnessed(): { tree_size: number; root_hash: string } | null {
    return this.last;
  }

  /** Verify the log, then co-sign its head at `treeSize`. */
  async observe(receipts: readonly ReceiptV2[], treeSize: number): Promise<WitnessDecision> {
    const refuse = (reasons: string[], checks: WitnessChecks | null = null): WitnessDecision => ({
      ok: false,
      statement: null,
      reasons,
      checks,
    });

    for (const [i, r] of receipts.entries()) {
      const verdict = await this.options.verifyReceipt(r);
      if (!verdict.ok) return refuse([`receipt ${i} does not verify: ${verdict.reasons.join("; ")}`]);
    }

    const consistency = verifyLogConsistency(
      receipts,
      this.options.trustedKeys ? { trustedKeys: this.options.trustedKeys } : {},
    );
    if (!consistency.ok) return refuse(["the log's history is not consistent", ...consistency.reasons]);

    const target = receipts.find((r) => r.sth?.tree_size === treeSize);
    if (!target?.sth) return refuse([`no tree head of size ${treeSize} among the receipts`]);

    const previous = this.last ? { ...this.last } : null;
    let stillInHistory: boolean | null = null;
    if (this.last) {
      if (treeSize < this.last.tree_size) {
        return refuse([`refusing a head of size ${treeSize}: this witness already signed size ${this.last.tree_size}`]);
      }
      const earlier = consistency.heads.find((h) => h.tree_size === this.last!.tree_size);
      stillInHistory = earlier !== undefined && earlier.root_hash === this.last.root_hash;
      if (!stillInHistory) {
        return refuse(
          [`the log's history no longer contains the head this witness signed (size ${this.last.tree_size}) — fork or rollback`],
          {
            receipts_verified: receipts.length,
            heads_verified: consistency.heads.length,
            consistency_pairs_verified: consistency.pairs.length,
            previous_head: this.last,
            previous_head_still_in_history: false,
          },
        );
      }
    }

    const statement = cosign(target.sth, this.key);
    this.last = { tree_size: target.sth.tree_size, root_hash: target.sth.root_hash };
    return {
      ok: true,
      statement,
      reasons: [],
      checks: {
        receipts_verified: receipts.length,
        heads_verified: consistency.heads.length,
        consistency_pairs_verified: consistency.pairs.length,
        previous_head: previous,
        previous_head_still_in_history: stillInHistory,
      },
    };
  }

  /**
   * A head somebody PRESENTS for signing. It is signed only if it is exactly the
   * head this witness derived from the log itself; a forged or altered head is
   * refused, and the reason names the difference.
   */
  async cosignPresented(presented: STH, receipts: readonly ReceiptV2[]): Promise<WitnessDecision> {
    const genuine = receipts.find((r) => r.sth?.tree_size === presented.tree_size)?.sth;
    if (!genuine) {
      return { ok: false, statement: null, reasons: [`no head of size ${presented.tree_size} exists in the log`], checks: null };
    }
    const same =
      genuine.log_id === presented.log_id &&
      genuine.root_hash === presented.root_hash &&
      genuine.timestamp === presented.timestamp &&
      genuine.signature.ml_dsa === presented.signature.ml_dsa &&
      genuine.signature.ed25519 === presented.signature.ed25519;
    if (!same) {
      return {
        ok: false,
        statement: null,
        reasons: ["the presented tree head is not the head the log actually signed"],
        checks: null,
      };
    }
    return this.observe(receipts, presented.tree_size);
  }
}
