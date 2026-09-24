/**
 * Log consistency, verified from receipts alone.
 *
 * A single receipt can only show that ITS leaf is under ITS head. What makes a
 * transparency log worth having is that the history never forks: the tree that
 * existed at size m is a prefix of the tree at size n. This module checks that
 * across a set of receipts from one log, using nothing but their contents:
 *
 *   1. every tree head is signed by a key the receipts (or the caller) supply;
 *   2. the leaves 0..N-1 are all present (binding digests, from the receipts);
 *   3. every head's root equals the root recomputed from the leaves it covers;
 *   4. no two different roots claim the same tree size (equivocation);
 *   5. for consecutive sizes m < n, an RFC 6962 consistency proof, computed here
 *      from the leaves, verifies between the two SIGNED roots.
 *
 * The proof is derived by this checker rather than accepted from the log, so a
 * log operator cannot hand over a proof that flatters a rewritten history.
 */
import type { KeyDirectory } from "../types";
import { multihashDigest } from "../multihash";
import { hybridVerify } from "../sign";
import { consistencyProof, leafHash, merkleRoot, verifyConsistency } from "../merkle";
import { sthCore, sthSigningMessage } from "../record";
import { recordLeafDataV2 } from "./record";
import type { ReceiptV2 } from "./types";

export interface ConsistencyHead {
  readonly tree_size: number;
  readonly root_hash: string;
  readonly signature_ok: boolean;
  readonly root_matches_leaves: boolean;
}

export interface ConsistencyPair {
  readonly from: number;
  readonly to: number;
  readonly proof_length: number;
  readonly ok: boolean;
}

export interface ConsistencyResult {
  readonly ok: boolean;
  readonly log_id: string | null;
  readonly heads: readonly ConsistencyHead[];
  readonly pairs: readonly ConsistencyPair[];
  readonly reasons: readonly string[];
}

export interface ConsistencyOptions {
  /** Keys the verifier trusts for tree-head signatures; override the receipts' own directory. */
  readonly trustedKeys?: KeyDirectory;
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

function fail(reasons: string[], log_id: string | null = null): ConsistencyResult {
  return { ok: false, log_id, heads: [], pairs: [], reasons };
}

/** Verify that a set of receipts from one log describe a single append-only history. */
export function verifyLogConsistency(
  receipts: readonly ReceiptV2[],
  options: ConsistencyOptions = {},
): ConsistencyResult {
  const withHead = receipts.filter((r) => r.sth && r.inclusion);
  if (withHead.length < 2) {
    return fail(["consistency needs at least two receipts carrying tree heads"]);
  }
  const reasons: string[] = [];
  const logId = withHead[0]!.sth!.log_id;
  if (withHead.some((r) => r.sth!.log_id !== logId)) {
    return fail(["receipts come from more than one log"], logId);
  }

  // Leaves 0..N-1, from the binding digests.
  const leafByIndex = new Map<number, Uint8Array>();
  for (const r of withHead) {
    const index = r.inclusion!.leaf_index;
    const leaf = leafHash(recordLeafDataV2(r.binding_hash));
    const seen = leafByIndex.get(index);
    if (seen && !same(seen, leaf)) {
      reasons.push(`two different records claim leaf ${index}`);
    }
    leafByIndex.set(index, leaf);
  }
  const maxSize = Math.max(...withHead.map((r) => r.sth!.tree_size));
  const leaves: Uint8Array[] = [];
  for (let i = 0; i < maxSize; i++) {
    const leaf = leafByIndex.get(i);
    if (!leaf) {
      reasons.push(`leaf ${i} is missing, so the history up to size ${maxSize} cannot be recomputed`);
      return fail(reasons, logId);
    }
    leaves.push(leaf);
  }

  // One head per size; two different roots for one size is a fork.
  const headBySize = new Map<number, ReceiptV2>();
  for (const r of withHead) {
    const size = r.sth!.tree_size;
    const prior = headBySize.get(size);
    if (prior && prior.sth!.root_hash !== r.sth!.root_hash) {
      reasons.push(`equivocation: two different roots for tree size ${size}`);
    }
    headBySize.set(size, prior ?? r);
  }

  const heads: ConsistencyHead[] = [];
  const sizes = [...headBySize.keys()].sort((a, b) => a - b);
  for (const size of sizes) {
    const r = headBySize.get(size)!;
    const sth = r.sth!;
    const entry = options.trustedKeys?.[sth.signature.key_id] ?? r.key_directory[sth.signature.key_id];
    const signatureOk =
      entry !== undefined && hybridVerify(sthSigningMessage(sthCore(sth)), sth.signature, entry).ok;
    let rootMatches = false;
    try {
      const recomputed = merkleRoot(leaves.slice(0, size));
      rootMatches = same(recomputed, multihashDigest(sth.root_hash));
    } catch {
      rootMatches = false;
    }
    if (!signatureOk) reasons.push(`tree head ${size}: signature does not verify`);
    if (!rootMatches) reasons.push(`tree head ${size}: root does not match the leaves it covers`);
    heads.push({ tree_size: size, root_hash: sth.root_hash, signature_ok: signatureOk, root_matches_leaves: rootMatches });
  }

  const pairs: ConsistencyPair[] = [];
  for (let i = 0; i + 1 < sizes.length; i++) {
    const m = sizes[i]!;
    const n = sizes[i + 1]!;
    let ok = false;
    let length = 0;
    try {
      const proof = consistencyProof(leaves.slice(0, n), m);
      length = proof.length;
      ok = verifyConsistency(
        m,
        n,
        multihashDigest(headBySize.get(m)!.sth!.root_hash),
        multihashDigest(headBySize.get(n)!.sth!.root_hash),
        proof,
      );
    } catch {
      ok = false;
    }
    if (!ok) reasons.push(`consistency proof ${m} -> ${n} does not verify between the signed roots`);
    pairs.push({ from: m, to: n, proof_length: length, ok });
  }

  return {
    ok: reasons.length === 0 && heads.length >= 2 && pairs.every((p) => p.ok) && heads.every((h) => h.signature_ok && h.root_matches_leaves),
    log_id: logId,
    heads,
    pairs,
    reasons,
  };
}
