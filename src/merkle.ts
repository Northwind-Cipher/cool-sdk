/**
 * RFC 6962 Merkle tree primitives. Vendored verbatim from `cool-sdk`.
 *
 * What this proves: that a given leaf is included at a specific index in a tree
 * of a specific size whose root is `root`, and (via consistency proofs) that a
 * larger tree is an append-only extension of a smaller one — tampering with or
 * removing any logged entry changes the root.
 * What this does NOT prove: that the logged leaves are meaningful or that the
 * root has been witnessed/published — inclusion is only as trustworthy as the
 * STH whose root you check it against.
 *
 * Hashing is exactly RFC 6962:
 *   leaf hash  = SHA256(0x00 ‖ leafData)
 *   node hash  = SHA256(0x01 ‖ left ‖ right)
 *   empty tree = SHA256("")
 */
import { sha256 } from "@noble/hashes/sha2";
import { bytesEqual, concatBytes } from "./codec";

const LEAF_PREFIX = Uint8Array.of(0x00);
const NODE_PREFIX = Uint8Array.of(0x01);

/** RFC 6962 leaf hash: SHA256(0x00 ‖ data). */
export function leafHash(data: Uint8Array): Uint8Array {
  return sha256(concatBytes(LEAF_PREFIX, data));
}

/** RFC 6962 interior node hash: SHA256(0x01 ‖ left ‖ right). */
export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(NODE_PREFIX, left, right));
}

/** Largest power of two strictly less than n (n > 1). */
function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k << 1 < n) k <<= 1;
  return k;
}

/**
 * Merkle Tree Hash (MTH) of a list of already-computed leaf hashes.
 * `leafHashes[i]` must be the output of {@link leafHash} for entry i.
 */
export function merkleRoot(leafHashes: Uint8Array[]): Uint8Array {
  const n = leafHashes.length;
  if (n === 0) return sha256(new Uint8Array(0));
  if (n === 1) return leafHashes[0]!;
  const k = largestPowerOfTwoBelow(n);
  return nodeHash(merkleRoot(leafHashes.slice(0, k)), merkleRoot(leafHashes.slice(k)));
}

/**
 * Audit path (RFC 6962 PATH(m, D[n])) proving inclusion of leaf index `m`
 * in a tree built from `leafHashes` (length n). Returns sibling hashes bottom-up.
 */
export function inclusionProof(leafHashes: Uint8Array[], m: number): Uint8Array[] {
  const n = leafHashes.length;
  if (m < 0 || m >= n) throw new RangeError(`leaf index ${m} out of range for size ${n}`);
  if (n === 1) return [];
  const k = largestPowerOfTwoBelow(n);
  if (m < k) {
    return [...inclusionProof(leafHashes.slice(0, k), m), merkleRoot(leafHashes.slice(k))];
  }
  return [...inclusionProof(leafHashes.slice(k), m - k), merkleRoot(leafHashes.slice(0, k))];
}

/**
 * Recompute a tree root from a leaf hash and its audit path (RFC 6962).
 * Returns the reconstructed root; the caller compares it to a trusted STH root.
 */
export function rootFromInclusionProof(
  leafHashValue: Uint8Array,
  leafIndex: number,
  treeSize: number,
  auditPath: Uint8Array[],
): Uint8Array {
  if (leafIndex < 0 || leafIndex >= treeSize) {
    throw new RangeError(`leaf index ${leafIndex} out of range for size ${treeSize}`);
  }
  // Canonical RFC 6962 §2.1.1 audit-path verification.
  let fn = leafIndex; // node index within its level
  let sn = treeSize - 1; // last node index within its level
  let hash = leafHashValue;

  for (const sibling of auditPath) {
    if (sn === 0) throw new RangeError("audit path too long for tree size");
    if (fn % 2 === 1 || fn === sn) {
      hash = nodeHash(sibling, hash);
      if (fn % 2 === 0) {
        // fn === sn and fn is even: ascend until we hit a right child or the root.
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      hash = nodeHash(hash, sibling);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  if (sn !== 0) throw new RangeError("audit path too short for tree size");
  return hash;
}

/**
 * Verify an inclusion proof against an expected root.
 * Returns true only if the reconstructed root equals `expectedRoot`.
 */
export function verifyInclusion(
  leafHashValue: Uint8Array,
  leafIndex: number,
  treeSize: number,
  auditPath: Uint8Array[],
  expectedRoot: Uint8Array,
): boolean {
  let computed: Uint8Array;
  try {
    computed = rootFromInclusionProof(leafHashValue, leafIndex, treeSize, auditPath);
  } catch {
    return false;
  }
  return bytesEqual(computed, expectedRoot);
}

/**
 * Consistency proof (RFC 6962 PROOF(m, D[n])) between an older tree of size
 * `m` and a newer tree built from `leafHashes` of size n (m ≤ n).
 */
export function consistencyProof(leafHashes: Uint8Array[], m: number): Uint8Array[] {
  const n = leafHashes.length;
  if (m < 0 || m > n) throw new RangeError(`invalid first size ${m} for second size ${n}`);
  if (m === 0 || m === n) return [];
  return subproof(m, leafHashes, true);
}

function subproof(m: number, hashes: Uint8Array[], b: boolean): Uint8Array[] {
  const n = hashes.length;
  if (m === n) {
    return b ? [] : [merkleRoot(hashes)];
  }
  const k = largestPowerOfTwoBelow(n);
  if (m <= k) {
    return [...subproof(m, hashes.slice(0, k), b), merkleRoot(hashes.slice(k))];
  }
  return [...subproof(m - k, hashes.slice(k), false), merkleRoot(hashes.slice(0, k))];
}

/**
 * Verify a consistency proof: that the tree with root `secondRoot` (size n) is
 * an append-only extension of the tree with root `firstRoot` (size m).
 */
export function verifyConsistency(
  m: number,
  n: number,
  firstRoot: Uint8Array,
  secondRoot: Uint8Array,
  proof: Uint8Array[],
): boolean {
  if (m === 0) return true;
  if (m === n) return proof.length === 0 && bytesEqual(firstRoot, secondRoot);
  if (m > n) return false;

  let path = proof;
  // RFC 6962 §2.1.2 verification algorithm.
  if (isPowerOfTwo(m)) {
    path = [firstRoot, ...path];
  }
  if (path.length === 0) return false;

  let fn = m - 1;
  let sn = n - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  let pos = 0;
  let fr = path[pos]!;
  let sr = path[pos]!;
  pos++;

  while (sn > 0) {
    if (pos >= path.length) return false;
    const c = path[pos++]!;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  return pos === path.length && bytesEqual(fr, firstRoot) && bytesEqual(sr, secondRoot);
}

function isPowerOfTwo(x: number): boolean {
  return x > 0 && (x & (x - 1)) === 0;
}
