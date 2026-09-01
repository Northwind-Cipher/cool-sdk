/**
 * The log the evidence plane appends to.
 *
 * Until now the plane hard-wired the in-memory log, which has a consequence
 * nobody notices until they look closely: every process starts a fresh tree, so
 * a hundred records become a hundred trees of size one. Each receipt is
 * internally valid and the set proves nothing about ordering or completeness —
 * which is most of what a transparency log is for.
 *
 * This interface is the seam. `MemoryLog` satisfies it (tests, browsers), a
 * file-backed log satisfies it (the CLI, a single node), and a Trillian or Rekor
 * client would satisfy it without the plane noticing.
 */
import type { Multihash, STH } from "../types";

/** Where a leaf landed. */
export interface AppendResult {
  readonly leafIndex: number;
  readonly treeSize: number;
}

/**
 * An append-only RFC 6962 log.
 *
 * Deliberately narrow: append, prove, checkpoint. Anything a backend needs
 * beyond that — batching, replication, gossip — is its own business.
 */
export interface EvidenceLog {
  /** Entries currently in the tree. */
  readonly size: number;
  /** Append a leaf's data, returning its position. */
  append(leafData: Uint8Array): AppendResult;
  /** Sibling hashes proving the leaf is under the current root. */
  inclusionAuditPath(leafIndex: number): Multihash[];
  /** The current root, as a multihash. */
  rootHash(): Multihash;
  /** A signed tree head over the current tree. */
  buildSTH(timestamp: string): STH;
}
