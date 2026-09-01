/**
 * In-memory, append-only RFC 6962 transparency log. Vendored from `cool-sdk`.
 *
 * What this proves: that entries appended here get real Merkle inclusion proofs
 * and a Signed Tree Head (STH) whose root commits to every entry — enough to
 * demonstrate tamper-evident logging fully offline.
 * What this does NOT prove: independent witnessing or public availability. This
 * log lives in one browser tab; its STH carries only a CooL SELF co-signature
 * (`external: false`), which is shown to verifiers but NEVER counted as an
 * independent witness. A production deployment writes to Trillian/Rekor and
 * gossips the STH to external witnesses — neither exists in this build.
 */
import type { KeyPair, Multihash, STH, STHCore, Witness } from "./types";
import { multihashFromDigest } from "./multihash";
import { inclusionProof, leafHash, merkleRoot } from "./merkle";
import { hybridSign } from "./sign";
import { sthSigningMessage } from "./record";

/** The inclusion proof and tree size returned when appending a leaf. */
export interface AppendResult {
  readonly leafIndex: number;
  readonly treeSize: number;
}

/**
 * A minimal append-only log. Leaves are arbitrary byte strings (CooL appends
 * the 32-byte binding digest of each record). The log is signed by `logKey`
 * and self-co-signed as a non-independent witness.
 */
export class MemoryLog {
  private readonly leaves: Uint8Array[] = [];
  private readonly leafHashes: Uint8Array[] = [];

  /**
   * @param logId stable log identifier recorded in the STH
   * @param logKey the hybrid key that signs the STH (and self-co-signs it)
   */
  constructor(
    public readonly logId: string,
    private readonly logKey: KeyPair,
  ) {}

  /** Number of entries currently in the log. */
  get size(): number {
    return this.leaves.length;
  }

  /** Append a leaf, returning its index and the resulting tree size. */
  append(leafData: Uint8Array): AppendResult {
    const leafIndex = this.leaves.length;
    this.leaves.push(leafData);
    this.leafHashes.push(leafHash(leafData));
    return { leafIndex, treeSize: this.leaves.length };
  }

  /** Audit path (sibling hashes, as multihashes) proving inclusion of `leafIndex`. */
  inclusionAuditPath(leafIndex: number): Multihash[] {
    return inclusionProof(this.leafHashes, leafIndex).map(multihashFromDigest);
  }

  /** The current Merkle root as a multihash (the root digest, not re-hashed). */
  rootHash(): Multihash {
    return multihashFromDigest(merkleRoot(this.leafHashes));
  }

  /**
   * Build a Signed Tree Head over the current tree, signed by the log key and
   * carrying a single CooL self co-signature (`external: false`).
   * @param timestamp caller-supplied RFC 3339 STH time (the log keeps no clock)
   */
  buildSTH(timestamp: string): STH {
    const core: STHCore = {
      log_id: this.logId,
      tree_size: this.leaves.length,
      root_hash: this.rootHash(),
      timestamp,
    };
    const message = sthSigningMessage(core);
    const signature = hybridSign(message, this.logKey);
    const selfWitness: Witness = {
      id: "cool-self",
      external: false,
      alg: signature.alg,
      ml_dsa: signature.ml_dsa,
      ed25519: signature.ed25519,
    };
    return { ...core, signature, witnesses: [selfWitness] };
  }
}
