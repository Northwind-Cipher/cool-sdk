/**
 * A transparency log that survives the process.
 *
 * One append-only file of leaf digests, one line each, replayed on start-up.
 * That is enough to make the log's actual promise true across runs: record 40
 * proves it sits under a root that also covers records 1 to 39, so removing an
 * earlier record is detectable rather than merely rude.
 *
 * Deliberately simple, and honest about what it is not:
 *
 *   • It is one node. Nobody else is watching it, so an operator with disk
 *     access can still rewrite the file wholesale — what they cannot do is
 *     rewrite it and keep the old signed tree heads consistent, which is why
 *     `consistency()` and witness co-signatures exist.
 *   • Everything is held in memory as well; at millions of records this wants a
 *     real backend (Trillian, Rekor). The `EvidenceLog` interface is the seam
 *     for exactly that swap.
 *
 * The file format is boring on purpose: `<hex leaf digest>\n`. It can be
 * inspected with `wc -l`, diffed, and rebuilt by hand if it ever comes to that.
 */
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { KeyPair, Multihash, STH, STHCore, Witness } from "../types";
import { fromHex, toHex } from "../codec";
import { multihashFromDigest } from "../multihash";
import { consistencyProof, inclusionProof, leafHash, merkleRoot } from "../merkle";
import { hybridSign } from "../sign";
import { sthSigningMessage } from "../record";
import type { AppendResult, EvidenceLog } from "./log";

export interface FileLogOptions {
  /** Directory to keep the log in. Default `.cool/log`. */
  readonly dir?: string;
  /** Stable log id recorded in every STH. */
  readonly logId: string;
  /** The key that signs tree heads — sealed to the enclave measurement. */
  readonly logKey: KeyPair;
}

const LEAVES = "leaves.log";
const CHECKPOINT = "sth.json";

export class FileLog implements EvidenceLog {
  private readonly leafHashes: Uint8Array[] = [];
  private readonly dir: string;
  private readonly leafPath: string;
  private readonly logId: string;
  private readonly logKey: KeyPair;

  constructor(options: FileLogOptions) {
    this.dir = options.dir ?? join(process.cwd(), ".cool", "log");
    this.leafPath = join(this.dir, LEAVES);
    this.logId = options.logId;
    this.logKey = options.logKey;

    mkdirSync(this.dir, { recursive: true });
    this.replay();
  }

  /**
   * Rebuild the tree from disk.
   *
   * A malformed line is fatal rather than skipped: silently dropping a leaf
   * would change every root hash after it and produce a log that disagrees with
   * receipts already issued, which is worse than refusing to start.
   */
  private replay(): void {
    let text = "";
    try {
      text = readFileSync(this.leafPath, "utf8");
    } catch {
      return; // first run
    }
    const lines = text.split("\n").filter((line) => line.length > 0);
    lines.forEach((line, index) => {
      if (!/^[0-9a-f]{64}$/.test(line)) {
        throw new Error(
          `${LEAVES}:${index + 1} is not a 32-byte hex digest — refusing to start on a corrupt log`,
        );
      }
      this.leafHashes.push(fromHex(line));
    });
  }

  get size(): number {
    return this.leafHashes.length;
  }

  /** Where the log lives, for anyone who wants to inspect or back it up. */
  get path(): string {
    return this.leafPath;
  }

  append(leafData: Uint8Array): AppendResult {
    const hash = leafHash(leafData);
    const leafIndex = this.leafHashes.length;
    // Written before the in-memory push: a crash between the two leaves a leaf
    // on disk that the next start replays, which is recoverable. The reverse
    // loses it silently.
    appendFileSync(this.leafPath, `${toHex(hash)}\n`);
    this.leafHashes.push(hash);
    return { leafIndex, treeSize: this.leafHashes.length };
  }

  inclusionAuditPath(leafIndex: number): Multihash[] {
    return inclusionProof(this.leafHashes, leafIndex).map(multihashFromDigest);
  }

  rootHash(): Multihash {
    return multihashFromDigest(merkleRoot(this.leafHashes));
  }

  buildSTH(timestamp: string): STH {
    const core: STHCore = {
      log_id: this.logId,
      tree_size: this.leafHashes.length,
      root_hash: this.rootHash(),
      timestamp,
    };
    const signature = hybridSign(sthSigningMessage(core), this.logKey);
    const selfWitness: Witness = {
      id: "cool-self",
      external: false,
      alg: signature.alg,
      ml_dsa: signature.ml_dsa,
      ed25519: signature.ed25519,
    };
    const sth: STH = { ...core, signature, witnesses: [selfWitness] };
    this.checkpoint(sth);
    return sth;
  }

  /**
   * Keep the newest tree head on disk.
   *
   * It is what a monitor gossips, what a witness co-signs, and what proves the
   * log did not shrink while nobody was looking.
   */
  private checkpoint(sth: STH): void {
    const path = join(this.dir, CHECKPOINT);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${JSON.stringify(sth, null, 2)}\n`);
  }

  /** The last tree head written, if any. */
  lastCheckpoint(): STH | null {
    try {
      return JSON.parse(readFileSync(join(this.dir, CHECKPOINT), "utf8")) as STH;
    } catch {
      return null;
    }
  }

  /**
   * Proof that the tree only ever grew.
   *
   * Hand this and an older tree head to anyone who kept one, and they can check
   * that today's log still contains everything yesterday's did — the property an
   * append-only claim actually rests on.
   */
  consistency(fromSize: number): Multihash[] {
    return consistencyProof(this.leafHashes, fromSize).map(multihashFromDigest);
  }
}
