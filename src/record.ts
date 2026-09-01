/**
 * Signed Tree Head (STH) serialization — the bytes an STH signature and its
 * witness co-signatures cover.
 *
 * Deterministic over the STH's logical content (CDE canonicalization), so the
 * same tree head always produces the same signing message across
 * implementations.
 */
import type { STH, STHCore } from "./types";
import { canonicalCbor } from "./canonical";

/** Reduce an STH to the core fields covered by its signature and witnesses. */
export function sthCore(sth: STH): STHCore {
  return {
    log_id: sth.log_id,
    tree_size: sth.tree_size,
    root_hash: sth.root_hash,
    timestamp: sth.timestamp,
  };
}

/** The exact message signed over an STH: `canonicalCBOR(sthCore)`. */
export function sthSigningMessage(core: STHCore): Uint8Array {
  return canonicalCbor(core);
}
