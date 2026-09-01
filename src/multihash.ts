/**
 * Multihash-tagged SHA-256 digests (`mh:sha256:<hex>`). Vendored from `cool-sdk`.
 *
 * What this proves: that a digest string carries its algorithm label, so a
 * verifier never has to guess which hash produced it (crypto-agility).
 * What this does NOT prove: that the pre-image is authentic — a hash only
 * binds to whatever bytes were fed in.
 */
import { sha256 } from "@noble/hashes/sha2";
import type { Multihash } from "./types";
import { fromHex, toHex } from "./codec";

export const MULTIHASH_PREFIX = "mh:sha256:";

/** Compute the SHA-256 multihash of the given bytes. */
export function mhSha256(data: Uint8Array): Multihash {
  return `mh:sha256:${toHex(sha256(data))}`;
}

/** Wrap an already-computed 32-byte digest as a `mh:sha256:` multihash. */
export function multihashFromDigest(digest: Uint8Array): Multihash {
  if (digest.length !== 32) {
    throw new TypeError(`sha256 digest must be 32 bytes, got ${digest.length}`);
  }
  return `mh:sha256:${toHex(digest)}`;
}

/** True if the string is a well-formed `mh:sha256:` multihash. */
export function isMultihash(value: string): value is Multihash {
  return /^mh:sha256:[0-9a-f]{64}$/.test(value);
}

/**
 * Extract the raw 32-byte digest from a `mh:sha256:` multihash.
 * Throws if the prefix is missing or the digest is not 32 bytes.
 */
export function multihashDigest(mh: string): Uint8Array {
  if (!mh.startsWith(MULTIHASH_PREFIX)) {
    throw new TypeError(`expected '${MULTIHASH_PREFIX}' prefix`);
  }
  const digest = fromHex(mh.slice(MULTIHASH_PREFIX.length));
  if (digest.length !== 32) {
    throw new TypeError(`sha256 digest must be 32 bytes, got ${digest.length}`);
  }
  return digest;
}
