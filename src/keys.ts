/**
 * Hybrid keypair generation: ML-DSA-65 (FIPS 204) + Ed25519.
 * Vendored verbatim from `cool-sdk`.
 *
 * What this proves: that a holder of these secret keys can produce signatures
 * verifiable against the published public keys, under TWO independent schemes
 * (one post-quantum, one classical).
 * What this does NOT prove: anything about the identity behind a key — key ids
 * are operator-chosen labels, not certified identities. There is no PKI here.
 *
 * The keys this browser demo generates are throwaway, live only in the tab, and
 * MUST NOT be reused to protect anything real.
 */
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import type { DirectoryEntry, KeyDirectory, KeyPair } from "./types";
import { concatBytes, toBase64Field, utf8 } from "./codec";

const ML_DSA_SEED_BYTES = 32;

/** Options for {@link generateKeypair}. */
export interface GenerateKeypairOptions {
  /**
   * A 32-byte deterministic seed. If provided, the SAME keypair is produced
   * every time — used for reproducible conformance vectors and tests ONLY.
   * If omitted, a fresh random seed is drawn from the platform CSPRNG.
   */
  readonly seed?: Uint8Array;
}

function deriveEd25519Secret(seed: Uint8Array): Uint8Array {
  // Domain-separate the ed25519 secret from the ML-DSA seed so the two
  // schemes never share key material, while remaining deterministic.
  return sha256(concatBytes(seed, utf8("cool/ed25519")));
}

/**
 * Generate a hybrid ML-DSA-65 + Ed25519 keypair bound to a key id.
 * @param keyId operator-chosen label recorded in signatures and the key directory
 */
export function generateKeypair(keyId: string, options: GenerateKeypairOptions = {}): KeyPair {
  let seed = options.seed;
  if (seed === undefined) {
    seed = new Uint8Array(ML_DSA_SEED_BYTES);
    globalThis.crypto.getRandomValues(seed);
  } else if (seed.length !== ML_DSA_SEED_BYTES) {
    throw new TypeError(`seed must be ${ML_DSA_SEED_BYTES} bytes, got ${seed.length}`);
  }

  const mlDsa = ml_dsa65.keygen(seed);
  const ed25519Secret = deriveEd25519Secret(seed);
  const ed25519Public = ed25519.getPublicKey(ed25519Secret);

  const directoryEntry: DirectoryEntry = {
    ml_dsa_pub: toBase64Field(mlDsa.publicKey),
    ed25519_pub: toBase64Field(ed25519Public),
  };

  return {
    keyId,
    mlDsaSecret: mlDsa.secretKey,
    mlDsaPublic: mlDsa.publicKey,
    ed25519Secret,
    ed25519Public,
    directoryEntry,
  };
}

/** Build a single-entry key directory from a keypair. */
export function directoryFromKeypair(key: KeyPair): KeyDirectory {
  return { [key.keyId]: key.directoryEntry };
}

/** Merge several keypairs' directory entries into one key directory. */
export function mergeDirectories(...keys: KeyPair[]): KeyDirectory {
  const directory: Record<string, DirectoryEntry> = {};
  for (const key of keys) directory[key.keyId] = key.directoryEntry;
  return directory;
}
