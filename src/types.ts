/**
 * Shared primitive types for the CooL evidence model.
 *
 * These describe wire encodings, the hybrid signature block, the key directory,
 * and the RFC 6962 transparency-log structures (inclusion proof, signed tree
 * head, witness co-signature). The record cores that use them live in
 * `./phala/types.ts` (`cool.evidence.v1`, `cool.change.v2`).
 */

/** A multihash-tagged SHA-256 digest, e.g. `mh:sha256:<64 hex chars>`. */
export type Multihash = `mh:sha256:${string}`;

/** A `hex:<hex>` encoded field (used for salts). */
export type HexField = `hex:${string}`;

/** A `base64:<b64>` encoded field (used for keys and signatures). */
export type Base64Field = `base64:${string}`;

/** The hybrid signature algorithm identifier used throughout CooL. */
export type SignatureAlg = "ml-dsa-65+ed25519";

/**
 * A hybrid signature block: a classical Ed25519 signature AND a
 * post-quantum ML-DSA-65 (FIPS 204) signature over the same message.
 * BOTH must verify for the signature to be considered valid.
 */
export interface SignatureBlock {
  readonly alg: SignatureAlg;
  readonly key_id: string;
  readonly ml_dsa: Base64Field;
  readonly ed25519: Base64Field;
}

/** A public key directory entry: the two public keys for a hybrid key id. */
export interface DirectoryEntry {
  readonly ml_dsa_pub: Base64Field;
  readonly ed25519_pub: Base64Field;
}

/** A key directory mapping key ids to their public keys (carried in the receipt). */
export type KeyDirectory = Readonly<Record<string, DirectoryEntry>>;

/** Timing block. `seq` is a monotone sequence number; `issued_at` is informational. */
export interface RecordTime {
  readonly issued_at: string;
  readonly seq: number;
}

/** A Merkle inclusion proof (RFC 6962 audit path). */
export interface Inclusion {
  readonly leaf_index: number;
  readonly tree_size: number;
  readonly audit_path: Multihash[];
}

/**
 * A witness co-signature on a Signed Tree Head.
 * Only `external: true` witnesses are counted toward any independence
 * threshold. A CooL self-signature (`external: false`) is shown but NEVER
 * counted as independent.
 */
export interface Witness {
  readonly id: string;
  readonly external: boolean;
  readonly alg: SignatureAlg;
  readonly ml_dsa: Base64Field;
  readonly ed25519: Base64Field;
}

/** A Signed Tree Head (RFC 6962 STH) with optional witness co-signatures. */
export interface STH {
  readonly log_id: string;
  readonly tree_size: number;
  readonly root_hash: Multihash;
  readonly timestamp: string;
  readonly signature: SignatureBlock;
  readonly witnesses: Witness[];
}

/** The hashed core of an STH (what the STH signature and witnesses sign). */
export interface STHCore {
  readonly log_id: string;
  readonly tree_size: number;
  readonly root_hash: Multihash;
  readonly timestamp: string;
}

/** A generated hybrid keypair plus its directory entry. */
export interface KeyPair {
  readonly keyId: string;
  readonly mlDsaSecret: Uint8Array;
  readonly mlDsaPublic: Uint8Array;
  readonly ed25519Secret: Uint8Array;
  readonly ed25519Public: Uint8Array;
  readonly directoryEntry: DirectoryEntry;
}
