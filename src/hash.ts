/**
 * SHA-256 hashing and salted commitments. Vendored verbatim from `cool-sdk`.
 *
 * What this proves: a commitment `mh:sha256(salt ‖ data)` binds to the exact
 * bytes of `data` under a specific salt; recomputing it with the same salt and
 * data yields the same multihash, and any change to either is detectable.
 * What this does NOT prove: the data's correctness, meaning, or origin — and,
 * because a commitment hides its pre-image, it does not reveal the data either.
 *
 * Salts are 16 random bytes stored as explicit `hex:` fields. They raise the
 * cost of guessing low-entropy inputs and enable later selective disclosure.
 */
import { sha256 } from "@noble/hashes/sha2";
import type { HexField, Multihash } from "./types";
import { concatBytes, fromHexField, toHexField, utf8 } from "./codec";
import { mhSha256 } from "./multihash";

const SALT_BYTES = 16;

/** Raw SHA-256 of the given bytes. */
export function sha256Bytes(data: Uint8Array): Uint8Array {
  return sha256(data);
}

/** Generate a fresh 16-byte salt as a `hex:` field using the platform CSPRNG. */
export function randomSalt(): HexField {
  const salt = new Uint8Array(SALT_BYTES);
  globalThis.crypto.getRandomValues(salt);
  return toHexField(salt) as HexField;
}

/**
 * Compute a salted commitment `mh:sha256(salt_bytes ‖ data_bytes)`.
 * @param salt a `hex:` field (its bytes are prepended to the data)
 * @param data the committed value, as a UTF-8 string or raw bytes
 */
export function saltedCommit(salt: HexField, data: string | Uint8Array): Multihash {
  const saltBytes = fromHexField(salt);
  const dataBytes = typeof data === "string" ? utf8(data) : data;
  return mhSha256(concatBytes(saltBytes, dataBytes));
}
