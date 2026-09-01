/**
 * Hybrid signing and verification: ML-DSA-65 (FIPS 204) AND Ed25519.
 * Vendored verbatim from `cool-sdk`.
 *
 * What this proves: that the exact message bytes were signed by a holder of
 * BOTH secret keys for `key_id`. Verification requires BOTH signatures to
 * check out, so the record is unforgeable even if one scheme is later broken
 * (post-quantum resilience for the classical half; classical assurance today).
 * What this does NOT prove: that the signed content is correct, fair, or
 * safe — only that it was sealed by the named key and has not been altered.
 */
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { ed25519 } from "@noble/curves/ed25519";
import type { DirectoryEntry, KeyPair, SignatureBlock } from "./types";
import { fromBase64Field, toBase64Field } from "./codec";

export const SIGNATURE_ALG = "ml-dsa-65+ed25519" as const;

/** The outcome of verifying a hybrid signature, with per-scheme detail. */
export interface HybridVerifyResult {
  /** True only if BOTH schemes verify. */
  readonly ok: boolean;
  readonly mlDsaOk: boolean;
  readonly ed25519Ok: boolean;
}

/** Produce a hybrid signature block over `message` using both secret keys. */
export function hybridSign(message: Uint8Array, key: KeyPair): SignatureBlock {
  const mlDsaSig = ml_dsa65.sign(key.mlDsaSecret, message);
  const ed25519Sig = ed25519.sign(message, key.ed25519Secret);
  return {
    alg: SIGNATURE_ALG,
    key_id: key.keyId,
    ml_dsa: toBase64Field(mlDsaSig),
    ed25519: toBase64Field(ed25519Sig),
  };
}

/**
 * Verify a hybrid signature block over `message` against a directory entry.
 * Returns per-scheme results; `ok` is true only when BOTH verify. Never throws
 * on a bad signature — malformed bytes are reported as a failed verify.
 */
export function hybridVerify(
  message: Uint8Array,
  signature: SignatureBlock,
  entry: DirectoryEntry,
): HybridVerifyResult {
  let mlDsaOk = false;
  let ed25519Ok = false;

  try {
    mlDsaOk = ml_dsa65.verify(
      fromBase64Field(entry.ml_dsa_pub),
      message,
      fromBase64Field(signature.ml_dsa),
    );
  } catch {
    mlDsaOk = false;
  }

  try {
    ed25519Ok = ed25519.verify(
      fromBase64Field(signature.ed25519),
      message,
      fromBase64Field(entry.ed25519_pub),
    );
  } catch {
    ed25519Ok = false;
  }

  return { ok: mlDsaOk && ed25519Ok, mlDsaOk, ed25519Ok };
}
