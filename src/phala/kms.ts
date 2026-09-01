/**
 * Measurement-sealed keys (dstack-KMS).
 *
 * CooL signs with keys it never chose. The seed comes out of the enclave's key
 * provider, derived from the measurement of the running image, so the signing
 * identity is a property of the code rather than a secret an operator holds.
 * Two consequences, and they are the reason the integration exists:
 *
 *   • CooL's own staff cannot forge a record. There is no key to steal from a
 *     laptop, a vault, or a CI secret — outside the attested image the seed is
 *     simply not derivable.
 *   • Modifying the image is self-reporting. Different code measures
 *     differently, derives a different seed, and produces a different key id.
 *     The old records do not "break"; they keep verifying against a key the new
 *     deployment can no longer produce, which is exactly the signal an auditor
 *     wants.
 *
 * The derivation path is domain-separated so the record key, the log key and any
 * future transport key are independent even though one seed provider backs them.
 */
import type { KeyPair } from "../types";
import { generateKeypair } from "../keys";
import type { DstackClient } from "./dstack";
import { shortMeasurement } from "./quote";

/** Derivation paths CooL uses. Stable strings — changing one rotates a key. */
export const KEY_PATH = {
  /** Signs evidence and change records. */
  record: "cool/evidence/record/v2",
  /** Signs Signed Tree Heads for the transparency log. */
  log: "cool/evidence/log/v2",
} as const;

/** Options for {@link sealedKeypair}. */
export interface SealedKeyOptions {
  /** Derivation path handed to the key provider. Defaults to {@link KEY_PATH.record}. */
  readonly path?: string;
  /**
   * Key id recorded in signatures. Defaults to `cool-<role>-<mrtd prefix>`, so
   * the id itself names the image that holds the key — a reader can spot a key
   * rotation caused by a redeploy without opening the attestation.
   */
  readonly keyId?: string;
  /** Short role label used when the key id is derived. Default `enclave`. */
  readonly role?: string;
}

/**
 * Derive a hybrid ML-DSA-65 + Ed25519 keypair sealed to the enclave.
 *
 * The 32-byte seed never leaves the TEE in a hardware deployment; here it is
 * fetched through the {@link DstackClient} abstraction, which means the same
 * call works against the real guest agent and against the simulator.
 */
export async function sealedKeypair(
  client: DstackClient,
  options: SealedKeyOptions = {},
): Promise<KeyPair> {
  const path = options.path ?? KEY_PATH.record;
  const seed = await client.deriveKey(path);
  if (seed.length !== 32) {
    throw new Error(`key provider returned ${seed.length} bytes, expected a 32-byte seed`);
  }
  let keyId = options.keyId;
  if (!keyId) {
    const info = await client.info();
    keyId = `cool-${options.role ?? "enclave"}-${shortMeasurement(info.measurement, 10)}`;
  }
  return generateKeypair(keyId, { seed });
}

/** The pair of keys an evidence plane needs: one for records, one for the log. */
export interface SealedKeyset {
  readonly record: KeyPair;
  readonly log: KeyPair;
}

/** Derive both sealed keys in one round-trip pair. */
export async function sealedKeyset(client: DstackClient): Promise<SealedKeyset> {
  const [record, log] = await Promise.all([
    sealedKeypair(client, { path: KEY_PATH.record, role: "enclave" }),
    sealedKeypair(client, { path: KEY_PATH.log, role: "log" }),
  ]);
  return { record, log };
}
