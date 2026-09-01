/**
 * v2 record construction: the bytes that get hashed, signed and logged.
 *
 * Identical in spirit to v1's `../record.ts` — `binding_hash` is a deterministic
 * commitment to the whole core, and the signing message appends the binding
 * digest so the signature covers both the bytes and the commitment. The only
 * change is that these helpers are generic over the two cores (evidence and
 * change), because both flavours must hash, sign, log and verify by exactly the
 * same rules. One rule set means one verifier and no second implementation to
 * keep in step.
 *
 * Note what is inside the core in v2 and was not in v1: the runtime block, and
 * therefore the measurement and the quote digest. That is what makes "produced
 * inside this specific attested image" a signed claim rather than metadata
 * attached beside the signature.
 */
import type { Multihash, SignatureBlock } from "../types";
import { canonicalCbor } from "../canonical";
import { concatBytes } from "../codec";
import { mhSha256, multihashDigest } from "../multihash";
import type { RecordCoreV2, SignedRecordV2 } from "./types";

/** Strip the detached signature, leaving the hashed core. */
export function coreOfV2(record: SignedRecordV2): RecordCoreV2 {
  const clone = { ...record } as Record<string, unknown>;
  delete clone["signature"];
  return clone as unknown as RecordCoreV2;
}

/** `binding_hash = mh:sha256(canonicalCBOR(core))`. */
export function bindingHashV2(core: RecordCoreV2): Multihash {
  return mhSha256(canonicalCbor(core));
}

/** The signed message: `canonicalCBOR(core) ‖ binding_digest`. */
export function recordSigningMessageV2(core: RecordCoreV2, binding: Multihash): Uint8Array {
  return concatBytes(canonicalCbor(core), multihashDigest(binding));
}

/** The transparency-log leaf: the 32-byte binding digest. */
export function recordLeafDataV2(binding: Multihash): Uint8Array {
  return multihashDigest(binding);
}

/** Attach a signature to a core. */
export function signedRecordV2(core: RecordCoreV2, signature: SignatureBlock): SignedRecordV2 {
  return { ...core, signature } as SignedRecordV2;
}

/** Human label for a record, used by verdicts and the ledger. */
export function recordSubjectLabel(core: RecordCoreV2): string {
  return core.schema === "cool.evidence.v1"
    ? `${core.event.type} (${core.event.application_id})`
    : `${core.change.kind}: ${core.change.ref}`;
}
