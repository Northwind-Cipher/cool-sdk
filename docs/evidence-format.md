# Evidence format

Version: `cool.receipt.v2` envelope carrying a `cool.evidence.v1` record.
Structural validator: `validateReceiptV2Shape` (`cool-nwc/phala`) — hand-written,
names the exact failing field. A published JSON Schema is on the roadmap.

## Encodings

| Form | Grammar | Used for |
|---|---|---|
| multihash | `mh:sha256:<64 lowercase hex>` | every digest |
| hex field | `hex:<lowercase hex>` | 16-byte salts |
| base64 field | `base64:<standard base64>` | keys, signatures, raw quote bytes |
| ULID | Crockford base32, 26 chars | `record_id` |
| time | RFC 3339 / `date-time`, UTC | `issued_at`, `timestamp` |

## The record core (`cool.evidence.v1`)

This is the object that is canonicalized and hashed. The signature is **not**
part of it.

| Field | Type | Meaning |
|---|---|---|
| `schema` | `"cool.evidence.v1"` | |
| `record_id` | ULID | unique per record; sorts by time |
| `time.issued_at` | RFC 3339 | when the plane sealed it |
| `time.seq` | int ≥ 0 | monotone within one plane instance |
| `event.type` | string | dotted, e.g. `model.execution`, `agent.action`, `artifact.created`, `policy.decision` |
| `event.application_id` | string | the app that produced it |
| `event.execution_id` | string | the run / session / request this belongs to |
| `event.metadata_hash` | multihash | `mh:sha256(metadata_salt_bytes ‖ canonicalCBOR(metadata))` |
| `event.metadata_salt` | hex field | 16 random bytes |
| `event.commitments.{input,output,state}` | multihash \| null | `mh:sha256(salt ‖ bytes)` of a payload, or null |
| `event.commitments.{input,output,state}_salt` | hex field \| null | paired salt; null iff the commitment is null |
| `event.software` | `{ name, version, digest: multihash\|null }` \| null | workload identity (cleartext by design) |
| `runtime.tee_vendor` | `none \| intel-tdx \| amd-sev-snp \| nvidia-cc` | |
| `runtime.mode` | `mock \| simulated \| hardware` | |
| `runtime.enclave_measurement` | `{ mrtd, rtmr0..3 }` (hex fields) \| null | |
| `runtime.tee_quote` | multihash \| null | digest of the quote in the envelope; `hardware` requires it |
| `runtime.gpu` | GPU attestation ref \| null | |

## The signature

```
message      = canonicalCBOR(core) ‖ multihashDigest(binding_hash)   // 32-byte digest appended
signature    = { alg: "ml-dsa-65+ed25519", key_id, ml_dsa: base64, ed25519: base64 }
```

Both `ml_dsa` (FIPS 204 ML-DSA-65) and `ed25519` are computed over the same
message. Verification requires **both** to pass.

## The envelope (`cool.receipt.v2`)

| Field | Meaning |
|---|---|
| `record` | the core above, plus `signature` |
| `binding_hash` | `mh:sha256(canonicalCBOR(core))` — recompute and compare |
| `inclusion` | `{ leaf_index, tree_size, audit_path: multihash[] }` — RFC 6962 audit path, or null |
| `sth` | signed tree head: `{ log_id, tree_size, root_hash, timestamp, signature, witnesses[] }`, or null |
| `attestation` | `{ mode, note, quote, expected_measurement, key_binding }` |
| `anchor` | OpenTimestamps proof `{ kind, chain, target, tree_size, proof(base64), calendars[], submitted_at, heights[] }`, or null |
| `key_directory` | `{ [key_id]: { ml_dsa_pub: base64, ed25519_pub: base64 } }` — everything needed to verify offline |

`inclusion` and `sth` are present together or absent together.

## Canonicalization

`canonicalCbor` = RFC 8949 §4.2 Core Deterministic Encoding, via `cbor2`. The
same logical value always encodes to the same bytes regardless of property
insertion order, run, or machine. This is what makes `binding_hash` and the
signature reproducible across implementations. Never hash or sign the JSON form —
only `canonicalCBOR(core)`.

## Replay and freshness

Uniqueness is `(application_id, execution_id, record_id)`. `record_id` is a ULID
(time-ordered), `time.seq` is monotone within a plane instance, and
`time.issued_at` is UTC. Timestamps are **not** the sole replay defence — a
consumer that cares about freshness compares `issued_at` and `execution_id`
against its own expectations.

## Versioning

`record.schema` and the envelope `schema` are explicit. A verifier accepts the
versions it knows and rejects unknown ones with a reason — it never interprets a
newer schema as an older one. Changing what bytes get hashed or signed is a
schema-version change.
