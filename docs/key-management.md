# Key management

CooL separates **who signs** from **who is trusted**. Signing keys are always the customer's. Trust is an explicit verifier input, the trust snapshot. CooL never needs custody of a customer key.

## Key purposes

Every trusted key lists the purposes it is accepted for (`purposes`), and each verification asks for one. A key trusted only for `log` cannot sign a decision (`wrong_key_purpose`). Give each role its own key.

| Purpose | Signs |
|---|---|
| `evidence` | envelopes |
| `log` | signed tree heads |
| `witness` | witness co-signatures |
| `builder` | build provenance |
| `policy` | policy publications |
| `enforcement` | gateway external confirmations |
| `source` | source-system statements |
| `identity_issuer` | principal records and principal events |
| `evaluator` | authorization decisions |

## Algorithms

The default is the hybrid **ML-DSA-65 + Ed25519** (`ml-dsa-65+ed25519`). **Both signatures must verify.** Algorithms come from the registry (`src/platform/algorithms.ts`), and unknown or retired ids fail closed as `unsupported`. Changing algorithms means adding a registry entry and an RFC (`GOVERNANCE.md`). Existing evidence keeps its algorithm id.

## Lifecycle in the trust snapshot

Each `KeyRecord` has `valid_from`, an optional `valid_until`, and a `status`: `active`, `rotated`, `revoked` or `compromised`.
- **Rotation.** Set `status: "rotated"`, `rotated_at` and `successor` on the old key. A signature dated after `rotated_at` fails `key_rotated`.
- **Revocation.** Set `revoked_at`. A signature is accepted only with *independent* proof that it predates revocation, such as a log checkpoint or an anchor. A claimed timestamp is not enough.
- **Compromise.** Set `compromised_since`. The same rule applies: without independent proof of earlier signing, the result is `key_compromised`.
- **Freshness.** A snapshot with `max_age_ms` older than that gives `trust_snapshot_stale` (outcome `stale`). Without `max_age_ms`, the report states that later revocations are not reflected.
- Principals' keys are bound and retired through `principal.*` events. A request signed with a key retired **at event time** fails `key_not_bound`.

## Signing with a KMS or HSM

`Signer` is an interface: `{ keyId, directoryEntry, sign(message) → SignatureBlock }` (`src/platform/envelope.ts`). `localSigner` is the in-memory reference. To use a KMS or HSM, implement `sign` against your provider. The hybrid scheme needs both an ML-DSA-65 and an Ed25519 signature, so your provider must support both, or you combine a provider-held Ed25519 key with an ML-DSA key held in your secure enclave.

**No managed KMS/HSM adapter ships in the open core.** AWS KMS, GCP KMS, Azure Key Vault and PKCS#11 adapters are **planned**. They will be thin `Signer` implementations, and verification will not change.

## Keys in TEEs

In TEE mode the sealer generates its key inside the enclave or CVM and binds it in `user_data` (Nitro) or `report_data` (TDX). The verifier checks that binding. The key never leaves the TEE. On dstack the key is derived from app identity: see `docs/attestation.md#keys`.

## What never goes in a repository

Private keys, PEM blocks, `.env` files and HMAC commitment keys. CI scans the full history for them on every push (`security.yml`). Test keys are generated in memory from fixed seeds (`tests/support/`).
