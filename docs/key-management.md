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

A CooL signature has two halves: ML-DSA-65 (FIPS 204, pure, empty context) and Ed25519 (RFC 8032, pure), over the same message. Both must verify. A provider-backed signer is therefore two **component signers**, one per algorithm, and the two can live in different places. `hybridSigner()` combines them into an `AsyncSigner`.

Before returning, every remote signature is **verified locally against the configured public key**. A wrong key id, a wrong algorithm or a provider fault therefore fails at signing time, not at an auditor's.

Async signing paths:
- `signEnvelopeAsync`
- `signObjectAsync`
- `decideAsync`
- `ToolGateway({ key })`, which accepts an `AsyncSigner`

| Provider | Adapter | Key setup | Label |
|---|---|---|---|
| **AWS KMS** | `awsKmsSigner(client, { mlDsaKeyId, ed25519KeyId })` | `ML_DSA_65` (signs with `ML_DSA_SHAKE_256`) + `ECC_NIST_EDWARDS25519` (`ED25519_SHA_512`), `MessageType: RAW` | **experimental** |
| **Google Cloud KMS** | `gcpKmsSigner(client, { mlDsaVersion, ed25519Version })` | `PQ_SIGN_ML_DSA_65` + `EC_SIGN_ED25519` (both pure) | **experimental** |
| **PKCS#11 HSM** | `pkcs11Component(session, label, alg, publicKey)` | `CKM_ML_DSA` (PKCS#11 3.2) + `CKM_EDDSA` (3.0), if your HSM supports them | **experimental** |
| **Mixed** | `hybridSigner({ mlDsa: awsKmsComponent(…), ed25519: pkcs11Component(…) })` | any combination | follows its parts |
| **Azure Key Vault** | — | Key Vault offers neither Ed25519 nor ML-DSA | **unsupported** |

**Why "experimental":** the adapters are tested against in-process provider emulators. These hold the private key the way the service does, return public keys in the provider's own format, and enforce its API rules. They have not yet been run against the live services from this repository. To move one to *implemented*, run it against your account and commit the artifact:

```bash
npm i --no-save @aws-sdk/client-kms
COOL_AWS_MLDSA_KEY=alias/cool-mldsa COOL_AWS_ED25519_KEY=alias/cool-ed25519 npm run validate:kms -- aws
# writes artifacts/kms-validation/aws-<time>.json: public keys, a signed envelope, the verdict. No secrets.
```

Provider SDKs are not dependencies. Each adapter takes the smallest client shape it needs, and the doc comments in `src/platform/signers.ts` show the two-line wrappers for the AWS SDK v3 and `@google-cloud/kms`. Network calls happen only inside the client you pass in.

## Keys in TEEs

In TEE mode the sealer generates its key inside the enclave or CVM and binds it in `user_data` (Nitro) or `report_data` (TDX). The verifier checks that binding. The key never leaves the TEE. On dstack the key is derived from app identity: see `docs/attestation.md#keys`.

## What never goes in a repository

Private keys, PEM blocks, `.env` files and HMAC commitment keys. CI scans the full history for them on every push (`security.yml`). Test keys are generated in memory from fixed seeds (`tests/support/`).
