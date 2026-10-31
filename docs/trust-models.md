# Trust models: Phala / Intel TDX and AWS Nitro

CooL has two confidential-execution paths. They have different roots, different verifiers and different key models, and they stay separate at the attestation layer. Only their *verified* results are meant to be normalized. Each statement below is labelled with how it is known:

- **[code]**: true of the code in this repository, with tests.
- **[observed]**: seen in the recorded hardware runs under `artifacts/`.
- **[vendor]**: what the platform vendor documents. CooL relies on it and has not verified it independently.
- **[open]**: unresolved.

## Seven claims, never merged

A receipt can carry evidence for up to seven different statements. Each one is checked on its own, and none implies another.

| # | Claim | Established by | Does **not** establish |
|---|---|---|---|
| 1 | **Platform attestation**: genuine TEE hardware produced this statement | TDX quote → Intel PCK chain; Nitro COSE_Sign1 → AWS root | that the workload is correct, or that the host cannot deny service |
| 2 | **Workload measurement**: this code was running | MRTD/RTMR0–3 or PCR0–2 compared with a **pinned** policy | that the pinned code is bug-free; the pin is only as good as how it was approved |
| 3 | **Runtime key possession**: that code held this signing key | TDX `report_data`, or Nitro `user_data`/`public_key`, binds the key | that no other workload can hold the same key (see the dstack KMS below) |
| 4 | **Receipt signature**: this key signed these bytes | ML-DSA-65 + Ed25519 over the canonical core | that the signed claim is true |
| 5 | **Log inclusion**: the receipt is in this log | RFC 6962 audit path + signed tree head | that every real event was logged |
| 6 | **Witness co-signature**: another key saw this tree head | witness signature over the STH | organizational independence, unless that is shown separately |
| 7 | **Public anchoring**: the head existed by a point in time | OpenTimestamps proof against Bitcoin | anything about the content beyond its hash |

Neither path claims that every event was captured, that output was correct, or that the operator cannot stop the service.

## Phala / dstack / Intel TDX

**Hardware root.** TDX quotes are signed by the CPU's quoting enclave under Intel's PCK certificate chain, which roots at the Intel SGX Root CA. [vendor]

**Quote verification in CooL.** CooL does not embed DCAP. A `QuoteVerifier` is supplied: either Phala's attestation service (online), or a local `@phala/dcap-qvl` check against collateral archived from that service, which the validation run used. [code] [observed]

On `main`, CooL records `tcb_status` as `Unknown` and has **no quote-freshness check**. [code] TCB policy and freshness exist on the unmerged branch `feat/verifier-split-python-sdk`. [open]

**Measurement policy.** The enclave domain compares MRTD and RTMR0–3 with the pinned values. A mismatch fails closed under `requireHardware`. [code] [observed: "B against A's pin" rejected on RTMR3]

**Runtime identity.** The quote's `report_data` binds the CooL signing key, and the quote sits inside the signed receipt core. [code] [observed]

**Key management: the dstack KMS.**

- **Where keys come from.** CooL obtains its seed from dstack `GetKey(path)` (`src/phala/kms.ts`), with domain-separated paths for record and log keys. [code] dstack documents that its KMS releases keys only to CVMs whose attestation it accepts, and that it derives application keys from its own root key and the application identity. [vendor]
- **Release or derive?** From CooL's side, the KMS *derives* a seed and *releases* it to the CVM. The seed then exists inside the CVM's memory, and CooL expands it into the ML-DSA-65 and Ed25519 keypair there. The KMS itself can recompute it. [code] [vendor]
- **Bound to what? (the key finding of this audit)** The key follows the **application identity, not the workload image.** In the closure run, Deployments A and B had different RTMR3 values under the same `app_id`, and signed with the **same** key, `cool-enclave-f06dfda6dc`. [observed] Earlier docs said a redeploy rotates keys; that was wrong and has been corrected. The consequence is that a signature cannot tell A from B. Only claim 2, the pinned measurement, can, so the pin is mandatory for any workload-identity claim.
- **What remains trusted outside the TEE:** the dstack KMS and its own attestation and authorization policy, meaning which workloads it admits under an application identity [vendor] [open: CooL does not verify the KMS's attestation]. Also the operator, for availability. And Phala's attestation service, when online verification is used.
- **KMS unavailable.** `sealedKeypair` throws, so no key means no receipts. Evidence production fails closed, and availability is lost. [code]
- **Rotation and revocation.** There is no CooL-level revocation. The key changes only when the KMS derivation input changes. A compromised key cannot be revoked for offline verifiers, who keep accepting historical receipts signed by it. [code] [open]
- **Do not trust the KMS by name.** Its guarantees are its own trust assumptions. CooL inherits them and does not strengthen them.

**Offline limits.** Binding, signature and inclusion verify offline. Quote verification is offline only with archived collateral, and archived collateral cannot show revocations issued after it was fetched.

## AWS Nitro Enclaves

**Hardware root.** The attestation document is a CBOR COSE_Sign1 (ES384) signed by a per-enclave leaf certificate. That certificate chains through regional, zonal and instance intermediates to `AWS_NitroEnclaves_Root-G1` (subject `CN=aws.nitro-enclaves`, valid 2019–2049). [vendor]

**Root pinning.** The root is embedded in `src/nitro/trust-root.ts`. It came from `https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip` (zip SHA-256 `8cf60e2b…aff7c`) and was checked against AWS's published fingerprint `64:1A:03:21:…:BB:5B`. The module refuses to load if the embedded root and the pinned fingerprint ever diverge. Trust bundles are versioned, and every report names the bundle and root used. [code]

**Verification order** (`verifyNitroAttestation`) [code]:

1. Strict structure: size cap, duplicate keys rejected, `{1: -35}` only, empty unprotected header, no unknown fields, AWS field types and sizes.
2. `cabundle[0]` byte-equal to a pinned root.
3. Chain: issuer linkage, signature, CA flag, and validity at the stated time.
4. COSE signature, using the leaf P-384 key.
5. **Only then** are the claims consumed: debug mode (PCR0–2 zero is a fail), PCR policy, PCR8, key binding, `public_key`, freshness.

**PCR policy.** PCR0, PCR1 and PCR2 are mandatory pins. PCR8 must be stated explicitly, either as an expected value (signed image) or as `not_applicable`; the verifier will not guess. The policy's id, version and source are recorded in the report. [code]

**Key binding.** The CooL design is a fresh hybrid keypair generated inside the enclave per boot, with no KMS by default. `user_data` = SHA-256(`"cool.nitro.key-binding.v1\0"` ‖ canonical CBOR of the key id and both public keys). The digest is needed because ML-DSA-65 keys (1952 bytes) exceed the 1024-byte NSM field limit. `public_key` carries the Ed25519 key as DER SubjectPublicKeyInfo, unless the policy reserves it for another protocol. [code: verifier] [open: the enclave side is not built]

**Freshness.** In nonce mode (preferred), the verifier's nonce must be returned exactly, and an optional ledger rejects replays. Timestamp-window mode accepts a maximum age plus clock skew, and is reported as weaker. There is no silent downgrade: nonce mode with no nonce in the document is a fail. [code]

**Host and vsock.** The parent instance and any sidecar are untrusted transport. They can delay, drop, replay or reorder, but cannot forge: receipts are signed inside the enclave before they cross vsock. Drops become detectable *gaps* (`src/nitro/epochs.ts`) once a later sequence arrives; a dropped final receipt is invisible until then. [code: log side] [open: vsock transport not built]

**Limits.**

- The chain is checked with `node:crypto`, not a full RFC 5280 validator, so path-length, key-usage and name constraints are not evaluated.
- AWS publishes no CRL for this PKI, so there is no revocation check.
- An offline pass means "valid under the local bundle and policy", not "not revoked since the bundle was last reviewed".
- A valid document proves that a Nitro module made a signed statement with these claims. It does not prove the application is bug-free, that every event was recorded, or that the host cannot deny service.

## Normalization: the next step, not done yet

The two paths currently report in different vocabularies. TDX uses the receipt v2 domains (`pass | fail | absent | mock | simulated | pending`). Nitro uses `pass | fail | unknown | not_applicable | not_checked` with reason codes. A shared normalized attestation result, which the spec requires, is **not implemented**. The intended mapping keeps `unknown` and `not_checked` distinct from `absent`, and never maps either to `pass`. [open]
