# ADR 0002: Nitro receipt key, attestation binding and freshness

- **Status:** accepted for the verifier, proposed for the enclave side. Awaiting Kailosh's sign-off.
- **Date:** 2026-10-31

## Decision

1. **Ephemeral key, generated in the enclave.** Each enclave boot generates a fresh ML-DSA-65 + Ed25519 keypair (the same `generateKeypair` the TDX path uses). The private half never leaves the enclave. The key identifies one enclave *instance*.
2. **No AWS KMS by default.** KMS persistence is added only if stable identity across restarts is a real product requirement. If it is, the key policy must be conditioned on PCR0–2 (`kms:RecipientAttestation:PCR*`), with documented ownership, rotation, recovery and revocation. A stable key never substitutes for a fresh attestation binding.
3. **Binding: `user_data` is authoritative.** `user_data` = SHA-256(`"cool.nitro.key-binding.v1\0"` ‖ canonical CBOR `{ctx, key_id, keys: [{alg: "ml-dsa-65", pub}, {alg: "ed25519", pub}]}`). It is a digest because an ML-DSA-65 public key is 1952 bytes, and AWS caps `user_data` and `public_key` at 1024.
4. **`public_key` carries the Ed25519 SPKI** by default, and the verifier requires it to match. Policy can mark it `unused`, for deployments where `public_key` serves another protocol, such as a KMS recipient key. `user_data` still binds in that case. The two fields are never treated as interchangeable.
5. **Epochs are assigned by the log**, on registration of a *passing* attestation report. The registration is signed. Receipts carry `epoch` and `sequence`, the log detects gaps, and gaps are never erased.
6. **Freshness.** Use nonce mode for interactive trust decisions, and timestamp-window mode only for archived evidence, which is reported as weaker. Nonce mode never falls back to timestamp mode.
7. **PCR policy.** PCR0–2 are mandatory. PCR8 must be stated explicitly, either as a value or as `not_applicable`. Debug enclaves, whose PCR0–2 are all zero, always fail.

## Open items

- NSM semantics for `public_key` and `user_data` have been checked against AWS documentation only. Behaviour should be confirmed against a live NSM on a test enclave.
- **Conflict with Caution:** in Caution's TLS mode, Caddy already places its certificate fingerprint in `user_data` (Codeberg `caution/platform` README at commit `f40f1346…`). If the CooL workload cannot request its *own* attestation document, the binding needs a different design. This is the subject of Caution question 1 (ADR 0003).
- The enclave-side code (NSM client, key generation, receipt sealing, vsock framing) is not written.
