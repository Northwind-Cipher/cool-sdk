# Threat model

Assets: the integrity and authenticity of evidence records, and the privacy of
the data they commit to. Adversary: anyone who can obtain a receipt and wants it
to say something false — or wants to read the data behind it.

| # | Threat | CooL defense | Residual risk |
|---|---|---|---|
| 1 | Edit a field of a stored receipt | `binding_hash` = `mh(canonicalCBOR(core))`; the signature covers `core ‖ binding_digest`. Any change breaks both. | Compromise of the enclave signing key. |
| 2 | Re-encode / reorder JSON to change bytes | Hash and signature are over RFC 8949 CDE CBOR, not JSON. Key order is irrelevant. | A canonicalization bug — mitigated by cross-run/cross-machine tests; formal verification is on the roadmap. |
| 3 | Replay an old record as new | `(application_id, execution_id, record_id)` uniqueness; ULID `record_id`; monotone `seq`; UTC `issued_at`. | Freshness policy is the consumer's — CooL supplies the fields, not a clock authority. |
| 4 | Swap the signer (present a different key) | The signature names a `key_id`; verification uses `key_directory[key_id]`; `report_data` in a hardware quote commits to that exact key. | Trusting the wrong `key_id` — bring an allow-list; key-directory management. |
| 5 | Staple a valid quote from another enclave onto this record | `enclave` domain: quote digest must equal `runtime.tee_quote` (inside the signature), measurement must match, `report_data` must commit to the signing key. | TEE hardware / vendor attestation-service compromise. |
| 6 | Claim a simulated run was hardware | `mode: "simulated"` is in the signed core; verifier returns `simulated`, never `pass`; `requireHardware` makes it `ok: false`. | Operator turns the policy off. |
| 7 | Remove or reorder entries in the transparency log | RFC 6962 inclusion + consistency proofs; the STH root commits to every leaf. | No external witnesses in this build — a malicious operator with the log key could fork it; consistency proofs bound the damage. |
| 8 | Backdate a tree head | Optional OpenTimestamps anchor: the root is committed into a Bitcoin block, which cannot be pre-dated. | Anchor is optional and `pending` for ~1h after submission. |
| 9 | Read the prompt / output / metadata from a receipt | Only salted commitments are stored; plaintext is hashed and discarded inside the plane. | Weak/low-entropy payloads are still guessable from a commitment despite the salt — commit to high-entropy representations where it matters. |
| 10 | Man-in-the-middle the client → plane channel | RA-TLS: the client verifies the plane's quote against policy **before** transmitting; a mismatched endpoint fails the handshake and the caller is unaffected. | Client host compromise (the client holds no key, but it holds the plaintext before it is sent). |
| 11 | Tamper with the SDK itself (supply chain) | Minimal audited deps, no install scripts, `files` allowlist, OIDC trusted publishing + provenance. | A compromised upstream dependency; verify provenance on install. |
| 12 | DoS the evidence pipeline | Bounded, fail-open capture queue: oldest events dropped and **counted**, never blocking the request. | Under sustained overload, evidence is lost — visible in `cool.stats()`, not silent. |

## Explicitly out of scope

CooL does not protect against:

- application logic that is compromised or simply wrong, producing valid
  evidence of the wrong thing;
- TEE hardware vulnerabilities or a compromised vendor attestation service;
- an operator who configures incorrect trust roots or disables the security
  policy;
- a malicious but *approved* workload;
- traffic analysis / metadata leakage at the network layer.
