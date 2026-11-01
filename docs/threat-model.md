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

---

## System-wide threat model (4.x: authorization, enforcement, multi-platform)

This section extends the model above to agents, authorization and the tool-call boundary (spec chapter 5). **Attacker capabilities** are what an adversary can do. **Trust assumptions** are what CooL has to rely on. Each row is marked *mitigated*, *detected*, *partially mitigated* or *out of scope*.

### Adversaries and controls

| Adversary / capability | Control | Status | Test | Residual risk |
|---|---|---|---|---|
| Malicious agent sends a request beyond its authority | delegation chain verified at the boundary; scope subset; amount ceiling | mitigated | `authz`, `demo:agent` B | the boundary must be the only path to the tool |
| Agent substitutes parameters (amount, recipient) after approval | params commitment recomputed at the boundary | mitigated | `authz`, `authz-gateway` | — |
| Replay attacker resubmits a consumed authorization, including in a race | atomic nonce consumption; expiry; audience binding | mitigated | `authz` (25-way race), `demo:agent` D | single-host nonce store; HA store not built |
| Compromised workload or substituted artifact presents a valid authorization | execution binding (planned vs observed) | detected → refused | `authz`, `demo:agent` E | only as good as the observation source |
| Policy substitution (claim a decision used a different policy) | decision binds the policy digest | detected | `authz`, `demo:agent` C | — |
| Evaluator compromise (signs `permit` wrongly) | `reproducible` assurance lets anyone replay; the boundary re-checks delegation regardless | detected (when facts disclosed) / partially mitigated | `authz`, `demo:agent` B | with undisclosed facts, evaluator trust is an assumption |
| Stolen signing key | trust snapshot status (`revoked`, `compromised`), checkpoint-proven signing time | partially mitigated | `platform-envelope` | signatures before the revocation is known remain accepted |
| Identity issuer compromise | issuer is a trust root; lifecycle events are issuer-signed | out of scope (trust assumption) | — | a compromised issuer can mint principals |
| Malicious log operator (fork, rollback, split view) | consistency proofs; witness co-signatures; anchoring | detected | `witness-consistency`, `platform-envelope` | needs witnesses that are independent in practice |
| Witness collusion | witness threshold; witnesses only count if trusted | partially mitigated | `platform-envelope` | colluding witnesses defeat the threshold |
| Clock manipulation | event / observed / checkpoint times compared; a checkpoint proves "signed before"; nonce for live freshness | partially mitigated | `platform-envelope`, `nitro-attestation` | no RFC 3161 TSA yet |
| Host / proxy between enclave and log (drop, delay, replay, mutate) | receipts signed in-enclave; sequence gaps; mutation fails verification | detected | `nitro-path`, `demo:agent` G | a dropped **final** receipt is invisible until a later one arrives |
| Evidence omission (events never sent) | sequence numbers, heartbeats, `incomplete` outcome | detected where sequenced / out of scope otherwise | `evidence-v2`, `platform-modules` | unsequenced sources cannot show omission |
| Malicious connector | connectors yield inputs that are still validated and signed by the collector | partially mitigated | `platform-client` | a connector can feed false (but well-formed) facts |
| Malicious SDK dependency (supply chain) | 5 runtime deps, trusted publishing with provenance, SBOM, CodeQL, dependency audit | partially mitigated | CI | an upstream compromise before detection |
| Network partition / unavailable dependency | replay store and observation unavailable → `rejected`; verifier → `indeterminate` | mitigated (fail-closed at boundary) | `authz-gateway` | availability is traded for integrity |
| Denial of service | bounded queues; explicit refusal | partially mitigated | `capture` | sustained overload loses evidence, visibly |
| Insider modifying a policy quietly | policies are digest-addressed; `policy.updated` events; managed lifecycle in the commercial platform | detected | `demo:agent` C | requires those events to be recorded |
| Cross-tenant access (hosted control plane) | — | out of scope (not built) | — | to be addressed with the control plane |

### Boundaries

| Boundary | What crosses | Trusted? | Protection |
|---|---|---|---|
| agent → SDK | request inputs, plaintext params | the agent is **untrusted** | the SDK commits; it never trusts the agent's claims of authority |
| agent → gateway | request, params + salt, decision, delegation chain | untrusted input | full re-verification at the gateway |
| SDK → enclave | events to seal | enclave trusted per attestation policy | attestation binding; in-enclave keys |
| enclave → host proxy | signed frames | **untrusted** transport | framing limits; receipts signed before crossing |
| SDK → log | envelope digests | log operator semi-trusted | inclusion and consistency proofs; witnesses |
| log → witness | checkpoints | witness trusted per snapshot | the witness verifies consistency before signing |
| verifier → trust bundle | roots, keys, policies | the **only** trust input | versioned, pinned, never fetched at verify time |
| policy engine → enforcement | signed decision | evaluator trusted per snapshot | signature, binding, freshness; replay for `reproducible` |
| control plane → tenant | — | not built | — |

**Security review:** no independent review has taken place yet (spec chapter 42). Production assurance claims wait for one.
