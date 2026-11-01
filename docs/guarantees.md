# Guarantees: every claim, its property, its test, its limit

This page answers spec chapter 2. Every public claim CooL makes is listed here, with the security property behind it, the test that exercises it, and what it does **not** establish. If a claim is not on this page, CooL does not make it.

CooL never claims to be "immutable", "unhackable" or "bulletproof", never claims "complete capture", and never claims universal "proof of correct execution". Evidence gaps and uncertainty are reported as results in their own right: `incomplete`, `stale`, `unsupported`, `indeterminate`.

| Claim | Security property | Test | Limitation |
|---|---|---|---|
| A valid signature | the bytes were signed by a key accepted under the stated trust snapshot and purpose | `platform-envelope`, `authz` | does not prove the signed statement is true; does not establish who controls the key |
| Signer trusted | the key is in the verifier's snapshot, for this purpose, valid, not revoked or compromised (unless a checkpoint proves the signing predates it) | `platform-envelope` | only as current as the snapshot (`trust_snapshot_stale` → `stale`) |
| Canonical encoding | the committed bytes are deterministic CBOR and match the readable record | `platform-envelope` | — |
| Merkle inclusion | the record is leaf *i* of a tree of size *n* with this root | `platform-envelope`, `witness-consistency` | does not prove every real-world event was submitted |
| Log consistency | a later tree head extends an earlier one; forks and rollbacks are detected | `witness-consistency` | needs two heads to compare; a log can still withhold |
| Witness signature | a witness the verifier trusts observed this checkpoint | `platform-envelope`, `showcase` | not the truth of any leaf; independence is an operational property |
| Public anchor (OpenTimestamps) | the checkpoint digest existed by a Bitcoin block | `anchor` | anchors a commitment only; nothing about content |
| TEE attestation (Nitro, TDX) | a platform module signed a statement with these measurements, under the verifier's policy and trust bundle | `nitro-attestation`, `real-tee-validation` | not that the application is bug-free, nor that the host cannot deny service; Nitro revocation is not checked |
| Key binding to a TEE | the attested `user_data` / `report_data` binds the signing key | `nitro-attestation`, closure matrix | the key may not be exclusive to one image (dstack keys follow app identity) |
| Principal state | an issuer the verifier trusts asserted this identity; status and keys **at event time** | `authz` | the issuer can be wrong or compromised |
| Delegation chain | authority flowed from an accepted root without amplification, unexpired and unrevoked at event time | `authz` | intent is not proven; only signatures are |
| Request binding | action, target, parameters (by commitment), audience, nonce and expiry are fixed | `authz` | low-entropy parameters need keyed commitments to resist guessing |
| Decision, `trusted` | the evaluator signed this result for this request, policy digest and input digest | `authz` | you trust the evaluator to have run the policy |
| Decision, `reproducible` | re-evaluating the deterministic policy on the disclosed facts gives the same result | `authz`, `demo:agent` A/C | facts not disclosed cannot be checked; no ZK proof is used |
| Replay resistance | a nonce is consumed at most once at the boundary, atomically | `authz` (25-way race), `demo:agent` D | `FileNonceStore` is atomic on one host only |
| Execution binding | the observed workload equals the one the request was authorised for | `authz`, `demo:agent` E | only as good as the observation source |
| Enforcement | the gateway that owns the tool refused or executed it after the checks | `authz-gateway`, `demo:agent` B | actions outside the gateway are not covered |
| External confirmation | the authoritative system signed what it did | `authz-gateway` | not that the downstream effect is correct |
| Sequence completeness | sequenced evidence has no gaps up to the highest number seen | `evidence-v2`, `demo:agent` G | a dropped **final** event is undetectable until a later one or a heartbeat arrives |
| No plaintext in receipts | payload schemas reject secret-like values; requests carry commitments only | `platform-envelope`, `authz-schemas`, `showcase` | metadata (ids, resource names, times) is still visible: review privacy profiles |
| No network calls | the SDK paths make no outbound calls | `egress` | OpenTimestamps anchoring is opt-in and networked |
| Offline verification | bundles verify with no account or service | `platform-cli`, `showcase`, `demo:agent` | without your own trust snapshot the result is `indeterminate` |

## The outcome words

`verified`, `invalid`, `unsupported`, `stale`, `incomplete`, `indeterminate`. Precedence and meanings are defined in `src/platform/outcome.ts`. A report always carries every individual check as well, so the headline never hides the detail.
