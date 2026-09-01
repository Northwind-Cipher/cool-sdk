# Security model

## What a receipt proves

When `verifyEvidence` returns `ok: true`:

- the record's contents match its `binding_hash` (nothing was edited);
- **both** signatures verify against the embedded public key (it was sealed by
  the holder of that hybrid key);
- if a log proof is present, the record is included under a validly signed tree
  head (append-only);
- if a hardware quote is present and a verifier was supplied, the quote chains
  to a vendor root, its measurement matches, and its `report_data` commits to the
  signing key (it was produced in *that* attested environment).

## What it does not prove

- that the output was correct, fair, safe, or policy-compliant — CooL records
  what happened, it does not grade it;
- anything about a `key_id` beyond "this key signed this" — key ids are
  operator-chosen labels, not certified identities; bring your own allow-list;
- independent witnessing or public availability of the log — no external
  witnesses in this build;
- confidentiality, when `mode` is `simulated`.

## Trust boundaries

| Party | Trusted for | Checked by |
|---|---|---|
| CooL client (in the app) | nothing — it holds no key | — |
| Evidence plane (in a TEE) | producing a correct record for the event it was handed | the reader re-checks the quote, measurement, and key binding |
| dstack guest agent | issuing a genuine quote and a measurement-sealed key | a `QuoteVerifier` against the vendor root |
| TEE hardware + vendor attestation service | the measurement reflects the code; the quote is authentic | outside CooL's scope |
| Transparency log operator | not removing or reordering entries | RFC 6962 consistency proofs (external witnesses would strengthen this) |
| The reader | nothing | recomputes every domain from the bytes |

## Cryptographic assumptions

- SHA-256 collision resistance (commitments, Merkle tree, digests).
- Ed25519 EUF-CMA **or** ML-DSA-65 (FIPS 204) EUF-CMA — the hybrid holds if
  *either* survives.
- RFC 8949 CDE gives a single encoding per logical value (canonicalization).
- The platform CSPRNG (`crypto.getRandomValues`) for salts and keys.

## Failure semantics

**Fail-open toward the application.** A dead transparency endpoint, a closed
RA-TLS channel, a full capture queue — none of these throw into the caller's
request path. Loss is counted (`cool.stats()`), never silent.

**Fail-closed toward verification.** The verifier never reports success on a
check it could not perform. `requireAttestation` (connect) and `requireHardware`
(verify) turn "no real quote" into a hard failure instead of a silent downgrade.

## Key management

Signing and log keys are derived inside the enclave from the measurement (dstack
`GetKey`) — there is nothing to configure or rotate manually, and a redeploy
rotates them. Each receipt carries its own `key_directory`, so historical
receipts verify after rotation. Keys are never logged, never persisted outside
the enclave, and never appear in a receipt (only public halves do).

## Privacy

Metadata and every `payloads` value are committed as `mh:sha256(salt ‖ bytes)`
and discarded. Salts are stored beside the commitments so a value can be
selectively disclosed later and checked. `software` identity (name/version/digest)
is cleartext by design. The SDK makes no network calls of its own and carries no
telemetry.

## Supply chain

- runtime dependencies: `@noble/curves`, `@noble/hashes`, `@noble/post-quantum`,
  `cbor2`, `ulid` — audited, minimal, no native code;
- no `postinstall` / install scripts; no downloads at install time;
- the published tarball is an explicit `files` allowlist (`dist`, `src`, README,
  LICENSE, CHANGELOG);
- releases are published by a tagged GitHub Actions workflow using npm trusted
  publishing (OIDC) with provenance — no long-lived tokens.

## Known limitations

- No external transparency witnesses — log integrity rests on the operator plus
  consistency proofs.
- Bitcoin anchoring is implemented but confirmation against block headers is
  opt-in and `pending` until aggregated.
- Remote quote verification against live Intel DCAP collateral is exercised only
  against a mock in CI.
- Phala Cloud / real TDX deployment is documented, not CI-tested.
