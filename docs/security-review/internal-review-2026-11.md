# Internal adversarial review, November 2026

**Who:** the maintainers, AI-assisted. **This is not an independent review**, and nothing here should be read as one. See [README.md](README.md).

**Commit range:** the 4.0.0 additions:
- RFC 3161 timestamps
- the AMD SEV-SNP and NVIDIA NRAS verifiers
- KMS/HSM signers
- shared replay stores
- the Nitro enclave kit
- the capability registry

**Method:** for each component we asked one question: *what input makes the verifier say `verified`, or the gateway execute, when it should not?* We then tested the answer:
- GENUINE third-party evidence, tampered systematically
- exhaustive single-bit flips where the input is small enough (RFC 3161)
- random mutation fuzzing (SNP, TSA)
- fault injection (Redis: errors, hangs, dropped connections, wrong credentials)
- races across independent clients

## Findings

All findings are fixed in 4.0.0 and each has a regression test.

| ID | Severity | Component | Finding | Fix | Test |
|---|---|---|---|---|---|
| IR-01 | High | SEV-SNP | The 72-byte r/s fields hold 48-byte P-384 values, and the bytes after the signature are reserved. None of these are signed, so they could be altered without breaking the signature, and the report bytes would not be canonical. | `structure` now requires the padding and the reserved area to be zero (`malformed` otherwise) | `snp: any change inside the signed region…`, the 300-case fuzz "an altered report must never verify" |
| IR-02 | Medium | RFC 3161 | Several fields CMS leaves unsigned were accepted loosely: the SignedData version, the digestAlgorithms set, the SignerInfo version, the sid issuer Name (only the serial was compared), AlgorithmIdentifier parameters, and SEQUENCE-vs-SET tags. A bit flip in any of them left the token `verified`. | exact checks for each; the sid must name the ESS-bound certificate by issuer *and* serial | `rfc3161: every byte that is signed, compared or used in the chain is authenticated (exhaustive single-bit flips)` |
| IR-03 | Medium | Redis store | After a command timed out, its late reply could be paired with the next command on the same connection. A stale `close` event from a torn-down socket also killed its replacement. Both failed *safe* (`unavailable`), but they stopped the gateway working until restart. | a timeout tears the connection down and fails all pending replies; socket handlers act only on the current socket | `redis: every failure is unavailable…` (hang → recover) |
| IR-04 | Low | NVIDIA NRAS | A token with `iat` in the future counted as fresh. | `issued_in_future` → `invalid` | `nvidia: a token dated in the future is rejected` |
| IR-05 | Low | RFC 3161 | Token size was unbounded before parsing. | 64 KiB default limit (`maxBytes`) | `rfc3161: oversized input is refused before parsing` |
| IR-06 | Low | Redis store | A server could stream an unbounded reply into memory. | the connection fails above 1 MiB of buffered reply | — (defensive) |
| IR-07 | Info | NVIDIA NRAS | NVIDIA's own SDK verifies NRAS tokens against the leaf in `x5c` without validating the chain. | CooL validates the chain to pinned NRAS intermediates and checks that the JWK equals the certificate key | `nvidia: the default anchors are NVIDIA's…` |

## Accepted, documented limitations (not fixed)

| Area | Limitation | Where stated |
|---|---|---|
| RFC 3161 | TSA revocation (CRL/OCSP) is not checked offline. Certificates carried in the token but unused (e.g. a TSA's own copy of its root) are not authenticated, by CMS design; the chain ends at the *pinned* anchor instead. | report `limitations`; `docs/capabilities.md` |
| SEV-SNP | VCEK revocation is checked only against serials you supply. The ID block and author key are not evaluated. A report has no timestamp. | report `limitations` |
| NVIDIA | The raw SPDM evidence is appraised by NRAS, not by CooL. Anchors are NRAS intermediates, because the CA 001 root is not published at a documented location. | `src/nvidia/anchors.ts`, report `limitations` |
| Path validation | TSA, SNP and NRAS chains check signatures, validity, CA flags and (TSA) EKU. They do not implement full RFC 5280: name constraints, policies and path-length are not evaluated. | this page; external review question 5 |
| Redis | Durability is the operator's: a failover that loses acknowledged writes can forget nonces inside the TTL. | `docs/capabilities.md` |

## Not reviewed in this pass

- The commercial platform.
- The pre-4.0 receipt engine (`src/phala/`), beyond what its existing adversarial tests cover.
- Side channels in `@noble/*`. We rely on their own audits.
