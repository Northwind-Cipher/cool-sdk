# Adversarial test plan (spec page 42), with results

Controlled tests only, all in `tests/`, and all run by `npm test`. "Observed" is what the code does today. "Residual risk" is what a pass does **not** rule out.

## Supply chain

| Attack | Expected | Observed | Test | Residual risk |
|---|---|---|---|---|
| Replace the artifact after signing | deny; target refuses | `deny (artifact_digest_mismatch)`, and the target independently recomputes and refuses | platform-supply-chain, platform-enforcement | an artifact swapped *between* the target's check and its use (TOCTOU) |
| Wrong provenance subject | deny | `deny (wrong_provenance_subject)` | platform-supply-chain | none in the gate |
| Untrusted builder | deny | `deny (untrusted_builder)`, or unknown facts → deny | platform-supply-chain | a trusted builder that is itself compromised |
| Replay old provenance for a new artifact | deny | subject mismatch → deny | platform-supply-chain | none in the gate |
| Dependency changed after approval | deny | change-control `changed_after_approval` → deny | platform-modules | needs an SBOM connector; none ships |
| Missing SBOM | flag | `audit_only (sbom_missing)`, admitted and flagged | platform-supply-chain | policy choice; make it `deny` for strict environments |

## Identity

| Attack | Expected | Observed | Test |
|---|---|---|---|
| Revoked credential or key | reject unless proven earlier | `key_revoked`; accepted only with a trusted checkpoint dated before revocation | platform-envelope |
| Token replay | detect | `ReplayGuard → replayed` | platform-modules |
| Out-of-scope action, cross-tenant access | deny | `no_matching_grant` | platform-modules |
| Unknown identity | deny | `unknown_identity` | platform-modules |
| Expired or rotated key | reject | `key_expired`, `key_rotated` | platform-envelope |
| Compromised key | reject | `key_compromised` | platform-envelope |

Residual risk: CooL relies on the identity provider's own assertions. It does not detect a compromised IdP.

## Change control

| Attack | Expected | Observed | Test |
|---|---|---|---|
| Alter config after approval | deny | `deny (changed_after_approval)` | platform-modules |
| Stale approval reused | require approval | `approval_stale` | platform-modules |
| Self-approval | deny | `self_approval` | platform-modules |
| Promote after a failed or unknown health check | refuse | `fail → rollback`, `unknown → hold` | platform-modules |
| Unauthorized rollback | refuse | `rejected` without an approval | platform-modules |
| Bypass canary | n/a | the controller never skips a stage; there is no external rollout system integrated | platform-modules |

## Runtime

| Attack | Expected | Observed | Test |
|---|---|---|---|
| Spoofed source event | not acted on | `untrusted_source`; no response | platform-modules |
| Duplicate or out-of-order event | dedup | `duplicate` | platform-modules |
| Suppressed telemetry | detect | heartbeat silence and sequence gaps reported | platform-modules |
| Unauthorized isolation | refuse | coordinator rejects decisions that don't permit `isolate`; dry run by default | platform-enforcement, platform-modules |
| False positive response | limit blast radius | runtime policy ships in **observe** mode | platform-modules |

## Incident and evidence

| Attack | Expected | Observed | Test |
|---|---|---|---|
| Alter a bundle (add or remove an entry) | detect | `manifest_mismatch` | platform-supply-chain, platform-cli |
| Remove a source record | detect | `missing_evidence`; timeline `missing` | platform-envelope, platform-modules |
| Contradictory timestamps | flag | `contradicted`, with the contradiction listed | platform-modules |
| Corrupt Merkle proof | detect | `inclusion_invalid` | platform-envelope |
| Forged tree head | detect | `checkpoint_signature_invalid` | platform-envelope |
| Present an inference as a verified fact | label | heuristic links are `inferred`, never `verified` | platform-modules |
| Edit the readable record but not its bytes | detect | `core_mismatch` | platform-envelope |
| Non-canonical re-encoding | detect | `non_canonical_encoding` | platform-envelope |

## Nitro

| Attack | Expected | Observed | Test |
|---|---|---|---|
| Altered receipt (proxy mutates bytes) | reject, store nothing | `rejected`; nothing stored | nitro-path |
| Dropped middle receipt | gap | gap `unresolved` → `filled_late`, never erased | nitro-path, nitro-epochs |
| Dropped final receipt | undetectable until a later sequence | as expected, and documented | nitro-epochs |
| Stale attestation at registration | refuse | `attestation_stale` → no epoch | nitro-path |
| Debug enclave | refuse | `debug_enclave` | nitro-path, nitro-attestation |
| Changed PCR, wrong key, broken chain, nonce replay, malformed CBOR | reject with a reason | see `tests/nitro-attestation.test.ts` (23 cases plus 600 corruptions) | nitro-attestation |

Residual risk on all Nitro rows: proven on a synthetic PKI and a third-party AWS document, **not** on a CooL enclave.
