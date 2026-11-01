# Changelog

All notable changes to `cool-nwc` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[semantic versioning](https://semver.org). The evidence schema is versioned
independently (`cool.evidence.v1`, `cool.receipt.v2`).

## [Unreleased]

## [4.0.0] — 2026-11-01

**CooL's open core, under Apache-2.0.** This package now contains everything needed to adopt CooL and to verify its evidence independently. The operational, enterprise layer moves to the separately licensed commercial CooL platform. See `docs/open-core.md`.

### Added
- **`cool-nwc/authz`**, the agent authorization protocol:
  - **Principals.** Issuer-signed records with key binding and status **at event time**.
  - **Delegation chains.** Scopes must be subsets, with depth and cycle limits, audience and validity checks, revocation, and privilege-amplification detection.
  - **Canonical authorization requests.** Parameters and context are carried only as salted or **HMAC-keyed commitments**, with NFC normalization.
  - **Signed decisions.** `permit` / `deny` / `indeterminate` / `error`, with `trusted` or **`reproducible`** assurance. In `reproducible` mode the verifier re-runs the deterministic policy.
  - **Atomic replay stores.** `MemoryNonceStore` and `FileNonceStore`, which uses O_EXCL.
  - **Execution binding**, and the reference enforcement boundary **`ToolGateway`**, which fails closed and issues **signed external confirmations**.
- **Policy evaluation is public again.** `evaluatePolicy`, `validatePolicy`, `policyDigest` and `simulatePolicy` are back in `cool-nwc/platform`, because independent replay must not be paywalled. The managed lifecycle (`PolicyRegistry`, overrides) stays commercial.
- **Six verification outcomes**: `verified`, `invalid`, `unsupported`, `stale`, `incomplete`, `indeterminate`. `outcome` is on every envelope and bundle report.
- **Bundles.** Signed protocol objects can travel as attachments (`attachments_bound`). Gaps in sequenced evidence give **`incomplete`** (`sequence_complete`).
- **TEE adapter interface.** `nitroAdapter` and `tdxAdapter` are implemented. Phala dstack is partial. AMD SEV-SNP and NVIDIA CC return `unsupported`.
- **Legacy compatibility.** `wrapLegacyReceipt` / `verifyWrappedLegacy` bring `cool.receipt.v2` into the envelope unchanged.
- **17 new event families**, 50 in total (`docs/event-taxonomy.md`). New key purposes: `identity_issuer`, `evaluator`. Algorithm registry entry `hmac-sha-256`.
- **New schemas and test vectors**: `cool.principal.v1`, `cool.delegation.v1`, `cool.authz-request.v1`, `cool.authz-decision.v1`, `cool.external-confirmation.v1`, and `spec/test-vectors/authz-commitments.v1.json`.
- **`npm run demo:agent`**: scenarios A–H, self-checking. **`npm run bench`**: microbenchmarks.
- **Tests**: authorization, the gateway, schema conformance, outcomes, and **egress**, which proves the showcase and demo make zero network calls.
- **Release.** A CycloneDX SBOM is attached to every GitHub release.
- **Docs**: guarantees, feature matrix, repository audit, system threat model, authorization, demo scenarios, event taxonomy, TEE support, key management, deployment modes, telemetry and egress, performance, compliance mapping (sample), release criteria, `GOVERNANCE.md` (RFC process), the CVA/RCVA/ZK research spike, and the status of every feature.

### Changed
- **License:** Apache-2.0 for 4.0.0 and later. 3.1.0–3.1.1 were published under BUSL-1.1 and keep those terms.
- `verifyBundle` returns `entries` (envelopes ordered by time) in place of `timeline`. Cross-system correlation is a commercial feature. Bundles carry decision records as generic `DecisionRecord`s, bound by digest exactly as before.
- `CoolClient` keeps the `evidence`, `trust` and `connectors` namespaces. `policyMode`, `enforcement` and the module namespaces moved to the commercial platform.
- `NitroReceiptSealer.acceptEpoch()` takes a structural `EpochAssignment`.

### Removed (moved to the commercial CooL platform)
- `cool-nwc/platform`:
  - the policy *lifecycle* (`PolicyRegistry`, `overrideDecision`). Evaluation stays public, see Added
  - `EnforcementCoordinator`, `LocalDirectoryTarget`, `LocalDenylistTarget`
  - correlation (`correlate`, `buildTimeline`)
  - the supply-chain, identity, change-control, runtime-guard and incident modules
- `cool-nwc/nitro`: `NitroLogServer`, `EpochLog`, `verifyEpochRegistration`.
- `cool-nwc/phala`: the observing `Witness` service class. Co-signing and witness verification (`cosign`, `attachWitness`, `countWitnesses`) stay.
- CLI: `cool decide`, `cool gate-demo`.
- `examples/supply-chain-gate`; the validation evidence-plane and witness service deployment files. The verification scripts and `artifacts/` stay.
- Internal documents: IP reports, ADRs, status reports, research and pricing notes.

### Migration
- If you used the removed APIs, pin `cool-nwc@3.1.1` (BUSL-1.1) or contact Northwind Cipher about the commercial platform.
- The evidence formats are unchanged. Receipts, envelopes and bundles produced by 3.x verify with 4.0.0.

## [3.1.1] — 2026-11-01

The first npm release of the 3.1 line. The code is identical to 3.1.0. That version was tagged but never reached npm, because the release workflow's npm was too old for trusted publishing.

### Fixed
- Release workflow: install npm ≥ 11.5.1 before publishing, which trusted publishing (OIDC) requires.

## [3.1.0] — 2026-10-31

New capabilities under two new subpaths. **No breaking change:** `CooL`, `CoolTee`, `cool.evidence.v1`, `cool.receipt.v2` and `cool verify` behave exactly as in 3.0.0.

### Added
- **`npm run showcase`** (repository): twelve chapters covering every capability. Every printed claim is an assertion (47 today), and CI runs it as a test. See `docs/showcase.md`.
- **`cool-nwc/platform`**: a technology-neutral evidence platform on the existing cryptographic core.
  - `cool.envelope.v1` with explicit `createEnvelope` / `canonicalize` / `commit` / `signEnvelope` / `verifyEnvelope` / `inspectEnvelope`. The exact canonical bytes are carried, so non-canonical encodings are rejected.
  - An eleven-check verification report (`pass | fail | unknown | not_applicable | not_checked`, plus reason codes). An invalid signature and an untrusted signer are separate failures.
  - 33 typed, versioned event families (`PayloadRegistry`), with a guard against secret values in payloads.
  - `TrustStore` with key purpose, validity, rotation, revocation and compromise. A revoked key is accepted only with a trusted checkpoint that predates the revocation.
  - A fail-closed algorithm registry.
  - A deterministic policy engine (`cool.policy.v1`): tri-valued logic, so unknown is never safe; the most restrictive decision wins; lifecycle with rollback; simulation; attributable overrides.
  - `EnforcementCoordinator`: disabled and dry-run by default, idempotent, timeouts stay unknown until reconciled, and external confirmation is required. Reference targets: `LocalDirectoryTarget` and `LocalDenylistTarget`.
  - `TransparencyLog` with witnessed checkpoints; signed evidence bundles (`exportBundle` / `verifyBundle`) whose verifier recomputes everything.
  - Correlation and timelines that keep contradictions and gaps visible.
  - A connector framework with `GitConnector` and `FileConfigConnector`.
  - `CoolClient` with module namespaces, policy modes, a redacted `inspectConfig`, a pluggable `Signer`, and a deterministic `close`.
  - Modules: supply-chain gate, identity & authority, change control, runtime guard, incident evidence.
- **`cool-nwc/nitro`**: AWS Nitro Enclaves.
  - The offline attestation verifier, pinned to `AWS_NitroEnclaves_Root-G1`.
  - The in-enclave `NitroReceiptSealer`, behind `NsmSource`.
  - vsock framing with a forward-only host proxy.
  - `NitroLogServer`: registration on attestation, signed acknowledgements, epochs, gaps that are never erased, witnessed checkpoints.
  - `normalizeNitro` / `normalizeTdx`.
  - **Not run in a real enclave.** Tested on a genuine third-party AWS document and a synthetic PKI.
- **CLI:** `cool bundle verify`, `cool decide` and `cool gate-demo`, with stable exit codes (`docs/cli-exit-codes.md`).
- JSON Schemas in `spec/schemas/`, and the `examples/supply-chain-gate` example (run in CI).
- Docs: `docs/platform.md`, `docs/trust-models.md`, `docs/nitro.md`, `docs/showcase.md`, `docs/migration-platform.md`, `docs/adversarial-test-plan.md`, ADRs 0001–0003, and the implementation status report.

### Changed
- **Licensing:** the repository moves from Apache-2.0 to the Business Source License 1.1 (Change Date 2030-01-01, Change License Apache-2.0). Versions released before this change, including 3.0.0, remain available under Apache-2.0. A few vendored files keep their Apache-2.0 license. See `LICENSE`, `NOTICE.txt` and `docs/IP-OWNERSHIP.md`.
- Added copyright and SPDX headers to Northwind-owned source files (comment-only).

### Fixed
- **Documentation:** dstack keys follow the application identity, not the workload image. A redeploy under the same `app_id` keeps the same key. Workload identity comes from the pinned measurement.
- **Documentation:** the README no longer lists ML-KEM-1024, X25519, ChaCha20-Poly1305 or RFC 3161. None of them is implemented.

## [3.0.0] — 2026-09-02

The SDK is now a standalone, publicly consumable package. The public surface is
built around **generic execution evidence** rather than AI inference capture.

### Added
- `CooL` — the high-level client: `new CooL({ applicationId }).record({ type, metadata, payloads, software, gpu })`.
- `cool.evidence.v1` — a generic evidence record (event type + salted metadata
  commitment + optional input/output/state commitments + software identity),
  carried through the same canonical-CBOR → hash → hybrid-sign → RFC 6962 log →
  verify pipeline as change records.
- `verifyEvidence()` and `formatVerdict()` (boxed, plain-ASCII report) from the
  root and from the `cool-nwc/verify` subpath.
- Typed error set: `CooLError` with stable `code`s and an `action` hint, plus
  `ConfigurationError`, `DstackUnavailableError`, `AttestationRequiredError`,
  `AttestationError`, `EvidenceError`, `ClosedError`.
- `security.requireAttestation` — fail closed (at connect and at verify) when no
  verified hardware root is present.
- `scripts/demo.ts` (`npm run demo`), five runnable examples, and a documentation
  tree under `docs/`.
- CI that packs the tarball, installs it into a clean project, and verifies the
  evidence round-trip and the type resolution under `nodenext` and `bundler`.

### Changed
- **Breaking:** the receipt record schema is `cool.evidence.v1` (was
  `cool.inference.v2`). The envelope stays `cool.receipt.v2`.
- **Breaking:** `applicationId` is a first-class client option and is stamped
  into every record.
- Package name kept as `cool-nwc`; repository moved to
  `github.com/Northwind-Cipher/cool-sdk`.

### Removed
- **Breaking:** the AI-inference capture surface — `Cool.complete()`,
  `CoolTee.complete()` / `completeSealed()`, the `backend` / `TeeBackend`
  option, `InferenceEvent`, the `cool.inference.*` schemas, `PhalaPrivateLLM`
  and the OpenAI-compatible completion client, and the legacy v1 `cool.receipt.v1`
  client / JSON-Schema / precompiled Ajv validator. The `ajv` runtime dependency
  is gone.

See [`docs/migration.md`](docs/migration.md) for moving from the inference API to
`record()`.
