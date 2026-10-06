# Changelog

All notable changes to `cool-nwc` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[semantic versioning](https://semver.org). The evidence schema is versioned
independently (`cool.evidence.v1`, `cool.receipt.v2`).

## [Unreleased]

### Changed

- **Licensing:** the repository moves from Apache-2.0 to the Business Source License 1.1 (Change Date 2030-01-01, Change License Apache-2.0). Versions released before this change, including 3.0.0, remain available under Apache-2.0. A few vendored files keep their Apache-2.0 license. See `LICENSE`, `NOTICE.txt` and `docs/IP-OWNERSHIP.md`.
- Added copyright and SPDX headers to Northwind-owned source files (comment-only).

### Added — Edgeless Systems Contrast support

CooL evidence cryptographically bound to a confidential Kubernetes workload.

Contrast's attestation is a *credential*, not a quote — its Coordinator verifies
each pod's SNP/TDX report against a signed manifest and issues a mesh
certificate carrying the claims it verified. CooL binds to that on both sides:
its signing key is derived from the Contrast workload secret (released only to a
pod that passed attestation), and the pod's mesh key signs a commitment to that
key. The resulting identity lives inside the signed record core, so a receipt
from one workload cannot be presented as another's.

### Added
- `cool-nwc/contrast` — `ContrastWorkload` (reads the credential Contrast mounts
  at `/contrast`), the workload verifier, and browser-safe X.509 / DER /
  manifest helpers. No new runtime dependency.
- An eighth verdict domain, **`workload`**, for orchestrator-issued attestation.
  It reaches `pass` only against a Coordinator root CA the verifier pinned; an
  unpinned chain is reported, never passed, and a Contrast `insecure` (non-CC)
  platform reports `simulated`.
- `verifyEvidence` options: `coordinatorRootCA`, `expectedManifest`,
  `allowedPolicyHashes`, `expectedRegisters`. `requireHardware` is now satisfied
  by either a verified vendor quote or a pinned workload credential, and the
  verdict always names which route was taken.
- `cool verify --coordinator-root <pem> --manifest <json>`.
- `CooL.change()` on the high-level client — the governance half of the evidence
  model, previously only on `CoolTee`.
- `AttestationSource` — what the evidence plane actually requires of a
  confidential runtime. `DstackClient` satisfies it; so does `ContrastWorkload`.
- `cool.change`/`record` accept `runtime`, and `attestation.provider: "contrast"`
  (auto-detected from `$COOL_CONTRAST_ROOT`).
- `tools/contrast-fixture/` — generates the test fixtures from **Contrast's own**
  `internal/ca`, `internal/seedengine`, `internal/attestation/tdx` and
  `internal/oid`, so the 29 Contrast tests assert cross-implementation agreement
  rather than agreement with something CooL wrote for itself.
- `examples/contrast/` — an AI service, Kubernetes manifests, a Dockerfile, a
  deploy script, an independent verifier, and an end-to-end demo
  (`npm run demo:contrast`) that needs no cluster.
- `docs/contrast.md` — architecture, the exact binding, trust model, security
  review, and an explicit account of what was and was not tested.

### Changed
- `DstackClient.getQuote` may return `null`; `AttestationSource.getQuote`
  returns `QuoteEnvelope | null`. Existing implementations are unaffected.
- A record may claim `mode: "hardware"` with no `tee_quote` when it carries a
  workload identity — Contrast has no quote to give the workload.
- The `enclave` domain now distinguishes "not in a TEE" from "attested by a
  workload credential instead".
- `cool attest` renders the Contrast credential when that is the live route.

### Fixed
- A sealed key id derived from the enclave measurement could collide between two
  distinct workloads built from the same image, filing two public keys under one
  id. Runtimes can now supply an unambiguous id (`AttestationSource.keyId`);
  Contrast derives it from the policy hash.
- A partial measurement pin (`expectedRegisters: { mrtd }`) no longer reports
  every unpinned register as drift.

### Compatibility
Backward compatible with `3.0.0` receipts **byte for byte**: the two new fields
are absent from the canonical CBOR when there is no credential, so previously
issued receipts hash, sign and verify identically. No hardware run has been
performed; `docs/contrast.md` §7 states exactly what was and was not tested.


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
