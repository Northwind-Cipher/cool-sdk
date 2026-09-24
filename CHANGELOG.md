# Changelog

All notable changes to `cool-nwc` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[semantic versioning](https://semver.org). The evidence schema is versioned
independently (`cool.evidence.v1`, `cool.receipt.v2`).

## [Unreleased]

### Changed

- **Licensing:** the repository moves from Apache-2.0 to the Business Source License 1.1 (Change Date 2030-01-01, Change License Apache-2.0). Versions released before this change, including 3.0.0, remain available under Apache-2.0. A few vendored files keep their Apache-2.0 license. See `LICENSE`, `NOTICE.txt` and `docs/IP-OWNERSHIP.md`.
- Added copyright and SPDX headers to Northwind-owned source files (comment-only).

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
