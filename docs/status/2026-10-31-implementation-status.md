# Implementation status: 2026-10-31

This is the status report against the *CooL Full-Length Claude Master Implementation Specification* (50 pages, Nitro/Caution integrated).

The specification is a **target state**. Its own execution protocol (pages 47–48) requires inspecting before editing, building in dependency order, and marking items done only with evidence. Everything below was checked against code, tests or recorded artifacts on 2026-10-31. Nothing is marked done because a document says so, or because a target date has passed.

**Caution workstream: paused at the owner's request.** Caution items are recorded but not pursued.

**Legend:**
- Milestones: `done_verified` (evidence attached) · `partial` · `not_started` · `blocked` · `paused` · `not_applicable`
- Capabilities: implemented · partial · spec-only · absent

## 1. Repository map

| Repository | State | Role |
|---|---|---|
| `Northwind-Cipher/cool-sdk` `main` | `cool-nwc@3.0.0`, TypeScript, ESM, Node ≥ 20. `typecheck`, `build`, `test`, `verify:package`. CI in `.github/workflows/`. | all current code |
| `Northwind-Cipher/cool-sdk` `feat/nitro-attestation` | this work: Nitro path plus the platform (`src/platform`, `src/nitro`) | PR #16 |
| `Northwind-Cipher/cool-sdk` `feat/verifier-split-python-sdk` | **local only, never pushed** (14 commits): verifier package, Python SDK, TCB policy, quote freshness | owner decision pending (ADR 0001) |
| `KenidoesCode/cool-*` | v0.1.1 snapshots from 2026-06-25 | historical (ADR 0001) |

There are no dependency cycles. The direction is `src/*.ts` (crypto core) ← `src/platform/*` (shared platform core) ← `src/platform/modules/*`, and both `src/nitro/*` and `src/cli/*` sit on top. The platform core imports no module.

## 2. Foundation capabilities (page 02)

| Capability | Status | Evidence |
|---|---|---|
| Canonical AI inference records | **implemented** | `cool.evidence.v1`, and `ai.inference.v1` in the platform |
| SHA-256 salted commitments, deterministic CBOR | **implemented** | `src/hash.ts`, `src/canonical.ts` |
| ML-DSA-65 + Ed25519 hybrid signatures | **implemented**, hardware-validated | `src/sign.ts`; closure matrix |
| RFC 6962 log, inclusion and consistency, STH, witnesses | **implemented** | TDX path validated; platform path tested |
| OpenTimestamps (Bitcoin) anchoring | **implemented** (TDX path) | `src/phala/anchor.ts` |
| Intel TDX via dstack | **implemented**, hardware-validated | `artifacts/closure-verification-matrix.md` |
| AWS Nitro | **partial**: everything except a real NSM helper and a live enclave run | `src/nitro/*`, 40 tests |
| NVIDIA confidential GPU | **partial**: commitment only; NRAS not validated | `src/phala/gpu.ts` |
| Algorithm registry with explicit identifiers, fail-closed | **implemented** | `src/platform/algorithms.ts` |
| Key lifecycle: purpose, validity, rotation, revocation, compromise | **implemented** (verifier side) | `src/platform/trust.ts`; tests for each transition |
| KMS/HSM key provider | **partial**: `Signer` interface; only `localSigner` ships | `src/platform/envelope.ts` |
| Intel SGX | **absent** | |
| ML-KEM-1024 + X25519, ChaCha20-Poly1305 | **absent**: no reviewed combiner; deliberately not listed in the registry | |
| RFC 3161 timestamping | **absent**: reported as a limitation on every `timestamp_valid` | |
| Content-addressed payload storage | **absent**: the log stores digests only; payload storage is the customer's | |

## 3. Findings that changed existing claims

1. **dstack keys follow app identity, not the workload image.** Corrected on `main` (03fe427).
2. **The README claimed ML-KEM, X25519, ChaCha20 and RFC 3161.** Corrected on `main` (03fe427).
3. **Caution's TLS mode already uses Nitro `user_data`.** ADR 0003.
4. **Two bugs found by tests and fixed before release:**
   - OpenSSL throws on a corrupted certificate key, found by the corruption fuzz
   - `audit_only` blocked admission, found while writing the gate

## 4. Spec coverage by page

| Page | Area | Status | Where |
|---|---|---|---|
| 01–04 | Mandate, foundation audit, architecture, reconnaissance | **done_verified** | this report; `docs/platform.md`; ADR 0001 |
| 05–07 | SDK goals, client, evidence API | **implemented** | `CoolClient` (namespaces, explicit config, policy modes, `close`, `inspectConfig`); separate create / canonicalize / commit / sign / publish / verify / inspect / export / import |
| 08 | Canonical envelope and event families | **implemented** | `cool.envelope.v1`; 33 typed families; `spec/schemas/` |
| 09 | Crypto and key management | **partial** | registry and lifecycle done; hybrid KEM and HSM provider absent |
| 09 (Nitro) | Platform trust models | **done_verified** | `docs/trust-models.md` |
| 10 | Transparency, timestamps, storage | **partial** | log, checkpoints, witnesses, freshness, rollback detection on TDX; **no RFC 3161**; in-memory log only |
| 10 (Nitro) | Key identity and attestation binding | **implemented** | ADR 0002; sealer; verifier |
| 11 | Shared policy engine | **implemented** | tri-valued logic, six decisions, lifecycle, simulate, override, modes |
| 12 | Connector framework | **implemented** (framework); **partial** (connectors) | `runConnector`; `GitConnector`, `FileConfigConnector`. No SaaS connectors |
| 13–14 | Supply Chain, SBOM and provenance | **implemented** (gate); **partial** (SBOM) | `dependency.inventory` payload and gate fact exist; no SBOM generator or parser |
| 15–16 | Identity, secrets, keys, certs | **partial** | lifecycle with provider confirmation, authorization matrix, replay guard; no IdP or vault connectors |
| 17–18 | Change Control, rollout and recovery | **partial** | approval binding, drift, staged rollout with rollback approval; no real rollout system |
| 19–20 | Runtime Guard, response | **partial** | attributable ingestion, dedup, telemetry gaps, quarantine via adapter; no EDR or Falco connector |
| 21–22 | Incident Evidence, forensic export | **implemented** | correlation (deterministic and heuristic with rule versions), labels, contradictions, gaps, signed bundles |
| 23 | Data model, storage, retention | **partial** | documented in `docs/platform.md#operations`; no storage layer |
| 24 | Multi-tenancy and admin security | **absent**: there is no hosted service | |
| 25 | API versioning and error semantics | **implemented** | versioned schemas; stable `CooLError` codes; reason codes |
| 26 | CLI | **partial** | `cool bundle verify`, `cool decide`, `cool gate-demo`; stable exit codes (`docs/cli-exit-codes.md`); no per-module subcommands yet |
| 27–29 | SCM/CI/registry, cloud/K8s/IaC, security-tool integrations | **absent**, except local git and config files | |
| 30 | AI remains first-class | **implemented** | `ai.inference.v1`; TDX receipts untouched |
| 31 | Threat model | **partial** | existing `docs/threat-model.md`; per-claim trust model in `docs/trust-models.md` |
| 32 | Secure build and release | **partial** | existing CI, CodeQL, secrets scan, dependency audit; no signed releases or SLSA provenance for CooL itself |
| 33 | Testing strategy | **implemented** | 226 tests: unit, negative, integration, schema conformance, fuzz, end-to-end |
| 34 | Performance | **partial** | measured (≈6–8 ms per operation); no load or soak testing |
| 35 | Observability | **partial** | redacted logger hook, audit events; no metrics exporter |
| 36 | UX surfaces | **partial**: CLI only for the platform (the existing `cool ui` covers the TDX path) | |
| 37 | Compliance | **partial** (existing `cool compliance` mapping); no certification is claimed | |
| 38 | Migration | **implemented** | `docs/migration-platform.md`; no breaking change |
| 39 | Documentation | **implemented** | listed in §8 |
| 40 | Phases 0–4 | 0 done · 1 done · 2 done (local) · 3–4 partial | see above |
| 40 | Phase 5 (enterprise) | **absent** | |
| 41 | Definition of done | see §6 | |
| 42 | Adversarial test plan | **implemented** | `docs/adversarial-test-plan.md`, with expected and observed results |
| 43–44 | Pilots, packaging | **hypothesis only** | `docs/pilots-and-packaging.md`; no pilot run |
| 45 | Deployment models, offline | **partial** | offline verification tested; hosted models absent |
| 46 | Risks, non-goals | respected | no SIEM/EDR/vault replacement; no blocking claims |
| 47–48 | Execution protocol, output format | followed | this report |
| 49 | First milestone: deployment gate | **done_verified (local)** | `tests/platform-supply-chain.test.ts`; `cool gate-demo`; `examples/supply-chain-gate`. The target is a real local directory, **not** a cluster. |
| 49 (Nitro) | Nitro milestone demo | **partial** | full path proven on the synthetic PKI (`tests/nitro-path.test.ts`); not on a real enclave |
| 50 | Final sign-off | see §7 | |

## 5. CooL × Caution milestone register (planned 25–28 October 2026)

| Day | Item | Status | Evidence / blocker |
|---|---|---|---|
| 1 | Reconcile README and docs | **partial** | README and two docs corrected; website not reviewed (no access) |
| 1 | Phala/TDX trust model incl. KMS | **done_verified** | `docs/trust-models.md` |
| 1 | EQTY Lab / AI-notary research | **partial** | `docs/research/ai-notary-landscape.md` |
| 1 | Founders agreement | **not_started** | not something Claude can send or sign |
| 1 | DPIIT application | **not_started** | Claude cannot file it |
| 1 | Read Caution docs and repository | **done_verified** | ADR 0003 |
| 2 | Send the Caution questions | **paused** | drafted in ADR 0003; not sent |
| 2 | Caution go/change decision | **paused** | |
| 2 | Key design, epochs, freshness, PCR policy | **done_verified** | ADR 0002; code and tests |
| 2 | Trust model sign-off by Kailosh | **not_started** | review pending |
| 3 | TypeScript verifier and adversarial tests | **done_verified** | `tests/nitro-attestation.test.ts` |
| 3 | Nitro SDK: NSM, signing, vsock | **partial** | sealer and framing done; real NSM helper and real vsock absent |
| 3 | Log server: epochs, gaps, acks, transitions | **done_verified** (in memory) | `src/nitro/server.ts`, `tests/nitro-path.test.ts`; acks are now signed |
| 4 | Agent in a Caution enclave | **paused** | |
| 4 | Witness co-signs; public anchor | **partial** | witness done and verified; anchoring not wired for Nitro |
| 4 | Tamper demo: altered, dropped, stale | **done_verified** (synthetic PKI) | `tests/nitro-path.test.ts` |
| 4 | Publish repository | **partial** | on PR #16, awaiting merge |
| 4 | "AWS Nitro via Caution" claim | **not_applicable** | forbidden until a live demo exists |

## 6. Definition of done (page 41), checked honestly

| Criterion | Status |
|---|---|
| Public contract and schema documented | yes: `spec/schemas/`, `docs/platform.md`, `docs/nitro.md` |
| Validation and errors implemented | yes: strict payloads; stable codes; reason codes |
| Security review | **no**: no independent review has happened |
| Unit, integration, negative and regression tests | yes: 226 tests, 0 failing |
| Compatibility documented | yes: `docs/migration-platform.md` |
| Telemetry and failure behaviour | partial: failure table done; no metrics exporter |
| Runnable docs | yes: `npm run showcase` (47 self-checked claims), `examples/supply-chain-gate`, run in CI; `cool gate-demo` |
| No secret leakage | tested: redaction, `inspectConfig`, payload secret guard, no key material committed |
| Threat model updated | partial: `docs/trust-models.md` added; `docs/threat-model.md` not revised |
| Enforcement done (explicit policy, scoped adapter, dry-run, confirmation, idempotency, audited override) | yes, for the two local reference adapters |

## 7. Final sign-off checklist (page 50)

| Item | Status |
|---|---|
| Source and repository audit | **done_verified** |
| Reconciled website / README / docs | **partial** (website pending) |
| Phala/TDX and Nitro trust models; Phala KMS analysis | **done_verified**, sign-off pending |
| Caution question and response log | **paused** |
| EQTY Lab / competitor research | **partial** |
| Founders agreement status | **not_started**, no evidence |
| DPIIT application status | **not_started**, no evidence |
| Design reviewed by Kailosh | **not_started** |
| TypeScript offline verifier | **done_verified** |
| Nitro SDK and vsock path | **partial** (no real NSM or vsock) |
| Epoch / gap detection | **done_verified** |
| Witness and anchor verification | **partial** (witness yes; Nitro anchor no) |
| Adversarial demo | **done_verified** at the test level |
| Published trust model and limitations | **partial** (on PR #16) |
| Factual post-demo website update | **not_applicable** |

## 8. Documentation added

- `docs/showcase.md`: the twelve-chapter, self-checking showcase (`npm run showcase`)
- `docs/platform.md`: architecture, sequence diagrams, responsibility matrix, failure behaviour, operations, deployment models
- `docs/trust-models.md`
- `docs/nitro.md`
- `docs/cli-exit-codes.md`
- `docs/migration-platform.md`
- `docs/adversarial-test-plan.md`
- `docs/pilots-and-packaging.md`
- `docs/research/ai-notary-landscape.md`
- `docs/adr/0001`–`0003`
- `spec/schemas/*.schema.json` (5)

## 9. Commands run, with results

```text
npm run typecheck        → clean
npm run build            → 125 files compiled
npm test                 → 226 tests, 226 pass, 0 fail, 0 skipped (119 pre-existing on main + 107 new)
npm run showcase         → "all 47 claims held" (12 chapters; also run as tests/showcase.test.ts)
npm run verify:package   → "The published package works on install."
examples/supply-chain-gate → "benign audit_only completed confirmed: true · tampered deny · bundle pass"
cool gate-demo; cool bundle verify --trust → exit 0
benchmark (Node 24, n=200) → create+sign 6.84 ms · publish+checkpoint 7.54 ms · verify 5.88 ms
```

## 10. What genuinely remains, and why

| Remaining | Why it cannot be finished here |
|---|---|
| Real `/dev/nsm` helper, live Nitro run, real vsock | needs an AWS Nitro-enabled EC2 instance |
| SaaS connectors (GitHub, CI, registries, cloud audit, Kubernetes) | needs credentials, accounts and a decision on the first providers (decision register) |
| Hosted control plane, tenancy, RBAC, admin audit, retention service | there is no CooL service to build these into |
| RFC 3161, hybrid KEM channel | needs a TSA choice, and a reviewed KEM combiner (the spec forbids inventing one) |
| Independent security review | must be done by someone other than the author |
| Pilots, pricing, ICP validation | needs customers |
| Founders agreement, DPIIT, sign-offs | human and legal actions |
| Caution items | paused by the owner |

## 11. Decisions needed from the owner

1. Approve ADR 0001 and ADR 0002 and the trust models.
2. Push or merge `feat/verifier-split-python-sdk`?
3. Choose the first SCM, CI and registry providers, and the deployment target, for real connectors.
4. Provision AWS Nitro test infrastructure.
5. Archive or point the `KenidoesCode` v0.1 repositories.
