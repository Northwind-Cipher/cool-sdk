# Implementation status: 2026-10-31

This is the status report against the *CooL Full-Length Claude Master Implementation Specification* (50 pages, Nitro/Caution integrated).

The specification is a **target state**. Its own execution protocol (pages 47–48) requires inspecting before editing, building in dependency order, and marking items done only with evidence. This report follows that protocol. Everything below was checked against code, tests or recorded artifacts on 2026-10-31. Nothing is marked done because a document says so, or because a target date has passed.

**Legend:** `done_verified` (evidence attached) · `partial` · `not_started` · `blocked` · `not_applicable`. Capabilities: implemented · partial · spec-only · absent.

## 1. Repository map

| Repository | State | Role |
|---|---|---|
| `Northwind-Cipher/cool-sdk` `main` | `cool-nwc@3.0.0`, TypeScript, ESM, Node ≥ 20. `npm` scripts: `typecheck`, `build`, `test` (node:test + tsx), `verify:package`. CI in `.github/workflows/{ci,release,security}.yml`. | **all current code** |
| `Northwind-Cipher/cool-sdk` `feat/verifier-split-python-sdk` | **local only, never pushed**, 14 commits: `packages/cool-verifier`, `spec/test-vectors` (24 vectors), `sdk/python`, browser verifier, TCB policy, quote freshness, `cool deploy` | the spec/verifier/SDK split |
| `Northwind-Cipher/cool-sdk` `feat/contrast-integration` | pushed, unmerged | Edgeless Contrast path |
| `KenidoesCode/cool-spec`, `cool-verifier`, `cool-sdk` | last pushed 2026-06-25, v0.1.1 | historical snapshots (ADR 0001) |

The dependency direction on `main` is clean: `src/*.ts` (core: canonical, hash, sign, merkle, keys) ← `src/phala/*` (TEE, log, witness, anchor, policy) ← `src/cli/*`. The new `src/nitro/*` depends only on core. No cycles were found.

## 2. Foundation capabilities (spec page 02)

| Capability | Status | Evidence |
|---|---|---|
| Canonical records binding model / input / output / time | **implemented** | `src/record.ts`, `cool.evidence.v1`; tests |
| SHA-256 salted commitments | **implemented** | `src/hash.ts` `saltedCommit` |
| Deterministic CBOR | **implemented** | `src/canonical.ts` (cbor2 CDE) |
| ML-DSA-65 (FIPS 204) + Ed25519 hybrid signatures | **implemented** | `src/sign.ts`; hardware-validated |
| RFC 6962 Merkle log, inclusion and consistency proofs, signed tree heads | **implemented** | `src/merkle.ts`, `src/phala/consistency.ts`; 36/36 pairs on hardware |
| Witness co-signing | **implemented** (process and key separation) | `src/phala/witness.ts`; closure run. **Organizational independence not demonstrated.** |
| Public anchoring | **implemented** (OpenTimestamps / Bitcoin) | `src/phala/anchor.ts` |
| Selective disclosure | **implemented** | `src/phala/disclose.ts` |
| Intel TDX attestation via Phala dstack | **implemented**, hardware-validated | `artifacts/closure-verification-matrix.md` |
| AWS Nitro attestation | **partial**: offline verifier and epoch/gap log only | `src/nitro/`, 30 tests (this change) |
| NVIDIA confidential GPU | **partial**: commitment to the evidence bundle; NRAS verification not validated | `src/phala/gpu.ts` |
| Intel SGX | **absent** | no code |
| **ML-KEM-1024 + X25519** | **absent** | not in any source file on any branch |
| **ChaCha20-Poly1305** | **absent** | not in any source file on any branch |
| **RFC 3161 timestamping** | **absent** | not in any source file on any branch |
| Content-addressed commitment storage | **absent** | no code |
| Algorithm registry | **partial** | a single `SIGNATURE_ALG` constant; no registry or agility |
| Key lifecycle (rotation / revocation / compromise) | **absent** | no revocation anywhere; KMS keys rotate only with app identity |

The README listed ML-KEM, X25519, ChaCha20-Poly1305 and RFC 3161 as used. That was **false** and has been corrected.

## 3. Findings that change existing claims

1. **dstack keys do not rotate on a workload change.** Deployments A and B, with different RTMR3 values under the same `app_id`, signed with the same key (`artifacts/closure/raw`). `docs/attestation.md`, `docs/security-model.md` and the `src/phala/kms.ts` comment claimed the opposite and are now corrected. Security impact: none, *provided the measurement is pinned*, because the enclave domain rejected B against A's pin. Without a pin, a signature cannot distinguish workloads.
2. **The README overclaimed four primitives** (finding 2 in §2).
3. **Caution's TLS mode already uses Nitro `user_data`**, which collides with the planned CooL key binding (ADR 0002 and 0003).
4. **Fuzzing found a verifier bug before release**: OpenSSL throws on a corrupted certificate key. Fixed, and kept as a regression test.

## 4. CooL × Caution milestone register (planned 25–28 October 2026)

| Day | Item | Status | Evidence / blocker |
|---|---|---|---|
| 1 | Reconcile website / README / docs; witness status first | **partial** | README and two docs corrected in this change. The website was not reviewed (no access). |
| 1 | Phala/TDX trust model incl. KMS | **done_verified** | `docs/trust-models.md` |
| 1 | EQTY Lab and AI-notary research | **partial** | `docs/research/ai-notary-landscape.md`: EQTY done, others listed as not yet researched |
| 1 | Founders agreement to Kailosh for signature | **not_started** | not something Claude can send or sign; no evidence it was sent |
| 1 | DPIIT application | **not_started** | no evidence of an application; Claude cannot file it |
| 1 | Read Caution docs and repository | **done_verified** | ADR 0003, with source URLs and Codeberg commit `f40f1346…` |
| 2 | Send the two Caution questions | **not_started** | drafted verbatim in ADR 0003; **not sent** |
| 2 | Go/change decision on Caution | **blocked** | no response; fallback recorded in ADR 0003 |
| 2 | Enclave key design, `public_key` + `user_data` binding | **done_verified** (design) | ADR 0002; verifier enforces it |
| 2 | KMS only if needed | **done_verified** (decision) | ADR 0002 §2 |
| 2 | Server-assigned epoch, `[epoch].[sequence]` | **done_verified** (log side) | `src/nitro/epochs.ts`, `tests/nitro-epochs.test.ts` |
| 2 | Nonce vs timestamp freshness, no silent downgrade | **done_verified** | `nonce_absent` test |
| 2 | PCR0–2 required; PCR8 only for signed images | **done_verified** | `pcr8_signing` tests |
| 2 | Trust model for both paths, signed off by Kailosh | **partial** | written; **sign-off pending** |
| 3 | TS verifier: COSE, CBOR, offline chain, PCRs, binding, freshness | **done_verified** | `src/nitro/attestation.ts`; 23 tests including a real AWS document |
| 3 | Verifier adversarial tests | **done_verified**, with one gap | all listed cases covered. The genuine fixture is third-party, not from a CooL enclave (see PROVENANCE.md). |
| 3 | Nitro SDK: NSM document, sign receipts, vsock | **not_started** | needs an NSM client and a Nitro instance |
| 3 | Log server: epochs, duplicates, ordering, gaps, acks, transitions | **partial** | logic and tests done. Acknowledgements are unsigned; there is no persistence and no network service. |
| 4 | Node.js agent in a Caution enclave over vsock | **blocked** | no Caution access; SDK side not built |
| 4 | Witness co-signs checkpoint; public anchor | **not_started** for Nitro | exists for the TDX path |
| 4 | Tamper demo: altered, dropped, stale | **partial** | all three proven in unit tests; no end-to-end demo bundle |
| 4 | Publish repository with trust model and tests | **partial** | pushed to branch `feat/nitro-attestation`; awaiting merge |
| 4 | Technical note for the Caution call | **not_started** | there was no call to prepare for: the questions were never sent |
| 4 | "AWS Nitro via Caution" on the website | **not_applicable** yet | forbidden until a live demo works |

**Revised schedule.** The owner is Kailosh unless delegated. Items run in dependency order, and dates are to be set by the owner.

1. Send the Caution questions (ADR 0003).
2. Sign off ADR 0001, ADR 0002 and the trust models.
3. Decide on pushing or merging `feat/verifier-split-python-sdk`.
4. Provision a Nitro-enabled EC2 test instance and capture a genuine CooL-bound document.
5. Build the enclave SDK and vsock path.
6. Build the end-to-end demo bundle.
7. Only then, any public claim.

## 5. Five-module platform (spec pages 03 and 13–22)

| Module | Status |
|---|---|
| Shared evidence envelope (page 08, technology-neutral, typed payload registry) | **absent**. Today: `cool.evidence.v1` (typed `model.execution`-style events) and `cool.change.v2` (prompt / model / params / agent changes). |
| Shared policy engine (page 11: allow/deny/require_approval…, lifecycle, modes) | **partial**. `src/phala/policy.ts` governs change records with fixed rules (`POL-001`…), with no versioned lifecycle or modes. |
| Connector framework (page 12) | **absent** |
| Supply Chain (SBOM, SLSA/in-toto, deployment gate) | **absent** |
| Identity & Authority | **absent** |
| Change Control | **partial**. Change records with approvals exist for AI artefacts only. |
| Runtime Guard | **absent** |
| Incident Evidence (correlation, timeline, signed export) | **partial**. Audit packs (`cool pack`) exist; there is no correlation or timeline. |
| Multi-tenancy, RBAC, retention, admin audit (pages 23–24, 35) | **absent** |
| Structured verification status `pass/fail/unknown/not_applicable/not_checked` | **partial**. Nitro uses it; receipt v2 uses `pass/fail/absent/mock/simulated/pending`. |

The specification itself warns against building all five domains before proving the first paid workflow (page 43). The first milestone (page 49: a supply-chain deployment gate with an offline-verifiable bundle) has **not started**.

## 6. Top 20 gaps, ranked

1. No enclave-side Nitro code (NSM, key generation, receipt sealing, vsock).
2. No genuine Nitro document from a CooL-controlled enclave.
3. Caution questions unsent; Caution's `user_data` collision unresolved.
4. Verifier split, TCB policy and quote freshness sit on an **unpushed** branch.
5. No key revocation or compromise handling on either path.
6. No technology-neutral evidence envelope or typed payload registry (page 08).
7. No normalized attestation result across TDX and Nitro.
8. Nitro verification is not integrated into `cool.receipt.v2` or `cool verify`.
9. The page 49 supply-chain gate milestone has not started.
10. No versioned policy engine with modes and lifecycle (page 11).
11. ML-KEM / X25519 / ChaCha20-Poly1305 are absent. Any confidential channel claim must wait for a reviewed combiner.
12. RFC 3161 is absent. Only OpenTimestamps provides trusted time.
13. The epoch log is in memory only: no persistence, no signed acknowledgements, no service.
14. The X.509 path check is not full RFC 5280 (path length, key usage, name constraints).
15. Witness organizational independence has not been demonstrated.
16. GPU attestation is not hardware-validated.
17. The validation runs used a dev OS image (`is_dev: true`).
18. No connector framework, so no SCM/CI/registry integrations (page 27).
19. No tenancy, RBAC, retention or admin audit.
20. The website has not been reconciled with the corrected README and docs.

## 7. Final sign-off checklist (spec page 50)

| Item | Status |
|---|---|
| Source and repository audit | **done_verified** (this document) |
| Reconciled website / README / docs | **partial** (website pending) |
| Phala/TDX and Nitro trust models; Phala KMS analysis | **done_verified**, sign-off pending |
| Caution question/response log | **partial** (questions logged, not sent) |
| EQTY Lab / competitor research | **partial** |
| Founders agreement status | **not_started**, no evidence |
| DPIIT application status | **not_started**, no evidence |
| Design reviewed by Kailosh | **not_started** |
| TypeScript offline verifier (Nitro) | **done_verified** |
| Nitro SDK and vsock path | **not_started** |
| Epoch / gap detection | **done_verified** (logic) |
| Witness and anchor verification (Nitro) | **not_started** |
| Adversarial demo | **partial** (unit level only) |
| Published trust model and limitations | **partial** (on branch, unmerged) |
| Factual post-demo website update | **not_applicable** until the demo |

## 8. Commands run, with results

```text
npm run typecheck        → clean
npm run build            → 91 files compiled
npm test                 → 149 tests, 149 pass, 0 fail, 0 skipped (was 119; +30 Nitro)
npm run verify:package   → "The published package works on install."
import("cool-nwc/nitro") → resolves through the package export
```

## 9. Decisions needed from the owner

1. Send the two Caution questions (text in ADR 0003)?
2. Push or merge `feat/verifier-split-python-sdk`?
3. Approve ADR 0002, particularly the default `public_key` use.
4. Provision AWS Nitro test infrastructure: who pays, and which account?
5. Archive the `KenidoesCode` v0.1 repositories, or add a pointer from them?
