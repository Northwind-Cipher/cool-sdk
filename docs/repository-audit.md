# Repository audit and the public/private split (4.0)

This audit answers spec chapter 3: what is in each repository, which side of the line each part is on, and why. **The rule:** anything needed to create, sign, verify, replay, inspect or export evidence is public. Anything that is the operation of CooL at scale, or the enterprise workflow on top of it, is private.

## This repository: `cool-nwc` (public, Apache-2.0 from 4.0.0)

| Path | Lines (approx.) | Contents | Side | Reason |
|---|---|---|---|---|
| `src/platform/` | 2,000 | envelope, trust snapshots, the algorithm registry, 50 payload families, the transparency log, bundles, outcomes, **deterministic policy evaluation**, legacy wrapping, TEE adapters | public | the evidence core and its verifier |
| `src/authz/` | 1,100 | principals, delegation, requests and commitments, decisions, replay stores, execution binding, `ToolGateway`, confirmations | public | an independent party must be able to verify and **replay** an authorization |
| `src/nitro/` | 1,100 | Nitro attestation verifier, pinned root, normalization, in-enclave sealer, vsock framing | public | verifying hardware evidence must never be paid |
| `src/phala/` | 6,200 | receipt engine (`cool.receipt.v2`), TDX/dstack capture, Merkle log, witness verification, disclosure, OpenTimestamps, compliance mapping | public | the original SDK; verification paths |
| `src/cli/` | 3,700 | `cool` CLI, including `bundle verify`, `doctor`, `walkthrough` | public | the developer and auditor tool |
| `spec/` | — | JSON Schemas, test vectors | public | the format is the interoperability contract |
| `tests/`, `examples/`, `scripts/` (showcase, `demo:agent`) | — | 27 test files, examples, demos | public | they prove the public claims |
| `artifacts/`, `phala-validation/` | — | recorded TDX hardware validation and the scripts that check it | public | evidence for our own claims |

**Moved back to public in this release:** `evaluatePolicy`, `validatePolicy`, `policyDigest` and `simulatePolicy` (`src/platform/policy.ts`). Reproducible decisions need anyone to be able to re-run the evaluator, and spec chapter 26 forbids a paywall on verification.

## Private: `cool-platform` (commercial licence, private repository)

| Module | Contents | Why it is private |
|---|---|---|
| `policy.ts` | `PolicyRegistry` (versions, activation, approvals) and `overrideDecision` | managed lifecycle and workflow: operations, not verification |
| `enforcement.ts` | `EnforcementCoordinator`, which fans out to adapters and tracks confirmation | enterprise integration and operations |
| `correlation.ts`, `bundle-timeline.ts` | incident linking, cases, timelines | investigation product |
| `modules/` | deployment gate, credential lifecycle, change control, runtime guard | response products |
| `nitro/` | Nitro log server (epochs, gap accounting, acknowledgements) | the operated service |
| `witness-service.ts` | the witness *service*; witness *verification* stays public | the operated service |
| `cli/` | commercial CLI commands | operator tooling |

**What the private side may depend on:** the public `cool-nwc` package. The public side never imports private code. Every output of the private side (decisions, bundles, checkpoints, witness signatures, confirmations) verifies with the public verifier.

## Checks performed for this audit

- No private module source is in the 4.0 tree: the split removed it. Releases 3.1.0–3.1.1 shipped those modules under BUSL-1.1, and they remain in git history and on npm under that licence. New private work exists only in `cool-platform`.
- No key material in any tracked file. Test keys are seeded in memory.
- `LICENSE` is Apache-2.0. Versions 3.1.0–3.1.1 keep BUSL-1.1 (`docs/feature-matrix.md#licensing-rules`).
