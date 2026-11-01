# Status of every chapter of the 4.0 master specification

This page is the final report spec chapter 48 asks for. Every capability carries one label.

| Label | Meaning |
|---|---|
| **implemented** | the code exists, is tested, and is in the public package or the private platform |
| **partial** | the code exists, with documented gaps |
| **experimental** | the code exists, but has not been validated in its real environment |
| **planned** | design only, not built |
| **unsupported** | explicitly out of scope; the verifier says `unsupported` |

| Ch. | Capability | Label | Where / note |
|---|---|---|---|
| 1–2 | Mission; claims ↔ properties ↔ tests | implemented | `docs/guarantees.md` |
| 3 | Repository audit; public/private split | implemented | `docs/repository-audit.md`, `docs/feature-matrix.md` |
| 4 | Architecture | implemented | `docs/architecture.md` |
| 5 | System threat model | implemented | `docs/threat-model.md` |
| 6 | Principals with event-time state | implemented | `src/authz/principal.ts` |
| 6 | Delegation chains (scope subset, depth, cycles, revocation) | implemented | `src/authz/delegation.ts` |
| 7 | Canonical authorization request; salted and HMAC commitments; NFC | implemented | `src/authz/request.ts`, `spec/test-vectors/authz-commitments.v1.json` |
| 8 | Signed decisions; `trusted` and `reproducible` assurance | implemented | `src/authz/decision.ts` |
| 8 | Deterministic policy language `cool.policy.v1` | implemented | `src/platform/policy.ts` |
| 9 | Replay resistance (atomic nonce store) | implemented | `src/authz/replay.ts`, single host only |
| 9 | Distributed nonce store (Redis/DynamoDB) | planned | the interface is ready (`NonceStore`) |
| 10 | Execution binding | implemented | `src/authz/execution.ts` |
| 11–12 | AWS Nitro verifier | implemented | genuine-document fixture plus corruption cases |
| 11–12 | Nitro in-enclave runtime | experimental | no real enclave run yet |
| 13 | Intel TDX via dstack | implemented | hardware-validated on Phala Cloud |
| 13 | Phala dstack KMS / runtime evidence | partial | `docs/tee-support.md` |
| 14 | AMD SEV-SNP | unsupported | the adapter returns `unsupported` |
| 15 | NVIDIA Confidential Computing | unsupported | GPU evidence commitment only |
| 16 | Unified envelope; legacy `cool.receipt.v2` wrapping | implemented | `src/platform/legacy.ts` |
| 17 | Event taxonomy (50 families) | implemented | `docs/event-taxonomy.md` |
| 18 | Privacy: commitments, keyed commitments, disclosure | implemented | — |
| 19 | Crypto agility (algorithm registry) | implemented | hybrid ML-DSA-65 + Ed25519 |
| 20 | KMS/HSM signing via the `Signer` interface | partial | interface only; provider adapters planned |
| 21 | Transparency log, consistency proofs | implemented | — |
| 22 | Witness verification (public) / witness service (private) | implemented | — |
| 22 | OpenTimestamps anchoring | implemented | opt-in, networked |
| 23 | RFC 3161 timestamping | planned | — |
| 24 | Enforcement boundary (`ToolGateway`) with signed confirmations | implemented | `src/authz/gateway.ts` |
| 24 | Enterprise enforcement adapters (cloud IAM, payments, K8s admission) | planned | private coordinator exists |
| 25 | Completeness: sequence-gap detection | partial | a dropped final event is undetectable until the next one; heartbeats planned |
| 26 | Offline verifier with six outcomes | implemented | `src/platform/outcome.ts` |
| 27 | CVA / RCVA | implemented | commitments plus reveal |
| 27 | Zero-knowledge policy proofs | planned (research) | `docs/research/cva-rcva-zk.md` |
| 28 | Agent tool integrations | partial | the `ToolGateway` reference; MCP/LangChain adapters planned |
| 29 | CI/CD, SBOM, provenance | implemented | `docs/release-criteria.md` |
| 29 | Reproducible-build verification | planned | — |
| 30 | Public/private feature sets | implemented | `docs/feature-matrix.md` |
| 31 | Packaging and pricing; entitlements | partial | private `cool-platform` (entitlements module) |
| 32 | Hosted control plane, multi-tenancy | planned | — |
| 33 | SSO/SAML/OIDC, SCIM, RBAC/ABAC | planned | — |
| 34 | Observability (metrics, SIEM export) | planned | — |
| 35 | Performance measurements | partial | `npm run bench` with a reference run (`docs/performance.md`); no CI regression gate |
| 36 | Retention, legal hold, deletion | planned | — |
| 37 | Supply chain | implemented | trusted publishing, SBOM, history secret scan |
| 38 | Test strategy (unit, adversarial, fuzz, egress) | implemented | 27 test files |
| 39 | Documentation set | implemented | `docs/` |
| 40 | Versioning and compatibility | implemented | additive `v1` schemas; RFC process |
| 41 | Deployment modes | partial | embedded and offline implemented; self-hosted partial; air-gapped and SaaS planned (`docs/deployment-modes.md`) |
| 42 | Independent security review | planned | not yet commissioned |
| 43 | Compliance mapping | implemented (sample) | `docs/compliance-mapping.md`, not a certification |
| 44 | No telemetry; egress tested | implemented | `docs/telemetry-and-egress.md` |
| 45 | OSS governance; RFC process | implemented | `GOVERNANCE.md` |
| 46 | Go-to-market | planned | private discovery notes only |
| 47 | Demo scenarios A–H | implemented | `npm run demo:agent`, `docs/demo-scenarios.md` |
| 49 | Release criteria | implemented | `docs/release-criteria.md` |
| 50 | Vision | — | `README.md` |

**Nothing labelled planned or unsupported is claimed anywhere else in this repository.** If you find such a claim, it is a bug: please open an issue.
