# Security review package

**Status:**
- **Independent third-party review: not commissioned.** No audit or certification is claimed anywhere.
- **Internal adversarial review: done.** See [internal-review-2026-11.md](internal-review-2026-11.md). It was performed by the maintainers and is AI-assisted. It is *not* independent and is no substitute for an external review.

This folder is what a review firm needs to start on day one. When a review is commissioned, its report, findings and fix commits will be published here, and the `external-review` capability will move from `planned` (`src/platform/capabilities.ts`).

## Scope, in priority order

| # | Component | Path | Lines | Why it matters |
|---|---|---|---:|---|
| 1 | Envelope verifier, trust snapshot, outcomes | `src/platform/envelope.ts`, `trust.ts`, `outcome.ts`, `bundle.ts` | ~1,400 | every verdict flows through here |
| 2 | Authorization protocol and enforcement boundary | `src/authz/` | ~1,350 | decides whether a consequential action happens |
| 3 | Parsers of attacker-controlled bytes | `src/platform/der.ts`, `timestamp.ts`; `src/snp/`; `src/nvidia/`; `src/nitro/attestation.ts` | ~2,000 | DER, CBOR/COSE, JWT, binary reports |
| 4 | Remote signers and replay stores | `src/platform/signers.ts`, `src/authz/replay-shared.ts` | ~500 | key custody boundary; fail-closed replay |
| 5 | Nitro enclave kit | `src/nitro/kit.ts`, `examples/nitro-enclave/` | ~400 | trust established before any key is accepted |
| 6 | Receipt engine and CLI | `src/phala/`, `src/cli/` | ~9,900 | file and terminal handling, legacy format |

**Out of scope:** the commercial `cool-platform` (it gets a separate engagement), and third-party services (AWS, AMD KDS, NVIDIA NRAS, DigiCert, Phala).

## What reviewers get

- **Threat model:** [../threat-model.md](../threat-model.md) (adversaries, controls, boundaries). Claims and their limits: [../guarantees.md](../guarantees.md).
- **Labels:** every capability and the evidence behind it, in [../capabilities.md](../capabilities.md), generated from code.
- **Genuine fixtures** (`tests/fixtures/`):
  - an AWS Nitro attestation document
  - an AMD SEV-SNP Milan report with its VCEK
  - a DigiCert RFC 3161 token
  - an NVIDIA NRAS JWKS snapshot
- **Test harness:** `npm test`, about 250 tests, including:
  - fuzzing (Nitro, SNP, TSA, DER)
  - exhaustive single-bit flips (TSA)
  - races (nonce stores)
  - a network tripwire (egress)
- **Review questions we want answered:**
  1. Can any input produce `verified` without the stated property holding? Look especially at outcome precedence, `not_applicable` handling, and checks that default to pass.
  2. Domain separation: can a signature from one object type, context or key purpose be replayed as another?
  3. Can the gateway execute a tool without a consumed nonce, a matching decision, or a verified delegation chain, including under concurrency and store failures?
  4. Parser robustness: memory or CPU exhaustion, and inconsistent parsing between our DER/CBOR readers and node:crypto/OpenSSL.
  5. Certificate path validation in the TSA, SNP and NRAS chains: what is skipped relative to RFC 5280 (name constraints, policies, path length), and does it matter for these PKIs?
  6. Supply chain: the dependency set (`@noble/*`, `cbor2`), the build, and npm provenance.

## Engaging a reviewer

To commission an external review, contact the maintainers (`SECURITY.md`). We will share a fixed commit, this package and a contact for questions. Findings follow coordinated disclosure: fixes ship first, then the report is published here in full.
