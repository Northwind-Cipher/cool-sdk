# Open core: what is open, and what the commercial platform adds

CooL is split along one line. **Everything a developer needs to adopt CooL, and everything anyone needs to verify CooL evidence independently, is open source.** What an enterprise pays for is operating CooL at scale, and turning evidence into faster investigations and controlled risk.

The open core is licensed under **Apache-2.0** and lives in this repository. The commercial platform is a separate, private codebase built on top of it. It depends on the open core; the open core never depends on it.

## Open source (this repository, Apache-2.0)

| Area | What is included |
|---|---|
| **Evidence format** | `cool.receipt.v2`, `cool.evidence.v1`, `cool.change.v2`, `cool.envelope.v1`, `cool.bundle.v1`, `cool.trust-snapshot.v1`, `cool.verification-report.v1`; the authorization objects (`cool.principal.v1`, `cool.delegation.v1`, `cool.authz-request.v1`, `cool.authz-decision.v1`, `cool.external-confirmation.v1`); JSON Schemas in `spec/schemas/`; 50 typed event payloads; test vectors |
| **Specifications and security docs** | evidence format, verification, trust models (Phala/TDX and AWS Nitro), threat model, security model |
| **Cryptographic core** | canonical CBOR, SHA-256 commitments, ML-DSA-65 + Ed25519 hybrid signatures, RFC 6962 Merkle proofs, the algorithm registry |
| **SDKs and capture** | `CooL`, `CoolTee` (with the attestation simulator and dstack client), `CoolClient`, reference connectors (local git, config files), the in-enclave Nitro receipt sealer, enclave↔host framing |
| **Local verification** | receipts, envelopes (eleven separate checks), bundles, TDX quotes via a configured verifier, AWS Nitro attestation against the pinned AWS root, log consistency, witness signatures, selective disclosure, OpenTimestamps proofs, normalized TDX/Nitro attestation results |
| **Trust and keys** | trust snapshots with key purpose, validity, rotation, revocation and compromise |
| **Transparency** | the in-process reference log, signed tree heads, inclusion proofs, witness co-signature *verification* |
| **Authorization and enforcement** | principals, delegation chains, committed requests, signed decisions, **deterministic policy evaluation and replay** (`cool.policy.v1`), atomic nonce stores, execution binding, the reference `ToolGateway` and signed external confirmations |
| **CLI** | `verify`, `seal`, `records`, `disclose`, `witness`, `anchor`, `log`, `attest`, `pack`, `compliance`, `policy`, `ui`, `bundle verify`, `doctor`, `walkthrough`, … |
| **Evidence of our claims** | `artifacts/` (the Intel TDX validation records) and the scripts that verify them (`phala-validation/*-verify.mjs`) |
| **Examples and the open showcase** | `examples/`, `npm run showcase` |

## Commercial CooL platform (private, separately licensed)

| Product | What it adds |
|---|---|
| **CooL Evidence Cloud** | managed evidence ingestion, storage and retention; the production evidence-plane, log and witness *services*; the Nitro log server (epochs, gap accounting, acknowledgements) |
| **CooL Incident Intelligence** | cross-system correlation, deterministic and heuristic linking, incident cases and reconstruction |
| **CooL Risk Controls** | managed policy lifecycle (registry, activation, approvals, overrides), enforcement coordination with external confirmation, response modules (deployment gate, identity and credential lifecycle, change control, runtime guard) |
| **CooL Assurance** | enterprise risk reporting and evidence packages, support, and service commitments |

## Why the line is here

- **Verification must not depend on us.** A customer, an auditor or a regulator must be able to check CooL evidence with no account and no network call to Northwind Cipher. Every verifier is therefore open, including those for the commercial products' outputs (bundles, decisions bound by digest, witness signatures).
- **The format is not a lock-in.** Open schemas and test vectors let anyone produce or consume CooL evidence.
- **What is sold is operations and outcomes**: running the infrastructure, the integrations, the workflows and the guarantees. Access to cryptography is not what is sold.

## Status, stated plainly

The commercial products above are at very different stages. Some exist as code (the policy registry, enforcement coordination, the reference modules and the Nitro log server). Others are plans: the hosted Evidence Cloud, enterprise SSO and SCIM, on-premises and air-gapped deployment, and enterprise reporting. None of them is a generally available product today. This page describes the boundary, not a product catalogue.

## Licensing history

- `cool-nwc` 4.0.0 and later: Apache-2.0.
- `cool-nwc` 3.1.0–3.1.1: published under the Business Source License 1.1, and those copies keep those terms.
- `cool-nwc` 3.0.0 and earlier: Apache-2.0.
