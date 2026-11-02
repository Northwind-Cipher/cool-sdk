# Feature matrix: public, commercial self-hosted, commercial hosted

This page answers spec chapters 3 and 30. The rule is simple. **Anything needed to create, sign with your own keys, verify, inspect or export evidence is public and free.** Paid offerings cover operating CooL at scale and the enterprise workflow on top of it. Verifying a cryptographic claim is never behind a paywall.

Each boundary below has a **technical enforcement point**: the place in the code where the line is drawn. It also has a **licensing rule**.

| Capability | Public (Apache-2.0) | Commercial, self-hosted | Commercial, hosted (SaaS) | Enforcement point / licence |
|---|:-:|:-:|:-:|---|
| Evidence formats, schemas, test vectors | ✅ | ✅ | ✅ | `spec/`, Apache-2.0 |
| Local evidence creation; customer-held keys (`localSigner`, `Signer` for your KMS/HSM) | ✅ | ✅ | ✅ | `cool-nwc`, Apache-2.0 |
| Offline verifier: envelopes, receipts, bundles, Nitro, TDX, consistency, witness signatures, disclosure | ✅ | ✅ | ✅ | `cool-nwc`, Apache-2.0. **Never gated** |
| Authorization protocol: principals, delegation, requests, deterministic decisions, replay, execution binding | ✅ | ✅ | ✅ | `cool-nwc/authz`, Apache-2.0 |
| Reference enforcement boundary (`ToolGateway`) | ✅ | ✅ | ✅ | `cool-nwc/authz`, Apache-2.0 |
| Shared replay stores (Redis built in; Postgres and DynamoDB backends) | ✅ | ✅ | ✅ | `cool-nwc/authz`, Apache-2.0 |
| KMS / HSM signers (AWS KMS, Google Cloud KMS, PKCS#11; experimental) | ✅ | ✅ | ✅ | `cool-nwc/platform`, Apache-2.0. **Custody stays with the customer** |
| Verifiers for AMD SEV-SNP, NVIDIA NRAS results, RFC 3161 timestamps | ✅ | ✅ | ✅ | `cool-nwc/snp`, `cool-nwc/nvidia`, `cool-nwc/platform`, Apache-2.0. **Never gated** |
| Nitro Enclaves deployment kit | ✅ | ✅ | ✅ | `examples/nitro-enclave`, Apache-2.0 |
| Reference connectors (git, config files); local transparency log | ✅ | ✅ | ✅ | `cool-nwc/platform`, Apache-2.0 |
| CLI, examples, showcase, agent demo | ✅ | ✅ | ✅ | `cool-nwc`, Apache-2.0 |
| Managed policy lifecycle, approvals, overrides | — | ✅ | ✅ | private `cool-platform` (`PolicyRegistry`), commercial licence; entitlement check |
| Enforcement coordination and enterprise adapters (cloud IAM, payments, K8s admission) | — | ✅ | ✅ | private `cool-platform` (`EnforcementCoordinator`); adapters planned |
| Incident correlation, timelines, cases | — | ✅ | ✅ | private `cool-platform` (`correlation`, `IncidentCase`) |
| Operational modules: deployment gate, credential lifecycle, change control, runtime guard | — | ✅ | ✅ | private `cool-platform` |
| Log server with epochs, gap accounting, acknowledgements; witness service | — | ✅ | ✅ (managed) | private `cool-platform` (`NitroLogServer`, `Witness`) |
| Multi-tenant control plane: OIDC SSO, SCIM 2.0, RBAC with separation of duties | — | ✅ implemented | planned (not operated) | private `cool-platform` (`src/server/`). SAML: unsupported; ABAC: planned |
| Retention, legal hold, deletion receipts, crypto-shredding; SIEM feed, OpenMetrics, alert webhook | — | ✅ implemented | planned (not operated) | private `cool-platform`. Native SIEM connectors, OpenTelemetry, fleet views, SLA: planned |

## What customers keep, whichever tier they use

- **Their keys.** The verifier never needs CooL-managed custody.
- **Their data.** Payloads stay with the customer, and evidence carries only commitments.
- **Independent verification.** Exported bundles verify with the public verifier, offline.
- **Portability.** If a customer leaves, every bundle they exported remains verifiable forever.

## Licensing rules

- `cool-nwc` 4.0.0 and later, which includes this repository, `spec/` and the verifier: **Apache-2.0**.
- `cool-nwc` 3.1.0–3.1.1: published under BUSL-1.1, and they keep those terms.
- The commercial platform is licensed separately, as self-hosted enterprise or hosted SaaS. It is never required to verify evidence.
