# Deployment modes

CooL is a library first. Every mode below uses the same evidence format and the same open verifier. What changes is who runs the collector, the log and the witnesses, and who holds the keys.

| Mode | Who runs what | Keys | Network | Status |
|---|---|---|---|---|
| **Embedded / local** | your process uses `cool-nwc` directly: envelopes, the in-process log, the `ToolGateway`, bundles on disk | yours (`localSigner`, or a KMS/HSM `AsyncSigner`: AWS KMS, Google Cloud KMS, PKCS#11; see `docs/key-management.md`) | none required: the SDK makes no outbound calls (`tests/egress.test.ts`) | **implemented** |
| **Offline verifier only** | an auditor runs `cool bundle verify` / `verifyBundle` on an exported bundle with their own trust snapshot | the verifier's trust snapshot only | none | **implemented** |
| **TEE-backed capture** | the sealer runs in AWS Nitro or Intel TDX (dstack); the signing key is bound by attestation | generated inside the TEE | the vsock/host relay | **TDX: implemented** (hardware-validated) · **Nitro: experimental** (deployment kit ready, not yet run on AWS hardware) |
| **Self-hosted control plane** (commercial) | the multi-tenant control plane on your infrastructure: per-tenant logs, OIDC SSO, SCIM, RBAC, retention and legal hold, SIEM feed, metrics; plus the commercial modules | yours | inside your perimeter | **implemented** (container + compose with TLS and Redis); horizontal scaling not built |
| **Air-gapped** | as self-hosted, with trust snapshots and bundles moved by media; OpenTimestamps anchoring disabled | yours | none | **planned**: the library already works offline; there is no packaged distribution, update channel or documented procedure yet |
| **Hosted (SaaS)** | Northwind Cipher operates the same control plane for you | customer-held signing keys | TLS to the service | **planned**: the software exists, but **no hosted service is operated or offered** |

## Invariants across every mode

- **Exported bundles verify with the public verifier, offline,** in every mode, including after leaving a hosted service.
- **CooL is never in the enforcement path unless you put it there.** The `ToolGateway` runs where your tool runs.
- **No telemetry** (`docs/telemetry-and-egress.md`).
- **Trust snapshots are explicit inputs.** Nothing is fetched at verification time.
