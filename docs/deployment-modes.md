# Deployment modes

CooL is a library first. Every mode below uses the same evidence format and the same open verifier. What changes is who runs the collector, the log and the witnesses, and who holds the keys.

| Mode | Who runs what | Keys | Network | Status |
|---|---|---|---|---|
| **Embedded / local** | your process uses `cool-nwc` directly: envelopes, the in-process log, the `ToolGateway`, bundles on disk | yours (`localSigner`, or your own `Signer` backed by a KMS/HSM) | none required: the SDK makes no outbound calls (`tests/egress.test.ts`) | **implemented** |
| **Offline verifier only** | an auditor runs `cool bundle verify` / `verifyBundle` on an exported bundle with their own trust snapshot | the verifier's trust snapshot only | none | **implemented** |
| **TEE-backed capture** | the sealer runs in AWS Nitro or Intel TDX (dstack); the signing key is bound by attestation | generated inside the TEE | the vsock/host relay | **TDX: hardware-validated · Nitro: experimental** (`docs/tee-support.md`) |
| **Self-hosted platform** | the commercial modules (log server, witnesses, managed policy, coordination) on your infrastructure | yours | inside your perimeter | **partial**: modules exist as a library; no packaged server |
| **Air-gapped** | as self-hosted, with trust snapshots and bundles moved by media; OpenTimestamps anchoring disabled | yours | none | **planned**: the library already works offline; there is no packaged distribution, update channel or documented procedure yet |
| **Hosted (SaaS)** | Northwind Cipher operates ingestion, the log, witnesses and the control plane | customer-held signing keys recommended; managed keys optional | TLS to the service | **planned**: not built |

## Invariants across every mode

- **Exported bundles verify with the public verifier, offline,** in every mode, including after leaving a hosted service.
- **CooL is never in the enforcement path unless you put it there.** The `ToolGateway` runs where your tool runs.
- **No telemetry** (`docs/telemetry-and-egress.md`).
- **Trust snapshots are explicit inputs.** Nothing is fetched at verification time.
