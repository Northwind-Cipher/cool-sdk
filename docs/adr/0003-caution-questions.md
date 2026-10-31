# ADR 0003: Questions for Caution, and what we know without answers

- **Status:** open. **The questions have NOT been sent.**
- **Date:** 2026-10-31

## The two questions

These are ready to send to Caution's founders, verbatim:

> **1. Attestation access.** How do workloads obtain Nitro attestation documents in your deployment: is `/dev/nsm` exposed inside the enclave, or is attestation mediated by a sidecar or service? If mediated, what is the trust boundary, and how is the response bound to the enclave?
>
> **2. Key lifecycle.** What is the signing-key mechanism: a Caution-managed mechanism, or AWS KMS with a PCR-conditioned key policy? How are keys generated, bound to measurements, rotated, persisted and revoked?

| | |
|---|---|
| Date sent | **not sent** |
| Sent by | — |
| Response | **none** |
| Resulting decision | none yet; the fallback is below |

Record the actual date, sender and verbatim response here once it happens. Do not infer answers from marketing material.

## What public material shows (checked 2026-10-31)

| Source | What it says | What it does not say |
|---|---|---|
| [caution.co](https://caution.co) | A "verifiable compute platform". AWS Nitro "today", with TDX, SEV-SNP and TPM 2.0 "coming in 2026". Git-push deploys, reproducible builds, `caution verify`. Bring-your-own or managed compute. | Anything about key management; no pricing figures |
| [Codeberg `caution/platform`](https://codeberg.org/caution/platform), commit `f40f1346344733792996a614c847516bef7d9cf9` (2026-10-28) | AGPL-3.0 plus a commercial licence. Attestation served at `https://<app-url>/attestation`. `caution verify` rebuilds the image and compares PCRs. In TLS mode, **Caddy runs in the enclave and puts its certificate fingerprint in Nitro `user_data`**. The browser `/verify` page checks nonce-bound evidence and PCR0–2. | Whether `/dev/nsm` is exposed to the workload; who generates or holds signing keys; whether AWS KMS is used; what crosses vsock beyond the HTTP proxy |

**The finding that matters for CooL:** Caution's TLS mode already claims `user_data`. If the workload cannot request its own document, CooL's key binding (ADR 0002) cannot use that field as designed. Question 1 decides this.

## Fallback while unanswered

Build against documented AWS Nitro primitives (`/dev/nsm`, vsock) on a plain Nitro-enabled EC2 instance, and label it the **local/reference Nitro implementation**, never "Caution-deployed". Every Caution-specific assumption stays marked unresolved.

## Claims policy

No partnership language, logo, customer claim or implied endorsement without Caution's explicit written approval. Even after a working demo, describe Caution as a deployment environment unless a partnership is agreed.
