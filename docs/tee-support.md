# TEE platform support

All platforms share one adapter contract (`src/platform/tee.ts`). Each adapter returns:
- the platform's **own claims, untouched**, with no invented universal "PCR" field
- a normalized summary, only where meanings are comparable
- the verifier name and version, and the validation time
- an **outcome** and its limitations

A new platform is a new adapter. The evidence core and the envelope parser do not change.

A platform is labelled **supported** only with real evidence validation, adversarial fixtures, a version matrix, collateral handling and documented validation. A parser on its own is not support (spec chapter 49).

| Platform | Label | What is validated | What is not |
|---|---|---|---|
| **AWS Nitro Enclaves** | **implemented** (verifier) · **experimental** (runtime) | COSE_Sign1 and CBOR strict parsing; chain to the pinned `AWS_NitroEnclaves_Root-G1` (fingerprint checked against AWS's published value); PCR0–2 policy, PCR8 explicit; `user_data` / `public_key` key binding; nonce and timestamp freshness; debug-enclave rejection. A **genuine AWS document** fixture plus 600 corruption cases. The in-enclave sealer and vsock framing are tested on a synthetic PKI | no CooL workload has run in a real enclave; no real NSM helper; no real vsock; no revocation (AWS publishes no CRL) |
| **Intel TDX** (via Phala dstack) | **implemented** | recorded hardware validation on Phala Cloud `tdx.small` (`artifacts/closure-verification-matrix.md`); `report_data` binds the key; measurement pinning; fail-closed `requireHardware` | quote chain via a configured verifier; TCB recorded as `Unknown` on `main`; no quote freshness on `main` |
| **Phala dstack** | **partial** | runtime/deployment evidence and KMS-derived keys, as a separate claim from the TDX quote | keys follow app identity, not the image (`docs/attestation.md#keys`); the KMS's own attestation is not verified |
| **AMD SEV-SNP** | **unsupported** | — (the adapter returns `unsupported`) | report parsing, VCEK/VLEK chain, TCB, collateral |
| **NVIDIA Confidential Computing** | **unsupported** | GPU evidence can be *committed to* (`src/phala/gpu.ts`) | verification (NRAS not integrated); CPU/GPU binding correlation |

## Rules every adapter follows

- **Raw evidence is preserved.** It travels by digest, or as the document itself.
- **The trust bundle is versioned** and never fetched at verification time.
- **Stale collateral or documents give `stale`.** An unsupported platform gives `unsupported`. An unavailable service gives `indeterminate`. None of these is ever `verified`.
- **Attestation is limited evidence.** It supports a measured platform state under the verifier's policy. It does not prove application behaviour or complete capture.
