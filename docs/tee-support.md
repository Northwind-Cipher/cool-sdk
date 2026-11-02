# TEE platform support

All platforms share one adapter contract (`src/platform/tee.ts`). Each adapter returns:
- the platform's **own claims, untouched**, with no invented universal "PCR" field
- the verifier name and version, and the validation time
- an **outcome** and its limitations

A new platform is a new adapter. The evidence core and the envelope parser do not change.

**Labels** come from `src/platform/capabilities.ts` (the full table is in [capabilities.md](capabilities.md)), and a test keeps each adapter's `support` equal to them:
- **implemented:** validated against **genuine** evidence.
- **experimental:** built and tested, but not yet validated on real hardware.
- **partial:** built with documented gaps.
- **unsupported:** the verifier says so instead of guessing.

| Platform | Label | Validated against | What is not covered |
|---|---|---|---|
| **AWS Nitro Enclaves: verifier** (`cool-nwc/nitro`) | **implemented** | a **genuine AWS attestation document** plus 600 corruption cases. COSE_Sign1 and strict CBOR; chain to the pinned `AWS_NitroEnclaves_Root-G1`; PCR0–2 policy, PCR8 explicit; `user_data` key binding; nonce/timestamp freshness; debug-enclave rejection | revocation (AWS publishes no CRL); full RFC 5280 path validation |
| **AWS Nitro Enclaves: CooL running inside an enclave** | **experimental** | the [deployment kit](../examples/nitro-enclave/README.md): Rust NSM helper on `/dev/nsm`, enclave server, host collector. Tested end to end over real sockets with a synthetic NSM; CI builds the enclave image and compiles the helper | **not yet run on AWS hardware.** It becomes implemented when `artifacts/nitro-validation/` holds a passing artifact with `"synthetic": false` |
| **Intel TDX** (via Phala dstack) | **implemented** | recorded hardware validation on Phala Cloud `tdx.small` (`artifacts/closure-verification-matrix.md`); `report_data` binds the key; measurement pinning; fail-closed `requireHardware` | TCB recorded as `Unknown`; no quote freshness on this path; the quote chain goes through a configured verifier |
| **Phala dstack** | **partial** | runtime/deployment evidence and KMS-derived keys, as a separate claim from the TDX quote | keys follow app identity, not the image (`docs/attestation.md#keys`); the KMS's own attestation is not verified |
| **AMD SEV-SNP** (`cool-nwc/snp`) | **implemented** | a **genuine Milan attestation report and its VCEK** (virtee/sev test data), chaining to **AMD's ARK/ASK fetched from AMD KDS and pinned** (Milan, Genoa, Turin; VCEK and VLEK). Checks: structure and canonical unsigned bytes; ECDSA P-384 signature; certificate TCB = `REPORTED_TCB`; VCEK `hwID` = `CHIP_ID`; DEBUG policy; measurement pin; `REPORT_DATA` binding; TCB minimum; VMPL. 300-case mutation fuzz | VCEK revocation only via serials you supply (AMD KDS CRL); ID block/author key not evaluated; a report carries no timestamp, so freshness needs a nonce in `REPORT_DATA` |
| **NVIDIA Confidential Computing** (`cool-nwc/nvidia`) | **experimental** | verifies NRAS attestation **results** offline: ES384 signatures; `x5c` chains to **NRAS intermediates pinned from NVIDIA's live JWKS** (all 208 published keys chain to them); expiry; nonce; overall result; per-GPU `submods` binding; GPU appraisal claims; CPU-TEE binding nonce | **no result from a real CC GPU yet** (tokens in tests are synthetic, in NRAS's shape). The raw SPDM evidence is appraised by NVIDIA's NRAS, not re-appraised by CooL |

## Using them

```ts
import { verifySnpReport } from "cool-nwc/snp";
const r = verifySnpReport(reportBytes, { certificate: vcekDer, expectedMeasurement, expectedReportData });
// r.outcome: "verified" only if every applicable check passed; no measurement pin → "indeterminate"

import { verifyNrasResult, cpuBindingNonce } from "cool-nwc/nvidia";
const g = verifyNrasResult(nrasResponse, { jwks: archivedJwks, expectedNonce: cpuBindingNonce(cpuReportData), cpuReportData });
```

## Rules every adapter follows

- **Raw evidence is preserved.** It travels by digest, or as the document itself.
- **Trust anchors are pinned in code**, with their fingerprints re-checked at load. They are never fetched at verification time.
- **Outcomes are honest.** Stale collateral or certificates give `stale`. An unknown format gives `unsupported`. A missing pin or nonce gives `indeterminate`. None of these is ever `verified`.
- **Attestation is limited evidence.** It supports a measured platform state under the verifier's policy. It does not prove that application behaviour is correct, or that capture was complete.
