# CooL x Phala Cloud - Verification Matrix (corrected)

This file supersedes an earlier version that reported "7 / 7 REAL". That wording was not supported by the
evidence and has been withdrawn. The authoritative matrix is [`closure-verification-matrix.md`](closure-verification-matrix.md); [`final-verification-matrix.md`](final-verification-matrix.md) is the earlier run, superseded on witness and consistency.

## Run 1 (commit de7230b, original evidence)

Evidence: `artifacts/receipts/deployment-a-receipt.json` (Phala CVM `48fab3a0-eac5-44ec-834f-3de2e701e7b4`, image
`sha256:cc4c8b917bfacd492e6afe6e6815777c4af5108d069284542466a7fbc7f64b75`). Tree size 1, single receipt.

| Domain | Result in Run 1 | Corrected characterization |
|---|---|---|
| Binding | PASS | Verified |
| Signature | PASS | Verified |
| Inclusion | PASS | Verified mechanism; trivial tree (size 1, empty audit path) |
| Consistency | Reported as PASS | NOT exercised. It is not a verdict domain and the size-1 tree cannot produce a proof. Verified separately in Run 2 |
| Witness | Reported as PASS | Cryptographic separation demonstrated; operational independence NOT demonstrated |
| Attestation | PASS | Real TDX quote accepted by Phala's online attestation service; raw response was not archived in Run 1 (archived in Run 2) |
| Enclave | PASS | Real measurements match the raw quote; in Run 1 the domain could report pass while attestation was unverified unless `requireHardware` was set (fixed under `requireHardware` in Run 2) |

## Run 2

See `final-verification-matrix.md`. Result: 6 of 7 verified with real evidence; witness is cryptographically
verified with operational independence not demonstrated.
