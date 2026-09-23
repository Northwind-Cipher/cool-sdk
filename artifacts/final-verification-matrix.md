# CooL x Phala Cloud - Final Verification Matrix (Run 2)

Evidence: fresh Phala Cloud CVM `3c1fcf8c-3c11-4965-936d-b32545c711a0` (app `facc79f103f122331845c5a52ab425ff29fe6512`,
`tdx.small`, US-WEST-1, node prod5, dstack-dev-0.5.9), Deployment A image
`pranauvshrinaath/cool-phala-validation:final-a` (`sha256:3535a90e49a375c4f92a1cdc0d05190d05ca551053d03d96c4f16e198860eff5`),
Deployment B image `final-b` (`sha256:1372fbe7ab61418519772146e59765a042c16a5d3f0080c1356e1cff4875ebca`).
All checks below were run outside the CVM by `phala-validation/final-verify.mjs` and
`phala-validation/offline-dcap-verify.mjs` against receipts pulled from the workload.
The CVM has been deleted. Run 1 evidence (original commit de7230b) is preserved unchanged.

"Real" means the mechanism was exercised with real evidence, not merely that code exists.

| Domain | Mechanism | Real? | Evidence | External verification | Result | Limitations |
|---|---|---|---|---|---|---|
| Binding | Recompute `binding_hash` from canonical CBOR of the record core | YES (6 real receipts) | `final-evidence/binding-domain-final.json` | Recomputed with cbor2 + node:crypto by a script that does not call verifyReceiptV2 | PASS | Shares the cbor2 library with the SDK |
| Signature | ML-DSA-65 and Ed25519 over `core \|\| binding digest` | YES (6 receipts) | `final-evidence/signature-domain-final.json` | Both verified by calling @noble libraries directly | PASS | Same @noble libraries back the SDK; no second implementation |
| Inclusion | RFC 6962 audit path to enclave-signed tree head | YES; final receipt is leaf 5 of a size-6 tree, audit path length 2 | `final-evidence/inclusion-domain-final.json` | Path and STH signature checked outside the CVM | PASS | Log and its key are inside the same enclave/operator |
| Consistency | RFC 6962 consistency proof between signed heads | YES as a CooL log mechanism on the deployed enclave's own signed heads (sizes 1-6, 21 pairs, headline 2 -> 6); NOT a field of the receipt verdict | `final-evidence/consistency-domain-final.json`; test `tests/real-tee-validation.test.ts` | Proof computed externally from public leaf hashes and checked against roots from enclave-signed STHs; forged first roots rejected | PASS (mechanism) | Not exercised as a `verifyReceiptV2` verdict; the deployed log exposes no proof endpoint; Run 1 receipts (size 1) did not exercise it |
| Witness | Hybrid cosignature over the STH by a distinct key, `external:true` | Cryptographic: YES. Operational independence: NO | `final-evidence/witness-domain-final.json` | Signature verified directly and through verifyReceiptV2 | PARTIAL: cryptographically independent PASS; operationally independent NOT DEMONSTRATED | Key generated and used by the validating operator; no third party was available |
| Attestation | Real Intel TDX quote, verified by Phala Cloud's attestation service; also verified locally with archived Intel collateral | YES (TDX v4, TEE type 0x81) | `final-evidence/attestation-domain-final.json`, `phala-attestation-api-response-A.json` (raw response, 26 KB), `offline-dcap-verification-A.json` | ONLINE service returned verified:true (HTTP 200). Local `@phala/dcap-qvl` check with archived collateral: PASS, TCB UpToDate, no advisories; one-byte-flipped quote rejected | PASS | Primary verification is online. The local check is offline at verify time only; collateral was obtained online via Phala and the library is Phala-authored. CooL's own `tcb_status` field still records "Unknown". No freshness/nonce check |
| Enclave | MRTD/RTMR0-3 vs quote, `report_data` key binding, measurement pin, fail-closed `requireHardware` | YES | `final-evidence/enclave-domain-final.json`, `workload-change-final.json` | All five registers equal the values parsed from the raw quote; `report_data` equals the digest of the signing key; wrong pin fails; requireHardware without a verifier fails; with a verifier passes | PASS | Pins are copied from the receipts under test; dev OS image; the fail-closed behaviour applies when `requireHardware` is set (default behaviour unchanged) |

## Cross-cutting tests

| Test | Result | Evidence |
|---|---|---|
| Workload change: MRTD/RTMR0/1/2 identical, RTMR3 different (A `c4c39cf2...` vs B `287839dc...`) | PASS | `final-evidence/workload-change-final.json` |
| B against A's pin | FAIL as required (`differs ... in rtmr3`) | same |
| B against B's pin | PASS as required | same |
| Historical receipt A verified after B exists | PASS | same |
| Tamper: flip `binding_hash` | FAIL: binding, signature, inclusion fail; attestation and enclave still pass | `final-evidence/tamper-final.json`, `tamper-final/` |
| Tamper: flip `record.event.metadata_hash` | FAIL: binding and signature fail; inclusion passes (the log committed to the original digest) | same |
| Full `verifyReceiptV2` on the witnessed final receipt (requireHardware, Phala verifier, witness threshold 1) | ok: true; binding, signature, inclusion, witnesses, attestation, enclave pass; anchor absent | `final-evidence/final-external-verification.json` |

## Determination

6 of 7 domains are verified with real evidence. The seventh, witness, is verified cryptographically but its
operational third-party independence was not demonstrated, so the result is **not** reported as 7/7 verified.
Consistency is verified as a mechanism on the real deployed log, not as a receipt verdict.
