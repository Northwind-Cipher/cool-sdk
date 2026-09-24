# CooL x Phala Cloud - Closure Verification Matrix (final run)

Hardware: two Phala Cloud `tdx.small` CVMs.

| Role | CVM | app_id | Node | Image |
|---|---|---|---|---|
| Primary log (Deployment A, then B) | `45cd7bc9-a468-44c3-ae5d-aa5786234df1` | `774f4f4493d59bdc5faf921dbfe28a1f92428f44` | prod5, US-WEST-1 | A: `closure2-a` `sha256:9030c0b6833c75460b771443be43ca91dc06842927ad5c081a43ebaaf02e3b27`; B: `closure2-b` `sha256:91bd07cf20960f53c0f0e9202f1f4369b38987566d89af21ec77529328d91c31` |
| Witness | `dbd1bc32-a83f-401e-b3c2-e5a5209b4eab` | `21bbe8405dd597bce7390b0fbfcb30fedc96f311` | prod9, US-WEST-1 | `closure2-a` (command `node witness.mjs`) |

Everything below was verified outside the CVMs by `phala-validation/closure-verify.mjs` from the files in `artifacts/closure/`
(run output: `artifacts/closure/verification/`). Verification through Phala's attestation service is ONLINE; the local
`@phala/dcap-qvl` check is offline at verify time using collateral archived from Phala's response. Fixture tests
(`npm test`, 119/119, 0 skipped) prove software behaviour, not silicon; this matrix is the hardware evidence.

| Domain | Evidence | Verification | Negative control | Status |
|---|---|---|---|---|
| Binding | 8 receipts, `verification/binding-domain-final.json` | Canonical CBOR (cbor2) + node:crypto recompute, outside the SDK verifier | flipped `binding_hash`, flipped record field: binding fails (`tamper-final.json`) | VERIFIED |
| Signature | `verification/signature-domain-final.json` | ML-DSA-65 and Ed25519 both verified directly with @noble over the exact signed bytes | ed25519 bytes altered, ml-dsa bytes altered: signature fails | VERIFIED |
| Inclusion | `verification/inclusion-domain-final.json` (final receipt: leaf 7 of an 8-entry tree, audit path length 3) | Each head's root recomputed from all leaves with an independent RFC 6962 implementation; STH signatures verified | altered root, forged STH, altered audit path: inclusion fails | VERIFIED |
| Consistency | `verification/consistency-domain-final.json`; 8-event deployed log, heads of sizes 1..8 | SDK `verifyLogConsistency` (signatures, leaves, roots, equivocation, pairwise proofs) and an independent RFC 6962/9162 implementation: 36 of 36 pairs verify against enclave-signed heads | modified old root, modified new root, wrong sizes, truncated proof, forked history: 28 of 28 rejected per class | VERIFIED |
| Witness | `verification/witness-domain-final.json`, `witness/` | Separate CVM and node, own app_id, own enclave-sealed key (attested: its quote binds the witness key). It pulled the primary's receipts itself, verified all 8 (incl. real quotes and the pinned measurement), 8 heads, 7 consistency pairs, and for each later head that its previous signed head was still in the history, then signed sizes 1..8. Verifier requires it (`witnessThreshold: 1` now fails the verdict without it) | forged root/time/size/signature heads presented to the witness: refused (HTTP 409); forged witness signature, altered head, primary key substituted, no statement: witness domain not pass; witness after the primary log was replaced: refused | VERIFIED (see the operator statement below) |
| Attestation | `verification/attestation-domain-final.json`, raw Phala responses `phala-attestation-response-primary.json`, `-witness.json` | Raw TDX v4 quote (type 0x81) parsed: MRTD, RTMR0-3 and report_data equal the receipt; report_data binds the CooL signing key; Phala's service verified both quotes (ONLINE); local dcap-qvl with archived collateral: PASS, TCB `UpToDate`, no advisories | one flipped quote byte: Phala returned `verified:false`, local check rejected, receipt fails attestation and enclave | VERIFIED |
| Enclave | `verification/enclave-domain-final.json`, `runtime-A.json` | Complete non-zero MRTD/RTMR0-3 equal the raw quote; agent identity present; report_data binds the key; runtime status derived from evidence, observed inside the CVM: `intel-tdx · REAL` (hardware required, exit 0), `UNVERIFIED` (no verifier), `MEASUREMENT MISMATCH` (wrong pin, exit 1) | wrong pin, zero pin, requireHardware without a verifier: enclave fails | VERIFIED |

## Cross-cutting tests

| Test | Result | Evidence |
|---|---|---|
| Workload change: MRTD, RTMR0, RTMR1, RTMR2 identical; RTMR3 different | PASS | `verification/workload-change-final.json` |
| B against A's pin | rejected (rtmr3) | same |
| B against B's pin | accepted | same |
| A's witnessed receipt re-verified after B was deployed (both quotes re-checked online) | PASS | same |
| Tamper matrix, 11 single-field changes (binding hash, metadata, both signatures, root, forged STH, audit path, forged witness signature, wrong quote, wrong report_data, altered quote bytes) | every row `ok:false` with the expected domain failing | `verification/tamper-final.json` |
| Full verdict on the witnessed final receipt (requireHardware, Phala verifier, A's pin, witness threshold 1) | ok; binding, signature, inclusion, witnesses, attestation, enclave pass; anchor absent | `verification/final-external-verification.json` |

## Operator statement (witness)

The primary and the witness were deployed from the same Phala account. What is demonstrated is separation of key custody
(the witness key is sealed to a different app and cannot be derived by the primary workload), process, CVM and physical node,
measured witness code that the verifier can pin, and a witness that verifies before it signs. What is NOT demonstrated is
that a different organization operated the witness. No claim of third-party operation is made.

## Limits

CPU Intel TDX only, dev OS image (`is_dev: true`). Attestation verification is online through Phala; the local check depends on
Phala-supplied collateral and library; CooL itself records `tcb_status` as "Unknown". No quote freshness check. The deployed
images predate the verifier change that makes `witnessThreshold` fatal (the deployed workloads do not use it; the change is
tested in `tests/witness-consistency.test.ts` and exercised by `closure-verify.mjs`). Evidence manifest is unsigned. No
compliance certification, Phala endorsement or production-readiness claim is made.
