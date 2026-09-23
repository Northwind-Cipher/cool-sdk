# CooL x Phala Cloud Real-TEE Validation Report (corrected, final)

This report replaces an earlier version that claimed "7/7 REAL". An independent audit found that wording was not
supported. It is not a certification, and it does not claim any Phala partnership, endorsement or commercial
relationship.

## Result

Real-TEE validation completed on Phala Cloud Intel TDX hardware. Binding, signature, inclusion, real hardware
attestation evidence, enclave measurement evidence, tamper rejection and workload-change enforcement were
demonstrated. Consistency was verified as a mechanism on the real deployed log's signed heads but is not a receipt
verdict domain and was not exercised on the size-1 Run 1 receipt. Witness cryptography was demonstrated, but
operational third-party witness independence was not.

## System under test

- Repository `Northwind-Cipher/cool-sdk`, `cool-nwc@3.0.0`. Run 1 baseline commit `0eaf98533a55dcea7829218f7701da48a56b8b5c`;
  Run 1 validation commit `de7230b82fda26b9d961dd1c2e071efaea6ba6c6`; Run 2 changes are in the closeout commit on `main`.
- Phala Cloud `tdx.small` (1 vCPU, 2 GB), US-WEST-1, dstack-dev-0.5.9 (`is_dev: true`), real dstack guest agent over `/var/run/dstack.sock`.
- Run 1 CVM `48fab3a0-eac5-44ec-834f-3de2e701e7b4`; Run 2 CVM `3c1fcf8c-3c11-4965-936d-b32545c711a0`. Both deleted.
- Run 2 images: Deployment A (primary) `sha256:3535a90e...0eff5` (`final-a`); Deployment B (workload change) `sha256:1372fbe7...ebca` (`final-b`).
  Docker image digests are recorded separately from, and never equated with, TDX measurements.

## Run 1 (original, commit de7230b)

Established real hardware evidence and found two SDK-integration gaps and one SDK bug (below). Evidence in
`artifacts/receipts`, `artifacts/attestation`, `artifacts/final-evidence` (original files), `artifacts/tamper`.
Its tree had one entry, so it did not exercise consistency or a non-trivial inclusion path.

## Engineering findings and fixes

1. Unix-socket transport is not wired by the top-level `CooL` class; the workload passes `HttpDstackClient` with `unixFetch` explicitly.
2. Default RPC paths (`/prpc/...`) do not match the deployed agent (`/Info`, `/GetQuote`, `/GetKey`); overridden through the client's `paths` option.
3. Bug: the real agent returns `tcb_info` as a JSON-encoded string; `HttpDstackClient.info()` read fields off it as an object and silently
   produced an all-zero measurement. Fixed in `src/phala/dstack.ts` (`parseTcbInfo`). The fix was validated against real hardware and is now covered
   by a dedicated regression test (`tests/real-tee-validation.test.ts`, two tests). Negative control: both tests fail against the pre-fix `dstack.ts`.
4. Semantics: the enclave domain could report `pass` while attestation was `absent`. Under `requireHardware` it now fails closed
   (`src/phala/verify.ts`, `verifyEnclaveDomain`). Behaviour without `requireHardware` is unchanged.

## Run 2 evidence (fresh, `artifacts/final-evidence/`)

- **Real hardware:** the raw quote in the final receipt parses as TDX v4, TEE type 0x81; MRTD, RTMR0-3 and `report_data` parsed from the quote bytes equal the receipt values.
- **Attestation:** online verification by Phala Cloud's attestation service (HTTP 200, `verified: true`, `proof_of_cloud: true`); the full response (26 KB, including Intel PCK CRL, TCB info and QE identity collateral) is archived as `phala-attestation-api-response-A.json`.
  A local check with `@phala/dcap-qvl` using that collateral passed with TCB status `UpToDate` and no advisory IDs; a one-byte-flipped quote was rejected (`offline-dcap-verification-A.json`).
  The local check is offline at verify time only; the collateral was obtained online through Phala's API and the library is Phala-authored.
- **Key binding:** the quote's `report_data` equals the digest of the CooL signing key's public halves, recomputed by the verifier and by `final-verify.mjs`.
- **Log:** six receipts from one log; final receipt is leaf 5 of a size-6 tree with a two-hash audit path. Consistency proofs between all 21 pairs of enclave-signed heads (headline 2 -> 6) verified; forged first roots rejected.
- **Workload change:** MRTD/RTMR0/1/2 identical between A and B; RTMR3 differs. B against A's pin fails (rtmr3); B against B's pin passes; A remains valid after B exists.
- **Fail-closed:** wrong pin fails; `requireHardware` without a verifier fails both attestation (absent) and enclave; with a verifier both pass.
- **Tamper:** flipping `binding_hash` fails binding, signature and inclusion; flipping `metadata_hash` fails binding and signature (inclusion still passes because the log committed to the original digest). Attestation and enclave remain valid in both.
- **Witness:** a distinct-key cosignature verifies (directly and through `verifyReceiptV2`); the key was generated and used by the validating operator, so operational independence was not demonstrated.

## Limitations

- CPU Intel TDX only; no GPU claim. Dev OS image, single node per run, synthetic data.
- Attestation is verified online through Phala; the offline check depends on Phala-supplied collateral and library. CooL's recorded `tcb_status` remains "Unknown". No quote freshness or nonce.
- Consistency is not part of the receipt verdict; proofs were computed externally from public leaf hashes.
- Witness and measurement approvals are operator-controlled; pins are taken from the receipts under test.
- Evidence manifest is an unsigned file in the same repository.
- Cost is an estimate (elapsed time x hourly rate, about $0.04 in total across both runs), not read from billing.
- No compliance certification (SOC 2, ISO 27001, HIPAA) is claimed.

## Reproduction

See `COOL_PHALA_REPRODUCTION.md`. Integrity of the evidence files: `artifacts/evidence-manifest.json`.
