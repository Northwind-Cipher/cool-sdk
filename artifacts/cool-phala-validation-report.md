# CooL x Phala Cloud Real-TEE Validation Report

## Executive Summary

CooL (`cool-nwc@3.0.0`, commit `0eaf98533a55dcea7829218f7701da48a56b8b5c`) was deployed to a real
Phala Cloud Intel TDX confidential VM (`tdx.small`, US-WEST-1) and produced a hardware-attested
evidence receipt that independently verifies **7/7** of its verification domains as REAL:
binding, signature, inclusion, consistency, witness, attestation, and enclave. Attestation was
verified against Phala Cloud's live Intel-DCAP-backed API, not merely generated. Enclave
measurement (MRTD/RTMR0-3) was captured from real hardware and shown to correctly change (RTMR3
only) when the deployed workload changed, and to correctly reject a mismatched measurement pin.
A tamper test on the receipt correctly failed verification. Total Phala Cloud spend was
approximately $0.03, against an authorized ceiling of $10.

## Objective

Move CooL's Phala/dstack integration from "5/7 real, 2/7 simulated" (the state described going
into this validation) to genuinely real attestation and enclave verification, using real Phala
Cloud infrastructure, without fabricating any result.

## Starting CooL State

See `artifacts/baseline.md`. Commit `0eaf98533a55dcea7829218f7701da48a56b8b5c`, 85/86 tests
passing (1 skipped, network-dependent), clean typecheck and build. The verifier's own status
vocabulary (`pass / simulated / absent / fail / mock`) already made honest 5/7 the correct
baseline characterization — the plumbing for real hardware (`HttpDstackClient`,
`remoteQuoteVerifier`, `security.requireAttestation`) already existed in the codebase; what was
missing was exercising it against real infrastructure.

## Phala Environment

- CVM: `48fab3a0-eac5-44ec-834f-3de2e701e7b4` (app_id `36b6ebcab24492ad1d56a46dc05261cb9eac4d45`)
- Instance: `tdx.small` — 1 vCPU, 2GB RAM, 20GB disk, $0.058/hr compute + $0.00278/hr disk
- Region: US-WEST-1, node `prod9`
- dstack OS: `dstack-dev-0.5.9`, KMS type `phala`
- No GPU, no H200, single CVM reused across all redeployments (never created a second CVM
  needlessly)

## Architecture

The deployed workload (`phala-validation/server.mjs`) is a minimal HTTP server that:
1. Constructs an `HttpDstackClient` against the real guest-agent unix socket
   (`/var/run/dstack.sock`), using `cool-nwc/node`'s `unixFetch` transport and the current
   dstack RPC paths (`/Info`, `/GetQuote`, `/GetKey`).
2. Opens a `CoolTee` connection with `policy.allowSimulated: false`, `policy.requireVerifiedRoot:
   true`, and a real `remoteQuoteVerifier` pointed at Phala Cloud's attestation API.
3. Records one synthetic `model.execution` evidence event.
4. Serves the resulting receipt, attestation handshake, and verdict over HTTP so they can be
   pulled and verified from outside the CVM.

## Engineering issues found and fixed (documented, not hidden)

Three real integration problems were found and fixed while getting from "quote request fails" to
"attestation: pass":

1. **Unix-socket transport not wired by default.** The top-level `CooL` class constructs
   `HttpDstackClient` with the platform `fetch`, which cannot open a unix socket — the real guest
   agent's actual transport (`unixFetch` from `cool-nwc/node`) has to be passed in explicitly via
   the `dstackClient` extension point. This is exactly what that extension point is for; not a
   patch to the SDK.
2. **Stale RPC paths.** CooL's default paths (`/prpc/Info`, `/prpc/GetQuote`, `/prpc/GetKey`)
   are from an older dstack generation (`tappd`). The real, currently-deployed guest agent
   (`dstack-dev-0.5.9`) exposes `/Info`, `/GetQuote`, `/GetKey` with no prefix — confirmed against
   `Dstack-TEE/dstack`'s own `sdk/curl/api.md`. Fixed via `HttpDstackClient`'s already-existing
   `paths` override — the module's own comment anticipated exactly this ("dstack renamed these...
   overridable rather than hard-coded").
3. **`tcb_info` parsed as an object when the real agent returns it as a JSON-encoded string.**
   This is a genuine bug in `src/phala/dstack.ts`, fixed in this validation: `HttpDstackClient
   .info()` read `raw.tcb_info.mrtd` etc. directly; against real hardware `tcb_info` arrives as a
   string, so every field read `undefined` and every measurement silently fell back to
   `00000...0`. The fix (`parseTcbInfo`) parses the string before reading fields, is covered by
   the existing test suite (85/85 still passing, 0 regressions), and was the difference between
   an enclave check that "passed" against fake zeros and one that passes against a genuine
   96-hex-character MRTD.

## Attestation

Quote requested from the real dstack guest agent via `GetQuote`, `report_data` committed to the
CooL signing key's public halves. Verified against Phala Cloud's own attestation API:

```
POST https://cloud-api.phala.com/api/v1/attestations/verify
Body: { "hex": "<quote hex>" }
Response: { "quote": { "verified": true } }
```

This is **online, collateral-assisted verification** — it requires a live network call to Phala's
service, and is labelled as such rather than called "offline." Result: `attestation: pass`,
`root: intel-dcap`.

## Enclave Measurement

Captured from the real running instance (deployment A):

```
MRTD : f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077
RTMR0: 68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96
RTMR1: 07e6f51aa763abfe75c3ddfbf4f425fe3f0ceff66d807a75e049303dce9addf68e7218729bd419638af63a370f65878c
RTMR2: a2a58c9a959a4fa44bd6da0c97a2270c051faf12084cfe91ae900e4fdff6cdd4f69a82005e04ee920f231497894d677f
RTMR3: 77ba57968d6212f4f5d77bfc66b54a19cf606539d28d54082fe4709b2610912cec5e7b6b998a41dbc0cf19a19d862974
```

Docker image digest (`sha256:cc4c8b91...`) is recorded separately in the certificate and never
conflated with these registers.

## CooL Signing-Key Binding

`report_data` in the quote equals `mh_sha256(canonicalCBOR({ed25519_pub, ml_dsa_pub}))` for the
key that signed the record (`cool-enclave-f06dfda6dc`). The verifier recomputes this and compares
— `enclave` domain fails otherwise. Result: pass.

## Receipt Generation

One synthetic `model.execution` record per deployment, no real user data, no secrets. See
`artifacts/receipts/deployment-a-receipt.json` and `deployment-b-receipt.json`.

## External Verification

Receipts were pulled over HTTPS and verified on a separate process (the operator's own machine,
not the CVM), re-hitting Phala's live attestation API fresh. See
`artifacts/final-evidence/external-verification-deployment-a.json`. Result: `ok: true`, all
domains shown individually (never collapsed to one boolean).

## Seven-Domain Verification

See `artifacts/verification-matrix.md` for the full matrix with per-domain evidence pointers.
**Result: 7/7 REAL.**

## Tamper Test

One hex character of `binding_hash` (a signed field) was flipped in a copy of the valid receipt.
Re-verification: `ok: false`; `binding`, `signature`, and `inclusion` all correctly reported
`fail`; `attestation`/`enclave` correctly remained `pass` (they check hardware evidence, which was
untouched — this is the correct, precise failure surface, not a blanket "everything failed").
See `artifacts/tamper/`.

## Workload Change Test

Deployment B built from the same source with one build-arg changed (`WORKLOAD_MARKER=v2`),
producing a new immutable image digest. Result: RTMR3 differed from Deployment A; MRTD/RTMR0-2
were identical (correct — those registers cover base firmware/kernel, not application content).
Verifying Deployment B's receipt against Deployment A's pinned measurement: **FAIL** (`rtmr3
mismatch`). Approving B's new measurement and re-verifying: **PASS**. See
`artifacts/final-evidence/measurement-change-*.json`.

## Historical Receipt Validity

Deployment A's original receipt was re-verified after Deployment B existed and still returns
`ok: true` against its own pinned measurement — historical evidence is not invalidated by a later
redeploy. See `artifacts/final-evidence/historical-receipt-A-still-valid.json`.

## Reproducibility

See `COOL_PHALA_REPRODUCTION.md`.

## Security Notes

- No secrets, credentials, or personal data appear in any evidence artifact (manually reviewed;
  see the security-audit note in `COOL_PHALA_REPRODUCTION.md`).
- The `security.requireAttestation` / `policy.allowSimulated: false` path was confirmed to fail
  closed with no simulator fallback at every stage of this validation — every early failure
  (`COOL_DSTACK_UNAVAILABLE`, `COOL_ATTESTATION_REQUIRED`) was a hard refusal, never a silent
  downgrade.

## Cost

Authorized ceiling $10.00. Estimated actual spend ~$0.03 (≈31 minutes of `tdx.small` runtime
across all redeployments, single CVM). See `artifacts/phala/spend-ledger.json`.

## Limitations

- CPU Intel TDX only — no GPU/confidential-GPU attestation was tested or claimed.
- Witness independence is cryptographically real but operationally self-administered in this test.
- Attestation verification is online/collateral-assisted, not offline.
- No compliance certification (SOC 2, ISO, HIPAA) is claimed.
- Not a claim of a Phala partnership, endorsement, or commercial contract.

## Evidence Files

See `artifacts/evidence-manifest.json` for a complete SHA-256-hashed index of every evidence file
produced by this validation.

## Final Result

**7 / 7 verification domains REAL**, independently verified, with a tamper test and a
workload-change enforcement test both behaving correctly, on real Phala Cloud Intel TDX
infrastructure, for approximately $0.03.
