# CooL Baseline — Pre-Change State

## Source

- Repository: https://github.com/Northwind-Cipher/cool-sdk.git
- Commit: `0eaf98533a55dcea7829218f7701da48a56b8b5c`
- Branch: `main`
- Package: `cool-nwc@3.0.0`
- Node: `v24.15.0`
- npm: `11.12.1`

## Build / test status (before any change)

- `npm install`: clean, 0 vulnerabilities
- `npm run typecheck`: clean, no errors
- `npm run build`: clean — 82 files compiled into `dist/`
- `npm test`: **85 pass / 0 fail / 1 skipped**
  - Skipped test: `the public calendars accept a real head` (OpenTimestamps calendar — requires live network to public OTS calendar servers, unrelated to attestation/enclave)

## Seven-domain verifier (`src/phala/verify.ts`)

The verifier (`verifyReceiptV2`) implements **7 checks** (it calls this "domains"): `binding`,
`signature`, `inclusion`, `witnesses`, `attestation`, `enclave`, `anchor`. Note: the task brief's
"consistency" is not a distinct verdict domain in this codebase — RFC 6962 consistency proofs are
a Merkle-log operation (`src/merkle.ts`, tested in `features.test.ts: "log: consistency proves the
tree only grew"`), not a field of the verdict. The 7 verdict domains as implemented are:
binding, signature, inclusion, **witnesses**, attestation, enclave, **anchor**.

Each domain has an explicit status vocabulary, not a boolean — this is the key fact governing what
"REAL" can mean in this codebase:

| Domain | Possible statuses | Currently reachable state (local/no hardware) |
|---|---|---|
| binding | pass / fail | **pass** (pure math, always real) |
| signature | pass / fail | **pass** (pure math, always real) |
| inclusion | pass / fail / absent | **pass** (pure math, always real) |
| witnesses | pass / absent | **absent** by default (needs external co-signer; can be made real with 0 extra infra — see below) |
| attestation | pass / simulated / absent / fail / mock | **simulated** (default local run) or **mock** (no quote at all) |
| enclave | pass / simulated / absent / fail | **simulated** (mirrors attestation status) |
| anchor | pass / pending / absent / fail | **absent** (no OpenTimestamps anchor attached) |

Critically, `attestation` can reach `pass` **only** when:
1. `HttpDstackClient` talks to a **real dstack guest agent** (`quote.root !== "cool-sim-root"`), AND
2. A `QuoteVerifier` is supplied that actually chains the raw quote bytes to a vendor root (e.g.
   `remoteQuoteVerifier` against Intel DCAP / Phala's own attestation service) and returns `ok: true`.

Without both, the verifier reports `absent` ("quote present ... no verifier configured, so it is
REPORTED, not verified") rather than optimistically passing. There is no code path in this
repository that can produce `attestation: pass` from software alone — this is enforced structurally
in `verifyAttestationDomain` (`src/phala/verify.ts:337-379`), not just by convention.

`enclave` mirrors `attestation`'s status once its own four independent checks pass (quote-in-signature,
measurement match, report_data key binding, measurement pin) — see `verifyEnclaveDomain`
(`src/phala/verify.ts:381-444`), lines 440-443.

## Baseline classification (measured, not assumed)

| # | Domain | Real today? | Why |
|---|---|---|---|
| 1 | binding | REAL | Pure cryptographic recomputation, no dependency on hardware or network |
| 2 | signature | REAL | Hybrid ML-DSA-65 + Ed25519 verify, pure math |
| 3 | inclusion | REAL | RFC 6962 Merkle audit path + signed tree head, pure math |
| 4 | consistency | REAL (as log op) | RFC 6962 consistency proof, tested; not a verdict field but implemented and real |
| 5 | witness | REAL-CAPABLE, ABSENT by default | Independent co-signer verification is real crypto (`verifyWitnessesDomain`); simply has no external witness configured in default receipts |
| 6 | attestation | SIMULATED | No dstack hardware + no quote verifier wired up in default path |
| 7 | enclave | SIMULATED | Mirrors attestation; the four internal checks are real, but status is capped at `simulated` because attestation is simulated |

This matches the task brief's premise (5 real / 2 simulated) once witness is treated as
"real machinery, not yet exercised with an external witness" rather than a separate defect — the
witness path requires zero additional infrastructure to flip to genuinely `pass` (just configure a
second independent signer), unlike attestation/enclave which require actual TDX hardware plus a
real quote-verification service.

## What is required to move attestation + enclave from SIMULATED to REAL

1. **Real hardware**: Deploy the evidence-plane workload inside an actual Phala Cloud Intel TDX
   confidential VM, with `HttpDstackClient` pointed at the real guest agent socket
   (`/var/run/dstack.sock`), `attestation.provider: "dstack"`, `security.requireAttestation: true`
   (which sets `allowSimulated: false` internally — `src/client.ts:229`).
2. **Real quote verification**: Configure `remoteQuoteVerifier` (`src/phala/quote.ts:209`) against
   a real Intel DCAP / Phala attestation-verification endpoint. Local hardware alone produces a
   real quote but caps the domain at `absent` ("reported, not verified") without this step.
3. **Measurement pin discipline**: capture the real MRTD/RTMR0-3 from the running instance and set
   `expectedMeasurement`, to exercise the pin-match/pin-mismatch behavior for real.

No code changes are strictly required to reach `attestation: pass` / `enclave: pass` — the
plumbing (`HttpDstackClient`, `remoteQuoteVerifier`, `security.requireAttestation`,
`expectedMeasurement`) already exists in the current `main` branch. What's missing is **exercising
it against real infrastructure**, which is the deployment step, not an implementation gap.

## Local dstack simulator note

`docs/dstack.md` documents a second local step — `phala simulator start` — which runs the *real*
`HttpDstackClient` wire protocol against a local binary (not `SimulatedDstackClient`). This
produces `mode: "hardware"` receipts with `quote.root: "intel-tdx"`-shaped structure but still no
real TDX silicon underneath, so a correctly-configured verifier should still not report `pass` on
attestation unless the simulator's own quotes chain to a real root (they won't, by design). This
step is useful for exercising the wire protocol at $0 before spending on a real CVM, and will be
attempted next.
