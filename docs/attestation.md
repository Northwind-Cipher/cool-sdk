# Attestation

CooL's evidence plane can run in three modes. The mode is recorded in every
receipt and is never blurred.

| `mode` | What it means | Verifier verdict on `attestation` / `enclave` |
|---|---|---|
| `mock` | no attestation path at all | `mock` / `absent` |
| `simulated` | a structurally complete quote under a **CooL-held** root — real signature, real key binding, no vendor root | `simulated` / `simulated` |
| `hardware` | a vendor quote produced by real silicon (Intel TDX today) | `pass` / `pass` — **only** with a quote verifier and a real vendor root |

`simulated` is not a soft `pass`. It is exactly what it says: the shape and the
key binding are real; Intel/AMD/NVIDIA as the root of trust is not.

## What is bound to what

When the plane starts it:

1. reads the runtime measurement (`Info`),
2. derives a signing key **sealed to that measurement** (`GetKey`),
3. asks the hardware for a quote whose 64 bytes of `report_data` are
   `enclaveReportData(signingKey.publicKey)` — a commitment to the signing
   identity (`GetQuote`).

The quote's digest then goes **inside** the signed record core (`runtime.tee_quote`),
before the record is signed. So:

- the signature covers the attestation — a valid quote cannot be moved onto a
  record it did not attest;
- `report_data` ties the quote to the exact key that signed — "an attested
  enclave holds this key" and "this key signed this record" are one chain;
- the measurement is in the signed core — it cannot be relabelled after the fact.

The `enclave` verifier domain re-checks all of that from the bytes.

## Quote verification stages — do not conflate them

| Stage | Who does it | CooL status |
|---|---|---|
| quote **retrieved** | the plane, at startup | always, in `simulated` and `hardware` |
| quote **parsed / structurally checked** | `checkQuoteStructure` | always |
| quote **cryptographically verified against a vendor root** | a `QuoteVerifier` you supply (`remoteQuoteVerifier` → Intel DCAP collateral) | only `attestation: pass` |
| **measurement** matches the image you approved | your `expectedMeasurement` pin | only then is `enclave` pinned |
| **policy** accepts that measurement / vendor / signer | you | outside the verdict |

"We got a quote" is not "the quote is verified", and "the quote is verified" is
not "I accept this workload". CooL keeps these separate on purpose.

## Requiring hardware

```ts
const cool = new CooL({
  applicationId: "regulated",
  attestation: { provider: "dstack" },
  security: { requireAttestation: true },   // connect fails if the handshake isn't hardware-backed
});

// and at verification time:
await verifyEvidence(evidence, {
  requireHardware: true,
  quoteVerifier: remoteQuoteVerifier({ endpoint: DCAP_URL, root: "intel-dcap" }),
  expectedMeasurement: PINNED,
});
```

With `requireAttestation`, CooL never silently downgrades from hardware to
simulation — if the quote isn't real, it throws `AttestationRequiredError` at
connect and returns `ok: false` at verify.

## Keys

The signing and log keys are **derived inside the enclave** from the measurement
(dstack `GetKey`). There is no key to configure and none to leak into config.
A redeploy that changes the image rotates the keys automatically; historical
receipts stay verifiable because each carries its own `key_directory`.

## `requireHardware` and the enclave domain

Without `requireHardware`, the `enclave` domain checks the binding between the quote and the record (quote digest inside the
signed core, measurement equality, `report_data` committing to the signing key, and the measurement pin if one is set). It can
report `pass` while `attestation` is only `absent` (a quote that was reported but not chained to a vendor root).

With `requireHardware: true` (also set by `security.requireAttestation`), the `enclave` domain fails closed unless `attestation`
is `pass`, and the overall verdict is `ok: false`. Verification of a hardware quote needs a `quoteVerifier` (for example
`remoteQuoteVerifier`); that verification is online unless you supply a local verifier with collateral.

## Runtime modes

The CLI and SDK derive a runtime status from evidence. It is never read from the vendor label, a pinned measurement, a Docker
digest or the client class (`HttpDstackClient` is always "hardware", whatever answers behind it).

| Status | Meaning |
|---|---|
| `intel-tdx · REAL` | A dstack agent answered with a complete, non-zero MRTD and RTMR0-3 and an agent identity; a quote was obtained; a configured verifier chained it to a vendor root; the key binding and any pin held; the channel opened. |
| `intel-tdx · UNVERIFIED` | The agent's evidence is complete but nothing verified the quote. This cannot be told apart from a protocol simulator, so it is not shown as real. |
| `intel-tdx · SIMULATED` | CooL's in-process simulator. Every receipt says `simulated`. Never hardware evidence. |
| `UNAVAILABLE` | No dstack agent could be reached. |
| `EVIDENCE INCOMPLETE` / `ATTESTATION FAILED` / `MEASUREMENT MISMATCH` | An agent answered but its evidence is incomplete, or the handshake failed. Not real. |

**Local / development.** With no agent (`DSTACK_ENDPOINT` unset and no `/var/run/dstack.sock`) the CLI runs the simulator and says
`SIMULATED — no dstack hardware agent detected`. An endpoint that is configured or detected but does not answer is an error, never a
quiet switch to the simulator.

**Real TDX.** Inside a CVM the socket is detected automatically. Use `DSTACK_RPC_STYLE=plain` for the current agent paths
(`/Info`, `/GetQuote`, `/GetKey`), `QUOTE_VERIFIER_URL=phala` (or your own verifier URL) to chain the quote, and
`COOL_EXPECTED_MEASUREMENT='{"mrtd":"hex:…","rtmr0":…,"rtmr1":…,"rtmr2":…,"rtmr3":…}'` to pin the approved image. Without a pin the
CLI pins whatever the agent reports, which proves nothing about which workload is running. Phala's verification is online.

**Hardware required.** `COOL_REQUIRE_HARDWARE=1` or `--require-hardware` (not `verify`, where the flag keeps its verifier meaning)
makes the CLI fail closed: no agent, no verifier, a failed attestation, a measurement mismatch or any status other than REAL is an
error with a non-zero exit. Library equivalents: `policy.allowSimulated: false`, `policy.requireVerifiedRoot`, `verify(..., { requireHardware: true })`;
`CoolTee.runtime` and `CooL.environment.runtime` expose the derived status.
