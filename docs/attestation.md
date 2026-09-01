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
