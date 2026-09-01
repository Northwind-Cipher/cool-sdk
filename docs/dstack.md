# Phala dstack

CooL talks to a [dstack](https://github.com/Dstack-TEE/dstack) guest agent over
its RPC surface — `Info`, `GetQuote(reportData)`, `GetKey(path)` — reached at
`/var/run/dstack.sock` inside a CVM, or an `http://` URL against the simulator.
CooL does not bundle `@phala/dstack-sdk`; it speaks the protocol directly through
`HttpDstackClient`. Pin a known-good dstack runtime for production rather than
tracking `latest`.

## 1. Local development — no dstack at all

```ts
const cool = new CooL({ applicationId: "dev" });   // provider defaults to "local"
```

The simulator runs the identical pipeline. Every receipt says `simulated`. Good
for tests, CI, and most of a hackathon.

## 2. The dstack simulator (hardware path, no hardware)

Install the Phala CLI and start the simulator, then point CooL at it:

```sh
npm install -g phala
phala simulator start          # serves the guest-agent RPC over a local endpoint
```

```sh
export COOL_DSTACK_ENDPOINT=http://127.0.0.1:8090   # use the address the simulator prints
node your-app.js
```

```ts
const cool = new CooL({
  applicationId: "refund-agent",
  attestation: { provider: "dstack" },   // endpoint picked up from COOL_DSTACK_ENDPOINT
});
```

The quote *structure* and key binding are exercised end to end; the root is still
CooL-held, so receipts remain `simulated`. Confirm the current simulator command
and port against the Phala docs — they have moved between releases.

## 3. Self-hosted Intel TDX

Run your app inside a dstack CVM with the guest-agent socket mounted:

```yaml
# docker-compose.yaml (inside the CVM)
services:
  app:
    image: your/app
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
    environment:
      - COOL_IMAGE_DIGEST=sha256:...   # the image you built and reviewed
```

```ts
const cool = new CooL({
  applicationId: "refund-agent",
  attestation: { provider: "dstack", endpoint: "/var/run/dstack.sock", vendor: "intel-tdx" },
  security: { requireAttestation: true, expectedMeasurement: PINNED },
});
```

To get `attestation: pass` (not just `hardware`), the *verifier* also needs a
quote verifier:

```ts
import { remoteQuoteVerifier } from "cool-nwc/phala";
await verifyEvidence(evidence, {
  quoteVerifier: remoteQuoteVerifier({ endpoint: process.env.QUOTE_VERIFIER_URL, root: "intel-dcap" }),
  expectedMeasurement: PINNED,
  requireHardware: true,
});
```

## 4. Phala Cloud

Deploy the same compose file through the Phala CLI:

```sh
phala auth login
phala deploy            # or `phala cvms create` — follow the current CLI help
```

Phala Cloud provides the TDX host and the guest agent; nothing in the CooL
integration changes. Pull the running instance's measurement and set it as
`expectedMeasurement` / `COOL_IMAGE_DIGEST`.

> Deployment to Phala Cloud requires a Phala account and TDX capacity, and has
> **not** been exercised as part of this repository's CI. The configuration
> above is the intended path; the external steps are yours to run.

## Compatibility

| CooL | dstack protocol | Environment | Status |
|---|---|---|---|
| 3.x | `Info` / `GetQuote` / `GetKey` | local simulator (built-in) | tested in CI |
| 3.x | same | dstack simulator binary | supported; run it yourself |
| 3.x | same | self-hosted Intel TDX | supported; not in CI |
| 3.x | same | Phala Cloud | supported; not in CI |

## What dstack contributes — precisely

- a **confidential VM** (Intel TDX) to run the evidence plane in;
- an **attested workload identity** — the MRTD + RTMR measurement set;
- a **quote** binding that identity to CooL's signing key via `report_data`;
- a **measurement-sealed key** so the signer is the code, not an operator.

It does **not** make CooL "secure" on its own, and CooL does not create the TEE —
it uses the one dstack provides.
