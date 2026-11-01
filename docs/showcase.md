# The CooL open showcase

One command runs every capability of the open evidence core end to end:

```bash
npm install
npm run showcase              # writes to a fresh temp directory
npm run showcase -- ./out     # keep the artifacts
```

**The showcase checks itself.** Every line it prints with ✓ is an assertion made while it runs. If any claim does not hold, the line turns red and the process exits `1`. CI runs it on every push (`tests/showcase.test.ts`). It makes no network calls.

## The eight chapters

| # | Chapter | What it proves | Real or labelled |
|---|---|---|---|
| 01 | AI change receipts | a prompt change becomes a signed, logged receipt that verifies offline; no plaintext; one edited field breaks binding and signature | Intel TDX path on CooL's **simulator**. Attestation is reported `simulated`, never `pass`. The hardware results are in [`artifacts/`](../artifacts) |
| 02 | Disclosure and witness signatures | the true text opens a sealed field and a doctored one is refused; an external witness counts and the operator's own signature does not | real |
| 03 | One evidence envelope | `cool.envelope.v1` passes all applicable checks; an unknown key's valid signature is *not trusted*; a revoked key is rejected; strict payloads | real |
| 04 | Transparency and checkpoints | inclusion proof and a witnessed checkpoint verify; a forged tree head is rejected | real |
| 05 | Reference capture | real commits from this repository become `scm.commit` evidence, with no e-mail addresses | real |
| 06 | AWS Nitro, genuine document | a real AWS attestation verifies to the pinned AWS root; its debug mode is caught; one flipped bit fails the signature | **genuine** third-party AWS document |
| 07 | AWS Nitro sealing | a fresh in-enclave key bound by attestation; sealed receipts cross the host and verify; an altered one fails | **synthetic** test PKI; no real enclave |
| 08 | Portable proof | the bundle verifies end to end; with no trust snapshot of your own the result is *unknown*; removing one record is detected | real |

## What it leaves behind

| File | What it is |
|---|---|
| `evidence-bundle.json` | the signed evidence. Verify it with `cool bundle verify evidence-bundle.json --trust trust.json` (exit `0`) |
| `trust.json` | the trust snapshot used (public keys only) |
| `showcase-report.json` | every claim, with its result |

## Not shown here

- **The commercial platform**, see [open-core.md](open-core.md):
  - policy and enforcement
  - the deployment gate and the other response modules
  - incident reconstruction
  - the Nitro log server, with its epochs and gap detection
- **Real hardware.** No CooL code has run inside a Nitro enclave. The TDX hardware evidence is in `artifacts/`.
