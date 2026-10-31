# The CooL showcase

One command runs every CooL capability end to end:

```bash
npm install
npm run showcase              # writes to a fresh temp directory
npm run showcase -- ./out     # keep the artifacts
```

**The showcase checks itself.** Every line it prints with ✓ is an assertion made while it runs. If any claim does not hold, the line turns red and the process exits `1`. CI runs it on every push (`tests/showcase.test.ts`), so the demo cannot drift away from what the code actually does. It makes no network calls.

## The twelve chapters

| # | Chapter | What it proves | Real or labelled |
|---|---|---|---|
| 01 | AI change receipts | a prompt change becomes a signed, logged receipt that verifies offline; no plaintext; one edited field breaks binding and signature | Intel TDX path on CooL's **simulator**. Attestation is reported `simulated`, never `pass`. The hardware results are in [`artifacts/`](../artifacts) |
| 02 | Disclosure and witnesses | the true text opens a sealed field and a doctored one is refused; an external witness counts and the operator's own signature does not | real |
| 03 | One evidence envelope | `cool.envelope.v1` passes all applicable checks; an unknown key's valid signature is *not trusted*; a revoked key is rejected; strict payloads | real |
| 04 | Policy that does not guess | a missing fact is unknown, so the policy denies; the most restrictive rule wins | real |
| 05 | Supply-chain deployment gate | verified provenance is admitted and confirmed; a tampered artifact is denied and production keeps the approved bytes | real; the target is a **local directory** |
| 06 | Identity & Authority | a provider timeout leaves the credential *unknown*; only confirmation rotates it; cross-tenant access is denied; token replay is detected | real |
| 07 | Change Control | a config edited after approval is denied; drift is recorded; unknown health holds a rollout; an unapproved rollback is refused | real |
| 08 | Runtime Guard | spoofed events are never acted on; escalation leads to quarantine (dry run, then enforced and confirmed); suppressed telemetry is detected | real; the response target is a **local deny-list file** |
| 09 | AWS Nitro, genuine document | a real AWS attestation verifies to the pinned AWS root; its debug mode is caught; one flipped bit fails the signature | **genuine** third-party AWS document |
| 10 | AWS Nitro receipt path | fresh in-enclave key, attested; receipts cross an untrusted host; a dropped receipt becomes a gap; a late copy fills it; an altered receipt is rejected; a stale attestation gets no epoch; the checkpoint is witnessed | **synthetic** test PKI; no real enclave |
| 11 | Incident Evidence | a case built from evidence references; the spoof is labelled *source-asserted*; a backdated completion is *contradicted*; an unexported log line is *missing*; so the case bundle does **not** pass | real |
| 12 | Portable proof | the release bundle verifies end to end; with no trust of your own the result is *unknown*; removing one record is detected | real |

## What it leaves behind

| File | What it is |
|---|---|
| `release-bundle.json` | the release's signed evidence. It verifies: `cool bundle verify release-bundle.json --trust trust.json` exits `0` |
| `incident-bundle.json` | the incident case. It deliberately **fails** (exit `1`): it contains a spoofed event and a reference to evidence that was never exported |
| `trust.json` | the trust snapshot used (public keys only) |
| `showcase-report.json` | every claim, with its result (`cool.showcase-report.v1`) |
| `prod/`, `denylist.txt` | the real side effects of the two enforcement targets |

## What it does not show

- **Real hardware.** The showcase does not use TDX or Nitro hardware. The TDX hardware evidence is in `artifacts/closure-verification-matrix.md`. No CooL code has run in a Nitro enclave.
- **Real integrations.** No cluster, cloud, CI or SaaS system is used.
- **Public anchoring.** It is not run, because the showcase uses no network. Run `cool anchor` separately.
- **Production readiness.** No independent security review has taken place.
