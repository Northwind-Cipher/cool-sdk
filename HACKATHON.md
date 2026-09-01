# CooL at a hackathon

**The story:** you build an AI application. CooL gives it a cryptographic
evidence layer — every execution produces a receipt anyone can verify offline,
with no account and without seeing your data. Phala dstack gives that evidence
generation a hardware-attested place to run. Independent verification is what
makes the receipts useful to anyone outside your app.

You should be building your idea, not fighting CooL's install. If `npm install
cool-nwc` and the quickstart don't work on a clean machine, that's a bug — file
it.

## 5-minute walkthrough

```
00:00  npm install cool-nwc
00:20  new CooL({ applicationId: "my-app" })
00:40  await cool.record({ type: "model.execution", metadata: {...}, payloads: {...} })
01:20  await verifyEvidence(evidence)   →  ok: true, 7 domains
02:00  show the receipt — no prompt, no output, no metadata values in it
02:40  attestation.provider: "dstack"  →  the same receipt, mode: "hardware"
03:20  flip one hex digit of metadata_hash
03:40  verifyEvidence again  →  ok: false, "binding FAILED", "signature FAILED"
04:10  cool verify evidence.json  — offline CLI, exit code 1
04:40  where this goes: external witnesses, GPU attestation, hosted verifier
```

Every command in that list actually runs. `npm run demo` performs steps 00:40 →
03:40 unattended.

## Build on it

Starter shapes in [`examples/`](examples):

- `basic` — record + verify, the minimum.
- `agent` — an AI agent that emits a verifiable trail of tool calls and decisions
  (shared `executionId` per run).
- `express` — evidence per HTTP request, off the response path, `flush()` on
  shutdown.
- `verification` — produce evidence here, verify it "somewhere else".
- `dstack` — the hardware path, with `requireAttestation`.

Ideas that fit CooL well: agent action logs, model-provenance receipts for a
marketplace, a "verify this AI output" widget, regulated-workflow audit packs
(`cool pack build`), tamper-evident eval results.

## What to claim, and what not to

Say: *cryptographically verifiable*, *tamper-evident*, *hardware-attested* (only
with real dstack), *offline-verifiable*, *privacy-preserving by commitment*.

Don't say: *quantum-proof*, *unhackable*, *production-ready*, *proves the output
is correct*. CooL records what happened; it doesn't grade it. In the simulator,
`attestation` and `enclave` read `simulated`, never `pass` — that distinction is
the point of the project, so don't blur it in a demo.

## If dstack isn't available

The simulator runs the identical code path and every receipt says `simulated`.
That's a fine demo — just narrate it honestly. For the hardware path without a
CVM, use the dstack simulator binary: see [`docs/dstack.md`](docs/dstack.md).
