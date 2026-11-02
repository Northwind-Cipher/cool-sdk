# The agent-action demo: scenarios A–H

```bash
npm install
npm run demo:agent              # fresh temp directory
npm run demo:agent -- ./out     # keep the artifacts
```

One self-checking script (`scripts/demo-agent.ts`) runs all eight scenarios from spec chapter 47. Every ✓ is an assertion, and the run exits 1 if any claim fails. CI runs it as a test (`tests/evidence-v2.test.ts`) and again with the network blocked (`tests/egress.test.ts`).

**What is real:**
- every signature, digest and policy evaluation
- the nonce store, which is atomic and file-based
- the gateway's checks
- **the refund ledger file the gateway writes to**

The gateway owns that ledger, so "rejected" means the ledger did not change. The ledger stands in for a payment system.

**What is labelled:** scenario H's attestation is signed on a **synthetic** test PKI.

| | Scenario | Expected result | How it is checked |
|---|---|---|---|
| **A** | A legitimate agent action under policy | refund 200 within a 500 delegation → `permit` → gateway executes → ledger has `rf_1` → signed confirmation `completed` | the confirmation verifies against the trusted gateway key; the decision verifies offline and **replays identically** (assurance `reproducible`) |
| **B** | A request beyond authority | refund 900 → policy `deny` → gateway `rejected`, ledger unchanged. Also: a misconfigured policy that permits 900 is **still refused at the boundary** because the delegation ceiling is 500 | ledger line count; confirmation `rejected` with reason |
| **C** | The policy changes later | after `refunds@2` (limit 100) is published, A's decision still verifies against `refunds@1`; presenting v2 as A's policy is caught | `policy_binding: policy_mismatch` |
| **D** | Replay of a consumed authorization | resubmitting A → `rejected (replayed)`. Three **simultaneous** submissions of one authorization → exactly one refund | atomic nonce consumption (`FileNonceStore`, O_EXCL) |
| **E** | Workload substitution | the gateway observes a different artifact digest than the request bound → `rejected (execution_mismatch)` | ledger unchanged |
| **F** | Receipt tampering | flipping A's confirmation envelope from completed to rejected → `invalid`; altering the signed confirmation → `unverified` | canonical-encoding and digest checks; signature |
| **G** | A dropped event | sequenced receipts `7.0, 7.1, 7.3` → the bundle is **`incomplete`** (`sequence_gap: 7.2`), not verified | bundle `sequence_complete`; a dropped *final* receipt is only detectable once a later one arrives |
| **H** | Stale attestation | an hour-old Nitro document under a 5-minute window → **`stale`** | `nitroAdapter` outcome |

At the end the demo exports `agent-evidence-bundle.json`, with 17 envelopes and 16 signed protocol objects as attachments, and verifies it offline. You can check it yourself:

```bash
node dist/cli/index.js bundle verify <dir>/agent-evidence-bundle.json --trust <dir>/trust.json
```

## What the demo proves, and what it doesn't

- **Proves:** each action's identity, authority, request, decision and outcome are signed, bound to each other and independently checkable. Refusals happen at the boundary that owns the action, and the evidence says so.
- **Does not prove:** that the agent's reasoning was right; that actions taken *outside* the gateway were captured; that a real payment system behaved like the ledger; that any hardware protected the run.
