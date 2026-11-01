# Compliance mapping (sample)

> **This is a sample mapping for discussion with your auditor. It is not legal advice and not a certification.** CooL produces evidence that *supports* a control. Whether a control is met depends on your process, your scope and your auditor.

`cool compliance` prints the receipt-level mapping that ships in `src/phala/compliance.ts`. The table below extends it to the 4.x authorization and enforcement evidence.

| Regime / control | What the control asks | CooL evidence that supports it | Gaps CooL does not close |
|---|---|---|---|
| **EU AI Act Art. 12**, record-keeping | automatic logging of events over the system's lifetime | envelopes in a Merkle log; `authorization.*`, `tool.invoked`, `external.confirmed`; sequence-gap detection | capture of events that never pass through CooL; retention (your storage) |
| **EU AI Act Art. 14**, human oversight | humans can oversee, intervene and stop | `require_approval` → `indeterminate`, so the gateway refuses until approved; signed refusals | the approval workflow itself (commercial, managed policy) |
| **EU AI Act Art. 15**, accuracy, robustness, cybersecurity | resilience against manipulation | tamper-evident evidence; replay protection; execution binding; TEE attestation | model accuracy |
| **SOC 2 CC6.1 / CC6.3**, logical access | access is authorised and least privilege | principals with event-time state; delegation chains without amplification; signed decisions | your IdP's controls |
| **SOC 2 CC7.2**, monitoring | anomalies are detected and evaluated | bundle outcomes (`invalid` / `incomplete` / `stale`); log consistency; witnesses | alerting and SIEM (planned) |
| **SOC 2 CC8.1**, change management | changes are authorised and tracked | `policy.updated` with the previous digest; policy-version binding in decisions (scenario C) | change approval (commercial change control) |
| **ISO/IEC 27001 A.8.15**, logging | logs are produced, protected and analysed | signed, logged, witnessed envelopes; offline verification | log review procedures |
| **ISO/IEC 42001 Cl. 9**, performance evaluation | AI system evidence is available for evaluation | exportable bundles; reproducible decisions | evaluation criteria |
| **DPDP Rules 2025 s.8**, reasonable security safeguards | protect personal data | commitments only; secret-like fields rejected; no telemetry | data minimisation in *your* payloads |
| **RBI Digital Lending**, model governance | traceable automated decisions | decision ↔ request ↔ policy-digest binding; replayable evaluation | the regulatory reporting format |

## How to use this with an auditor

1. Export a bundle for the audit period: `exportBundle`, or the demo's `agent-evidence-bundle.json` as a template.
2. Give the auditor the bundle, your trust snapshot and the public verifier. They need no CooL account.
3. Map each sampled control to the envelope families above. The verification report lists every check, not only the headline outcome.
