# Research spike: CVA, RCVA and zero-knowledge proofs

**Status: research. Nothing on this page is implemented, and no CooL claim depends on it.**

This spike (spec chapter 27) asks one question: can CooL verify more than "this was signed" without revealing the inputs? It records what was considered, what the protocol already supports without zero-knowledge, and what would justify building more.

## Terms

| Term | Meaning here |
|---|---|
| **CVA**: committed-value authorization | the decision is bound to *commitments* of the parameters and context, not their plaintext. **This is what 4.x already does** (`params_commitment`, `context_commitment`) |
| **RCVA**: revealable CVA | a holder can later reveal the salt and the value so any verifier can recompute the commitment (`paramsMatch`, `contextMatches`). **Already implemented.** Disclosure is all-or-nothing per field group |
| **ZK policy proof** | a proof that "`evaluatePolicy(policy, facts)` = permit" for hidden facts, checkable against the policy digest and the commitments. **Not implemented** |

## What 4.x already gives without ZK

- **`trusted` assurance.** A verifier accepts the evaluator's signature over the request digest, the policy digest and the input digest. The facts stay private, and you trust the evaluator.
- **`reproducible` assurance.** The facts are disclosed to the verifier, who re-runs the deterministic `cool.policy.v1` and gets the same answer. This needs no trust in the evaluator and gives no privacy from that verifier.
- **Selective disclosure** of envelope fields (`cool disclose`). It reveals some fields and keeps others committed.

## Candidate ZK approaches considered

| Approach | Fit | Cost / risk |
|---|---|---|
| A zkVM (RISC Zero, SP1) running the TypeScript policy logic ported to Rust | general; proves the real evaluator | proofs take seconds to minutes; large prover; new trusted setup or toolchain risk; the guest code must match `cool.policy.v1` exactly |
| A circuit for a policy subset (comparisons, set membership, ranges), e.g. Circom/Halo2 | fast verification; small proofs | it only covers numeric thresholds and allow-lists; every new operator needs new circuit work and an audit |
| Range proofs only (Bulletproofs) for amounts | narrow and well understood | covers "amount ≤ limit" only |
| TEE-attested evaluation (the evaluator runs in Nitro/TDX) | uses machinery CooL already has | moves trust to the hardware vendor; it is not zero knowledge |

## Recommendation

1. **Don't build ZK now.** `trusted` plus `reproducible`, with keyed commitments, covers the demo scenarios and the stated customer questions.
2. **The next step, if demand appears, is TEE-attested evaluation:** record the evaluator's attestation as an `attestation.recorded` envelope linked to its decisions. It reuses the Nitro/TDX adapters.
3. **Revisit ZK for range checks only** (amount limits) once a customer needs to prove compliance to a third party who must not see amounts. Prototype it with Bulletproofs behind a new assurance level, `proven`, and never relabel existing evidence.

## Criteria for promoting this past research

- a written threat model for the proof system, including setup assumptions
- test vectors shared with an independent implementation
- verification cost measured on the target verifiers
- an external review before any public claim

Until all four exist, the word "proof" is not used for policy decisions.
