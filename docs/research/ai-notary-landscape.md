# AI-notary and verifiable-compute landscape

- **Researched:** 2026-10-31. This is a **first pass**, not a complete competitive analysis.
- Statements are labelled **[vendor]** (the company's own claims, unverified), **[third-party]** (partner or press coverage, also unverified) or **[analysis]** (our reading of both).

## EQTY Lab: Verifiable Compute

| | |
|---|---|
| **What it sells** | "Verifiable Compute", launched December 2024 with Intel and NVIDIA. Runs AI workloads in TEEs on Intel Xeon and NVIDIA GPUs and issues cryptographic certificates per operation; called an "AI notary system". [vendor] |
| **Evidence model** | Tamper-resistant records of the data and code used in training and inference; audit and lineage certificates checkable in a browser. Attestations are compiled into manifests and anchored to the Hedera network. [vendor] [third-party: Hedera case study] |
| **Enforcement claim** | A "governance gate" that can halt an AI system when mandatory controls fail. Connectors listed for ServiceNow, Databricks and Palantir. [vendor] |
| **Buyer** | Regulated enterprise and public sector. The company says it worked with EMEA agencies on alignment with the EU AI Act. [vendor] |
| **Later products** | Press headlines mention a "Verifiable Runtime" for NVIDIA enterprise AI and a deployment on NVIDIA Blackwell. These were **not read in full**, so their details are unconfirmed. |
| **Pricing** | Not public. |
| **Independently verified technical properties** | **None found.** Every source is a press release or partner material. Performance figures (for example the "400,000x" in Hedera material) are unverified. |

**[analysis] How CooL differs.** EQTY's pitch includes GPU attestation and an enforcement gate. CooL claims neither today: no GPU attestation, and no enforcement (`docs/trust-models.md`). CooL's differentiators are an offline verifier that needs no account, per-domain verdicts that never collapse into one boolean, a published negative-control matrix, and RFC 6962 plus witness plus Bitcoin anchoring rather than a single ledger. CooL should not claim parity on GPUs or enforcement.

Sources:

- [Nasdaq / BusinessWire release](https://www.nasdaq.com/press-release/eqty-lab-intel-and-nvidia-unveil-verifiable-compute-solution-secure-trusted-ai-2024)
- [BusinessWire](https://www.businesswire.com/news/home/20241218897420/en)
- [Hedera case study](https://hedera.com/case-study/eqtylab/)
- [Hedera blog](https://hedera.com/blog/eqty-labs-verifiable-compute-brings-trust-to-ai-with-hedera)

## Caution

Caution is covered in [ADR 0003](../adr/0003-caution-questions.md). In short: a verifiable-compute platform on AWS Nitro, AGPL-3.0 plus a commercial licence, with reproducible builds and `caution verify`. It is a potential deployment environment for CooL's Nitro path, not a competitor in evidence or verification. [analysis]

## Not yet researched

The specification asks for "other AI-notary / verifiable-AI products". Still to do:

- Phala's own attestation explorer
- Opaque Systems
- Anjuna
- Edgeless Systems (beyond the Contrast integration on `feat/contrast-integration`)
- Fortanix
- Google Confidential Space

Each should get the same table, filled in from primary sources.
