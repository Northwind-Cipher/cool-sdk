# Pilots and packaging (spec pages 43–44)

**Everything here is a hypothesis.** No pilot has been run, no customer has been interviewed, and no price has been tested. This page exists so the work can start from something concrete, not to claim results.

## Initial customer hypothesis

Software and platform teams that run CI/CD into production, carry real dependency risk, and are asked by auditors or customers to *show* their provenance and release controls.

## First paid workflow to prove

The deployment gate, which is built in this repository (`cool gate-demo`): refuse an artifact whose bytes don't match signed provenance from a trusted builder, and hand an auditor a bundle they can verify themselves.

The spec warns against building all five modules before this one workflow is proven paid. That warning stands. The other four modules exist as thin libraries, not products.

## Interview guide

1. How do you verify that what runs in production is what CI built?
2. Can you trace a production artifact back to its source commit, builder and approval? How long does that take?
3. What happens today when provenance is missing?
4. Which system actually blocks a deployment, and who owns it?
5. How long did your last incident reconstruction take? What evidence was missing?
6. What do auditors or customers ask you to prove?
7. Which integrations would you need on day one (CI, registry, cluster)?
8. Why would you pay for this instead of assembling Sigstore, in-toto and SLSA tooling yourselves?

## What to measure in a pilot

- setup time
- share of deployments covered
- invalid releases refused
- false positives
- verification latency (measured locally at ≈6 ms per envelope)
- investigation time
- operational burden
- willingness to pay

## Packaging hypothesis

| Package | Contents | Status in this repository |
|---|---|---|
| **CooL Verify** | CLI and SDK, local verification, bundle verification, basic CI policy | **exists**: `cool bundle verify`, `cool decide`, `cool-nwc/platform` |
| **CooL Control** | shared policies, deployment gates, identity and change integrations, approvals | **partial**: the policy engine and gate exist; real integrations do not |
| **CooL Evidence** | investigations, timelines, retention, signed exports | **partial**: timelines and bundles exist; there is no retention or hosted storage |
| **CooL Platform** | APIs, custom adapters, embedded verification | **partial**: adapter and connector interfaces exist |

Pricing should be tested against buyer value: protected deployments, workloads, connectors, retention or organization size. Not against how many cryptographic primitives are used. Keep the verifier free and useful, because it drives adoption.

No TAM figures are given here because none have been supported.
