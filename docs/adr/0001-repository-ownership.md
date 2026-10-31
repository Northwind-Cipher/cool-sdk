# ADR 0001: Where the platform work lives

- **Status:** proposed, awaiting Kailosh's review
- **Date:** 2026-10-31

## Context

The master specification names three repositories: `KenidoesCode/cool-spec`, `KenidoesCode/cool-verifier` and `KenidoesCode/cool-sdk`. An audit on 2026-10-31 found:

| Repository | Last push | Content |
|---|---|---|
| `KenidoesCode/cool-spec` | 2026-06-25 | v0.1.1 spec snapshot, 3 commits |
| `KenidoesCode/cool-verifier` | 2026-06-25 | v0.1.1 CLI, 2 commits |
| `KenidoesCode/cool-sdk` | 2026-06-25 | v0.1.1 SDK (`@northwind/cool-sdk`, Apache-2.0), 2 commits |
| `Northwind-Cipher/cool-sdk` | 2026-10 | `cool-nwc@3.0.0` (BUSL-1.1): all current code, the hardware validation evidence and the CLI |

The specification's "spec / verifier / SDK" split already exists **inside** `Northwind-Cipher/cool-sdk`, on the local branch `feat/verifier-split-python-sdk`: `packages/cool-verifier`, `spec/test-vectors`, `sdk/python` and `apps/browser-verifier`. That branch has **never been pushed** and is 14 commits ahead of `origin/main`.

## Decision

1. All new work goes into `Northwind-Cipher/cool-sdk`. The `KenidoesCode` repositories are treated as historical v0.1 snapshots and are not modified. Changing them would fork the work and leave the June code looking current.
2. The Nitro work is based on `origin/main`, not on the unpushed branch. Building on that branch would publish its 14 commits, which include internal material such as `docs/demo-script.md`, `brag-output-*/` and `deploy.bat`, without the owner deciding to publish them.
3. New code goes in `src/nitro/`, behind the subpath export `cool-nwc/nitro`, and does not depend on the verifier split. When that split merges, `src/nitro/attestation.ts`, `trust-root.ts` and `epochs.ts` move into `packages/cool-verifier/src/nitro/` unchanged, because they import only the canonical, codec, hash, sign and types modules.
4. No repository restructure beyond that is proposed here.

## Consequences

- The `KenidoesCode` repositories should carry a pointer to `Northwind-Cipher/cool-sdk`, or be archived. That is the owner's call.
- **Decision needed from the owner:** push or merge `feat/verifier-split-python-sdk`. It holds the TCB policy, quote freshness, Python SDK and conformance corpus that the specification also asks for.
