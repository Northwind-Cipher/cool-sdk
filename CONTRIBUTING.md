# Contributing

Thanks for looking. CooL is infrastructure software — small, explicit, and
conservative about its public surface.

## Setup

```sh
git clone https://github.com/Northwind-Cipher/cool-sdk
cd cool-sdk
npm install
npm run verify:all      # typecheck + validator check + tests
```

Node ≥ 20. There is no build step for development; tests run TypeScript directly
through `tsx`.

## Working on it

| Command | What it does |
|---|---|
| `npm test` | the full `node --test` suite |
| `npm run typecheck` | `tsc --noEmit`, strict |
| `npm run build` | compile `src/` → `dist/` and patch ESM specifiers |
| `npm run demo` | the valid → tamper → fail walkthrough |
| `npm run verify:package` | pack the tarball, install it into a clean project, run it |

Run `npm run verify:package` before sending anything that touches the public API,
the exports map, or the build — it is the check that catches "works in the repo,
breaks on install".

## Ground rules

- **Keep the public API small.** New top-level exports need a reason. Internal
  helpers stay internal (`src/phala/*` is the advanced tier, not a dumping
  ground).
- **Never weaken an honesty rule.** `simulated` is never `pass`. A verifier
  never reports success on a check it did not perform. A domain that cannot be
  evaluated is `absent`, not silently skipped.
- **Canonicalization and signing bytes are frozen.** Changing what gets hashed
  or signed is an evidence-schema change: bump the schema version, update the
  structural validator, and add vectors.
- **No new runtime dependencies** without discussion. The current set is
  `@noble/*`, `cbor2`, `ulid`.
- **No secrets, no telemetry, no install scripts, no network calls** at install
  or during basic local use.

## Commits and PRs

- One logical change per PR. Describe *why*, not just *what*.
- Every behavioural change needs a test that fails before and passes after.
- Update `CHANGELOG.md` under `## [Unreleased]` (add the heading if missing).
- Security-sensitive changes: note it in the PR and follow
  [`SECURITY.md`](SECURITY.md) for anything that shouldn't be public yet.

## Releases

Maintainers only — see [`docs/release.md`](docs/release.md). Publishing is done
by the tagged GitHub Actions workflow with npm trusted publishing (OIDC); there
are no long-lived npm tokens.

## Licensing and contributions

- CooL is licensed under the Business Source License 1.1 (`LICENSE`). By submitting a contribution you agree that it may be distributed under the license of the file or project it modifies, and you confirm that you have the right to submit it.
- Only submit code you wrote or have the right to license. **Do not submit confidential, proprietary or third-party material** (including code copied from other projects, employers or clients) unless its license is compatible and is recorded.
- Third-party code and dependencies **keep their own licenses and notices**. If you add or update a dependency, update `docs/THIRD_PARTY_LICENSES.md` and do not strip existing copyright or license headers.
- New original source files should carry the header used across the repository (`Copyright (c) 2026 Northwind Cipher Pvt. Ltd.` and `SPDX-License-Identifier: BUSL-1.1`). Do not add that header to vendored or third-party files.
- No contributor license agreement is currently defined by this repository. Northwind Cipher Pvt. Ltd. may require one before merging significant contributions; the maintainers will tell you.
- Security reports must follow `SECURITY.md` and must not be filed as public issues.
