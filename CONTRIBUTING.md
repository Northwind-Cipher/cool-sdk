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
