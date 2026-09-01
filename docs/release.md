# Release (maintainers)

Publishing is done by `.github/workflows/release.yml` on a version tag, using
**npm trusted publishing (OIDC)** — there are no npm tokens in the repo or in CI
secrets. The workflow generates provenance automatically.

## Checklist

1. `main` is green (`ci.yml`).
2. Bump `version` in `package.json` (semver). Breaking public-API or
   evidence-schema changes → major.
3. Update `CHANGELOG.md`: move `## [Unreleased]` to `## [x.y.z] — YYYY-MM-DD`.
4. Locally:
   ```sh
   npm run verify:all
   npm run verify:package      # pack → clean install → run → typecheck
   npm pack --dry-run          # inspect file list and size
   ```
5. Commit, then tag:
   ```sh
   git tag vX.Y.Z
   git push origin main --tags
   ```
6. `release.yml` runs: checkout → install → verify:all → build → `npm publish`
   (with `--provenance`, via OIDC) → create the GitHub Release with the
   changelog section.
7. Verify: `npm view cool-nwc@X.Y.Z` shows the version and a provenance link;
   install it in a scratch dir and run the quickstart.

## First publish

The npm package name and the GitHub repo must be linked for trusted publishing:
configure the `cool-nwc` package on npm to trust
`Northwind-Cipher/cool-sdk` → `.github/workflows/release.yml`
(npm: *Settings → Publishing access → Trusted publisher*). Until that is done the
release job's publish step will fail closed — which is the intended default.

## Evidence schema versions

`cool.evidence.v1` / `cool.receipt.v2` are versioned independently of the package.
A schema change ships its own structural-validator update and a `docs/migration.md`
entry, and bumps the package major.
