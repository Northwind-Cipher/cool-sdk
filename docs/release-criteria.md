# Release criteria and supply chain

A version of `cool-nwc` is released only when **every** item below holds. The release workflow (`.github/workflows/release.yml`) enforces the automated items. The others are part of the release checklist in `docs/release.md`.

## Automated gates (CI, every pull request and release)

| Gate | Where |
|---|---|
| Typecheck, unit tests, adversarial and fuzz tests on Node 20 and 22 | `ci.yml` |
| The tamper demo fails as expected, the showcase and the agent demo hold every claim | `ci.yml`, `tests/evidence-v2.test.ts` |
| No network calls on the SDK paths | `tests/egress.test.ts` |
| A consumer install from the packed tarball works; the examples run | `ci.yml` |
| `npm audit` has no high or critical findings | `security.yml` |
| No key files or private-key blocks anywhere in the history | `security.yml` |
| CodeQL | `security.yml` |
| Package contents are checked (`verify:package`) | `release.yml` |
| **npm provenance** through trusted publishing (OIDC, no long-lived token) | `release.yml` |
| **SBOM**: CycloneDX `sbom.cdx.json` attached to the GitHub release | `release.yml` |

## Manual criteria

- **Claims.** Every claim in `README.md` and `docs/guarantees.md` maps to a test. The feature labels (`docs/tee-support.md`, `docs/milestones-status.md`) are current.
- **Compatibility.** Schema changes are additive within `v1`. Breaking changes need a new schema id and a migration note. `cool.receipt.v2` stays verifiable (`legacy.receipt`).
- **Changelog.** `CHANGELOG.md` has an entry with breaking changes called out.
- **Security.** Changes to the verifier, crypto or the authorization protocol get a second reviewer (`GOVERNANCE.md`).

## Reproducible builds

The build is `node scripts/build.mjs` (tsc, no bundler, no minifier). The tarball is reproducible given the same lockfile, the same Node and npm versions and the same commit. Byte-for-byte reproducibility is **not yet verified by CI**. That job is planned, and until it exists CooL does not claim reproducible builds.

## How to verify a release

```bash
npm view cool-nwc@<version> dist.attestations   # provenance
npm audit signatures                            # registry signatures and attestations
# SBOM: download sbom.cdx.json from the GitHub release for <version>
```
