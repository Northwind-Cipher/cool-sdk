# CooL V1 IP protection report

Date: 2026-09-24. This report describes what was done and what was found. It is not legal advice.

> A software license does not prevent someone from seeing or copying code that is intentionally published publicly. Repository visibility and access controls are separate from licensing.

## 1. Repository state before protection

| Item | Value |
|---|---|
| HEAD | `fd1f3c62c521903e1081c9468f087ff56f5dc057` on `main`, up to date with `origin/main` (0 ahead / 0 behind), working tree clean |
| Origin | `https://github.com/Northwind-Cipher/cool-sdk.git` |
| License | Apache-2.0 (`LICENSE`, `package.json`, README badge) |
| Package manager | npm (`package-lock.json`) |
| Baseline | typecheck PASS, build PASS, tests 119 total / 119 pass / 0 fail / 0 skip |
| GitHub (unauthenticated API) | Public repository, organization-owned `Northwind-Cipher`, not a fork, default branch `main` |
| Headers | No copyright or SPDX headers in source files |
| Vendored code | 8 files from `cool-sdk` (Apache-2.0), see `docs/IP-OWNERSHIP.md` |

## 2. Repository state after protection

Business Source License 1.1 in `LICENSE`; `NOTICE.txt`; Apache-2.0 text preserved in `LICENSES/Apache-2.0.txt`; SPDX/copyright headers on Northwind-owned source;
`docs/IP-OWNERSHIP.md`, `docs/THIRD_PARTY_LICENSES.md`, this report; rewritten `README.md`; expanded `SECURITY.md` and `CONTRIBUTING.md`; `.github/CODEOWNERS` (inactive
until an owner is set); hardened `.gitignore`; `package.json` `license` set to `BUSL-1.1`; changelog entry. Baseline results are unchanged (119/119, 0 skips).

## 3. License

- Official Business Source License 1.1 text taken verbatim from `mariadb.com/bsl11` on 2026-09-24 (paragraph breaks that the web page had collapsed were restored; no words were changed). The page
  does not show the Parameters block, so it is populated in the customary form.
- Licensor: Northwind Cipher Pvt. Ltd. Licensed Work: CooL (cool-nwc). Additional Use Grant: production use permitted below USD 1,000,000 ARR (you and affiliates together); at or above, a
  separate commercial license. Non-production use as the Terms provide. Change Date: January 1, 2030. Change License: Apache License, Version 2.0.
- **Change License compatibility check.** BSL 1.1 Covenant 1 requires the Change License to be "the GPL Version 2.0 or any later version, or a license that is compatible with GPL Version 2.0 or a later
  version", where compatible means software under the Change License can be included in a program with software under GPL 2.0 or a later version. Apache-2.0 is not compatible with GPLv2-only, but Apache-2.0 software
  can be included in GPLv3 programs, and GPLv3 is a later version of the GPL. On that reading Apache-2.0 satisfies the covenant, and the requested Change License was implemented exactly. Because the wording
  turns on that "later version" reading, **have counsel confirm it** before relying on it.
- BSL 1.1 is not an open source license, and no document in this repository describes it as one.

## 4. Copyright ownership

Documented in `docs/IP-OWNERSHIP.md`. Northwind Cipher is named as copyright holder on original code, **but the repository cannot prove that every contributor's work is owned by Northwind Cipher Pvt. Ltd.**, and it
cannot prove that the upstream `cool-sdk` project (source of eight vendored files) is controlled by Northwind. Those files were treated as third-party Apache-2.0 code.

## 5. Third-party inventory

`docs/THIRD_PARTY_LICENSES.md`: 37 lockfile entries (5 runtime, 32 development), all MIT or Apache-2.0; vendored files; optional tools and services listed.

## 6. Secret scan

Pattern-based scan (no dedicated scanner was installed) of the working tree and every revision of every branch (`git grep` over all commits): API-key, token, cloud-key, private-key-block, bearer, generic secret-assignment and
Phala-style patterns, plus tracked sensitive file names across all history. **Result: no matches, no tracked `.env`/key/certificate-with-private-key files, no untracked sensitive files.** The archived Phala API response contains
public Intel certificates only. Limits: pattern scanning can miss unusual formats; run a dedicated scanner (for example gitleaks) in CI. Nothing needs rotation on the basis of this scan.

## 7. Dependency license result

All dependencies MIT or Apache-2.0; no copyleft, unknown, or missing license. No dependency versions changed.

## 8. Source header result

Applied to 80 Northwind-owned source files (TypeScript, JavaScript and `.mjs`). Not applied to: the 8 vendored files, `phala-validation/server.mjs` and `witness.mjs` (baked into the recorded hardware-evidence images and kept byte-identical), `dist/`,
`node_modules/`, lockfiles, HTML, JSON and fixtures. Shebang preserved (`src/cli/index.ts`). No duplicate headers. **Every stamped file differs from HEAD only by the inserted header comment** (checked by stripping the header and comparing with HEAD: 80 of 80).

## 9. Git history result

No history rewritten, no force push, no amended or squashed commits, authorship unchanged. One new commit on top of `fd1f3c62`. The remote branch `chore/dependabot-ignore-noble-minor` (not in `main`) still holds a commit by another contributor that carries an attribution trailer worth reviewing; it was not touched.

## 10. GitHub visibility result

The repository is **public** (determined from the unauthenticated GitHub API). Visibility was not changed. Branch protection, rulesets, collaborators, deploy keys, GitHub Apps and Actions secrets could not be inspected because no authenticated GitHub CLI or token is available in this environment. Because the repository is already public and previously Apache-2.0, existing copies and forks made under Apache-2.0 cannot be recalled, and viewing or forking a public repository is not prevented by any license. If you want to approach enterprise partners
without publishing the implementation, consider moving the repository to private before the publication strategy is settled; that is a deliberate decision left to you.

## 11. Files changed

License and notices (`LICENSE`, `LICENSES/Apache-2.0.txt`, `NOTICE.txt`); documentation (`README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `docs/IP-OWNERSHIP.md`, `docs/THIRD_PARTY_LICENSES.md`, `docs/IP-PROTECTION-REPORT.md`);
configuration (`.gitignore`, `.github/CODEOWNERS`, `package.json`); comment-only headers in 80 source files; regenerated `artifacts/evidence-manifest.json` (its entries for source files whose hashes changed because of the headers). Existing evidence files are untouched.

## 12-15. Tests, typecheck, build

Before: 119 total, 119 pass, 0 fail, 0 skip; typecheck PASS; build PASS. After: identical (119/119, 0 skip); `npm run verify:package` (pack, install into a clean project, run) PASS.

## 16. Security status

No secrets found; no private keys; hardware-truthful runtime status and fail-closed policies unchanged; no source behaviour changed.

## 17. Remaining legal and operational actions (for the maintainers)

1. Confirm with counsel that Apache-2.0 satisfies the BSL 1.1 Change License covenant as read above, and review the Additional Use Grant wording (ARR definition, affiliates, currency).
2. Confirm that Northwind Cipher Pvt. Ltd. owns, or has sufficient license to, all contributions (contributor and employment/assignment arrangements) and the upstream `cool-sdk` code, before relying on the relicensing. Obtain written assignments or a CLA if needed.
3. Publish the BSL-licensed work under a **new version number**; `cool-nwc@3.0.0` already exists under Apache-2.0.
4. Decide repository visibility deliberately (section 10) and review branch protection and rulesets in GitHub settings.
5. Enable GitHub private vulnerability reporting or add a monitored security contact; then set a real owner in `.github/CODEOWNERS`.
6. Consider trademark registration for the names and logo; none is recorded here.
7. Add a dedicated secret scanner (for example gitleaks) and a license checker to CI.
