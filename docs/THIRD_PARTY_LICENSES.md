# Third-party licenses

Generated from `package-lock.json` and the installed packages on 2026-09-24. This file is an inventory, not legal advice. The code that Northwind Cipher owns is licensed
under the Business Source License 1.1 (see `LICENSE`); the components below keep their own licenses and copyright notices, and none of them is relicensed by this repository.

Result of the license audit: every package in the lockfile (37 entries: 5 runtime, 32 development) declares MIT or Apache-2.0. No copyleft (GPL/AGPL/LGPL/MPL), unknown or missing licenses were found. Both licenses are permissive and compatible with distributing CooL under the Business Source License 1.1.

Attribution: MIT and Apache-2.0 require the copyright notice and license text to accompany copies or substantial portions of the software. CooL does not copy
these packages into this repository (npm installs them). Container images or bundles that include `node_modules` must keep each package's license file.

## Runtime dependencies

| Package | Version | License | License/notice file in the package | Source |
|---|---|---|---|---|
| `@noble/curves` | 1.9.7 | MIT | LICENSE | npm: @noble/curves |
| `@noble/hashes` | 1.8.0 | MIT | LICENSE | npm: @noble/hashes |
| `@noble/post-quantum` | 0.4.1 | MIT | LICENSE | npm: @noble/post-quantum |
| `cbor2` | 1.12.0 | MIT | LICENSE.md | npm: cbor2 |
| `ulid` | 2.4.0 | MIT | LICENSE | npm: ulid |

## Development-only dependencies (not part of the published runtime)

| Package | Version | License | License/notice file in the package | Source |
|---|---|---|---|---|
| `@esbuild/aix-ppc64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/aix-ppc64 |
| `@esbuild/android-arm` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/android-arm |
| `@esbuild/android-arm64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/android-arm64 |
| `@esbuild/android-x64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/android-x64 |
| `@esbuild/darwin-arm64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/darwin-arm64 |
| `@esbuild/darwin-x64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/darwin-x64 |
| `@esbuild/freebsd-arm64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/freebsd-arm64 |
| `@esbuild/freebsd-x64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/freebsd-x64 |
| `@esbuild/linux-arm` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/linux-arm |
| `@esbuild/linux-arm64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/linux-arm64 |
| `@esbuild/linux-ia32` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/linux-ia32 |
| `@esbuild/linux-loong64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/linux-loong64 |
| `@esbuild/linux-mips64el` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/linux-mips64el |
| `@esbuild/linux-ppc64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/linux-ppc64 |
| `@esbuild/linux-riscv64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/linux-riscv64 |
| `@esbuild/linux-s390x` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/linux-s390x |
| `@esbuild/linux-x64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/linux-x64 |
| `@esbuild/netbsd-arm64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/netbsd-arm64 |
| `@esbuild/netbsd-x64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/netbsd-x64 |
| `@esbuild/openbsd-arm64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/openbsd-arm64 |
| `@esbuild/openbsd-x64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/openbsd-x64 |
| `@esbuild/openharmony-arm64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/openharmony-arm64 |
| `@esbuild/sunos-x64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/sunos-x64 |
| `@esbuild/win32-arm64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/win32-arm64 |
| `@esbuild/win32-ia32` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/win32-ia32 |
| `@esbuild/win32-x64` | 0.28.2 | MIT | (not present in the installed copy) | npm: @esbuild/win32-x64 |
| `@types/node` | 26.4.1 | MIT | LICENSE | npm: @types/node |
| `esbuild` | 0.28.2 | MIT | LICENSE.md | npm: esbuild |
| `fsevents` | 2.3.3 | MIT | (not present in the installed copy) | npm: fsevents |
| `tsx` | 4.23.13 | MIT | LICENSE | npm: tsx |
| `typescript` | 5.9.3 | Apache-2.0 | LICENSE.txt | npm: typescript |
| `undici-types` | 8.3.0 | MIT | LICENSE | npm: undici-types |

## Vendored source (copied into this repository)

| Files | Origin | License | Handling |
|---|---|---|---|
| `src/canonical.ts`, `src/codec.ts`, `src/hash.ts`, `src/keys.ts`, `src/log-memory.ts`, `src/merkle.ts`, `src/multihash.ts`, `src/sign.ts` | `cool-sdk` (github.com/KenidoesCode/cool-sdk) | Apache-2.0 (per the header of `src/codec.ts`) | No Northwind header added; original license retained (`LICENSES/Apache-2.0.txt`). `src/codec.ts` documents its one modification. See docs/IP-OWNERSHIP.md. |

## Tools and services referenced but not vendored or declared

| Item | License / terms | Use |
|---|---|---|
| `@phala/dcap-qvl` | Apache-2.0 | Optional; installed with `npm i --no-save` for the local DCAP check in `phala-validation/`. Not a declared dependency |
| Docker base image `node:22-slim` | Node.js (MIT) and Debian packages under their own licenses | Base of the validation images |
| Phala Cloud attestation API, OpenTimestamps calendars | Third-party services under their own terms | Online verification and anchoring; responses archived under `artifacts/` are third-party data |
| Business Source License 1.1 text | (c) 2024 MariaDB plc; "Business Source License" is a trademark of MariaDB plc | Used as the license text permits |
