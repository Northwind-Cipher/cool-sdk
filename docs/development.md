# Development

```sh
git clone https://github.com/Northwind-Cipher/cool-sdk
cd cool-sdk
npm install
npm run verify:all
```

Node ≥ 20. No build step for development — tests run TypeScript through `tsx`.

## Layout

```
src/                 the SDK
  client.ts          the CooL facade  (the public API)
  verify.ts          verifyEvidence + formatVerdict
  errors.ts          typed errors
  index.ts           the "." entry;  tee.ts = kitchen sink
  canonical|hash|multihash|sign|keys|merkle|log-memory|record|codec|types.ts   primitives
  phala/             the advanced tier: engine, client (CoolTee), dstack, ratls,
                     quote, kms, structure, verify, anchor, witness, policy,
                     compliance, disclose, pack, query, gpu, types
  cli/               the `cool` command
scripts/             build.mjs, demo.ts, verify-package.mjs
tests/               node --test suites
examples/            runnable consumer projects
docs/                this
```

## Commands

| Command | Purpose |
|---|---|
| `npm test` | full suite (`node --test` + `tsx`) |
| `npm run typecheck` | `tsc --noEmit`, strict, `noUnusedLocals` |
| `npm run build` | `src/` → `dist/`, then patch ESM specifiers and copy `cli/ui/app.html` |
| `npm run demo` | valid → tamper → fail walkthrough |
| `npm run verify:package` | pack, install into a clean temp project, run, typecheck under `nodenext` + `bundler` |
| `npm run verify:all` | typecheck + tests |

## Testing conventions

- Every behavioural change gets a test that fails before and passes after.
- Adversarial tests assert the property, then attack it (`tests/evidence.test.ts`,
  `tests/verifier.test.ts`).
- One skipped test (`anchor.test.ts` → "public calendars accept a real head")
  is an opt-in network test; it is skipped offline by design.
- CLI tests spawn the `cool` binary in a temp directory — a CLI's contract is a
  process, an exit code, and bytes on stdout.

## Changing the evidence schema

The bytes that get hashed (`canonicalCbor(core)`) and signed
(`core ‖ binding_digest`) are frozen. To change them:

1. bump `record.schema` (`cool.evidence.vN`);
2. update `src/phala/structure.ts` (the structural validator);
3. teach `src/phala/verify.ts` the new `subject.kind` / fields;
4. add vectors and a migration note.

Never reinterpret a newer schema as an older one.

## Release

Maintainers: [`release.md`](release.md).
