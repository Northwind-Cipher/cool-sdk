# Troubleshooting

Run `npx cool-nwc doctor` first — it checks Node, web crypto, the dstack socket,
a quote verifier, and a seal→verify round trip.

---

### `npm install` fails compiling something

CooL has **no native code and no build step**. If a compiler runs, it's another
dependency in your tree. `cool-nwc` itself needs only Node ≥ 20 and pure-JS deps
(`@noble/*`, `cbor2`, `ulid`).

### `Cannot find module 'cool-nwc'` after install / ESM errors

`cool-nwc` is ESM-only. Your project needs `"type": "module"` (or `.mjs` files),
or a bundler configured for ESM. There is no CommonJS build; a `require("cool-nwc")`
will not work.

### Types don't resolve / `moduleResolution` errors

The package ships `.d.ts` and is tested under `moduleResolution: "nodenext"` and
`"bundler"`. If you're on `"node10"`/`"node"`, switch to `"bundler"` or
`"nodenext"`. `npm run verify:package` in this repo reproduces the consumer setup.

### `COOL_DSTACK_UNAVAILABLE`

```
CooL could not reach the dstack guest agent

  run the application inside a dstack CVM with /var/run/dstack.sock mounted,
  start the dstack simulator, or use attestation.provider: 'local'
```

You set `attestation.provider: "dstack"` (or `$COOL_DSTACK_ENDPOINT`) but nothing
is listening. For local work, drop the provider (defaults to `local`). For the
hardware path without a CVM, run the dstack simulator and set
`COOL_DSTACK_ENDPOINT`. See [dstack.md](dstack.md).

### `COOL_ATTESTATION_REQUIRED`

`security.requireAttestation` is set and the RA-TLS handshake did not produce a
verified hardware quote. Either deploy inside attested hardware, or remove
`requireAttestation` for development. CooL will not silently downgrade to the
simulator when you asked for hardware.

### `ConfigurationError: requireAttestation is set but provider is 'local'`

These two contradict. Use `provider: "dstack"` with `requireAttestation`, or
neither.

### Verification returns `ok: false` with `attestation`/`enclave` = `simulated`

Expected in local / simulator mode. To *require* hardware at verify time pass
`{ requireHardware: true }` — and understand it will fail until you run against
real dstack with a `quoteVerifier`.

### Verification fails: "recomputed binding_hash does not match"

The record was modified after signing (or serialised through something that
mutated numbers/strings). This is the tamper-detection working. If it happens on
an untouched receipt, check that whatever transported it preserved the JSON
exactly (no float re-formatting, no key re-casing).

### `cool verify` exits non-zero in CI but the receipt "looks fine"

That's the contract — any failed domain is a non-zero exit. Run
`cool verify <file>` locally to see the boxed report and the `reasons`.

### The transparency endpoint / anchor calendar is down

The SDK is fail-open: your app keeps producing signed, logged evidence. The
`anchor` domain stays `absent`/`pending`; nothing else is affected.

### Large metadata

Metadata is CBOR-encoded and hashed; very large objects cost CPU and memory on
the seal path. Commit a digest or a summary rather than a multi-megabyte blob.

### Browser / edge runtime

`cool-nwc` targets Node (it uses `node:*` for the filesystem log and unix-socket
transport via `cool-nwc/node`). The core client + verifier need only WebCrypto
and `btoa`/`atob`, but browser/edge use is **not** currently tested — don't rely
on it.
