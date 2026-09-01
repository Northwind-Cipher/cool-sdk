# Getting started

## Install

```sh
npm install cool-nwc
```

Node **≥ 20**, ESM. TypeScript types are included. No native build, no postinstall
script, no network access at install time.

## Record a piece of evidence

```ts
import { CooL, verifyEvidence } from "cool-nwc";

const cool = new CooL({ applicationId: "my-app" });

const { evidence, recordId, digest } = await cool.record({
  type: "model.execution",
  metadata: { model: "my-model", version: "1.0.0" },
});

const verdict = await verifyEvidence(evidence);
console.log(verdict.ok); // true
```

`new CooL()` does no I/O. The first `record()` connects the evidence plane. With
no `attestation.provider`, that plane is the built-in **simulator**: identical
code path, every receipt labelled `simulated`.

## Commit to sensitive data without storing it

```ts
await cool.record({
  type: "model.execution",
  metadata: { route: "/score" },
  payloads: {
    input: JSON.stringify(request.body),   // hashed with a random salt, then discarded
    output: JSON.stringify(response),
    state: undefined,
  },
});
```

The receipt carries `mh:sha256(salt ‖ bytes)` and the salt — never the bytes. An
auditor you later choose to show the plaintext to can check it against the
commitment (`cool disclose`, or `disclose()` from `cool-nwc/phala`).

## Verify — anywhere, offline

```ts
import { verifyEvidence, formatVerdict } from "cool-nwc";

const verdict = await verifyEvidence(JSON.parse(fileContents));
console.log(formatVerdict(verdict));
```

or from the CLI:

```sh
npx cool-nwc verify evidence.json   # exit 0 = verified, non-zero = failed
```

## Shut down cleanly

```ts
process.on("SIGTERM", async () => {
  await cool.flush();   // drain queued async events
  await cool.close();
});
```

## Next

- [configuration and the `CooL` options](../README.md#api)
- [the evidence record, field by field](evidence-format.md)
- [what the verifier checks](verification.md)
- [running inside Phala dstack](dstack.md)
- [troubleshooting](troubleshooting.md)
