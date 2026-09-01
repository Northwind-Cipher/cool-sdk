# Migration — inference capture → `record()`

`cool-nwc` 3.0 removes the AI-inference capture surface. If you used
`Cool.complete()`, `CoolTee.complete()` / `completeSealed()`, a `backend` option,
`PhalaPrivateLLM`, or the v1 `cool.receipt.v1` client, this is the map.

## Why

The SDK now records **generic execution evidence**: an event type plus a salted
commitment to your metadata, with optional commitments to input/output/state. It
never takes a raw prompt or wraps a model call. Everything the old inference path
committed, `record()` still commits — you just say what the event was.

## API changes

| Removed | Replacement |
|---|---|
| `new Cool({ signing, backend })` + `cool.complete({ model, prompt })` (v1) | `new CooL({ applicationId })` + `cool.record({ type, metadata, payloads })` |
| `CoolTee.connect({ backend })` | drop `backend` — you call your model yourself |
| `cool.complete({ model, prompt })` | `cool.recordAsync({ type, metadata, payloads })` (fire-and-forget) |
| `cool.completeSealed({ model, prompt })` → `{ output, receipt }` | `await cool.record({ type, metadata, payloads })` → `{ evidence, recordId, ... }` |
| `PhalaPrivateLLM` / `ConfidentialCompletion` | call the model with your own HTTP client; pass `simulatedGpu(...)` / `gpuRefFromReport(...)` as `record({ gpu })` |
| `verifyReceipt` (v1, `cool.receipt.v1`) | `verifyEvidence` (`cool.receipt.v2`) |
| `import { ... } from "cool-nwc/v1"` | primitives are on the root: `import { canonicalCbor, hybridSign, ... } from "cool-nwc"` |

## Before

```ts
import { CoolTee } from "cool-nwc";

const cool = await CoolTee.connect({
  app: { name: "refund-agent", imageDigest: process.env.IMAGE_DIGEST! },
  backend: async ({ model, prompt, params }) => ({ output: await yourModel(model, prompt, params) }),
});

const { output, receipt } = await cool.completeSealed({
  model: "phala/deepseek-v4-pro@2026.07",
  prompt: "Assess application A-40182",
  params: { temperature: 0.2 },
});
```

## After

```ts
import { CooL } from "cool-nwc";

const cool = new CooL({ applicationId: "refund-agent" });

const prompt = "Assess application A-40182";
const output = await yourModel("phala/deepseek-v4-pro@2026.07", prompt, { temperature: 0.2 });

const { evidence } = await cool.record({
  type: "model.execution",
  metadata: { model: "phala/deepseek-v4-pro@2026.07", params: { temperature: 0.2 } },
  payloads: { input: prompt, output },
});
```

`await verifyReceipt(receipt)` → `await verifyEvidence(evidence)`. The verdict
shape is the same seven domains; `subject.kind` is now `"evidence"` (or
`"change"`), never `"inference"`.

## `change()` is unchanged

`cool.change({ kind, ref, before, after, actor, approval })` — recording a change
to an AI system itself — works exactly as before, on `CoolTee` (`cool-nwc/phala`).

## Old receipts

`cool.receipt.v1` receipts are not readable by the 3.0 verifier. Re-verify them
with `cool-nwc@2.5.x`, or re-seal the underlying events as `cool.evidence.v1`.
