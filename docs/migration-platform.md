# Migrating to the platform envelope

**There is no breaking change.** `cool.evidence.v1`, `cool.change.v2` and `cool.receipt.v2` are untouched, and `CooL`, `CoolTee` and `cool verify` behave exactly as before. Every pre-existing test (the 119 on `main`, plus the 30 Nitro verifier tests) passes unmodified alongside the new ones. The platform lives under a new subpath, `cool-nwc/platform`, with its own record type, `cool.envelope.v1`.

## Why a new envelope

The existing records are AI-shaped: a model, input, output and change kind. The platform needs one technology-neutral record for builds, deployments, credentials, configuration, runtime events and incidents. Domain fields move into a typed, versioned payload (`<event_type>.v<n>`). The cryptography is the same code:

| | `cool.receipt.v2` | `cool.envelope.v1` |
|---|---|---|
| Canonicalization | canonical CBOR (CDE) | same, and the exact bytes are carried in `core_cbor` |
| Digest | SHA-256 multihash | same, domain-separated (`cool.envelope.v1\0`) |
| Signature | ML-DSA-65 + Ed25519 | same, over a domain-separated digest |
| Transparency | RFC 6962 + STH | same `MemoryLog`; the leaf is the 32-byte digest |
| Verdict | `pass/fail/absent/mock/simulated/pending` | `pass/fail/unknown/not_applicable/not_checked`, with reason codes |
| Signer trust | key directory in the receipt | a separate `TrustStore` with purpose, validity and status |

## Mapping an AI inference record

```ts
// before
await cool.record({ type: "model.execution", metadata: { model, version }, payloads: { input, output } });

// after: the same facts as an ai.inference envelope
const salt = randomSalt();
cool.evidence.record({
  event_type: "ai.inference",
  occurred_at, source: { system: "my-app" }, actor: { id: "workload:my-app", type: "workload" },
  action: "infer", resource: { type: "model", ref: `${model}@${version}` },
  payload: {
    model, model_version: version,
    input_commitment: saltedCommit(salt, input),
    output_commitment: saltedCommit(randomSalt(), output),
  },
});
```

**Do not commit low-entropy values without a salt.** A bare hash of "yes" or a short prompt can be guessed. The `ai.inference` schema accepts only digests for input and output. The payload never carries plaintext.

## Verdict mapping

When you need one status across both record types, use `normalizeTdx()` / `normalizeNitro()` (`cool-nwc/nitro`) for attestation results. The rule is conservative: `absent`, `pending`, `simulated` and `mock` all become `unknown`, and none of them ever becomes `pass`.

## Semantics that changed meaning, so check them

- `signer_trusted` is new and separate. A receipt with a valid signature from a key you never pinned was `signature: pass` before. In a report it is now `signature_valid: pass` and `signer_trusted: fail`. Supply a `TrustStore`.
- A revoked key is now rejected unless a trusted checkpoint proves the signature predates the revocation.
- Documentation previously said a dstack redeploy rotates keys. It does not; see `docs/attestation.md#keys`.
