# Architecture

```
Application
    │  new CooL({...}).record({ type, metadata, payloads })
    ▼
CooL (src/client.ts)            facade: lazy connect, config validation, typed errors
    │
    ▼
CoolTee (src/phala/client.ts)   wiring: attest → open queue → seal; nothing reaches
    │                           the caller's request path
    ├── CaptureQueue            bounded, fail-open, out-of-band. drop = counted, never silent
    ├── AttestedChannel         RA-TLS handshake against the evidence plane's quote
    ▼
EvidencePlane (src/phala/engine.ts)   runs INSIDE the enclave in production
    │  for each event:
    │   1. commit  — salted sha256 of metadata and payloads; plaintext discarded
    │   2. bind    — mh(canonicalCBOR(core))   (core includes measurement + quote digest)
    │   3. sign    — hybrid ML-DSA-65 + Ed25519 with the measurement-sealed key
    │   4. log     — append the binding digest to the RFC 6962 tree; take an STH + proof
    ▼
Receipt (cool.receipt.v2)  →  Verifier (src/phala/verify.ts)   offline, 7 domains
```

## Layers

| Layer | Files | Responsibility |
|---|---|---|
| Client facade | `src/client.ts`, `src/errors.ts` | small public API, config validation, environment detection, error typing |
| Verifier | `src/verify.ts`, `src/phala/verify.ts`, `src/phala/structure.ts` | offline verdict; structural validation; the human formatter |
| Evidence engine | `src/phala/engine.ts`, `src/phala/record.ts` | commit → bind → sign → log |
| Cryptography | `src/canonical.ts`, `src/hash.ts`, `src/multihash.ts`, `src/sign.ts`, `src/keys.ts`, `src/merkle.ts`, `src/log-memory.ts`, `src/record.ts` | CDE-CBOR, SHA-256, hybrid signatures, RFC 6962 |
| Attestation | `src/phala/dstack.ts`, `src/phala/ratls.ts`, `src/phala/quote.ts`, `src/phala/kms.ts` | dstack guest-agent client (HTTP + simulated), RA-TLS, TDX quote structure + binding, measurement-sealed keys |
| Transparency | `src/phala/log.ts`, `src/phala/log-file.ts`, `src/phala/witness.ts`, `src/phala/anchor.ts` | in-memory / file-backed logs, witness co-signatures, OpenTimestamps anchoring |
| Governance | `src/phala/policy.ts`, `src/phala/compliance.ts`, `src/phala/disclose.ts`, `src/phala/pack.ts`, `src/phala/query.ts` | policy engine, obligation mapping, selective disclosure, audit packs |
| CLI | `src/cli/*` | `cool` — verify, doctor, walkthrough, seal, records, pack, disclose |

## Trust boundaries

```
        untrusted                    trusted (in production)                 untrusted
  ┌──────────────────┐   RA-TLS   ┌──────────────────────────┐          ┌──────────────┐
  │  application code │──────────▶│  EvidencePlane in a TEE   │─receipt─▶│  the reader  │
  │  (CooL client)    │  quote    │  measurement-sealed key   │  (JSON)  │  verifies it │
  └──────────────────┘  checked   └──────────────────────────┘          └──────────────┘
```

- The **client** is untrusted: it hands plaintext across an attested channel and
  never sees the signing key.
- The **plane** is trusted only as far as its attestation goes — the reader
  re-checks the quote, the measurement, and the key binding.
- The **reader** trusts nothing: every domain is recomputed from the bytes.

## Deployment shapes

| Shape | `attestation.provider` | What's real |
|---|---|---|
| local dev / CI | `local` (default) | signatures, log, canonicalization. Attestation is `simulated`. |
| dstack simulator | `dstack` + `COOL_DSTACK_ENDPOINT` | quote *structure* and key binding, under a CooL-held root. Still `simulated`. |
| dstack on Intel TDX (self-hosted or Phala Cloud) | `dstack` + `/var/run/dstack.sock` | hardware quote, measurement-sealed key. `hardware` once a quote verifier confirms the vendor root. |
