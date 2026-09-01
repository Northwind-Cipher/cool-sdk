<div align="center">

<img src="assets/hero.svg" alt="CooL — Cryptographic Observability & On-chain Ledger" width="880">

# CooL

### Cryptographic Observability &amp; On-chain Ledger

**Tamper-evident, offline-verifiable evidence about what your software actually did — without storing what it did it to.**

[![CI](https://github.com/Northwind-Cipher/cool-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/Northwind-Cipher/cool-sdk/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/cool-nwc.svg)](https://www.npmjs.com/package/cool-nwc)
[![node](https://img.shields.io/node/v/cool-nwc.svg)](https://nodejs.org)
[![types](https://img.shields.io/badge/types-included-blue.svg)](#typescript)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

</div>

---

## What CooL is

CooL is a developer SDK for producing **independently verifiable evidence about execution**.
Your application calls `record()`; CooL returns a self-contained receipt that anyone can verify
later — offline, with no account and no trust in CooL — proving:

- **which software** ran (name, version, content digest),
- **which event** happened (a dotted type plus a salted commitment to your metadata),
- **that the record is unforged** — a hybrid post-quantum + classical signature over a
  deterministic commitment to its contents,
- **that it is in an append-only log** — an RFC 6962 inclusion proof under a signed tree head,
- and, when it runs inside a TEE, **where it ran** — the enclave measurement and a quote whose
  `report_data` commits to the very key that signed the record.

It does this **without recording your prompts, outputs, or private data**. Sensitive values are
committed as salted hashes and discarded; the receipt never carries plaintext.

```
OBSERVE → COMMIT → SIGN → ATTEST → ANCHOR → VERIFY
```

CooL records *what happened*. It does not grade it — nothing here proves an output was correct,
fair, or safe.

## Why

AI and regulated systems increasingly have to answer questions after the fact:

> What software executed? Which version? Which model? In what environment? Was the record
> modified? Was it produced inside a trusted environment? Can someone *else* verify it — without
> our logs, and without seeing our data?

A log line answers none of these, because a log can be edited and a screenshot proves nothing.
CooL is the cryptographic evidence layer that makes each of those a checkable statement.

## Install

```sh
npm install cool-nwc
```

Node **≥ 20**. ESM. TypeScript declarations included. No native build step, no postinstall
scripts, no network calls at install or at runtime.

## 30-second quickstart

```ts
import { CooL, verifyEvidence } from "cool-nwc";

const cool = new CooL({ applicationId: "my-app" });

const { evidence } = await cool.record({
  type: "model.execution",
  metadata: { model: "my-model", version: "1.0.0" },
  // optional — commit to sensitive data without storing it
  payloads: { input: "the request", output: "the response" },
});

const verdict = await verifyEvidence(evidence);
console.log(verdict.ok);            // true
console.log(verdict.checks.signature.status);  // "pass"
```

`new CooL()` does no I/O. The first `record()` connects the evidence plane: with no
`attestation.provider` it runs the **built-in simulator** — the same code path, clearly labelled
`simulated` in every receipt, never `pass` on a hardware-dependent domain.

## Tamper demo

```sh
npm run demo        # in a clone of this repo
```

```
3. verify the evidence — offline
    +----------------------------------------------------------+
    | OK  binding      valid                                   |
    | OK  signature    valid                                   |
    | OK  inclusion    valid                                   |
    | ~   attestation  simulated                               |
    | ~   enclave      simulated                               |
    +----------------------------------------------------------+
    | RESULT      VERIFIED                                     |

4. tamper with the evidence  (flip one hex digit of metadata_hash)

5. verify again
    +----------------------------------------------------------+
    | X   binding      FAILED                                  |
    | X   signature    FAILED                                  |
    +----------------------------------------------------------+
    | RESULT      FAILED                                       |
    Failures:
      - binding: recomputed binding_hash does not match the receipt
      - signature: ML-DSA-65 and Ed25519 did not verify
```

## Architecture

```
                        APPLICATION
                            |
                            v
                    +---------------+
                    |   CooL SDK    |   new CooL({...}).record({...})
                    +-------+-------+
                            |  evidence event (metadata + optional payloads)
                            v
                    +-------+--------+
                    | Evidence Plane |   runs inside the enclave in production
                    +---+--------+---+
                       /          \
              commit  /            \  attest
                     v              v
              +----------+     +-----------+
              |  CRYPTO  |     |  dstack   |
              | sha256   |     | TDX quote |
              | ML-DSA65 |     | sealed key|
              | Ed25519  |     +-----+-----+
              +----+-----+           |
                   |  sign            |
                   v                  v
              +--------------------------+
              |     EVIDENCE RECORD      |   cool.evidence.v1
              +------------+-------------+
                           |  append
                           v
                  +------------------+
                  |  TRANSPARENCY    |   RFC 6962 log, signed tree head
                  |  (+ optional     |
                  |   OTS anchor)    |
                  +--------+---------+
                           |
                           v
                  +------------------+
                  |    VERIFIER      |   offline · 7 domains · never a bare bool
                  +------------------+
```

## The evidence record

`cool.evidence.v1`, carried in a `cool.receipt.v2` envelope:

```jsonc
{
  "schema": "cool.receipt.v2",
  "record": {
    "schema": "cool.evidence.v1",
    "record_id": "01J…",                 // ULID
    "time": { "issued_at": "…Z", "seq": 0 },
    "event": {
      "type": "model.execution",
      "application_id": "my-app",
      "execution_id": "01J…",
      "metadata_hash": "mh:sha256:…",     // salted commitment to canonical(metadata)
      "metadata_salt": "hex:…",
      "commitments": {                    // optional salted commitments; plaintext discarded
        "input": "mh:sha256:…",  "input_salt": "hex:…",
        "output": "mh:sha256:…", "output_salt": "hex:…",
        "state": null, "state_salt": null
      },
      "software": { "name": "my-service", "version": "2.3.1", "digest": null }
    },
    "runtime": { "tee_vendor": "intel-tdx", "mode": "simulated", "enclave_measurement": {…}, "tee_quote": "mh:sha256:…", "gpu": null },
    "signature": { "alg": "ml-dsa-65+ed25519", "key_id": "…", "ml_dsa": "base64:…", "ed25519": "base64:…" }
  },
  "binding_hash": "mh:sha256:…",          // mh(canonicalCBOR(core))
  "inclusion": { "leaf_index": 0, "tree_size": 1, "audit_path": [] },
  "sth": {…},                             // RFC 6962 signed tree head
  "attestation": {…},                     // quote + pinned measurement + key binding
  "anchor": null,                         // optional OpenTimestamps proof
  "key_directory": { "…": { "ml_dsa_pub": "base64:…", "ed25519_pub": "base64:…" } }
}
```

Full field-by-field spec: [`docs/evidence-format.md`](docs/evidence-format.md).

## Cryptography

| Primitive | Role | Notes |
|---|---|---|
| SHA-256 | commitments, Merkle tree, quote/report-data digests | via `@noble/hashes` |
| Salted commitments | `mh:sha256(salt ‖ bytes)` for metadata and payloads | 16-byte CSPRNG salt, stored beside the commitment for later disclosure |
| Canonical CBOR (RFC 8949 CDE) | the exact bytes that get hashed and signed | deterministic across runs, machines, implementations |
| Ed25519 | classical signature | via `@noble/curves` |
| ML-DSA-65 (FIPS 204) | post-quantum signature | via `@noble/post-quantum` |
| Hybrid verify | **both** signatures must verify | resilient if either scheme is later broken |
| RFC 6962 Merkle | inclusion + consistency proofs | tampering with any logged entry changes the root |

CooL uses ML-DSA/Ed25519 **hybrid** signatures. That makes the *records* resistant to a future
break of one scheme; it does **not** make CooL a "quantum-safe system", and the docs never say so.

## Phala dstack

Without dstack, CooL runs its simulator: real signatures over a real quote *structure* under a
CooL-held root. Every such receipt is labelled `simulated`, and the verifier reports `simulated`
— never `pass` — on the two domains that depend on hardware.

With dstack, the evidence plane runs inside an Intel TDX confidential VM. dstack contributes:

- **attested workload identity** — an MRTD + RTMR measurement set inside the signed record,
- **a TEE quote** whose `report_data` commits to the record's signing key, so "an attested
  enclave holds this key" and "this key signed this record" are one chain,
- **a measurement-sealed signing key** — derived inside the enclave, never configured, rotates
  automatically when the image changes.

```ts
const cool = new CooL({
  applicationId: "refund-agent",
  attestation: { provider: "dstack", endpoint: "/var/run/dstack.sock", vendor: "intel-tdx" },
  security: { requireAttestation: true },   // refuse to run, and to verify, without a real quote
});
```

Local simulator, self-hosted TDX, and Phala Cloud paths: [`docs/dstack.md`](docs/dstack.md).
CooL uses the `@phala/dstack` guest-agent protocol (`Info` / `GetQuote` / `GetKey` over
`/var/run/dstack.sock`); it does not bundle the dstack SDK and it does not create a TEE itself.

## Security model

CooL is **fail-open toward your application, fail-closed toward verification.** If the
transparency service is down your app keeps running; a verifier never reports success on a
check it could not perform.

| Threat | CooL defense | Residual risk |
|---|---|---|
| Evidence modified after the fact | binding hash + hybrid signature over canonical CBOR | signing-key compromise |
| Replaying an old record | `execution_id` + `record_id` (ULID) + monotone `seq` + `issued_at` | policy-dependent freshness window |
| Substituting the signer | signature is bound to a `key_id` in the receipt's key directory | key-directory trust / key management |
| Claiming a run happened in a TEE | measurement + quote digest are inside the signed core | TEE hardware assumptions |
| Stapling a valid quote onto another record | quote `report_data` must commit to the signing key; quote digest must match `runtime.tee_quote` | — |
| Editing the transparency log | RFC 6962 inclusion + consistency proofs | root trust; no external witnesses in this build |
| Simulator passed off as hardware | `mode: "simulated"` in every receipt; verifier returns `simulated`, never `pass`; `requireAttestation` / `requireHardware` make it a hard failure | operator disables the policy |

CooL does **not** protect against: compromised application logic that produces valid evidence of
the wrong thing, TEE hardware vulnerabilities, incorrect trust roots, or a compromised
dependency. See [`docs/threat-model.md`](docs/threat-model.md).

## API

| Import | Contents |
|---|---|
| `cool-nwc` | `CooL`, `verifyEvidence`, `formatVerdict`, typed errors, crypto primitives |
| `cool-nwc/verify` | the standalone verifier only |
| `cool-nwc/phala` | the advanced tier: `CoolTee`, dstack clients, quote/anchor/witness/policy/disclosure |
| `cool-nwc/node` | filesystem-backed transparency log, unix-socket transport |
| `cool-nwc/tee` | everything, in one import |

### `new CooL(options?)`

| option | type | default |
|---|---|---|
| `applicationId` | `string` | `"cool-app"` |
| `attestation.provider` | `"local" \| "dstack"` | `"local"` (or `"dstack"` if `$COOL_DSTACK_ENDPOINT` is set) |
| `attestation.endpoint` | `string` | `$COOL_DSTACK_ENDPOINT`, then `/var/run/dstack.sock` |
| `security.requireAttestation` | `boolean` | `false` |
| `security.expectedMeasurement` | `Measurement` | — (pin the image you approved) |
| `logId`, `onEvidence`, `clock`, `newId`, `seq` | — | test / advanced hooks |

### `cool.record(input) → { evidence, recordId, executionId, digest }`

`input`: `{ type, executionId?, metadata?, payloads?, software?, gpu? }`. Metadata and every
`payloads` value are committed as salted hashes and discarded.

### `cool.verify(evidence, options?) → Verdict` &nbsp;·&nbsp; `verifyEvidence(evidence, options?)`

Returns a structured verdict — never a bare boolean:

```ts
{ ok: false,
  checks: { binding, signature, inclusion, witnesses, attestation, enclave, anchor },
  reasons: ["signature: ML-DSA-65 did not verify …"] }
```

Each domain fails independently. `options.requireHardware` / `options.expectedMeasurement`
turn simulator receipts and image mismatches into `ok: false`.

Also: `cool.ready()`, `cool.flush()`, `cool.close()`, and the getters `cool.attestation`
(RA-TLS transcript), `cool.keyDirectory`, `cool.environment`, `cool.evidence`.

Errors are typed (`CooLError` + `ConfigurationError`, `DstackUnavailableError`,
`AttestationRequiredError`, `EvidenceError`, …) each with a stable `code` and an `action`.

## The `cool` command

`npm install -g cool-nwc` puts `cool` on your PATH:

```sh
cool verify evidence.json     # offline; no enclave, no account
cool doctor                   # Node version, web crypto, dstack socket, round-trip
cool walkthrough              # learn the model by doing it, ~3 minutes
cool seal … · cool records … · cool pack build … · cool disclose …
```

`cool verify` exits non-zero on any failure — the code a CI job gates on.

## Examples

[`examples/`](examples): `basic`, `verification`, `express`, `agent`, `dstack`. Each is a
runnable project — `npm install && npm start`.

## Documentation

[`docs/`](docs): [getting-started](docs/getting-started.md) ·
[architecture](docs/architecture.md) · [evidence-format](docs/evidence-format.md) ·
[verification](docs/verification.md) · [attestation](docs/attestation.md) ·
[dstack](docs/dstack.md) · [security-model](docs/security-model.md) ·
[threat-model](docs/threat-model.md) · [troubleshooting](docs/troubleshooting.md) ·
[development](docs/development.md) · [migration](docs/migration.md)

## TypeScript

`strict`. Public APIs carry no `any`. `.d.ts` files ship in the package and are tested from an
external consumer project under both `moduleResolution: "nodenext"` and `"bundler"` on every CI
run (`npm run verify:package`).

## Roadmap

| Status | Item |
|---|---|
| shipped | evidence records, hybrid signatures, RFC 6962 log, offline verifier, dstack (HTTP + simulator), TDX quote structure + binding, OpenTimestamps anchor, `cool` CLI |
| experimental | remote quote verification against Intel DCAP collateral, Bitcoin anchor confirmation |
| planned | external transparency witnesses / gossip, NVIDIA confidential-GPU verification, additional TEE vendors, a hosted verifier service, a published JSON Schema for `cool.evidence.v1` |
| research | formal verification of the canonicalization + verifier core |

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md). Security-sensitive reports: [`SECURITY.md`](SECURITY.md).

## License

Apache-2.0 · Northwind Cipher Pvt. Ltd.
