# Verification

```ts
import { verifyEvidence, formatVerdict } from "cool-nwc";

const verdict = await verifyEvidence(evidence, options);
```

`verifyEvidence` never throws on bad input — a malformed or tampered receipt
comes back as a verdict with failed domains and `reasons`. No network is needed
for any domain except chaining a hardware quote to its vendor root
(`options.quoteVerifier`) or confirming a Bitcoin anchor (`options.blockHeaders`).

## The verdict

```ts
interface Verdict {
  ok: boolean;                     // never a bare boolean elsewhere
  schema: "cool.receipt.v2";
  subject: { kind: "evidence" | "change"; subject; issued_at; record_id; key_id; tee } | null;
  checks: {
    binding; signature; inclusion; witnesses; attestation; enclave; anchor;
  };                               // each: { status, detail }
  reasons: string[];
}
```

`status` is one of `pass | fail | absent | mock | simulated | pending`.

## The seven domains

| Domain | Passes when | Notes |
|---|---|---|
| `binding` | `mh(canonicalCBOR(core))` recomputes to `binding_hash` | pure maths |
| `signature` | **both** ML-DSA-65 and Ed25519 verify over `core ‖ binding_digest`, against `key_directory[key_id]` | pure maths |
| `inclusion` | the audit path reconstructs `sth.root_hash` and the STH signature verifies | `absent` if the receipt carries no log proof |
| `witnesses` | ≥ `witnessThreshold` **external** co-signatures verify | a CooL self-signature is shown, never counted; `absent` in this build |
| `attestation` | a real quote verifier chains the quote to a real vendor root | `simulated` for the CooL sim root; `absent` if a hardware quote is present but no verifier was supplied; `mock` if no quote |
| `enclave` | quote digest == `runtime.tee_quote`, measurements match, `report_data` == commitment to the signing key, and the pinned measurement (if any) matches | this is the domain that ties a quote to *this* record |
| `anchor` | the recomputed commitment equals a real Bitcoin block's merkle root | `pending` between submission and aggregation; `absent` if never anchored |

## `ok`

```
ok  =  binding == pass
   &&  signature == pass
   &&  inclusion ∈ { pass, absent }
   &&  enclave != fail
   &&  attestation != fail
   &&  (not options.requireHardware  ||  attestation == pass)
```

`witnesses` and `anchor` never make `ok` true on their own, and `simulated` /
`mock` / `pending` are never `pass`.

## Options

| Option | Effect |
|---|---|
| `expectedMeasurement` | pin the image you approved; any mismatch fails `enclave` |
| `requireHardware` | a receipt that is not backed by a verified hardware quote cannot be `ok` |
| `witnessThreshold` | minimum independent witness co-signatures for `witnesses` to pass |
| `quoteVerifier` | chains a hardware quote to Intel DCAP / AMD KDS / NVIDIA NRAS (`remoteQuoteVerifier` from `cool-nwc/phala`) |
| `blockHeaders` | a Bitcoin block-header source for confirming an anchor |

## Cryptographic validity vs. policy

The verdict answers "is this receipt authentic and internally consistent?". It
does **not** answer "do I accept this measurement / this signer / this vendor?".
A receipt can be cryptographically valid and still policy-rejected — pin a
measurement, require hardware, or check `subject.key_id` against your own
allow-list.

## CLI

```sh
cool verify evidence.json               # one file
cool verify all                         # every receipt in .cool/receipts
cool verify last --require-hardware     # fail unless a real quote backs it
```

Exit codes: `0` verified · `1` verification failed · `2` bad configuration ·
`3` environment unavailable · `4` usage error.
