# AWS Nitro Enclaves

`cool-nwc/nitro` is the AWS Nitro Enclaves path. It covers:
- offline attestation verification
- the in-enclave receipt sealer
- enclave↔host framing
- the log server with epochs and gap detection
- an attestation result normalized with the TDX path

The trust model is in [trust-models.md](trust-models.md#aws-nitro-enclaves).

## Status

| Piece | Status |
|---|---|
| Offline attestation verifier (COSE_Sign1, chain to the pinned AWS root, PCR policy, key binding, freshness) | **implemented, tested.** Real AWS document plus a synthetic PKI |
| In-enclave sealer (`NitroReceiptSealer`): fresh key, attestation binding, `[epoch].[sequence]` receipts as `cool.envelope.v1` | **implemented, tested** against a synthetic NSM |
| NSM access (`NsmSource`, `CommandNsmSource` → helper binary) | **interface implemented; helper absent.** A helper that talks to `/dev/nsm` inside the enclave must be supplied |
| Enclave↔host framing and forward-only host proxy (`encodeFrame`, `FrameDecoder`, `forwardFrames`) | **implemented, tested** over in-memory streams. **Not run over a real vsock** |
| Log server (`NitroLogServer`): registration on attestation, receipt verification, epochs, gaps, signed acks, RFC 6962 log, witnessed checkpoints | **implemented, tested** (in memory) |
| Nitro evidence verified by the shared envelope verifier (`attestation_valid`) | **implemented, tested** |
| Normalized attestation result shared with TDX (`normalizeNitro`, `normalizeTdx`) | **implemented, tested** |
| Public anchoring of Nitro checkpoints | **not wired.** OpenTimestamps exists for the TDX path (`src/phala/anchor.ts`) and needs network access |
| Live run on a real Nitro instance | **not done.** Needs AWS Nitro-enabled EC2 |
| Live run in a Caution-deployed enclave | **out of scope** (Caution work paused); see ADR 0003 |

Do not describe CooL as "running on AWS Nitro" or "AWS Nitro via Caution". Nothing here has run inside a real enclave. Every end-to-end test uses the synthetic test PKI and is labelled as such.

## Verify a document

```ts
import { readFileSync } from "node:fs";
import { verifyNitroAttestation, memoryNonceLedger } from "cool-nwc/nitro";

const report = verifyNitroAttestation(readFileSync("attestation.cbor"), {
  // PCR0–2 are mandatory; PCR8 must be stated explicitly.
  policy: {
    id: "my-enclave",
    version: "2026.10.1",
    source: "reproducible build of v2026.10.1",
    pcrs: { 0: "…", 1: "…", 2: "…" },
    pcr8: "not_applicable",
  },
  // The receipt key the enclave must have bound in user_data.
  receiptKey: { keyId, entry: receipt.key_directory[keyId] },
  // Nonce mode for live checks; timestamp-window mode for archived evidence.
  freshness: { mode: "nonce", expected: challenge, ledger: memoryNonceLedger() },
});

report.overall_status;            // "pass" | "fail" | "unknown"
report.checks.pcr_policy;         // { status, reason, detail, limitation? }
report.reasons;                   // ["freshness: nonce_replayed", …]
```

`overall_status` is `pass` only when every required check passes. A missing policy, receipt key or freshness rule gives `unknown`, never `pass`. The verifier never throws on hostile input: malformed bytes produce a report with `structure: fail`.

**Archived evidence.** Nitro leaf certificates live about three hours. To judge a stored document, pass `certificateTime: "attestation-timestamp"` with a `timestamp-window` freshness rule. The report then states that validity was judged at the document's own time, which is weaker than a live check.

## Reason codes

| Check | Reason codes |
|---|---|
| `structure` | `well_formed`, `oversized_or_empty`, `malformed_cbor`, `unexpected_tag`, `not_cose_sign1`, `unexpected_header`, `unsupported_algorithm`, `invalid_signature_encoding`, `invalid_payload`, `unexpected_field`, `invalid_field` |
| `trust_root` | `root_pinned`, `untrusted_root`, `trust_bundle_stale` |
| `certificate_chain` | `chain_valid`, `invalid_certificate_encoding`, `certificate_not_yet_valid`, `certificate_expired`, `ca_flag_missing`, `chain_issuer_mismatch`, `chain_signature_invalid`, `leaf_is_ca` |
| `cose_signature` | `signature_valid`, `signature_invalid`, `unsupported_algorithm`, `invalid_certificate_key` |
| `debug_mode` | `not_debug`, `debug_enclave` |
| `pcr_policy` | `pcrs_match`, `pcr_mismatch`, `pcr_missing`, `policy_incomplete`, `no_policy` |
| `pcr8_signing` | `pcr8_match`, `pcr8_mismatch`, `pcr_missing`, `image_not_signed` |
| `key_binding` | `key_bound`, `key_binding_mismatch`, `user_data_absent`, `no_receipt_key` |
| `public_key` | `public_key_match`, `public_key_mismatch`, `public_key_absent`, `public_key_unused` |
| `freshness` | `nonce_fresh`, `nonce_absent`, `nonce_mismatch`, `nonce_replayed`, `within_window`, `attestation_stale`, `timestamp_in_future`, `freshness_policy_absent` |
| every claim check before the signature is trusted | `claims_unverified` |

## Epochs and gaps

```ts
import { EpochLog } from "cool-nwc/nitro";

const log = new EpochLog(logKeypair);
const { registration } = log.register(report, keyId, "refund-agent"); // refuses unless report passed
log.ingest({ receipt_id, key_id: keyId, epoch: registration.epoch, sequence: 0, digest });
log.gaps();   // every gap ever seen: "unresolved" or "filled_late"
log.events(); // registrations, epoch transitions, gaps, conflicts
```

The log assigns the epoch; a caller cannot choose one. A gap means evidence is **missing**. It does not show malice, because the log cannot tell suppression from a crash. A dropped *final* receipt is invisible until a later sequence arrives. A late arrival marks the gap `filled_late` rather than erasing it.

## Data and network

The verifier makes **no network calls** and reads only the bytes and options it is given. The log keeps state in memory; persisting it is the caller's job. Reports contain the document's PCRs, `user_data`, nonce and `public_key` in hex. These are public by construction, but review them before sharing if your protocol puts anything sensitive there.

## Tests

`tests/nitro-attestation.test.ts` and `tests/nitro-epochs.test.ts`, 30 tests. Fixture provenance is in `tests/fixtures/nitro/PROVENANCE.md`. They include a deterministic 300-case corruption test against both a real AWS document and a passing synthetic one. That test found one real bug: OpenSSL throwing on a corrupted certificate key. It stays in as the regression test.
