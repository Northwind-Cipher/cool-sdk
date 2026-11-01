# Event taxonomy

CooL has **50 typed, versioned event families** (`<event_type>.v1`, defined in `src/platform/payloads.ts`). Validation is strict: unknown fields, wrong types and missing required fields are rejected. Untyped JSON never becomes security-critical evidence.

## Five kinds of time

Every envelope separates five kinds of time:

| Time | Field | Who asserts it |
|---|---|---|
| event time | `occurred_at` | the source |
| observed time | `observed_at` | the collector |
| signed time | inside the signed objects (`decided_at`, `confirmed_at`, `issued_at`) | the signer |
| ingestion / checkpoint time | the STH `timestamp` in `checkpoint` | the log operator |
| trusted time | an OpenTimestamps anchor (RFC 3161 is not implemented) | an external anchor |

**Causality comes from references, not timestamps.** `provenance.refs` and `relations` hold digests of earlier envelopes, for example decision → request and confirmation → decision. Timestamps alone are never treated as causal order.

## Privacy classes

| Class | Meaning |
|---|---|
| **P0** | identifiers and digests only |
| **P1** | business metadata that may be sensitive, such as resource names and amounts as commitments. Review it before sharing |
| **P2** | must never appear. Secret-like field names are rejected unless they carry a digest |

## Families added for authorization (4.x)

| Family | Required fields (abridged) | Signer purpose | Privacy | Completeness note |
|---|---|---|---|---|
| `principal.enrolled` | principal_id, kind, issuer, basis, record_digest | evidence (recorder); the record itself is issuer-signed | P0 | one per principal |
| `principal.key_rotated` | principal_id, key_id, event_digest | evidence | P0 | — |
| `principal.status_changed` | principal_id, status, event_digest | evidence | P0 | revocations must be recorded to be visible offline |
| `delegation.granted` / `.revoked` | delegation_id, delegator, delegate, audience, expires_at | evidence | P1 (scope in the signed object) | revocation lists are inputs to verification |
| `authorization.requested` | request_id, request_digest, principal, action, resource, audience, params_commitment | evidence | P1 | params are a commitment only |
| `authorization.decided` | decision_id, decision, request_digest, policy_digest, evaluator, assurance | evidence; the decision itself is evaluator-signed | P0 | — |
| `policy.updated` | policy_id, version, policy_digest, previous_digest | evidence | P0 | — |
| `execution.started` | workload_id, artifact_digest, config_digest, platform | evidence | P0 | — |
| `tool.invoked` | tool, request_id | evidence; usually sequenced | P0 | sequence gaps → `incomplete` |
| `external.confirmed` | confirmation_id, target, request_id, outcome, reason, confirmation_digest | evidence; the confirmation itself is gateway-signed | P0 | absent → the action is unconfirmed |
| `attestation.recorded` | platform, document_digest, outcome | evidence | P0 | — |
| `receipt.published`, `checkpoint.signed`, `witness.signed` | digests, log id, tree size | evidence | P0 | — |
| `incident.annotated` | incident_id, annotation_digest, analyst | evidence | P1 | **an annotation, never a verified fact** |
| `legacy.receipt` | legacy_schema, record_id, receipt_digest | evidence | P0 | wraps a `cool.receipt.v2` unchanged |

The earlier families keep their definitions in the payload registry: supply chain, identity, change control, runtime, incidents and AI inference.

Every family has schema validation, invalid-case tests (`platform-envelope.test.ts`) and documentation here.
