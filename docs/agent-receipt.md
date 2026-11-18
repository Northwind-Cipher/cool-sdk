# The Agent Execution Receipt (`cool.agent-receipt.v1`)

One receipt records one action by an AI agent: a tool call, a file edit, a deployment. It answers: what was done, to what, by whom (as declared), on whose request (as declared), under which authority and policy (as declared), with what outcome, and when. It is signed and numbered.

- **Schema:** [`spec/schemas/cool.agent-receipt.v1.schema.json`](../spec/schemas/cool.agent-receipt.v1.schema.json)
- **Example:** [`examples/agent-receipt/receipt.json`](../examples/agent-receipt/receipt.json), its signed envelope [`envelope.json`](../examples/agent-receipt/envelope.json), and a sealed bundle you can verify ([`bundle/`](../examples/agent-receipt/bundle), fingerprint in [`FINGERPRINT.txt`](../examples/agent-receipt/FINGERPRINT.txt))
- **Producer:** [`@northwindcipher/mcp-server-cool`](mcp.md)

## Two forms, one source of truth

| Form | What it is | Signed? |
|---|---|---|
| **Envelope** | A `cool.envelope.v1` of event type `agent.execution` (payload schema `agent.execution.v1`). One per line in `.cool/mcp/receipts.jsonl` | Yes. Canonical CBOR, hybrid ML-DSA-65 + Ed25519 |
| **Receipt** | The readable `cool.agent-receipt.v1` view derived from the envelope. It carries `evidence.envelope_digest` so the two can be matched | No. Always check the envelope |

Verifiers check envelopes. The receipt view exists so people, SIEMs and auditors can read the record without parsing CBOR.

## Fields

| Field | Meaning | Source |
|---|---|---|
| `schema_version` | `cool.agent-receipt.v1` | fixed |
| `event_id` | ULID, unique per receipt | generated |
| `timestamp` | When the action was recorded, UTC | recording machine's clock |
| `time_source` | How far the timestamp can be trusted | fixed text |
| `agent_id` | The agent, e.g. `agent:claude-code` | **declared** |
| `initiator_id` | The person or system that asked, or the literal `unknown` | **declared** |
| `authority_ref` | The approval, ticket or grant relied on, or `null` | **declared** |
| `policy_version` | The policy said to be in force, or `null` | **declared**; CooL does not prove enforcement |
| `tool_name` | What was done | recorder |
| `target_resource` | What it was done to, or `null` | recorder |
| `correlation_id` | Links related receipts (session, request) | recorder |
| `sequence_number` | `<epoch>.<n>`, contiguous per workspace | recorder |
| `outcome` | `success`, `failure`, `denied`, `error`, `unknown` | recorder |
| `capture` | `mcp_tool`, `mcp_proxy`, `hook`, `sdk`, `cli` | recorder |
| `payload.input_digest` / `output_digest` | HMAC-SHA-256 digests, or `null` | computed |
| `payload.digest_scheme` | `hmac-sha-256` | fixed |
| `payload.raw_payload_stored` | always `false` | fixed |
| `signer.key_id` / `algorithm` / `fingerprint` | Which key signed, how, and the workspace fingerprint to pin | workspace keys |
| `evidence.envelope_digest` / `log` | The signed envelope's digest and where the log lives | computed |

**Declared** means: CooL proves the value has not changed since it was recorded. It does not prove the value was true. Every verification result says so.

## Privacy: digests, never payloads

Raw prompts, inputs, outputs and file contents are never written. Each is reduced to

```
input_digest  = "mh:sha256:" + hex( HMAC-SHA-256( commit_key, "cool.mcp.input.v1\0"  || canonical_json(input)  ) )
output_digest = "mh:sha256:" + hex( HMAC-SHA-256( commit_key, "cool.mcp.output.v1\0" || canonical_json(output) ) )
```

- `commit_key` is a random 32-byte key that stays in `.cool/mcp/keys.json` (git-ignored, mode 0600).
- Because the hash is keyed, someone holding a bundle cannot confirm a guess ("was the input `rm -rf /`?") by hashing it.
- The workspace owner can later prove a payload matched by disclosing the payload and the key to the person who needs it.
- **Canonical JSON** means object keys sorted by UTF-16 code units, no whitespace, and `JSON.stringify` for strings and numbers. `undefined` object members are dropped. Equal values give equal digests regardless of key order (tested).

The envelope itself is canonicalised with deterministic CBOR (`cool.envelope.v1`). That is the form that is signed.

## Numbering

Each workspace has one **epoch**, fixed when `.cool/` is created, and receipts are numbered 0, 1, 2 and so on within it. Numbers continue across restarts. A missing number is a **gap**: the verifier reports `sequence_gap`, and the result is INVALID. A gap can only be seen when a later receipt exists, so removing the final receipt needs an outside checkpoint to detect.

## Versioning rule

1. `cool.agent-receipt.v1` and `agent.execution.v1` are **frozen**. A field's meaning never changes within a version.
2. **Adding an optional field** to the payload produces `agent.execution.v2` and `cool.agent-receipt.v2`. v1 verifiers report v2 envelopes as `unsupported`, never as `verified`. The v1 schema sets `additionalProperties: false` to make this explicit.
3. **Removing or redefining a field, or changing the digest scheme or canonicalisation**, is a new major schema with a new name.
4. A verifier must keep accepting every older version it has ever accepted. Old receipts stay verifiable forever.
5. The npm package version (semver) is independent of the schema version. Release notes name the schema versions each release produces and accepts.
6. Every schema change ships with an updated JSON Schema, an updated example, and a golden test vector that must keep verifying.
