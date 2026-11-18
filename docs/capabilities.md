# Capabilities and their labels

<!-- GENERATED from src/platform/capabilities.ts by `npm run docs:capabilities`. Do not edit by hand: tests/capabilities.test.ts fails if this file drifts. -->

| Label | Meaning |
|---|---|
| **implemented** | built, tested, and validated against genuine evidence or a real service |
| **experimental** | built and tested, not yet validated against the real thing (hardware, cloud) |
| **partial** | built with documented gaps |
| **planned** | designed, not built |
| **unsupported** | deliberately not supported; the verifier says so |

| Area | Capability | Label | Evidence | Limits / what moves it up |
|---|---|---|---|---|
| evidence | Evidence envelope, schemas, canonical CBOR, hybrid ML-DSA-65 + Ed25519 signatures | **implemented** | platform-envelope, evidence-v2, test vectors | a signature says who signed, not that the statement is true |
| evidence | Bundles with attachments, sequence-gap detection, six outcomes | **implemented** | evidence-v2, demo:agent G | a dropped final event is undetectable until a later one arrives |
| evidence | cool.receipt.v2 wrapped in the envelope unchanged | **implemented** | evidence-v2 | — |
| authorization | Principals, delegation, committed requests, signed decisions, replayable policy | **implemented** | authz, authz-schemas, demo:agent A–C | intent is not proven; only signatures are |
| authorization | ToolGateway enforcement with signed external confirmations | **implemented** | authz-gateway, demo:agent B/D/E | actions outside the gateway are not covered |
| replay | Replay protection on one host (memory, O_EXCL file store) | **implemented** | authz (25-way race), demo:agent D | one host only |
| replay | Replay protection across machines: RedisNonceStore (RESP over TCP/TLS, SET NX PX) | **implemented** | replay-shared (protocol, races, faults) + CI job `redis` against a real redis:7 server | Redis must be configured for durability you accept; a failover that loses writes can forget nonces within the TTL |
| replay | Replay protection on Postgres / DynamoDB (SharedNonceStore backends) | **experimental** | replay-shared (semantics with emulated backends) | not yet run against a live Postgres or DynamoDB |
| tee | AWS Nitro attestation verification | **implemented** | GENUINE AWS document + 600 corruption cases (nitro-attestation) | no revocation (AWS publishes no CRL) |
| tee | CooL sealer inside a Nitro Enclave on AWS hardware | **experimental** | deployment kit (examples/nitro-enclave), nitro-kit tests over real sockets with a synthetic NSM, CI builds the image and compiles the NSM helper | not yet run on AWS hardware: becomes implemented when artifacts/nitro-validation/ holds a passing, non-synthetic artifact |
| tee | Intel TDX via Phala dstack | **implemented** | hardware validation on Phala Cloud tdx.small (artifacts/closure-verification-matrix.md) | TCB recorded as Unknown; quote freshness not checked on this path |
| tee | Phala dstack KMS / runtime evidence | **partial** | real-tee-validation | keys follow app identity, not the image; the KMS's own attestation is not verified |
| tee | AMD SEV-SNP report verification (VCEK/VLEK → ASK/ASVK → pinned ARK, TCB and chip binding) | **implemented** | GENUINE Milan report + VCEK (snp), AMD roots fetched from KDS and pinned, 300-case fuzz | CRL only if you supply revoked serials; ID block not evaluated |
| tee | NVIDIA Confidential Computing: NRAS result verification, CPU binding | **experimental** | nvidia (real NRAS JWKS chains to pinned intermediates; tokens synthetic) | no result from a real CC GPU yet; raw SPDM evidence is appraised by NRAS, not here |
| keys | AWS KMS signer (ML_DSA_65 + ECC_NIST_EDWARDS25519) | **experimental** | signers (provider emulator enforcing AWS API rules) | becomes implemented with a passing `npm run validate:kms -- aws` artifact |
| keys | Google Cloud KMS signer (PQ_SIGN_ML_DSA_65 + EC_SIGN_ED25519) | **experimental** | signers (provider emulator) | becomes implemented with a passing `npm run validate:kms -- gcp` artifact |
| keys | PKCS#11 HSM component signer (CKM_ML_DSA, CKM_EDDSA) | **experimental** | signers (emulated session) | not run against a physical HSM; needs an HSM supporting both mechanisms |
| keys | Azure Key Vault signer | **unsupported** | — | Key Vault offers neither Ed25519 nor ML-DSA, so it cannot hold either half of the hybrid |
| time | RFC 3161 trusted timestamps (request, offline verification, pinned TSA anchors) | **implemented** | GENUINE DigiCert token; exhaustive single-bit flips (timestamp) | TSA revocation not checked offline; RSASSA-PSS tokens unsupported |
| time | OpenTimestamps anchoring | **implemented** | anchor | opt-in and networked |
| transparency | RFC 6962 log, consistency proofs, witness verification | **implemented** | platform-envelope, witness-consistency | a log can still withhold entries; witnesses detect forks, not omissions |
| evidence | Agent Execution Receipt (cool.agent-receipt.v1 over agent.execution envelopes): keyed payload digests, sequence numbers, declared identity and authority | **implemented** | mcp tests (schema conformance, golden example bundle), spec/schemas/cool.agent-receipt.v1.schema.json | identity, initiator, authority and policy fields are declared by the recorder, not authenticated or enforced |
| integration | MCP server (@northwindcipher/mcp-server-cool): cool_record_change, cool_seal_log, cool_verify_receipt, cool_status over stdio | **implemented** | mcp tests drive it over real stdio with the official MCP SDK client; Claude Code `claude mcp list` reports it Connected; installed and run from its npm tarball | records only what the agent chooses to record through the tools; npm publication pending scope ownership |
| integration | MCP proxy mode: records every tools/call to a wrapped downstream MCP server | **implemented** | mcp tests: proxy over real stdio to a real downstream MCP server, success/failure outcomes, visible recording failures | calls that bypass the proxy (other servers, shell, direct APIs) are not recorded |
| integration | Offline bundle verifier: VALID / INVALID / INDETERMINATE with a reason per check | **implemented** | mcp tests: changed, deleted, reordered, replayed, bad-signature, missing-proof and missing-component fixtures; network disabled during verification | VALID requires keys pinned out of band (fingerprint or trust file); a dropped final receipt needs an external checkpoint to detect |
| integration | Claude Code plugin: MCP server, PostToolUse hook on prompt/agent/policy files, /cool-audit skill, marketplace | **experimental** | `claude plugin validate` passes for the plugin and marketplace; hook entry point tested with Claude Code's hook input format | not yet installed end-to-end from the marketplace (needs the npm package published) |
| integration | Claude Desktop extension (.mcpb) | **experimental** | `mcpb validate` and `mcpb pack` (2.1.2) pass; the unpacked bundle's server records, seals and verifies through an MCP client | not yet installed in Claude Desktop by us; unsigned |
| integration | Configs for Cursor, Windsurf, VS Code, Codex CLI, Gemini CLI, Cline and other MCP clients | **experimental** | standard MCP stdio; docs/mcp.md | configs documented, not yet run in each client |
| integration | JSONL export for SIEM forwarders (--export-jsonl) | **implemented** | mcp tests: one flat line per receipt, no payloads, failures reported | local file, at-least-once; a forwarder (Splunk, Elastic, Datadog agent) ships it |
| integration | OpenTelemetry log export | **planned** | — | use the JSONL export with an OTel collector filelog receiver meanwhile |
| transparency | Hosted witness / notary for MCP bundles (commercial) | **planned** | — | today the recorder holds its own keys; an independent witness is needed to detect a recorder that rewrites its whole history |
| assurance | Internal adversarial security review | **implemented** | docs/security-review/internal-review-2026-11.md | performed by the maintainers (AI-assisted); not independent |
| assurance | Independent third-party security review | **planned** | review package ready: docs/security-review/ | not commissioned: requires engaging an external firm; no audit is claimed |

Run `cool capabilities` to print this table from the installed package.
