# CooL for AI agents: MVP scope and threat boundary

Status: **frozen for 0.1.0** (2026-11-18). Anything not listed under "In scope" is out of scope for this release. A change to this file is a scope change and needs a version bump.

## The one sentence

When an AI agent acts through CooL, CooL creates a signed, numbered receipt. Anyone can later check, offline, that the receipts have not been altered, removed from the middle, reordered or replayed. It does **not** prove that every action went through CooL.

## In scope (0.1.0)

| Area | What ships | Test that proves it |
|---|---|---|
| Receipt | `cool.agent-receipt.v1`: a view of a signed `agent.execution` envelope. Hybrid ML-DSA-65 + Ed25519, a sequence number per workspace epoch, inputs and outputs as HMAC-SHA-256 digests only | `schema:`, `receipt:`, golden vector |
| Capture | MCP tools (`cool_record_change`), MCP proxy (every `tools/call`), Claude Code PostToolUse hook (prompt, agent and policy files), CLI `record` | `MCP:`, `proxy:`, `hook:` |
| Workspace | Explicit and validated. Absolute path, an existing directory, not `/` and not `$HOME`. Writes only inside `<workspace>/.cool/`. Keys are git-ignored | `workspace:` |
| Failure handling | Every failure is visible: tool errors, hook exit 1 with stderr, proxy warning appended to the result. Torn final line: set aside, capture continues. Corrupt middle line: recording and sealing stop | `capture:` |
| Seal | RFC 6962 Merkle tree over all receipts, a signed tree head, `cool.bundle.v1` plus `MANIFEST.json` (file hashes), `trust.json` (public keys only), `VERIFY.txt` | `seal:` |
| Verify | Offline. VALID / INVALID / INDETERMINATE with a reason for every check. VALID needs keys pinned out of band (a fingerprint or a trust file) | `verify:`, `tamper fixtures:` |
| Packaging | npm package with a `bin`; Claude Code plugin and marketplace; `.mcpb` for Claude Desktop; configs for other MCP clients | tarball smoke test, `claude plugin validate`, `mcpb validate` |
| Export | JSONL lines for SIEM forwarders | `export:` |

## Out of scope (0.1.0)

- Hosted service, accounts, SSO/SCIM, roles, retention policies.
- A witness or notary that is independent of the recorder (planned, commercial).
- Cloud KMS or HSM keys for the MCP workspace. The core library has KMS signers; the MCP server uses local keys.
- Running the recorder inside a TEE.
- Enforcement: blocking or approving actions. CooL records; it does not decide. The core library's `ToolGateway` does enforcement and is not wired into the MCP server.
- Authenticating who the agent or the initiator is.
- OpenTelemetry export (use JSONL with a collector meanwhile).

## Threat boundary

### What CooL detects, once receipts are sealed

| Attack | Detected by | Verdict |
|---|---|---|
| A receipt's bytes changed | signature, manifest digest, file hash | INVALID |
| A receipt removed from the middle | manifest digest; sequence gap | INVALID |
| Receipts reordered (proofs swapped) | inclusion proofs; log order check | INVALID |
| A receipt duplicated or replayed | duplicate check (digest, event id, sequence) | INVALID |
| A signature forged or corrupted | hybrid signature verification | INVALID |
| An inclusion proof removed | `requireCheckpoint` | INVALID |
| A bundle component missing or corrupt | component and manifest checks | INVALID |
| A bundle signed by another workspace | fingerprint mismatch / exporter not pinned | INVALID |
| Nobody told the verifier which key to trust | trust source | INDETERMINATE |

### What CooL does not detect: bypass cases

These are not bugs. They are the boundary of what a recorder that runs beside the agent can know. Each one is stated in every verification result.

1. **Actions that never pass through CooL.** If the agent calls another MCP server directly, runs a shell command, or calls an API, and it was not configured through the proxy, there is no receipt. The `mcp_tool` capture mode records only what the agent chooses to record.
2. **The hook covers selected files.** The Claude Code hook records edits to prompt, agent, policy and model-configuration files by default (`--all` records every edit). It sees only Write, Edit, MultiEdit and NotebookEdit. A file changed by a Bash command is not seen.
3. **CooL not running.** Anything done while the server, proxy or hook was not running is not recorded.
4. **The final receipt removed.** Removing receipts from the end before sealing leaves no gap. You need an earlier sealed checkpoint or tree size held by someone else to notice.
5. **A recorder that rewrites its own history.** The workspace keys live on the recording machine. Someone with those files can create a new, internally consistent history and seal it. An independent witness that holds earlier tree heads is what detects this (planned). Until then, share the fingerprint and keep earlier bundles.
6. **Declared fields.** `agent_id`, `initiator_id`, `authority_ref` and `policy_version` are what the recorder was told. CooL proves they were not changed after recording, not that they were true.
7. **Clock.** Timestamps come from the recording machine's clock.
8. **Payload digests are keyed.** Without the workspace's commitment key, a recipient cannot test a guess of a payload. The workspace owner can disclose the key or the payload later to prove a match.

## Words we do not use

Not "tamper-proof", not "complete", not "unbypassable", not "compliance certified". The accurate words are **tamper-evident**, **covering actions recorded through CooL**, and **offline-verifiable**.
