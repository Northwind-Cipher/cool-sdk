# @northwindcipher/mcp-server-cool

**Signed, tamper-evident, offline-verifiable receipts for what AI agents do.** It works with Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Codex CLI, Gemini CLI and any other MCP client.

```bash
claude mcp add cool -- npx -y @northwindcipher/mcp-server-cool --workspace "$PWD"
```

When an agent acts through CooL, CooL writes a receipt with:

- what was done and to what
- who did it and who asked (both as declared)
- the authority and policy cited (as declared)
- the outcome and the time

Each receipt is signed with ML-DSA-65 + Ed25519 and numbered, so gaps show. Inputs and outputs are kept only as keyed digests. `cool_seal_log` turns the receipts into a bundle that anyone can check offline:

```bash
npx -y @northwindcipher/mcp-server-cool verify .cool/bundles/<time> --fingerprint sha256:…
#  VALID | INVALID | INDETERMINATE, with a reason for every check
```

| Tool | |
|---|---|
| `cool_record_change` | record one action |
| `cool_seal_log` | seal into a portable bundle; returns the fingerprint to share |
| `cool_verify_receipt` | verify a bundle or a receipt |
| `cool_status` | counts, problems, fingerprint |

There are also `proxy` mode, which records **every** call to another MCP server, a Claude Code **hook** for prompt, agent and policy file edits, and **JSONL export** for SIEMs.

**What it proves:** the recorded history was not altered, pruned from the middle, reordered or replayed.
**What it does not:** that every action went through CooL, or that declared identities are true. See [MVP_SCOPE.md](MVP_SCOPE.md).

- Setup for every client: [docs/mcp.md](https://github.com/Northwind-Cipher/cool-sdk/blob/main/docs/mcp.md)
- Receipt format: [docs/agent-receipt.md](https://github.com/Northwind-Cipher/cool-sdk/blob/main/docs/agent-receipt.md)

Experimental, 0.1.0. Apache-2.0. © 2026 Northwind Cipher Pvt. Ltd.
