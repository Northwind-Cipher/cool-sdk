# Demo: CooL for AI agents in under three minutes

A script for a live demo or a screen recording. Everything in it is real: an MCP client talks to the CooL server over stdio, a downstream MCP server sits behind the CooL proxy, and verification runs offline.

```bash
cd mcp && npm run demo -- --pace     # pauses between steps; drop --pace for a 10-second run
```

| Time | On screen | Say |
|---|---|---|
| 0:00 | Title line | "AI agents now edit code, change prompts and deploy. When something goes wrong, the question is: what did the agent actually do, and can we trust the log? This is CooL." |
| 0:15 | **1. An agent works through CooL**: four tools offered; three actions recorded | "The agent changes CLAUDE.md, deploys under change ticket CHG-2026-0142, and calls a ticketing tool. That last one went through the CooL proxy, so it was recorded without the agent having to ask." |
| 0:40 | **2. What a receipt looks like** | "Each action becomes a signed, numbered receipt: who, on whose request, what, to what, the outcome, and the time. No prompt or payload is stored, only a keyed digest. The signature is post-quantum ML-DSA together with Ed25519." |
| 1:05 | **3. Seal** | "Sealing puts the receipts into a Merkle tree, signs the tree head, and writes a bundle. It also prints a fingerprint. The bundle can travel by email or a ticket. The fingerprint goes by a separate channel, such as a call." |
| 1:25 | **4. Verify: VALID** | "Someone else, an auditor or a customer, checks it offline with one command. Every check is listed: signatures, Merkle proofs, no gaps, no duplicates, correct order, the pinned key." |
| 1:45 | **5. Tamper** | "Now someone changes the deploy outcome after the fact, and even fixes up the file hash to cover their tracks." |
| 1:55 | **6. INVALID** | "Caught: the signed receipt no longer matches. And notice: without the fingerprint, even the untouched bundle is only INDETERMINATE. A bundle cannot vouch for its own keys." |
| 2:15 | **7. Limits** | "And this is what CooL does not claim. Identities are declared, not authenticated. Only actions that went through CooL are covered. The clock is the machine's clock. Every result says this, so nobody over-reads it." |
| 2:40 | Closing line | "CooL makes changes to the record detectable. Set it up in one line in Claude Code, Cursor, Codex, Gemini or any MCP client." |

## Do not say

"Tamper-proof", "complete audit trail", "compliance certified", "proves the agent was authorised". Say **tamper-evident**, **covers actions recorded through CooL**, and **verifiable offline**.
