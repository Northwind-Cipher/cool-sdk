---
name: cool-audit
description: Produce an audit of what CooL has recorded in this project. Seal the receipt log into a verifiable bundle, verify it, and report the result with its limits. Use when the user asks for an audit trail, evidence of agent changes, proof of what Claude changed, or runs /cool-audit.
---

# CooL audit

Produce an honest, verifiable account of the agent actions CooL has recorded in this project.

1. Call `cool_status`. Report the number of receipts and the last receipt. Report **every problem listed** (sequence gaps, torn writes, duplicates) in plain words. Do not hide or soften problems.
2. If there are receipts, call `cool_seal_log`. Note the bundle directory and the **fingerprint**.
3. Call `cool_verify_receipt` with no target to verify the bundle just sealed.
4. Report:
   - The verdict (VALID / INVALID / INDETERMINATE) and the reason for any check that did not pass.
   - A short table of the receipts: sequence, time, tool, target, outcome.
   - The fingerprint. Tell the user to send it to anyone who will verify the bundle **through a separate channel**, such as a call or a signed email. Without it, a recipient can only reach INDETERMINATE.
   - The command a recipient runs: `npx -y @northwindcipher/mcp-server-cool verify <bundle dir> --fingerprint <fingerprint>`.
5. Always state the limits, in these words or close to them:
   - Only actions that passed through CooL are covered: the MCP tools, the CooL proxy, and this plugin's hook on prompt, agent and policy files. Anything done another way is not in the record.
   - Agent and initiator identities, authority references and policy versions are **declared** by the recorder. They are not independently authenticated or enforced.
   - Timestamps come from this machine's clock.

Never describe the result as "tamper-proof", "complete" or "compliance certified". CooL makes changes to the record detectable. It does not prove that everything was recorded.
