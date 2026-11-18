# Example: an Agent Execution Receipt

These files were produced by a real run of `@northwindcipher/mcp-server-cool` in a throwaway workspace (`mcp/scripts/make-example.ts`). The names, ticket and repository are illustrative. The keys are example keys; only their public halves are here.

| File | What it is |
|---|---|
| `receipt.json` | The readable `cool.agent-receipt.v1` view: a GitHub PR created through the CooL proxy |
| `envelope.json` | The signed `agent.execution` envelope behind it, which is what verifiers check |
| `bundle/` | Both receipts from the run, sealed: `bundle.json`, `trust.json` (public keys), `MANIFEST.json`, `VERIFY.txt` |
| `FINGERPRINT.txt` | The workspace fingerprint. In real use you receive this separately from the bundle |

Verify it:

```bash
npx -y @northwindcipher/mcp-server-cool verify examples/agent-receipt/bundle --fingerprint "$(cat examples/agent-receipt/FINGERPRINT.txt)"
```

This bundle is also a **golden test vector**: `mcp/tests/mcp.test.ts` fails if a future version stops reporting it VALID.
