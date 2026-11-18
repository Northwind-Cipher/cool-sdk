# CooL for AI agents and coding assistants (MCP)

`@northwindcipher/mcp-server-cool` gives any AI tool that speaks the **Model Context Protocol** a way to leave a signed, tamper-evident record of what it did. Anyone can verify that record offline.

```
agent ──▶ CooL (MCP tools / proxy / hook) ──▶ .cool/mcp/receipts.jsonl ──seal──▶ .cool/bundles/<time>/ ──▶ verify (offline, anywhere)
```

> **Status:** experimental, version 0.1.0. Scope and limits: [`mcp/MVP_SCOPE.md`](../mcp/MVP_SCOPE.md). Receipt format: [agent-receipt.md](agent-receipt.md).
> **Before npm publication:** the `npx -y @northwindcipher/mcp-server-cool` commands below work once the package is published. Until then, build from source (see [Build from source](#build-from-source)) and use `node /path/to/cool-sdk/mcp/dist/cli.js` in place of `npx -y @northwindcipher/mcp-server-cool`.

## What it gives the agent

| Tool | What it does |
|---|---|
| `cool_record_change` | Record one action as a signed receipt. The input and output are hashed, never stored |
| `cool_seal_log` | Seal all receipts into a Merkle-tree bundle with a manifest. Returns the bundle path and the **fingerprint** |
| `cool_verify_receipt` | Verify a bundle or one receipt: **VALID / INVALID / INDETERMINATE**, with a reason per check |
| `cool_status` | Receipt count, the last receipt, any problems in the log, the fingerprint |

## Three ways to capture

| Mode | What gets recorded | Set up with |
|---|---|---|
| **Tools** (`mcp_tool`) | What the agent chooses to record via `cool_record_change` | add the server to your client |
| **Proxy** (`mcp_proxy`) | **Every** call to a wrapped MCP server, automatically | wrap the other server's command with `mcp-server-cool proxy` |
| **Hook** (`hook`) | Claude Code edits to prompt, agent and policy files, automatically | the Claude Code plugin |

The proxy is the strongest mode: the agent does not have to remember to record.

## The workspace (read this first)

CooL writes only inside **one project folder you name**, in `<folder>/.cool/`. It never guesses. Some clients (Claude Desktop, for instance) start servers in their own app folder, which is why CooL does not use the current directory unless you explicitly pass `--workspace .`.

The first of these that is set wins:

1. `workspace_root` in the tool call (an absolute path)
2. `--workspace <dir>` on the command line (relative values resolve against the server's start directory)
3. `COOL_WORKSPACE`, then `CLAUDE_PROJECT_DIR`
4. The client's MCP roots, if it offers exactly one

If none is set, every tool call fails with a clear `workspace_required` error. Your home folder and the filesystem root are refused. Signing keys live in `.cool/mcp/keys.json`, which is git-ignored. Commit nothing from `.cool/mcp/` except, if you want, `receipts.jsonl`.

## Client setup

Replace `/path/to/project` with your project's absolute path. **Tested** means we ran it; **documented** means it is standard MCP stdio configuration that we have not yet run in that client.

### Claude Code: tested (`claude mcp list` shows Connected)

```bash
cd /path/to/project
claude mcp add cool -- npx -y @northwindcipher/mcp-server-cool --workspace "$PWD"
```

Or install the plugin, which adds the server, the hook and `/cool-audit`:

```
/plugin marketplace add Northwind-Cipher/cool-sdk
/plugin install cool@northwindcipher
```

On Claude Code 2.1.275 or later this is one step: `/plugin install cool --marketplace Northwind-Cipher/cool-sdk`.

### Claude Desktop: documented, with a `.mcpb` that is built and validated

Either install `cool-0.1.0.mcpb` (Settings, Extensions, then install the file; it asks for the project folder), or edit `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cool": { "command": "npx", "args": ["-y", "@northwindcipher/mcp-server-cool", "--workspace", "/path/to/project"] }
  }
}
```

### Cursor: documented

`.cursor/mcp.json` in the project, or `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "cool": { "command": "npx", "args": ["-y", "@northwindcipher/mcp-server-cool", "--workspace", "/path/to/project"] }
  }
}
```

### Windsurf: documented

`~/.codeium/windsurf/mcp_config.json`, with the same `mcpServers` block as Cursor.

### VS Code (GitHub Copilot agent mode): documented

`.vscode/mcp.json`:

```json
{
  "servers": {
    "cool": { "type": "stdio", "command": "npx", "args": ["-y", "@northwindcipher/mcp-server-cool", "--workspace", "${workspaceFolder}"] }
  }
}
```

### OpenAI Codex CLI: documented

`~/.codex/config.toml`:

```toml
[mcp_servers.cool]
command = "npx"
args = ["-y", "@northwindcipher/mcp-server-cool", "--workspace", "/path/to/project"]
```

### Gemini CLI: documented

`.gemini/settings.json` in the project, or `~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "cool": { "command": "npx", "args": ["-y", "@northwindcipher/mcp-server-cool", "--workspace", "/path/to/project"] }
  }
}
```

### Cline, Continue, Zed and any other MCP client: documented

CooL is a standard stdio MCP server. Point your client at the command `npx` with arguments `-y @northwindcipher/mcp-server-cool --workspace /path/to/project`.

## Proxy: record every call to another MCP server

Replace the other server's command with CooL's proxy, and put the original command after `--`:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@northwindcipher/mcp-server-cool", "proxy", "--workspace", "/path/to/project", "--name", "github", "--",
               "npx", "-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "..." }
    }
  }
}
```

The agent sees the same tools. Each call produces a receipt with `capture: "mcp_proxy"`, `tool_name: "github.<tool>"`, the outcome, the duration, and digests of the arguments and result. If a receipt cannot be written, the call still completes. The failure is printed to stderr and appended to the result the agent sees, so it is never silent.

## Seal and verify

```bash
npx -y @northwindcipher/mcp-server-cool seal --workspace /path/to/project
# → .cool/bundles/2026-11-18T09-02-25-680Z/   and a fingerprint: sha256:816a…

npx -y @northwindcipher/mcp-server-cool verify .cool/bundles/2026-11-18T09-02-25-680Z --fingerprint sha256:816a…
```

| Verdict | Means | Exit code |
|---|---|---|
| **VALID** | Every check passed, against keys you pinned | 0 |
| **INVALID** | Something is wrong: altered, removed, reordered, replayed, wrongly signed, a component missing | 1 |
| **INDETERMINATE** | Nothing wrong was found, but something could not be decided. Usually no fingerprint was given | 2 |

**Send the fingerprint separately from the bundle** (a call, a signed email, your website). A bundle cannot vouch for its own keys. Without the fingerprint, the best possible result is INDETERMINATE. `--trust trust.json` is the alternative for organisations that distribute key lists.

Each result also states what the receipts cover and what they cannot: identities are declared, timestamps come from the recording machine, and actions outside CooL are not covered.

## SIEM export

`--export-jsonl /var/log/cool.jsonl` (or `COOL_EXPORT_JSONL`) appends one flat JSON line per receipt: time, tool, target, outcome, agent, initiator, sequence and envelope digest, with no payloads. Ship it with Splunk Universal Forwarder, Elastic Agent, the Datadog agent, or an OpenTelemetry Collector `filelog` receiver.

## Performance (measured)

`cd mcp && npm run bench` on Node 24.18, Windows 11, Intel Core i7-14650HX. Each receipt carried a 500-byte input; every bundle verified VALID.

| receipts | record p50 | record p95 | seal | verify bundle | verify per receipt | bundle.json |
|---:|---:|---:|---:|---:|---:|---:|
| 10 | 11.6 ms | 22.7 ms | 49 ms | 75 ms | 7.5 ms | 211 KiB |
| 100 | 11.5 ms | 22.3 ms | 63 ms | 459 ms | 4.6 ms | 2.0 MiB |
| 1000 | 12.3 ms | 24.4 ms | 2.5 s | 4.6 s | 4.6 ms | 19.9 MiB |

Recording includes the hybrid post-quantum signature and an `fsync`, and stays flat as the log grows. Bundles are about 20 KiB per receipt, mostly the ML-DSA-65 signatures and the inclusion proofs. Run the benchmark on your own hardware before quoting numbers.

## CLI reference

```
mcp-server-cool [serve] --workspace DIR [--export-jsonl FILE] [--agent-id ID]
mcp-server-cool proxy   --workspace DIR --name NAME -- COMMAND [ARGS...]
mcp-server-cool hook    [--workspace DIR] [--all]          # Claude Code PostToolUse; JSON on stdin
mcp-server-cool init | status | seal --workspace DIR
mcp-server-cool record  --workspace DIR --tool NAME [--target T] [--outcome O] [--initiator I] [--kind K]
mcp-server-cool verify  BUNDLE_DIR [--fingerprint FP | --trust FILE | --workspace DIR] [--json]
```

## Build from source

```bash
git clone https://github.com/Northwind-Cipher/cool-sdk && cd cool-sdk
npm ci && npm run build
cd mcp && npm pkg set dependencies.cool-nwc=file:.. && npm install && npm pkg set dependencies.cool-nwc=^4.1.0
npm run build && npm test            # 23 tests, including real stdio, proxy, hook and tamper fixtures
npm run build:mcpb                   # optional: cool-0.1.0.mcpb for Claude Desktop
```
