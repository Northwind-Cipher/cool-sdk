# Telemetry and network egress

**CooL collects no telemetry.** The SDK, the CLI and the verifier contain no analytics, no usage pings, no crash reporting and no update checks. No phone-home is planned for any open-source component.

## What makes network calls, and only when you ask

| Component | Destination | When |
|---|---|---|
| `cool anchor` / OpenTimestamps helpers | the public OpenTimestamps calendars you configure | only when you anchor or upgrade a proof |
| `CoolTee` with a dstack endpoint | your dstack guest agent (a local socket or URL) | only in TEE mode, to obtain quotes and keys |
| TDX quote verification via a configured verifier | the verifier URL you configure | only when you pass one |
| `CoolClient` | the CooL service URL you configure | only when you use the client |

Everything else, including envelope creation, signing, logging, the authorization protocol, the gateway and every verifier, is local.

## How this is tested

`tests/egress.test.ts` replaces `net`, `dns`, `http`, `https` and global `fetch` with tripwires, then runs:
- the full showcase
- the agent demo (`demo:agent`, scenarios A–H plus a bundle export and verification)

The test fails if any outbound call is attempted. The test runs in CI on every pull request.

## For commercial deployments

The commercial platform also ships with telemetry **off**. Any operational metrics a hosted service needs are described in the service's data-processing terms. They never cover evidence payloads, which carry only commitments in any case.
