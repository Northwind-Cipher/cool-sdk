/**
 * An AI agent that produces a verifiable trail of what it did — tool calls,
 * decisions, artefacts — without recording the raw prompts or tool payloads.
 *
 *   npm install
 *   node index.mjs
 */
import { CooL, verifyEvidence } from "cool-nwc";

const cool = new CooL({ applicationId: "research-agent" });
const executionId = `run-${Date.now()}`;

// One helper so every step in this run shares an execution id.
const step = (type, metadata, payloads) =>
  cool.record({ type, executionId, metadata, payloads });

async function main() {
  const trail = [];

  trail.push(await step("agent.run.started", { goal: "summarise Q3 filings" }));

  trail.push(
    await step(
      "tool.invocation",
      { tool: "web.search", provider: "internal" },
      { input: "Q3 2026 10-Q filings", output: "12 results" },
    ),
  );

  trail.push(
    await step(
      "model.execution",
      { model: "summariser@3", tokens_in: 8123, tokens_out: 412 },
      { input: "…12 documents…", output: "…the summary…" },
    ),
  );

  trail.push(
    await step("policy.decision", {
      policy: "no-financial-advice",
      decision: "allow",
      rationale_committed: true,
    }),
  );

  trail.push(await step("agent.run.completed", { steps: trail.length + 1, status: "ok" }));

  await cool.close();

  for (const { evidence, recordId } of trail) {
    const verdict = await verifyEvidence(evidence);
    const type = evidence.record.event.type;
    console.log(`${verdict.ok ? "OK " : "X  "} ${type.padEnd(24)} ${recordId}`);
  }
}

main();
