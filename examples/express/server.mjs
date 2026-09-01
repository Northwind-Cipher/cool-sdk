/**
 * Express: record evidence for each request that reaches a model, without
 * adding latency to the response and without logging sensitive data.
 *
 *   npm install
 *   node server.mjs
 *   curl -s localhost:3000/score -XPOST -H 'content-type: application/json' -d '{"applicant":"A-1"}'
 */
import express from "express";
import { CooL } from "cool-nwc";

const cool = new CooL({ applicationId: "scoring-api" });
await cool.ready();

const app = express();
app.use(express.json());

app.post("/score", async (req, res) => {
  const applicant = String(req.body?.applicant ?? "unknown");
  const score = Math.round(Math.random() * 1000) / 1000;

  // Commit the request/response to evidence. The plaintext is hashed inside the
  // evidence plane and discarded; the receipt id goes back to the caller.
  const { recordId } = await cool.record({
    type: "model.execution",
    executionId: req.header("x-request-id") ?? undefined,
    metadata: { route: "/score", model: "scorer@1" },
    payloads: { input: JSON.stringify(req.body), output: JSON.stringify({ score }) },
  });

  res.json({ score, evidence: recordId });
});

app.get("/evidence/health", (_req, res) => {
  res.json({ ok: cool.attestation.ok, mode: cool.environment.mode });
});

const server = app.listen(3000, () => console.log("listening on :3000"));

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, async () => {
    await cool.flush();
    await cool.close();
    server.close(() => process.exit(0));
  });
}
