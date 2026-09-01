/**
 * The 30-second integration: record a piece of execution evidence, verify it.
 *
 *   npm install
 *   node index.mjs
 */
import { CooL } from "cool-nwc";

const cool = new CooL({ applicationId: "my-app" });

const { evidence, recordId, digest } = await cool.record({
  type: "model.execution",
  metadata: { model: "my-model", version: "1.0.0" },
  // Optional: commit to sensitive data without storing it.
  payloads: { input: "the prompt or request body", output: "the model output" },
  software: { name: "my-service", version: "2.3.1", digest: null },
});

console.log("record id ", recordId);
console.log("digest    ", digest);
console.log("plaintext leaked?", JSON.stringify(evidence).includes("the prompt or request body"));

const verdict = await cool.verify(evidence);
console.log("verified  ", verdict.ok);
console.log("checks    ", Object.fromEntries(
  Object.entries(verdict.checks).map(([k, v]) => [k, v.status]),
));

await cool.close();
