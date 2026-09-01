/**
 * Independent verification — the auditor's situation.
 *
 * Evidence produced anywhere can be verified anywhere, offline, against the keys
 * it carries. This script produces one record, writes it to disk, then verifies
 * the file as if it had arrived by email — and shows a tampered copy failing.
 *
 *   npm install
 *   node index.mjs
 */
import { writeFileSync, readFileSync } from "node:fs";
import { CooL, verifyEvidence, formatVerdict } from "cool-nwc";

const cool = new CooL({ applicationId: "issuer" });
const { evidence } = await cool.record({
  type: "artifact.created",
  metadata: { artifact: "quarterly-report.pdf", sha256: "…" },
});
await cool.close();

writeFileSync("evidence.json", JSON.stringify(evidence, null, 2));

// --- somewhere else, later, with no access to the issuer ---
const fromFile = JSON.parse(readFileSync("evidence.json", "utf8"));
console.log(formatVerdict(await verifyEvidence(fromFile)));

// --- now tamper with it ---
fromFile.record.event.metadata_hash = fromFile.record.event.metadata_hash.replace(
  /.$/,
  (c) => (c === "0" ? "1" : "0"),
);
console.log("\n--- after tampering ---\n");
console.log(formatVerdict(await verifyEvidence(fromFile)));
