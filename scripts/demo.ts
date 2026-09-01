/**
 * `npm run demo` — the whole story in one script, no editing by hand.
 *
 *   1. an application executes
 *   2. CooL records evidence (metadata + payloads committed, never stored)
 *   3. the evidence is verified — offline, against the keys it carries
 *   4. the evidence is tampered with
 *   5. verification fails, and says exactly why
 *
 * With no dstack endpoint configured this runs the built-in simulator: every
 * line of output that depends on hardware says "simulated", never "verified".
 */
import { CooL, formatVerdict } from "../src/index";

const NO_COLOR = Boolean(process.env["NO_COLOR"]);
const dim = (s: string) => (NO_COLOR ? s : `\x1b[2m${s}\x1b[0m`);
const bold = (s: string) => (NO_COLOR ? s : `\x1b[1m${s}\x1b[0m`);
const green = (s: string) => (NO_COLOR ? s : `\x1b[32m${s}\x1b[0m`);
const red = (s: string) => (NO_COLOR ? s : `\x1b[31m${s}\x1b[0m`);

function heading(n: number, text: string): void {
  console.log(`\n${bold(`${n}.`)} ${bold(text)}`);
}

async function main(): Promise<void> {
  console.log(bold("CooL — Cryptographic Observability & On-chain Ledger"));
  console.log(dim("    demo · simulated evidence plane (no hardware) unless COOL_DSTACK_ENDPOINT is set"));

  const cool = new CooL({ applicationId: "demo-app" });

  heading(1, "the application executes");
  const model = "acme/credit-scorer@2026.06.0";
  const applicant = "applicant A-40182";
  const decision = "score 0.82 · APPROVE up to $12,000";
  console.log(dim(`    model    ${model}`));
  console.log(dim(`    input    ${applicant}   (stays in this process)`));
  console.log(dim(`    output   ${decision}   (stays in this process)`));

  heading(2, "CooL records evidence");
  const { evidence, recordId, executionId, digest } = await cool.record({
    type: "model.execution",
    metadata: { model, environment: "prod" },
    payloads: { input: applicant, output: decision },
    software: { name: "credit-scorer", version: "1.4.2", digest: null },
  });
  await cool.ready();
  console.log(dim(`    record id     ${recordId}`));
  console.log(dim(`    execution id  ${executionId}`));
  console.log(dim(`    binding       ${digest}`));
  console.log(dim(`    runtime       ${cool.environment.vendor} · ${cool.environment.mode}`));
  const wire = JSON.stringify(evidence);
  const leaked = wire.includes(applicant) || wire.includes(decision) || wire.includes("prod");
  console.log(
    leaked ? red("    ! plaintext leaked into the receipt") : green("    no plaintext in the receipt — metadata and payloads are salted hashes"),
  );

  heading(3, "verify the evidence — offline");
  const good = await cool.verify(evidence);
  console.log(formatVerdict(good).replace(/^/gm, "    "));

  heading(4, "tamper with the evidence");
  const forged = JSON.parse(wire) as typeof evidence;
  const ev = (forged.record as unknown as { event: { metadata_hash: string } }).event;
  const before = ev.metadata_hash;
  ev.metadata_hash = ev.metadata_hash.replace(/.$/, (c) => (c === "0" ? "1" : "0"));
  console.log(dim(`    metadata_hash  ${before}`));
  console.log(dim(`             ->    ${ev.metadata_hash}`));

  heading(5, "verify again");
  const bad = await cool.verify(forged);
  console.log(formatVerdict(bad).replace(/^/gm, "    "));

  await cool.close();

  console.log();
  if (good.ok && !bad.ok && !leaked) {
    console.log(green(bold("demo OK — a clean record verifies, a tampered one does not, and no plaintext was stored.")));
    process.exit(0);
  }
  console.log(red(bold("demo FAILED — see output above.")));
  process.exit(1);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
