/**
 * Running inside Phala dstack: bind evidence to a hardware-attested enclave.
 *
 * This is the same code as examples/basic, with two additions:
 *   - attestation.provider: "dstack"  — talk to the guest agent
 *   - security.requireAttestation      — refuse to run without a real quote
 *
 * The application must run inside a dstack CVM with /var/run/dstack.sock
 * mounted, or against the dstack simulator (COOL_DSTACK_ENDPOINT=http://...).
 * See docs/dstack.md.
 *
 *   npm install
 *   COOL_DSTACK_ENDPOINT=http://localhost:8090 node index.mjs   # simulator
 *   node index.mjs                                               # inside dstack
 */
import { CooL, DstackUnavailableError, AttestationRequiredError } from "cool-nwc";

const cool = new CooL({
  applicationId: "refund-agent",
  attestation: {
    provider: "dstack",
    endpoint: process.env.COOL_DSTACK_ENDPOINT ?? "/var/run/dstack.sock",
    vendor: "intel-tdx",
  },
  security: {
    requireAttestation: true,
    // Pin the image you reviewed. Any mismatch fails verification.
    // expectedMeasurement: PINNED_MEASUREMENT,
  },
});

try {
  await cool.ready();
} catch (error) {
  if (error instanceof DstackUnavailableError || error instanceof AttestationRequiredError) {
    console.error(`\n${error.code}: ${error.message}\n\n  ${error.action}\n`);
    process.exit(3);
  }
  throw error;
}

console.log("attestation:", cool.attestation.ok ? "hardware-backed" : "NOT verified");
console.log("environment:", cool.environment);

const { evidence } = await cool.record({
  type: "model.execution",
  metadata: { model: "phala/deepseek-v4-pro@2026.07" },
  payloads: { input: "assess application A-40182", output: "approve up to $500" },
});

const verdict = await cool.verify(evidence, { requireHardware: true });
console.log("verified (hardware required):", verdict.ok);

await cool.close();
