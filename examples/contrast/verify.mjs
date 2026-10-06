/**
 * The auditor's side. Takes receipts and a Coordinator root; returns verdicts.
 *
 *     node verify.mjs receipts.json \
 *       --coordinator-root verify/coordinator-root-ca.pem \
 *       --manifest manifest.json \
 *       --require-hardware
 *
 * Three things to notice, because they are the product:
 *
 *   1. Nothing here talks to the cluster, to the Coordinator, to Edgeless or to
 *      Northwind Cipher. The receipts and two files are the whole input.
 *   2. The Coordinator root must come from the READER's own
 *      `contrast verify -c <coordinator>`, which performs remote attestation of
 *      the Coordinator CVM against the manifest's reference values. A root taken
 *      from the pod would make the chain circular, and the verifier reports
 *      rather than passes when no root is pinned at all.
 *   3. `--require-hardware` then means something: a receipt whose workload
 *      credential does not chain to that pinned root cannot be `ok`.
 */
import { readFileSync } from "node:fs";
import { verifyEvidence, formatVerdict, domainOrder } from "cool-nwc/verify";

const args = process.argv.slice(2);
const flag = (name) => {
  const index = args.indexOf(`--${name}`);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (value === undefined || value.startsWith("--")) {
    console.error(`--${name} needs a file path`);
    process.exit(2);
  }
  return value;
};

const paths = args.filter((a, i) => !a.startsWith("--") && !args[i - 1]?.startsWith("--"));
if (paths.length === 0) {
  console.error("usage: node verify.mjs <receipts.json> [--coordinator-root <pem>] [--manifest <json>] [--require-hardware]");
  process.exit(2);
}

const rootPath = flag("coordinator-root");
const manifestPath = flag("manifest");

const options = {
  ...(rootPath ? { coordinatorRootCA: readFileSync(rootPath, "utf8") } : {}),
  ...(manifestPath ? { expectedManifest: new Uint8Array(readFileSync(manifestPath)) } : {}),
  ...(args.includes("--require-hardware") ? { requireHardware: true } : {}),
};

if (!rootPath) {
  console.warn(
    "warning: no --coordinator-root given. The workload credential will be REPORTED,\n" +
      "         not verified. Get the root with: contrast verify -c <coordinator>\n",
  );
}

let failures = 0;
let checked = 0;

for (const path of paths) {
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  const receipts = Array.isArray(parsed) ? parsed : [parsed];

  for (const receipt of receipts) {
    checked++;
    const verdict = await verifyEvidence(receipt, options);
    if (!verdict.ok) failures++;

    console.log(formatVerdict(verdict));

    // The domain details are where the Contrast half actually shows up.
    const workload = verdict.checks.workload;
    if (workload.status !== "absent") {
      console.log(`\n  workload  ${workload.status.toUpperCase()}: ${workload.detail}`);
    }
    const sealed = receipt?.record?.runtime?.workload;
    if (sealed) {
      console.log(
        `  sealed    ${sealed.platform}/${sealed.tee} · ${sealed.workload_name} · policy ${(sealed.policy_hash ?? "").slice(4, 20)}…`,
      );
    }
    console.log();
  }
}

console.log(`${checked - failures}/${checked} verified`);
if (failures > 0) {
  console.log(`\nDomains, in order: ${domainOrder().join(" → ")}`);
}
process.exit(failures === 0 ? 0 : 1);
