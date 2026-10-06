/**
 * Materialise one fixture Contrast pod on disk and print its path.
 *
 *     node --import tsx pod.mjs ai-service
 *     COOL_CONTRAST_ROOT=$(node --import tsx pod.mjs ai-service) node ai-service.mjs
 *
 * The fixture bundle stores certificates and keys as base64 DER, because this
 * repository forbids committed `.pem` files and PEM private-key blocks. This
 * writes one workload back out as the exact files Contrast's initializer
 * creates, into a temporary directory, so the service can be run locally
 * against a real Contrast credential with no cluster.
 *
 * The directory is NOT cleaned up — the service needs it for its whole run.
 * It lives under the OS temp directory; these keys are disposable and protect
 * nothing, and no confidential hardware was involved in producing them.
 */
import { contrastPod, fixtures } from "../../tests/support/contrast-pod.ts";

const name = process.argv[2] ?? "ai-service";
const available = Object.keys(fixtures.workloads).sort();

if (!fixtures.workloads[name]) {
  console.error(`no fixture workload '${name}'\n\navailable:\n  ${available.join("\n  ")}`);
  process.exit(2);
}

process.stdout.write(contrastPod(name));
