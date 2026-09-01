/**
 * Run the test suite.
 *
 * `node --test "tests/*.test.ts"` only expands the glob on Node >= 22 — on
 * Node 20 the quoted pattern is passed through literally and the runner reports
 * "Could not find 'tests/*.test.ts'". `engines` says Node >= 20, so the test
 * command has to work there too: enumerate the files here and hand the runner
 * an explicit list, which every supported Node accepts.
 */
import { readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const testDir = join(root, "tests");

const files = readdirSync(testDir)
  .filter((name) => name.endsWith(".test.ts"))
  .sort()
  .map((name) => join("tests", name));

if (files.length === 0) {
  console.error("no test files found under tests/");
  process.exit(1);
}

const result = spawnSync(
  process.execPath,
  ["--import", "tsx", "--test", ...process.argv.slice(2), ...files],
  { cwd: root, stdio: "inherit" },
);

process.exit(result.status ?? 1);
