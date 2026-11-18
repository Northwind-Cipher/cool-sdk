/** Compile src/ to dist/ and make the CLI executable. */
import { execFileSync } from "node:child_process";
import { chmodSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);
rmSync(join(root, "dist"), { recursive: true, force: true });
execFileSync(process.execPath, [require.resolve("typescript/bin/tsc"), "-p", join(root, "tsconfig.json")], { stdio: "inherit" });
const cli = join(root, "dist", "cli.js");
const src = readFileSync(cli, "utf8");
if (!src.startsWith("#!")) writeFileSync(cli, `#!/usr/bin/env node\n${src}`);
try { chmodSync(cli, 0o755); } catch { /* windows */ }
console.log("built", join(root, "dist"));
