/**
 * Build cool-<version>.mcpb for Claude Desktop: stage the manifest, the compiled server and
 * its production dependencies, then `mcpb validate` and `mcpb pack`.
 *
 *   npm run build && npm run build:mcpb
 *
 * Set COOL_NWC_TARBALL to a local cool-nwc .tgz to build before that version is on npm.
 * Set MCPB_BIN to use an already-installed mcpb CLI.
 */
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const stage = join(root, ".mcpb-stage");
if (!existsSync(join(root, "dist", "cli.js"))) throw new Error("run `npm run build` first");
rmSync(stage, { recursive: true, force: true });
mkdirSync(stage, { recursive: true });
cpSync(join(root, "mcpb", "manifest.json"), join(stage, "manifest.json"));
cpSync(join(root, "dist"), join(stage, "server"), { recursive: true });
cpSync(join(root, "..", "LICENSE"), join(stage, "LICENSE"));
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const manifest = JSON.parse(readFileSync(join(root, "mcpb", "manifest.json"), "utf8"));
if (manifest.version !== pkg.version) throw new Error(`mcpb/manifest.json version ${manifest.version} != package.json ${pkg.version}`);
const deps = { ...pkg.dependencies };
if (process.env.COOL_NWC_TARBALL) deps["cool-nwc"] = `file:${resolve(process.env.COOL_NWC_TARBALL)}`;
writeFileSync(join(stage, "package.json"), JSON.stringify({ name: "cool-mcpb", private: true, type: "module", dependencies: deps }, null, 2));
execSync("npm install --omit=dev --no-audit --no-fund --install-links", { cwd: stage, stdio: "inherit" });
const mcpb = process.env.MCPB_BIN ?? "npx -y @anthropic-ai/mcpb@2.1.2";
const out = join(root, `cool-${pkg.version}.mcpb`);
execSync(`${mcpb} validate "${join(stage, "manifest.json")}"`, { stdio: "inherit" });
execSync(`${mcpb} pack "${stage}" "${out}"`, { stdio: "inherit" });
console.log("wrote", out);
