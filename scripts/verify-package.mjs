/**
 * Prove the published package works *on install* — not in this repo, but in a
 * clean project that has never seen our source.
 *
 * The failure this catches is the classic one: a library that passes every test
 * in its own repository and then cannot be imported, because the exports map is
 * wrong, the emitted specifiers are extensionless, a dependency was left in
 * devDependencies, or the types resolve under `bundler` but not `nodenext`.
 *
 *   1. pack the tarball exactly as it ships (`prepack` compiles it);
 *   2. install it into a throwaway project in the system temp directory;
 *   3. run it — record a piece of evidence, verify it, assert the verdict, and
 *      assert no plaintext leaked into the receipt;
 *   4. typecheck a consumer file against it under BOTH `nodenext` and `bundler`;
 *   5. exercise the subpath exports and the `cool` bin.
 *
 * Run with:  npm run verify:package
 */
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdtempSync, rmSync, writeFileSync, readdirSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const shell = process.platform === "win32";
const tsc = createRequire(import.meta.url).resolve("typescript/bin/tsc");

let failures = 0;
const check = (label, ok, detail = "") => {
  if (!ok) failures++;
  console.log(`  [${ok ? "PASS" : "FAIL"}] ${label}${detail ? ` — ${detail}` : ""}`);
};

const run = (command, args, cwd, quiet = true) =>
  execFileSync(command, args, {
    cwd,
    shell: shell && (command === "npm" || command === "npx"),
    stdio: quiet ? ["ignore", "pipe", "pipe"] : "inherit",
    encoding: "utf8",
  });

console.log("CooL SDK — consumer install check\n");

const work = mkdtempSync(join(tmpdir(), "cool-consumer-"));
try {
  /* 1 · pack */
  console.log("packing (prepack compiles it):");
  run("npm", ["pack", "--silent"], root, false);
  const tarball = readdirSync(root).find((name) => name.endsWith(".tgz"));
  check("npm pack produced a tarball", Boolean(tarball), tarball ?? "");
  if (!tarball) process.exit(1);
  const tarballPath = join(work, tarball);
  copyFileSync(join(root, tarball), tarballPath);
  rmSync(join(root, tarball));

  /* 2 · install into a clean project */
  console.log("\ninstalling into a clean project:");
  writeFileSync(
    join(work, "package.json"),
    JSON.stringify(
      { name: "cool-consumer", private: true, type: "module", version: "0.0.0" },
      null,
      2,
    ),
  );
  run("npm", ["install", tarballPath.replace(/\\/g, "/"), "--no-audit", "--no-fund"], work);
  check("npm install <tarball> succeeded", true, work);

  /* 3 · run it */
  console.log("\nrunning it:");
  writeFileSync(
    join(work, "use.mjs"),
    `import { CooL, verifyEvidence } from "cool-nwc";

const cool = new CooL({ applicationId: "consumer" });
const { evidence } = await cool.record({
  type: "model.execution",
  metadata: { model: "example-model", version: "1.0.0" },
  payloads: { input: "does it work on install?", output: "yes" },
});
const verdict = await verifyEvidence(evidence);
await cool.close();

console.log(JSON.stringify({
  ok: verdict.ok,
  binding: verdict.checks.binding.status,
  signature: verdict.checks.signature.status,
  inclusion: verdict.checks.inclusion.status,
  attestation: verdict.checks.attestation.status,
  enclave: verdict.checks.enclave.status,
  plaintextLeaked:
    JSON.stringify(evidence).includes("does it work on install?") ||
    JSON.stringify(evidence).includes('"model":"example-model"'),
}));
`,
  );
  const output = run("node", ["use.mjs"], work);
  const summary = JSON.parse(output.trim().split("\n").pop() ?? "{}");
  check("the record verifies", summary.ok === true, JSON.stringify(summary));
  check(
    "binding + signature + inclusion pass",
    summary.binding === "pass" && summary.signature === "pass" && summary.inclusion === "pass",
  );
  check("attestation is labelled, not claimed", summary.attestation === "simulated");
  check("no plaintext in the receipt", summary.plaintextLeaked === false);

  /* 4 · typecheck a consumer under both resolution modes */
  console.log("\ntypechecking a consumer:");
  writeFileSync(
    join(work, "consumer.ts"),
    `import { CooL, verifyEvidence } from "cool-nwc";
import type { Evidence, Verdict } from "cool-nwc";

export async function boot(): Promise<Verdict> {
  const cool = new CooL({
    applicationId: "typed-consumer",
    attestation: { provider: "dstack", endpoint: "/var/run/dstack.sock" },
    security: { requireAttestation: true },
  });
  const { evidence }: { evidence: Evidence } = await cool.record({
    type: "agent.action",
    metadata: { tool: "search" },
  });
  await cool.close();
  return verifyEvidence(evidence, { requireHardware: true });
}
`,
  );

  for (const moduleResolution of ["nodenext", "bundler"]) {
    writeFileSync(
      join(work, `tsconfig.${moduleResolution}.json`),
      JSON.stringify(
        {
          compilerOptions: {
            target: "ES2022",
            lib: ["ES2022", "DOM"],
            module: moduleResolution === "nodenext" ? "nodenext" : "esnext",
            moduleResolution,
            strict: true,
            noEmit: true,
            skipLibCheck: true,
            types: [],
          },
          files: ["consumer.ts"],
        },
        null,
        2,
      ),
    );
    try {
      run(process.execPath, [tsc, "-p", `tsconfig.${moduleResolution}.json`], work);
      check(`types resolve under moduleResolution: ${moduleResolution}`, true);
    } catch (error) {
      check(
        `types resolve under moduleResolution: ${moduleResolution}`,
        false,
        String(error.stdout ?? error.message).split("\n").slice(0, 5).join(" | "),
      );
    }
  }

  /* 5 · subpath exports */
  console.log("\nsubpath exports:");
  writeFileSync(
    join(work, "subpaths.mjs"),
    `import { CoolTee } from "cool-nwc/phala";
import { verifyEvidence } from "cool-nwc/verify";
import { FileLog } from "cool-nwc/node";
console.log(JSON.stringify({
  phala: typeof CoolTee === "function",
  verify: typeof verifyEvidence === "function",
  node: typeof FileLog === "function",
}));
`,
  );
  const subpaths = JSON.parse(run("node", ["subpaths.mjs"], work).trim().split("\n").pop() ?? "{}");
  check("'/phala' entry point resolves", subpaths.phala === true);
  check("'/verify' entry point resolves", subpaths.verify === true);
  check("'/node' entry point resolves", subpaths.node === true);

  /* 6 · the `cool` command a global install puts on PATH */
  console.log("\nthe cool command:");
  const bin = join(work, "node_modules", "cool-nwc", "dist", "cli", "index.js");
  const version = run(process.execPath, [bin, "--version"], work).trim();
  check("`cool --version` answers", /^\d+\.\d+\.\d+$/.test(version), version);
  check(
    "`cool --help` lists the commands",
    run(process.execPath, [bin, "--help"], work).includes("walkthrough"),
  );

  const sealed = run(process.execPath, [bin, "seal", "prompt", "pkg#system", "installed"], work);
  check("`cool seal` writes a receipt", /sealed 0[0-9A-HJKMNP-TV-Z]{25}/.test(sealed));
  const verified = run(process.execPath, [bin, "verify", "last"], work);
  check("`cool verify last` accepts it", verified.includes("receipt verifies"));
  check("and labels the simulated attestation", verified.includes("simulated"));
} finally {
  rmSync(work, { recursive: true, force: true });
}

console.log(
  failures === 0
    ? "\nThe published package works on install.\n"
    : `\n${failures} check(s) FAILED.\n`,
);
process.exit(failures === 0 ? 0 : 1);
