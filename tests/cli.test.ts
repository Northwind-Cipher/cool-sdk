/**
 * The `cool` command, driven the way a user drives it.
 *
 * A CLI is the one part of a library that cannot be unit-tested into working:
 * its contract is a process, an exit code and some bytes on stdout. So these
 * tests spawn it — in a throwaway directory, with a pipe for stdin — and assert
 * the things a person or a pipeline actually depends on:
 *
 *   • `--version` and `--help` answer without booting an enclave;
 *   • `seal` writes a receipt file and `verify` accepts it;
 *   • a tampered receipt makes `verify` exit non-zero, because that exit code is
 *     what a CI job gates on;
 *   • `verify` on a file works with no enclave at all, which is the auditor's
 *     situation;
 *   • the interactive session runs its commands and leaves cleanly.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(root, "src", "cli", "index.ts");

/**
 * The TypeScript loader, as an absolute URL.
 *
 * `--import tsx` resolves against the child's working directory, and these tests
 * deliberately run in an empty temp directory — the same place a user would be.
 * Resolving it here keeps the child honest about its cwd.
 */
const LOADER = pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;

interface Run {
  stdout: string;
  code: number;
}

/** Run the CLI through tsx, with colour off so assertions match plain text. */
function cool(args: string[], cwd: string, input = ""): Run {
  try {
    const stdout = execFileSync(process.execPath, ["--import", LOADER, CLI, ...args], {
      cwd,
      input,
      encoding: "utf8",
      env: { ...process.env, NO_COLOR: "1", COOL_ENV: "test" },
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { stdout, code: 0 };
  } catch (error) {
    const err = error as { stdout?: string; status?: number };
    return { stdout: err.stdout ?? "", code: err.status ?? 1 };
  }
}

function workspace(): string {
  return mkdtempSync(join(tmpdir(), "cool-cli-"));
}

test("--version and --help answer without an enclave", () => {
  const dir = workspace();
  try {
    const version = cool(["--version"], dir);
    // Run from source there is no published package.json above the module, so
    // the CLI reports the `-dev` fallback. The installed binary reports the
    // package's real version — `npm run verify:package` asserts that equality.
    assert.match(version.stdout.trim(), /^\d+\.\d+\.\d+(-dev)?$/);
    assert.equal(version.code, 0);

    const help = cool(["--help"], dir);
    assert.match(help.stdout, /commands/, "the manual lists commands");
    assert.match(help.stdout, /concepts/, "…and the concepts behind them");
    assert.match(help.stdout, /walkthrough/);
    assert.equal(help.code, 0);

    // Documentation-grade help: a command page, and a concept page.
    const verifyDoc = cool(["help", "verify"], dir);
    assert.match(verifyDoc.stdout, /Examples/);
    assert.match(verifyDoc.stdout, /--require-hardware/);
    const conceptDoc = cool(["help", "attestation"], dir);
    assert.match(conceptDoc.stdout, /simulated/);
    assert.match(conceptDoc.stdout, /report_data|64 bytes/);
    // An unknown subject suggests rather than shrugs.
    const missing = cool(["help", "attestashun"], dir);
    assert.equal(missing.code, 1);
    assert.match(missing.stdout, /Did you mean/);
    // Nothing was sealed just by asking for help.
    assert.equal(readdirSync(dir).includes(".cool"), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("seal writes a receipt, verify accepts it, exit code 0", () => {
  const dir = workspace();
  try {
    const sealed = cool(["seal", "prompt", "billing/agent#system", "hello"], dir);
    assert.equal(sealed.code, 0);
    assert.match(sealed.stdout, /sealed 0[0-9A-HJKMNP-TV-Z]{25}/);

    const files = readdirSync(join(dir, ".cool", "receipts"));
    assert.equal(files.length, 1);

    const verified = cool(["verify", "last"], dir);
    assert.equal(verified.code, 0);
    assert.match(verified.stdout, /receipt verifies/);
    assert.match(verified.stdout, /simulated/, "a simulated run must say so");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a tampered receipt exits non-zero — the code CI gates on", () => {
  const dir = workspace();
  try {
    cool(["seal", "prompt", "app#system", "before"], dir);
    const receipts = join(dir, ".cool", "receipts");
    const name = readdirSync(receipts)[0]!;
    const path = join(receipts, name);

    const receipt = JSON.parse(readFileSync(path, "utf8")) as {
      record: { change: { after_hash: string } };
    };
    receipt.record.change.after_hash = receipt.record.change.after_hash.replace(/.$/, (ch) =>
      ch === "0" ? "1" : "0",
    );
    writeFileSync(path, JSON.stringify(receipt, null, 2));

    const verdict = cool(["verify", path], dir);
    assert.equal(verdict.code, 1);
    assert.match(verdict.stdout, /receipt REJECTED/);
    assert.match(verdict.stdout, /fail\s+binding/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("verify works on a bare file, with no enclave in the directory", () => {
  const source = workspace();
  const auditor = workspace();
  try {
    cool(["seal", "prompt", "app#system", "shipped"], source);
    const name = readdirSync(join(source, ".cool", "receipts"))[0]!;
    const path = join(source, ".cool", "receipts", name);

    // The auditor's directory has never run `cool`, and never will.
    const verdict = cool(["verify", path], auditor);
    assert.equal(verdict.code, 0);
    assert.match(verdict.stdout, /receipt verifies/);
    assert.equal(readdirSync(auditor).includes(".cool"), false);
  } finally {
    rmSync(source, { recursive: true, force: true });
    rmSync(auditor, { recursive: true, force: true });
  }
});

test("--require-hardware refuses a simulated receipt", () => {
  const dir = workspace();
  try {
    cool(["seal", "prompt", "app#system", "x"], dir);
    const strict = cool(["verify", "last", "--require-hardware"], dir);
    assert.equal(strict.code, 1);
    assert.match(strict.stdout, /receipt REJECTED/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the interactive session runs commands and exits cleanly", () => {
  const dir = workspace();
  try {
    const session = cool(
      ["repl"],
      dir,
      '/help\n/seal prompt app#system "hello"\n/verify last\n/stats\n/exit\n',
    );
    assert.equal(session.code, 0);
    assert.match(session.stdout, /commands/);
    assert.match(session.stdout, /sealed 0/);
    assert.match(session.stdout, /receipt verifies/);
    assert.match(session.stdout, /capture cost/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the walkthrough teaches by doing, and leaves the evidence behind", () => {
  const dir = workspace();
  try {
    const run = cool(["walkthrough"], dir);
    assert.equal(run.code, 0);
    // Every step actually happened rather than being narrated.
    assert.match(run.stdout, /sealed 0[0-9A-HJKMNP-TV-Z]{25}/, "1 · seal");
    assert.match(run.stdout, /receipt verifies/, "2 · verify");
    assert.match(run.stdout, /receipt REJECTED/, "3 · tamper");
    assert.match(run.stdout, /approved \(POL-002\)/, "4 · policy approves with two approvers");
    assert.match(run.stdout, /escalate \(POL-031\)/, "4 · …and escalates a permission widening");
    assert.match(run.stdout, /exactly what was committed/, "5 · disclosure");
    assert.match(run.stdout, /obligations/, "6 · audit pack");
    // The records are real and still there afterwards.
    assert.ok(readdirSync(join(dir, ".cool", "receipts")).length > 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the log grows across invocations instead of restarting", () => {
  const dir = workspace();
  try {
    cool(["seal", "prompt", "app#system", "one"], dir);
    cool(["seal", "prompt", "app#system", "two"], dir);
    const log = cool(["log"], dir);
    assert.match(log.stdout, /tree size\s+2/, "one tree, two leaves");
    assert.equal(cool(["verify", "all"], dir).code, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("witnessing makes the witnesses domain pass, honestly", () => {
  const dir = workspace();
  try {
    cool(["seal", "prompt", "app#system", "x"], dir);
    assert.match(cool(["verify", "last"], dir).stdout, /absent\s+witnesses/);
    const witnessed = cool(["witness", "cosign", "--key", "auditor"], dir);
    assert.equal(witnessed.code, 0);
    const after = cool(["verify", "last"], dir);
    assert.match(after.stdout, /pass\s+witnesses/);
    assert.match(after.stdout, /1 independent/);
    assert.match(after.stdout, /not counted/, "the self-signature is still excluded");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("disclosure opens one field and refuses the wrong text", () => {
  const dir = workspace();
  try {
    cool(["seal", "prompt", "app#system", "Approve refunds up to $500."], dir);
    const opened = cool(["disclose", "last", "change.after", "Approve refunds up to $500."], dir);
    assert.equal(opened.code, 0);
    assert.match(opened.stdout, /commitment/);
    const wrong = cool(["disclose", "last", "change.after", "something else"], dir);
    assert.equal(wrong.code, 1);
    assert.match(wrong.stdout, /does not match/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("policy prints its rules and can be dry-run", () => {
  const dir = workspace();
  try {
    const rules = cool(["policy"], dir);
    assert.match(rules.stdout, /POL-031/);
    assert.match(rules.stdout, /fallback/);
    const test1 = cool(["policy", "test", "agent-permission", "app#tools", "--env", "prod"], dir);
    assert.match(test1.stdout, /escalate/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("packs build and verify, and a tampered pack is rejected", () => {
  const dir = workspace();
  try {
    cool(["seal", "prompt", "app#system", "x"], dir);
    const built = cool(["pack", "build", "--out", "audit.json"], dir);
    assert.equal(built.code, 0);
    const path = join(dir, "audit.json");
    assert.equal(cool(["pack", "verify", path], dir).code, 0);

    const pack = JSON.parse(readFileSync(path, "utf8"));
    const record = pack.records[0].receipt.record;
    record.change.after_hash = record.change.after_hash.replace(/.$/, (ch: string) =>
      ch === "0" ? "1" : "0",
    );
    writeFileSync(path, JSON.stringify(pack));
    const verdict = cool(["pack", "verify", path], dir);
    assert.equal(verdict.code, 1);
    assert.match(verdict.stdout, /FAILED|failed/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("doctor reports the environment without pretending", () => {
  const dir = workspace();
  try {
    const report = cool(["doctor"], dir);
    assert.match(report.stdout, /node/);
    assert.match(report.stdout, /dstack endpoint/);
    assert.match(report.stdout, /simulator/, "an unset endpoint must be called out");
    assert.match(report.stdout, /seal \+ verify/);
    // Warnings, not failures: a laptop without a CVM is a supported state.
    assert.equal(report.code, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
