#!/usr/bin/env node
/**
 * `cool` — the command line for the evidence plane.
 *
 * Two modes, one implementation:
 *
 *   cool                    an interactive session: banner, prompt, panels
 *   cool verify last        the same commands, one shot, with an exit code
 *
 * Anything the interactive session can do, a pipeline can do too — there is no
 * interactive-only behaviour, and every command returns an exit code that means
 * something. The interactive mode exists because a prompt is a good place to
 * learn, not because it is a different product.
 *
 * Everything is built on `node:readline` and raw ANSI: no dependency in this CLI
 * that is not already required to compute a signature.
 */
import { createInterface } from "node:readline";
import { openWorkspace, type Workspace } from "./workspace";
import {
  VERSION,
  attest,
  banner,
  doctor,
  exportPack,
  seal,
  statusPanel,
  stats,
  verifyCommand,
} from "./commands";
import { help } from "./help";
import { walkthrough } from "./walkthrough";
import { discloseCommand, logCommand, records, witnessCommand } from "./evidence";
import { complianceCommand, packCommand, policyCommand } from "./governance";
import { Progress, c, clear, g, out } from "./tty";
import { updateNotice } from "./update";
import { updateCommand } from "./update-command";
import { wire } from "./wire";
import { anchorCommand } from "./anchor";
import { ui } from "./ui/index";

const USAGE = `
  ${c.bold("cool")} ${c.faint("— tamper-evident evidence for AI, sealed in a TEE")}

  ${c.brand("cool")}                        open the interactive session
  ${c.brand("cool ui")} [folder]            watch a real project in a browser console
  ${c.brand("cool walkthrough")}            learn the whole model in three minutes
  ${c.brand("cool help")} [command|topic]   the manual, including the concepts

  ${c.faint("evidence")}   seal · verify · records · disclose · log · witness
  ${c.faint("governance")} policy · compliance · pack
  ${c.faint("runtime")}    status · attest · stats · doctor · update · wire · ui

  ${c.faint("env")}  DSTACK_ENDPOINT      talk to a real guest agent inside a CVM
       QUOTE_VERIFIER_URL   chain hardware quotes to Intel/AMD
       COOL_ENV             environment recorded on each change (default: dev)

  ${c.faint("Receipts are written to")} ${c.dim(".cool/receipts/")}${c.faint(
    ", the log to",
  )} ${c.dim(".cool/log/")}${c.faint(".")}
`;

async function boot(quiet = false): Promise<Workspace> {
  const progress = quiet ? null : new Progress().start("starting the evidence plane");
  try {
    const workspace = await openWorkspace();
    progress?.succeed(
      `evidence plane ready ${c.faint(
        `(${workspace.info.vendor} · ${workspace.info.mode} · log ${workspace.cool.plane.logSize})`,
      )}`,
    );
    return workspace;
  } catch (error) {
    progress?.fail(`could not start: ${(error as Error).message}`);
    throw error;
  }
}

/** One command, from either mode. Returns a process exit code. */
async function run(name: string, args: string[], workspace: Workspace | null): Promise<number> {
  switch (name) {
    case "help":
    case "--help":
    case "-h":
      return help(args);
    case "walkthrough":
    case "tour":
      if (workspace) await walkthrough(workspace);
      return 0;
    case "status":
      if (workspace) statusPanel(workspace);
      return 0;
    case "seal":
      if (workspace) await seal(workspace, args);
      return 0;
    case "verify":
      return verifyCommand(workspace, args);
    case "records":
    case "ls":
      return records(workspace, args);
    case "disclose":
      return discloseCommand(workspace, args);
    case "witness":
      return witnessCommand(workspace, args);
    case "log":
      return workspace ? logCommand(workspace, args) : 1;
    case "policy":
      return policyCommand(args);
    case "compliance":
      return complianceCommand(workspace, args);
    case "pack":
      return packCommand(workspace, args);
    case "stats":
      await stats(workspace);
      return 0;
    case "attest":
      if (workspace) attest(workspace);
      return 0;
    case "export":
      if (workspace) await exportPack(workspace, args);
      return 0;
    case "update":
    case "upgrade":
      return updateCommand(args);
    case "anchor":
      return workspace ? anchorCommand(workspace, args) : 1;
    case "wire":
      return workspace ? wire(workspace) : 1;
    case "ui":
    case "console":
    case "dashboard":
      return ui(workspace, args);
    case "doctor":
      return doctor(workspace);
    default:
      out(`  ${c.red(g.fail)} unknown command ${c.bold(name)} — try ${c.brand("cool help")}`);
      return 1;
  }
}

/* ── interactive ──────────────────────────────────────────────────────── */

const SLASH = [
  "/help",
  "/walkthrough",
  "/status",
  "/seal",
  "/verify",
  "/records",
  "/disclose",
  "/witness",
  "/log",
  "/policy",
  "/compliance",
  "/pack",
  "/stats",
  "/attest",
  "/doctor",
  "/update",
  "/wire",
  "/ui",
  "/clear",
  "/exit",
];

async function interactive(): Promise<void> {
  clear();
  const workspace = await boot();
  out();
  banner(workspace);

  // One quiet line, after the banner, only in the interactive session. A
  // scripted run does no network I/O at all.
  const notice = await updateNotice(VERSION, workspace.root);
  if (notice) {
    out(`  ${c.yellow(g.warn)} ${c.faint(notice)}`);
    out();
  }

  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: `  ${c.brand(g.arrow)} `,
    historySize: 200,
    completer: (line: string) => {
      const hits = SLASH.filter((cmd) => cmd.startsWith(line));
      return [hits.length > 0 ? hits : SLASH, line];
    },
  });

  rl.prompt();

  for await (const line of rl) {
    const input = line.trim();
    if (input.length === 0) {
      rl.prompt();
      continue;
    }
    if (input === "/exit" || input === "exit" || input === "quit" || input === "/quit") break;
    if (input === "/clear" || input === "clear") {
      clear();
      banner(workspace);
      rl.prompt();
      continue;
    }

    const [word, ...args] = input.replace(/^\//, "").split(/\s+/);
    out();
    try {
      await run(word ?? "help", args, workspace);
    } catch (error) {
      out(`  ${c.red(g.fail)} ${(error as Error).message}`);
      out();
    }
    rl.prompt();
  }

  rl.close();
  out();
  out(
    `  ${c.faint("Receipts stay in")} ${c.dim(".cool/receipts/")}${c.faint(
      ". Anyone can verify them with",
    )} ${c.brand("cool verify all")}${c.faint(".")}`,
  );
  out();
  await workspace.cool.close();
}

/* ── entry ────────────────────────────────────────────────────────────── */

async function main(): Promise<void> {
  const argv = process.argv.slice(2);

  if (argv.includes("--version") || argv.includes("-v")) {
    out(VERSION);
    return;
  }
  // `repl` forces the session open even when stdin is a pipe — which is how it
  // gets tested, and how it runs in terminals that do not report a TTY.
  if (argv[0] === "repl" || (argv.length === 0 && process.stdin.isTTY)) {
    await interactive();
    return;
  }
  if (argv.length === 0) {
    out(USAGE);
    return;
  }

  const [name, ...args] = argv;
  // Reading and checking evidence needs no enclave — an auditor should be able
  // to work on a machine that has never run one.
  const readOnly =
    name === "help" ||
    name === "--help" ||
    name === "-h" ||
    name === "policy" ||
    name === "update" ||
    name === "upgrade" ||
    // `ui` takes a folder and opens the plane for THAT folder. Booting one here
    // first would create a `.cool/` in whatever directory the command happened
    // to be typed in — a stray log, in someone else's repository.
    name === "ui" ||
    name === "console" ||
    name === "dashboard" ||
    (name === "verify" && args.some((arg) => !arg.startsWith("--") && arg.includes(".")));
  const workspace = readOnly ? null : await boot(true);

  const code = await run(name ?? "help", args, workspace);
  if (workspace) await workspace.cool.close();
  process.exitCode = code;
}

void main().catch((error: unknown) => {
  out(`  ${c.red("cool:")} ${(error as Error).message}`);
  process.exitCode = 1;
});
