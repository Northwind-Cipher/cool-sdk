/**
 * `cool ui` — the console, over a real project.
 *
 * This is the same product the website demonstrates, with the two things a
 * demo cannot have: your files and your hardware. It opens a folder, seeds a
 * baseline from git so the first `before` is the committed contents rather than
 * an invented blank, watches for saves, and seals each real change into the
 * project's own on-disk log.
 *
 * What it deliberately does not do is decide anything about trust. The runtime
 * mode comes from whether a guest agent answers on `DSTACK_ENDPOINT`, and the
 * attestation verdict comes from whether a vendor root could check the quote.
 * Both are reported. Neither is improved by this file.
 *
 *     cool ui                    watch the current folder, open a browser
 *     cool ui ./agents           watch a subfolder
 *     cool ui --port 7000        somewhere else
 *     cool ui --host 0.0.0.0     expose it (inside a CVM, behind the gateway)
 *     cool ui --no-open          do not launch a browser
 */
import { spawn } from "node:child_process";
import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { basename, join, resolve, sep } from "node:path";
import { openWorkspace, type Workspace } from "../workspace";
import { c, g, out } from "../tty";
import { committedContents, gitContext, trackedFiles } from "./git";
import { shouldWatch, watchProject, type Watcher } from "./watch";
import { Console } from "./server";

const DEFAULT_PORT = 4319;

interface Args {
  readonly root: string;
  readonly port: number;
  readonly host: string;
  readonly environment: string;
  readonly open: boolean;
}

function parse(argv: string[]): Args {
  let root = process.cwd();
  let port = DEFAULT_PORT;
  let host = "127.0.0.1";
  let environment = process.env["COOL_ENV"] ?? "dev";
  let open = true;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--port" || arg === "-p") port = Number(argv[++i]) || DEFAULT_PORT;
    else if (arg === "--host") host = argv[++i] ?? host;
    else if (arg === "--env") environment = argv[++i] ?? environment;
    else if (arg === "--no-open") open = false;
    else if (!arg.startsWith("-")) root = resolve(arg);
  }

  return { root, port, host, environment, open };
}

/** Open the default browser, and never fail the command if it cannot. */
function launch(url: string): void {
  const command =
    process.platform === "win32" ? "cmd" : process.platform === "darwin" ? "open" : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  try {
    spawn(command, args, { stdio: "ignore", detached: true, windowsHide: true }).unref();
  } catch {
    // Headless machines and CVMs have no browser. The URL is printed anyway.
  }
}

/**
 * Seed the watcher's idea of "before".
 *
 * Preferring git's committed contents over the current bytes is what makes the
 * first change after startup a real diff. Seeding from the working tree instead
 * would make every first save look like a no-op, because the baseline would
 * already be the edited file.
 */
function baselineFor(root: string): { baseline: Map<string, string>; seeded: number } {
  const baseline = new Map<string, string>();
  let seeded = 0;

  for (const relative of trackedFiles(root).filter(shouldWatch)) {
    // git speaks POSIX paths on every platform; fs.watch reports the platform's
    // own separators, and the map is looked up by the latter.
    const key = relative.split("/").join(sep);
    const committed = committedContents(root, relative);
    if (committed !== null) {
      baseline.set(key, committed);
      seeded++;
      continue;
    }
    try {
      const absolute = join(root, relative);
      if (statSync(absolute).isFile()) {
        baseline.set(key, readFileSync(absolute, "utf8"));
        seeded++;
      }
    } catch {
      /* unreadable: it will be treated as a first write when it changes */
    }
  }

  return { baseline, seeded };
}

/**
 * The canonical, fully-expanded path of a folder.
 *
 * Not cosmetic. Node's recursive `fs.watch` on Windows asserts inside libuv
 * (`!_wcsnicmp(filename, dir, dirlen)`) and takes the whole process down with
 * it when the watched directory was given as a short 8.3 path — `KAILOS~1`
 * instead of `KAILOSH K` — because the events come back with the long name and
 * no longer match the prefix it was handed. The same happens through a symlink
 * on any platform. Resolving once, here, is the fix; doing it later would leave
 * the workspace and the watcher disagreeing about where the project is.
 */
function canonical(path: string): string {
  try {
    return realpathSync.native(path);
  } catch {
    try {
      return realpathSync(path);
    } catch {
      return path;
    }
  }
}

export async function ui(workspace: Workspace | null, argv: string[]): Promise<number> {
  const parsed = parse(argv);

  if (!existsSync(parsed.root)) {
    out(`  ${c.red(g.fail)} no such folder: ${c.bold(parsed.root)}`);
    return 1;
  }

  const args: Args = { ...parsed, root: canonical(parsed.root) };

  // The console must run against the folder being watched, not the folder the
  // command happened to be typed in — otherwise `.cool/` and the log would land
  // somewhere else entirely.
  const active =
    workspace && workspace.root === args.root ? workspace : await openWorkspace(args.root);

  const projectName = basename(args.root) || "project";
  const git = gitContext(args.root);

  const console_ = new Console({
    workspace: active,
    root: args.root,
    projectName,
    port: args.port,
    host: args.host,
    environment: args.environment,
    onLog: (line) => out(`  ${c.brand(g.arrow)} ${line}`),
  });

  const existing = await console_.loadExisting();

  let url: string;
  let movedFrom: number | null = null;
  try {
    const bound = await console_.listen();
    url = bound.url;
    movedFrom = bound.movedFrom;
  } catch (error) {
    out(`  ${c.red(g.fail)} could not listen on ${args.host} — ${(error as Error).message}`);
    return 1;
  }

  const { baseline, seeded } = baselineFor(args.root);

  let watcher: Watcher | null = null;
  watcher = watchProject({
    root: args.root,
    baseline,
    onChange: (change) => {
      void console_.sealChange(change);
    },
    onError: (message) => {
      out(`  ${c.yellow(g.warn)} ${message}`);
      console_.note(message);
    },
  });

  /* ── what the operator sees ── */

  const hardware = active.info.mode === "hardware";
  const verified = active.verifier !== null;

  out();
  out(`  ${c.bold("cool ui")} ${c.faint("— watching a real project")}`);
  out();
  out(`  ${c.faint("project")}   ${c.bold(projectName)} ${c.faint(args.root)}`);
  if (git.root) {
    out(
      `  ${c.faint("git")}       ${git.branch ?? "detached"}${
        git.commit ? ` · ${git.commit}` : ""
      }${git.author ? ` · ${git.author}` : ""}`,
    );
  } else {
    out(`  ${c.faint("git")}       ${c.dim("not a repository — records carry no commit provenance")}`);
  }
  out(`  ${c.faint("runtime")}   ${active.info.vendor} · ${active.info.mode}`);
  out(
    `  ${c.faint("evidence")}  ${existing} existing · log ${active.cool.plane.logSize} · ${c.dim(
      join(args.root, ".cool"),
    )}`,
  );
  out(`  ${c.faint("watching")}  ${seeded} files`);
  out();

  if (hardware && verified) {
    out(
      `  ${c.green(g.pass)} ${c.bold("hardware attestation active")} — receipts can reach ${c.bold(
        "pass",
      )}`,
    );
  } else if (hardware) {
    out(
      `  ${c.yellow(g.warn)} guest agent answering, but no ${c.bold(
        "QUOTE_VERIFIER_URL",
      )} — quotes are reported, not verified`,
    );
  } else {
    out(
      `  ${c.yellow(g.warn)} ${c.bold("simulated")} — no confidential VM. Every receipt says so in its own body.`,
    );
    out(`    ${c.faint("to reach a real quote:")} ${c.dim("cool help deploy")}`);
  }

  if (movedFrom !== null) {
    out(
      `  ${c.faint(`port ${movedFrom} was busy — using ${url.split(":").pop()} instead`)}`,
    );
  }

  out();
  out(`  ${c.brand(g.arrow)} ${c.bold(url)}`);
  out(`    ${c.faint("edit and save any prompt or config file in this folder")}`);
  out(`    ${c.faint("ctrl-c to stop")}`);
  out();

  if (args.open) launch(url);

  /* ── hold the process open until interrupted ── */

  await new Promise<void>((resolveWait) => {
    const stop = () => {
      out();
      out(`  ${c.faint("stopped. receipts stay in")} ${c.dim(join(args.root, ".cool/receipts"))}`);
      watcher?.close();
      console_.close();
      resolveWait();
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });

  return 0;
}
