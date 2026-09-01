/**
 * `cool update` — upgrade in place.
 *
 * The alternative people were doing is uninstall-then-reinstall, which is three
 * commands, easy to get wrong on Windows (the bin shims outlive a half-removed
 * package), and leaves them wondering whether it worked. This is one command
 * that checks the registry, runs the install, and then proves the new binary
 * answers.
 *
 * It refuses to be clever: no self-replacing binary, no download-and-exec. It
 * shells out to `npm install -g`, which is the thing every Node developer
 * already trusts and can run themselves if this ever misbehaves.
 */
import { execFileSync } from "node:child_process";
import { VERSION } from "./commands";
import { isNewer, latestVersion } from "./update";
import { Progress, c, fields, g, out, panel } from "./tty";

const PACKAGE = "cool-nwc";

function npm(args: string[]): { ok: boolean; out: string } {
  try {
    const stdout = execFileSync("npm", args, {
      encoding: "utf8",
      shell: process.platform === "win32",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, out: stdout };
  } catch (error) {
    const err = error as { stdout?: string; stderr?: string; message?: string };
    return { ok: false, out: `${err.stdout ?? ""}${err.stderr ?? ""}${err.message ?? ""}` };
  }
}

export async function updateCommand(args: string[]): Promise<number> {
  const check = args.includes("--check");
  const wanted = args.find((a) => !a.startsWith("--"));

  const progress = new Progress().start("asking the registry");
  const latest = await latestVersion();
  if (latest === null) {
    progress.fail("could not reach the npm registry");
    out(
      `  ${c.faint("Offline, or behind a proxy. You can always install from the domain:")}`,
    );
    out(`    ${c.brand(`npm i -g https://northwindcipher.com/sdk/${PACKAGE}-${VERSION}.tgz`)}`);
    out();
    return 1;
  }
  progress.succeed(`registry says ${c.bold(latest)}`);

  const target = wanted ?? latest;
  const behind = isNewer(latest, VERSION);

  panel("update", [
    `${c.grey("installed")}  ${VERSION}`,
    `${c.grey("latest")}     ${latest}`,
    `${c.grey("status")}     ${
      behind ? c.yellow("an update is available") : c.green("you are on the latest release")
    }`,
  ]);
  out();

  if (check) return behind ? 1 : 0;

  if (!behind && !wanted) {
    out(`  ${c.faint("Nothing to do.")} ${c.faint(`Force it with`)} ${c.brand(`cool update ${latest}`)}`);
    out();
    return 0;
  }

  const install = new Progress().start(`installing ${PACKAGE}@${target}`);
  const result = npm(["install", "-g", `${PACKAGE}@${target}`]);
  if (!result.ok) {
    install.fail("npm refused the install");
    out();
    // The three failures that actually happen, each with the fix.
    const text = result.out;
    if (/EEXIST|File exists/i.test(text)) {
      out(`  ${c.red(g.fail)} a leftover ${c.bold("cool")} shim from an older install is in the way.`);
      out(`  ${c.faint("Windows:")}`);
      out(`    ${c.dim('Remove-Item "$env:APPDATA\\npm\\cool*" -Force')}`);
      out(`  ${c.faint("macOS / Linux:")}`);
      out(`    ${c.dim("rm -f \"$(npm prefix -g)/bin/cool\"")}`);
    } else if (/EACCES|EPERM|permission/i.test(text)) {
      out(`  ${c.red(g.fail)} no permission to write to the global directory.`);
      out(`  ${c.faint("Run the shell as administrator, or point npm somewhere you own:")}`);
      out(`    ${c.dim("npm config set prefix ~/.npm-global")}`);
    } else {
      out(`  ${c.red(g.fail)} ${text.split("\n").find((l) => l.trim()) ?? "unknown error"}`);
    }
    out();
    out(`  ${c.faint("Full output:")}`);
    for (const line of text.split("\n").slice(0, 8)) out(`    ${c.faint(line)}`);
    out();
    return 1;
  }

  // Prove it, rather than assuming npm did what it said.
  const check2 = npm(["ls", "-g", "--depth=0", PACKAGE]);
  const installed = /cool-nwc@([0-9][^\s]*)/.exec(check2.out)?.[1] ?? "unknown";
  install.succeed(`installed ${c.bold(`${PACKAGE}@${installed}`)}`);

  fields([
    ["was", VERSION],
    ["now", installed],
    ["next", "run `cool doctor` to confirm, or `cool walkthrough` for what changed"],
  ]);
  out();
  out(
    `  ${c.faint("This process is still running the old code — the new one is on the next invocation.")}`,
  );
  out();
  return 0;
}
