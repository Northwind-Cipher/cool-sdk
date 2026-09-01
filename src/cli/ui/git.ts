/**
 * Real provenance, read from the real repository.
 *
 * The demo on the website invents a commit id because a browser tab has no git.
 * This does not: every field below comes out of the repository the user pointed
 * `cool ui` at, and when there is no repository the fields are `null` rather
 * than plausible — a record that says `branch: main` about a directory that is
 * not a git repo is a lie the receipt would then carry forever.
 *
 * `git` is invoked directly rather than through a library. The SDK's dependency
 * list is four cryptography packages and a CBOR codec, and it is going to stay
 * that way; shelling out to a binary the user already has is the smaller cost.
 * Every call is wrapped, short, and returns null on any failure — a missing git,
 * a detached HEAD and an empty repository all have to be survivable, because all
 * three are normal.
 */
import { execFileSync } from "node:child_process";

export interface GitContext {
  /** Absolute path of the repository root, or null when not a repo. */
  readonly root: string | null;
  readonly branch: string | null;
  /** Short hash of HEAD. Null in a repository with no commits yet. */
  readonly commit: string | null;
  readonly commitSubject: string | null;
  /** `Name <email>` of the configured user — who is making this change now. */
  readonly author: string | null;
  readonly authorEmail: string | null;
  readonly remote: string | null;
  /** True when the working tree has uncommitted changes. */
  readonly dirty: boolean;
}

const EMPTY: GitContext = {
  root: null,
  branch: null,
  commit: null,
  commitSubject: null,
  author: null,
  authorEmail: null,
  remote: null,
  dirty: false,
};

/**
 * One git invocation.
 *
 * `stdio: pipe` on stderr matters: git writes "not a git repository" there, and
 * letting it reach the terminal would print an error during what is a perfectly
 * ordinary case — someone running `cool ui` on a plain folder.
 */
function git(cwd: string, args: string[]): string | null {
  try {
    const out = execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 4000,
      windowsHide: true,
    });
    const trimmed = out.trim();
    return trimmed.length > 0 ? trimmed : null;
  } catch {
    return null;
  }
}

/** Read everything worth recording about the repository at `cwd`. */
export function gitContext(cwd: string): GitContext {
  const root = git(cwd, ["rev-parse", "--show-toplevel"]);
  if (!root) return EMPTY;

  // A detached HEAD reports "HEAD" here, which is accurate and worth keeping
  // rather than resolving to something friendlier that would be a guess.
  const branch = git(cwd, ["rev-parse", "--abbrev-ref", "HEAD"]);
  const commit = git(cwd, ["rev-parse", "--short", "HEAD"]);
  const commitSubject = commit ? git(cwd, ["log", "-1", "--format=%s"]) : null;
  const name = git(cwd, ["config", "user.name"]);
  const email = git(cwd, ["config", "user.email"]);
  const remote = git(cwd, ["config", "--get", "remote.origin.url"]);
  const status = git(cwd, ["status", "--porcelain"]);

  return {
    root,
    branch,
    commit,
    commitSubject,
    author: name && email ? `${name} <${email}>` : name,
    authorEmail: email,
    remote,
    dirty: status !== null,
  };
}

/**
 * The previous committed contents of a file.
 *
 * This is what makes the `before` side of a change real rather than remembered.
 * When the file is tracked, the baseline is what git has, so restarting `cool
 * ui` does not reset history or invent an empty previous value. Untracked files
 * return null and are recorded as first writes, which is what they are.
 */
export function committedContents(cwd: string, relativePath: string): string | null {
  // Forward slashes: git's pathspec syntax is POSIX on every platform.
  const spec = relativePath.split(/[\\/]/).join("/");
  return git(cwd, ["show", `HEAD:${spec}`]);
}

/** Files git is tracking, relative to the repository root. */
export function trackedFiles(cwd: string): string[] {
  const out = git(cwd, ["ls-files"]);
  if (!out) return [];
  return out.split("\n").map((line) => line.trim()).filter(Boolean);
}

/**
 * The actor for a change made right now.
 *
 * `session` rather than `oidc`: a person saving a file in an editor is exactly
 * the case the policy set treats as needing human approval, and claiming a CI
 * identity here would route the change down the wrong rule.
 */
export function actorFrom(context: GitContext): { id: string; method: string } {
  if (context.authorEmail) return { id: `user:${context.authorEmail}`, method: "session" };
  if (context.author) return { id: `user:${context.author}`, method: "session" };
  return { id: "user:local", method: "session" };
}

/** Labels the policy engine can match on, and an auditor can read. */
export function labelsFrom(context: GitContext, repoName: string): string[] {
  const labels = [`repo:${repoName}`];
  if (context.branch) labels.push(`branch:${context.branch}`);
  if (context.commit) labels.push(`commit:${context.commit}`);
  return labels;
}
