/**
 * Telling someone their copy is old.
 *
 * A security tool that silently runs a stale version is a bad outcome, and the
 * usual fix — phoning home on every invocation — is a worse one. So this is
 * deliberately restrained:
 *
 *   • it asks the public npm registry and nothing else, so no server of ours
 *     learns who is running what;
 *   • it sends no identifiers, not even a user agent we chose;
 *   • it caches for a day in the project's own `.cool/` directory;
 *   • it times out in a second and fails silent — a slow network must never make
 *     `cool verify` slow;
 *   • `COOL_NO_UPDATE_CHECK=1` turns it off entirely, and it never runs in CI.
 *
 * It is called from `doctor` and from the interactive banner only. A scripted
 * `cool verify` in a pipeline does no network I/O at all.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const PACKAGE = "cool-nwc";
const CACHE_HOURS = 24;

interface Cached {
  readonly checked_at: number;
  readonly latest: string | null;
}

/** Compare two semver-ish versions. Pre-release suffixes sort before release. */
export function isNewer(candidate: string, current: string): boolean {
  const parse = (v: string) => {
    const [core = "", pre] = v.split("-", 2);
    const parts = core.split(".").map((n) => Number.parseInt(n, 10) || 0);
    return { parts, pre: pre ?? null };
  };
  const a = parse(candidate);
  const b = parse(current);
  for (let i = 0; i < 3; i++) {
    const left = a.parts[i] ?? 0;
    const right = b.parts[i] ?? 0;
    if (left !== right) return left > right;
  }
  // Same numbers: a release beats a pre-release, never the other way round.
  if (a.pre === null && b.pre !== null) return true;
  return false;
}

function cachePath(root: string): string {
  return join(root, ".cool", "update-check.json");
}

function readCache(root: string): Cached | null {
  try {
    return JSON.parse(readFileSync(cachePath(root), "utf8")) as Cached;
  } catch {
    return null;
  }
}

function writeCache(root: string, value: Cached): void {
  try {
    mkdirSync(join(root, ".cool"), { recursive: true });
    writeFileSync(cachePath(root), `${JSON.stringify(value)}\n`);
  } catch {
    // A read-only directory is not a reason to fail a command.
  }
}

/**
 * The newest published version, or null if we should not or could not ask.
 *
 * Never throws. Never blocks for more than a second.
 */
export async function latestVersion(root = process.cwd()): Promise<string | null> {
  if (process.env["COOL_NO_UPDATE_CHECK"] || process.env["CI"]) return null;

  const cached = readCache(root);
  if (cached && Date.now() - cached.checked_at < CACHE_HOURS * 3600_000) {
    return cached.latest;
  }

  try {
    const response = await fetch(`https://registry.npmjs.org/${PACKAGE}/latest`, {
      // 2.5s, and no custom Accept header: the abbreviated-metadata media type
      // is not served on the /latest route and comes back as something json()
      // cannot parse.
      signal: AbortSignal.timeout(2500),
    });
    if (!response.ok) {
      writeCache(root, { checked_at: Date.now(), latest: null });
      return null;
    }
    const body = (await response.json()) as { version?: string };
    const latest = typeof body.version === "string" ? body.version : null;
    writeCache(root, { checked_at: Date.now(), latest });
    return latest;
  } catch {
    // Offline, blocked, slow, or behind a proxy that dislikes us. Not an error.
    writeCache(root, { checked_at: Date.now(), latest: null });
    return null;
  }
}

/** A one-line nudge, or nothing at all. */
export async function updateNotice(current: string, root = process.cwd()): Promise<string | null> {
  const latest = await latestVersion(root);
  if (!latest || !isNewer(latest, current)) return null;
  return `cool ${latest} is available (you have ${current}) — npm i -g ${PACKAGE}@latest`;
}
