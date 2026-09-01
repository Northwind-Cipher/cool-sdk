/**
 * The CLI's view of a project: where the evidence plane comes from, and where
 * receipts go.
 *
 * Two decisions shape everything else here.
 *
 * The plane is chosen from the environment, not from a flag, because the whole
 * point is that the same command behaves differently — and says so — depending
 * on whether it is inside a confidential VM. Set `DSTACK_ENDPOINT` and `cool`
 * talks to the guest agent; leave it unset and it runs the simulator and labels
 * every receipt it writes.
 *
 * Receipts land in `.cool/receipts/` beside the code they describe. A file per
 * record, named by its id: greppable, diffable, and trivially attachable to a
 * ticket or an audit request. There is no database and no daemon.
 */
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { CoolTee, DEFAULT_POLICY, HttpDstackClient, SimulatedDstackClient } from "../phala/index";
import { FileLog } from "../phala/log-file";
import { transportFor } from "../phala/unix";
import type { CaptureStats, DstackClient, EnclaveInfo, ReceiptV2, VerdictV2 } from "../phala/index";
import { remoteQuoteVerifier, sealedKeyset, verifyReceiptV2 } from "../phala/index";
import type { QuoteVerifier } from "../phala/index";

export const RECEIPT_DIR = ".cool/receipts";

export interface Workspace {
  readonly cool: CoolTee;
  /** The project's on-disk log, when one is in use. */
  readonly log: FileLog | null;
  readonly info: EnclaveInfo;
  readonly root: string;
  readonly verifier: QuoteVerifier | null;
}

/** Stable per-project image digest, so a project's key id does not wander. */
function projectImage(root: string): string {
  const digest = createHash("sha256").update(`cool-cli:${root}`).digest("hex").slice(0, 32);
  return `sha256:${digest}`;
}

/** Boot an evidence plane for the current directory. */
export async function openWorkspace(root = process.cwd()): Promise<Workspace> {
  // Three ways in, in the order a real deployment tries them:
  //   DSTACK_ENDPOINT           the guest agent inside a CVM (usually a socket)
  //   DSTACK_SIMULATOR_ENDPOINT Phala's own local simulator, which speaks the
  //                             real agent protocol — the honest halfway house
  //   nothing                   CooL's in-process simulator, labelled as such
  const endpoint =
    process.env["DSTACK_ENDPOINT"] ?? process.env["DSTACK_SIMULATOR_ENDPOINT"];
  const verifierUrl = process.env["QUOTE_VERIFIER_URL"];

  const client: DstackClient = endpoint
    ? new HttpDstackClient({
        endpoint,
        vendor: (process.env["DSTACK_VENDOR"] as "intel-tdx") ?? "intel-tdx",
        ...(process.env["DSTACK_INFO_METHOD"] === "POST" ? { infoMethod: "POST" as const } : {}),
        // A unix socket or a Windows named pipe needs node:http; `fetch` cannot
        // open one, which is what made /var/run/dstack.sock fail before.
        ...(transportFor(endpoint) ? { fetchImpl: transportFor(endpoint)! as typeof fetch } : {}),
      })
    : new SimulatedDstackClient({
        appName: basename(root) || "cool-cli",
        imageDigest: process.env["IMAGE_DIGEST"] ?? projectImage(root),
      });

  const verifier = verifierUrl
    ? remoteQuoteVerifier({
        endpoint: verifierUrl,
        root: "intel-dcap",
        ...(process.env["QUOTE_VERIFIER_KEY"]
          ? { headers: { authorization: `Bearer ${process.env["QUOTE_VERIFIER_KEY"]}` } }
          : {}),
      })
    : null;

  const info = await client.info();

  // One tree per project, kept in .cool/log and appended to across runs. Without
  // this every invocation would start a fresh tree of size one, and a hundred
  // such trees prove nothing about ordering or completeness.
  const keys = await sealedKeyset(client);
  const log = new FileLog({
    dir: join(root, ".cool", "log"),
    logId: `cool-${basename(root)}`,
    logKey: keys.log,
  });

  const cool = await CoolTee.connect({
    log,
    governance: DEFAULT_POLICY,
    dstack: client,
    expectedMeasurement: info.measurement,
    policy: {
      expectedMeasurement: info.measurement,
      ...(verifier ? { verifier } : { requireVerifiedRoot: false }),
    },
    logId: `cool-cli-${basename(root)}`,
    capture: { flushMs: 1 },
  });

  return { cool, info, root, verifier, log };
}

/** Persist a receipt where a human or a CI job can find it. */
export function saveReceipt(root: string, receipt: ReceiptV2): string {
  const dir = join(root, RECEIPT_DIR);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${receipt.record.record_id}.json`);
  writeFileSync(path, `${JSON.stringify(receipt, null, 2)}\n`);
  return path;
}

export interface StoredReceipt {
  readonly path: string;
  readonly receipt: ReceiptV2;
}

/** Every receipt in the project, oldest first. */
export function loadReceipts(root = process.cwd()): StoredReceipt[] {
  const dir = join(root, RECEIPT_DIR);
  let names: string[];
  try {
    names = readdirSync(dir).filter((name) => name.endsWith(".json"));
  } catch {
    return [];
  }
  const stored: StoredReceipt[] = [];
  for (const name of names.sort()) {
    const path = join(dir, name);
    try {
      stored.push({ path, receipt: JSON.parse(readFileSync(path, "utf8")) as ReceiptV2 });
    } catch {
      // A corrupt file is a finding, not a crash — `cool verify` will say so.
    }
  }
  return stored;
}

export function readReceipt(path: string): ReceiptV2 {
  return JSON.parse(readFileSync(resolve(path), "utf8")) as ReceiptV2;
}

/** Verify with whatever this environment can honestly check. */
export async function verify(
  receipt: ReceiptV2,
  workspace: Workspace | null,
  options: { requireHardware?: boolean; pin?: boolean } = {},
): Promise<VerdictV2> {
  return verifyReceiptV2(receipt, {
    ...(workspace?.verifier ? { quoteVerifier: workspace.verifier } : {}),
    ...(options.requireHardware ? { requireHardware: true } : {}),
    ...(options.pin && workspace ? { expectedMeasurement: workspace.info.measurement } : {}),
  });
}

/* ── analytics ────────────────────────────────────────────────────────── */

export interface Analytics {
  readonly total: number;
  readonly changes: number;
  readonly evidence: number;
  readonly byKind: [string, number][];
  readonly verified: number;
  readonly failed: number;
  readonly hardware: number;
  readonly simulated: number;
  /** Records per day over the last fortnight, oldest first. */
  readonly perDay: number[];
  readonly capture: CaptureStats | null;
  readonly treeSize: number;
}

export async function analytics(
  stored: StoredReceipt[],
  workspace: Workspace | null,
): Promise<Analytics> {
  const kinds = new Map<string, number>();
  let changes = 0;
  let evidence = 0;
  let hardware = 0;
  let simulated = 0;
  let verified = 0;
  let failed = 0;

  const days = 14;
  const perDay = new Array<number>(days).fill(0);
  const today = new Date().setHours(0, 0, 0, 0);

  for (const { receipt } of stored) {
    if (receipt.record.schema === "cool.change.v2") {
      changes++;
      const kind = receipt.record.change.kind;
      kinds.set(kind, (kinds.get(kind) ?? 0) + 1);
    } else {
      evidence++;
      const type = receipt.record.event.type;
      kinds.set(type, (kinds.get(type) ?? 0) + 1);
    }

    if (receipt.record.runtime.mode === "hardware") hardware++;
    else simulated++;

    const at = new Date(receipt.record.time.issued_at).setHours(0, 0, 0, 0);
    const index = days - 1 - Math.round((today - at) / 86_400_000);
    if (index >= 0 && index < days) perDay[index] = (perDay[index] ?? 0) + 1;

    const verdict = await verify(receipt, workspace);
    if (verdict.ok) verified++;
    else failed++;
  }

  return {
    total: stored.length,
    changes,
    evidence,
    byKind: [...kinds.entries()].sort((a, b) => b[1] - a[1]),
    verified,
    failed,
    hardware,
    simulated,
    perDay,
    capture: workspace?.cool.stats() ?? null,
    treeSize: stored.at(-1)?.receipt.sth?.tree_size ?? 0,
  };
}
