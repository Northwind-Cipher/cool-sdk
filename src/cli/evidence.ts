/**
 * The commands that work on evidence already sealed: searching it, opening one
 * field of it, witnessing the log, and inspecting the tree itself.
 *
 * All four operate on receipts loaded from disk, which is deliberate — every one
 * of them works for somebody who was handed a directory of JSON files and has no
 * enclave, no account and no reason to trust whoever produced them.
 */
import { writeFileSync, readFileSync } from "node:fs";
import { basename, relative } from "node:path";
import {
  attachWitness,
  cosign,
  countWitnesses,
  disclosableFields,
  disclose,
  environmentOf,
  query,
  subjectOf,
  verifyDisclosure,
} from "../phala/index";
import type { DisclosableField, Disclosure, Query, ReceiptV2 } from "../phala/index";
import { generateKeypair } from "../keys";
import { loadReceipts, saveReceipt, type Workspace } from "./workspace";
import { Progress, c, fields, g, out, panel, pad } from "./tty";

/* ── records ──────────────────────────────────────────────────────────── */

const flag = (args: string[], name: string): string | undefined => {
  const index = args.indexOf(`--${name}`);
  return index >= 0 ? args[index + 1] : undefined;
};

/** `cool records` — the question "what happened here" as a table. */
export function records(workspace: Workspace | null, args: string[]): number {
  const stored = loadReceipts(workspace?.root);
  const q: Query = {
    ...(flag(args, "kind") ? { changeKinds: [flag(args, "kind") as never] } : {}),
    ...(flag(args, "ref") ? { subject: flag(args, "ref")! } : {}),
    ...(flag(args, "env") ? { environment: flag(args, "env")! } : {}),
    ...(flag(args, "actor") ? { actor: flag(args, "actor")! } : {}),
    ...(flag(args, "decision") ? { decision: flag(args, "decision") as never } : {}),
    ...(flag(args, "since") ? { since: flag(args, "since")! } : {}),
    ...(flag(args, "limit") ? { limit: Number(flag(args, "limit")) } : {}),
  };

  const found = query(
    stored.map((entry) => entry.receipt),
    q,
  );

  if (found.length === 0) {
    out(
      `  ${c.faint(
        stored.length === 0
          ? "No records in this project yet — try `cool walkthrough`."
          : `No records match. ${stored.length} exist; try fewer filters.`,
      )}`,
    );
    out();
    return 0;
  }

  out();
  out(
    `  ${c.grey(pad("WHEN", 20))}${c.grey(pad("KIND", 18))}${c.grey(pad("SUBJECT", 34))}${c.grey("ENV")}`,
  );
  for (const receipt of found) {
    const isChange = receipt.record.schema === "cool.change.v2";
    const kind = isChange
      ? receipt.record.change.kind
      : receipt.record.schema === "cool.evidence.v1"
        ? receipt.record.event.type
        : "evidence";
    const decision = isChange ? receipt.record.change.approval?.decision : null;
    const mark =
      decision === "rejected" ? c.red(g.warn) : decision ? c.green(g.pass) : c.faint(g.dot);
    out(
      `  ${mark} ${pad(receipt.record.time.issued_at.slice(0, 19).replace("T", " "), 20)}` +
        `${c.cyan(pad(kind, 17))}${pad(subjectOf(receipt).slice(0, 32), 34)}` +
        `${c.faint(environmentOf(receipt) ?? "—")}`,
    );
  }
  out();
  out(`  ${c.faint(`${found.length} of ${stored.length} records`)}`);
  out();
  return 0;
}

/* ── disclose ─────────────────────────────────────────────────────────── */

/**
 * `cool disclose` — open one committed field, or check one you were given.
 *
 * The check path takes only a disclosure file and finds its receipt by id, so
 * the person verifying does not need to be told which file to pair it with.
 */
export function discloseCommand(workspace: Workspace | null, args: string[]): number {
  const stored = loadReceipts(workspace?.root);

  const checkPath = flag(args, "check");
  if (checkPath) {
    const disclosure = JSON.parse(readFileSync(checkPath, "utf8")) as Disclosure;
    const match = stored.find((entry) => entry.receipt.record.record_id === disclosure.record_id);
    if (!match) {
      out(`  ${c.red(g.fail)} no receipt in this project for record ${disclosure.record_id}`);
      out();
      return 1;
    }
    const verdict = verifyDisclosure(match.receipt, disclosure);
    out();
    out(
      verdict.ok
        ? `  ${c.green(`${g.pass} ${verdict.detail}`)}`
        : `  ${c.red(`${g.fail} ${verdict.detail}`)}`,
    );
    fields([
      ["record", disclosure.record_id],
      ["field", disclosure.field],
      ["value", disclosure.value.split("\n")[0] ?? ""],
    ]);
    out();
    return verdict.ok ? 0 : 1;
  }

  const [target, field, ...rest] = args.filter((a) => !a.startsWith("--"));
  const value = rest.join(" ");
  const entry =
    !target || target === "last"
      ? stored.at(-1)
      : stored.find((e) => e.receipt.record.record_id === target || basename(e.path) === target);

  if (!entry) {
    out(`  ${c.red(g.fail)} no such record. ${c.faint("Try `cool records`.")}`);
    out();
    return 1;
  }
  if (!field) {
    out(`  ${c.faint("Fields this record can open:")}`);
    for (const f of disclosableFields(entry.receipt)) out(`    ${c.brand(f)}`);
    out();
    return 1;
  }

  try {
    const disclosure = disclose(entry.receipt, field as DisclosableField, value);
    const outPath = flag(args, "out");
    if (outPath) {
      writeFileSync(outPath, `${JSON.stringify(disclosure, null, 2)}\n`);
      out(`  ${c.green(g.pass)} wrote ${c.bold(outPath)}`);
    }
    panel("disclosure", [
      `${c.grey("record")}      ${disclosure.record_id}`,
      `${c.grey("field")}       ${disclosure.field}`,
      `${c.grey("value")}       ${disclosure.value.split("\n")[0]}`,
      `${c.grey("salt")}        ${disclosure.salt}`,
      `${c.grey("commitment")}  ${disclosure.commitment}`,
    ]);
    out();
    out(
      `  ${c.faint("Anyone can check this with")} ${c.brand("cool disclose --check <file>")}${c.faint(
        " — it needs no enclave.",
      )}`,
    );
    out();
    return 0;
  } catch (error) {
    out(`  ${c.red(g.fail)} ${(error as Error).message}`);
    out();
    return 1;
  }
}

/* ── witness ──────────────────────────────────────────────────────────── */

/**
 * `cool witness` — make the witnesses domain mean something.
 *
 * The key is generated from a name so the same witness identity is reproducible
 * across runs; in a real deployment the witness is a different organisation
 * holding its own key, which is the entire point of the exercise.
 */
export function witnessCommand(workspace: Workspace | null, args: string[]): number {
  const stored = loadReceipts(workspace?.root);
  const sub = args[0] ?? "list";

  if (sub === "list") {
    let external = 0;
    let self = 0;
    for (const entry of stored) {
      const counts = countWitnesses(entry.receipt);
      external += counts.external;
      self += counts.self;
    }
    panel("witnesses", [
      `${c.grey("records")}            ${stored.length}`,
      `${c.grey("independent")}        ${external > 0 ? c.green(String(external)) : c.faint("0")}`,
      `${c.grey("self-signatures")}    ${c.faint(`${self} (shown, never counted)`)}`,
    ]);
    out();
    if (external === 0) {
      out(
        `  ${c.faint("Nobody independent has co-signed yet. Try")} ${c.brand(
          "cool witness cosign --key auditor",
        )}`,
      );
      out();
    }
    return 0;
  }

  if (sub !== "cosign") {
    out(`  ${c.red(g.fail)} usage: cool witness [list|cosign --key <name>]`);
    out();
    return 1;
  }
  if (!workspace) {
    out(`  ${c.red(g.fail)} co-signing needs this project's log`);
    return 1;
  }

  const name = flag(args, "key") ?? "auditor";
  const progress = new Progress().start(`co-signing as ${name}`);
  // A named, deterministic key: in production this belongs to somebody else
  // entirely, and that is the property being demonstrated.
  const key = generateKeypair(`witness-${name}`, {
    seed: new Uint8Array(
      Array.from({ length: 32 }, (_, i) => (name.charCodeAt(i % name.length) + i * 7) & 0xff),
    ),
  });

  // Each receipt embeds the tree head it was issued against, and a witness
  // statement is about one specific head. So co-sign the heads that actually
  // exist rather than a fresh one nobody has seen.
  let updated = 0;
  const heads = new Set<string>();
  for (const entry of stored) {
    if (!entry.receipt.sth) continue;
    const statement = cosign(entry.receipt.sth, key);
    saveReceipt(workspace.root, attachWitness(entry.receipt, statement));
    heads.add(`${entry.receipt.sth.log_id}@${entry.receipt.sth.tree_size}`);
    updated++;
  }
  progress.succeed(
    `co-signed ${heads.size} tree head${heads.size === 1 ? "" : "s"} as ${c.bold(key.keyId)}`,
  );

  fields([
    ["receipts updated", String(updated)],
    [
      "note",
      updated === 0
        ? "nothing to witness yet — seal a record first"
        : "verify them again: the witnesses domain now counts one independent signature",
    ],
  ]);
  out();
  return 0;
}

/* ── log ──────────────────────────────────────────────────────────────── */

/** `cool log` — the tree itself: size, root, checkpoint, consistency. */
export async function logCommand(workspace: Workspace, args: string[]): Promise<number> {
  const sth = workspace.cool.plane.currentSTH();
  const consistencyFrom = flag(args, "consistency");

  panel("transparency log", [
    `${c.grey("log id")}      ${sth.log_id}`,
    `${c.grey("tree size")}   ${c.bold(String(sth.tree_size))}`,
    `${c.grey("root")}        ${sth.root_hash}`,
    `${c.grey("signed at")}   ${sth.timestamp}`,
    `${c.grey("witnesses")}   ${sth.witnesses.length} ${c.faint("(self-signature not counted)")}`,
  ]);
  out();

  if (workspace.log) {
    out(`  ${c.grey("on disk")}     ${relative(workspace.root, workspace.log.path)}`);
    const previous = workspace.log.lastCheckpoint();
    if (previous && previous.tree_size !== sth.tree_size) {
      out(
        `  ${c.grey("last head")}   size ${previous.tree_size} at ${previous.timestamp.slice(0, 19)}`,
      );
    }
    if (consistencyFrom) {
      const from = Number(consistencyFrom);
      const proof = workspace.log.consistency(from);
      out();
      out(
        `  ${c.bold(`consistency ${from} → ${sth.tree_size}`)}  ${c.faint(
          `${proof.length} hash${proof.length === 1 ? "" : "es"}`,
        )}`,
      );
      for (const node of proof) out(`    ${c.faint(node)}`);
      out();
      out(
        `  ${c.faint(
          "Hand this and an older tree head to anyone who kept one: it proves the log only grew.",
        )}`,
      );
    }
  } else {
    out(`  ${c.faint("This log is in memory only — records will not share a tree across runs.")}`);
  }
  out();
  return 0;
}

/** Receipts as plain data, for anything that wants to pipe them. */
export function receiptsOf(workspace: Workspace | null): ReceiptV2[] {
  return loadReceipts(workspace?.root).map((entry) => entry.receipt);
}
