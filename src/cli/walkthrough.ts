/**
 * The walkthrough — teaching the model by doing it.
 *
 * This replaces the old `demo`, and the difference is the point. A demo shows
 * you a finished thing and asks you to be impressed. A walkthrough hands you the
 * thing one piece at a time, explains what each piece is for *before* running
 * it, and leaves the results in your directory afterwards so you can go back and
 * poke at them.
 *
 * Six steps, in the order the concepts depend on each other: seal, verify,
 * tamper, govern, disclose, pack. Nothing here is staged — every record it
 * creates is real, signed by this machine's enclave-derived key, and appended to
 * this project's log.
 */
import { createInterface } from "node:readline";
import {
  DEFAULT_POLICY,
  buildAuditPack,
  disclose,
  evaluate,
  verifyAuditPack,
  verifyDisclosure,
} from "../phala/index";
import type { ReceiptV2 } from "../phala/index";
import { saveReceipt, verify, type Workspace } from "./workspace";
import { Progress, c, columns, g, out, panel, rule } from "./tty";
import { printVerdict } from "./commands";

/** Wrap prose to the terminal, so paragraphs read like paragraphs. */
function say(text: string, indent = "  "): void {
  const width = columns() - indent.length - 2;
  let line = "";
  for (const word of text.split(/\s+/)) {
    if (line.length + word.length + 1 > width) {
      out(indent + line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) out(indent + line);
}

interface Pacer {
  next(label: string): Promise<void>;
  close(): void;
}

/** Wait for Enter — unless there is nobody there, in which case just carry on. */
function pacer(): Pacer {
  if (!process.stdin.isTTY) {
    return { next: async () => {}, close: () => {} };
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return {
    next: (label: string) =>
      new Promise<void>((resolve) => {
        rl.question(`  ${c.faint(`${label} — press Enter`)} `, () => {
          out();
          resolve();
        });
      }),
    close: () => rl.close(),
  };
}

export async function walkthrough(workspace: Workspace): Promise<void> {
  const step = pacer();
  const stamp = new Date().toISOString().slice(11, 19);

  panel("Walkthrough", [
    `${c.bold("Six steps, about three minutes.")} Everything is real: the records this`,
    "creates are signed by this machine's enclave-derived key and stay in",
    `${c.dim(".cool/")} when you are done.`,
  ]);
  out();

  /* ── 1 · seal ── */
  rule("1 of 6 · seal a change");
  say(
    "CooL records two things: what a model did, and what you changed about it. This is " +
      "the second. The text you are about to seal is committed as a salted hash and then " +
      "discarded — the receipt never contains it.",
  );
  out();
  await step.next("seal a prompt change");

  const before = "Approve refunds up to $50 without escalation.";
  const after = `Approve refunds up to $500 without escalation.\nEscalate anything disputed. (${stamp})`;

  const sealing = new Progress().start("capturing — async, off the request path");
  const receipt = await workspace.cool.change({
    kind: "prompt",
    ref: "billing/refund-agent#system",
    environment: "prod",
    before,
    after,
    actor: { id: "user:walkthrough", method: "cli" },
    approvers: ["priya@bank.example", "marcus@bank.example"],
  });
  const path = saveReceipt(workspace.root, receipt);
  sealing.succeed(`sealed ${c.bold(receipt.record.record_id)}`);

  say(
    `Signed with ${c.bold(receipt.record.signature.key_id)} — a key derived inside the ` +
      "enclave from the measurement of the code running there. Appended to the log as leaf " +
      `${receipt.inclusion?.leaf_index} of ${receipt.inclusion?.tree_size}.`,
  );
  say(c.faint(`Written to ${path.replace(workspace.root, ".")}`));
  out();
  await step.next("now verify it");

  /* ── 2 · verify ── */
  rule("2 of 6 · verify it");
  say(
    "This is the function an auditor runs. Offline, no account, no network: recompute " +
      "the commitment, check both signatures, walk the Merkle path, and confirm the quote " +
      "attests the very key that signed.",
  );
  out();
  const verdict = await verify(receipt, workspace, { pin: true });
  printVerdict(verdict, "the record you just sealed");
  say(
    c.faint(
      "Two domains say `simulated` rather than `pass`: this machine has no confidential " +
        "VM, so the quote comes from the built-in simulator. That is reported, never " +
        "rounded up.",
    ),
  );
  out();
  await step.next("break it on purpose");

  /* ── 3 · tamper ── */
  rule("3 of 6 · break it");
  say(
    "Evidence is only worth what its failures are worth. One character of one hash is " +
      "about to change — the smallest edit anyone would attempt.",
  );
  out();
  const forged = JSON.parse(JSON.stringify(receipt)) as ReceiptV2;
  const change = (forged.record as unknown as { change: { after_hash: string } }).change;
  change.after_hash = change.after_hash.replace(/.$/, (ch) => (ch === "0" ? "1" : "0"));
  const broken = await verify(forged, workspace);
  printVerdict(broken, "the same record, one character changed");
  say(
    "Binding fails because the contents no longer match the commitment, and the " +
      "signature fails because it covered both. Neither can be repaired without the " +
      "enclave key, which does not exist outside the measured image.",
  );
  out();
  await step.next("see the policy engine refuse something");

  /* ── 4 · govern ── */
  rule("4 of 6 · governance");
  say(
    "An approval that can be edited afterwards is not an approval. So policy is " +
      "evaluated inside the enclave and its verdict is sealed with the change. Here is the " +
      "same rule set deciding two cases.",
  );
  out();

  const approved = evaluate(DEFAULT_POLICY, {
    kind: "prompt",
    ref: "billing/refund-agent#system",
    environment: "prod",
    actor: { id: "user:walkthrough", method: "cli" },
    approvers: ["priya@bank.example", "marcus@bank.example"],
  });
  const refused = evaluate(DEFAULT_POLICY, {
    kind: "agent-permission",
    ref: "support/copilot#tools",
    environment: "prod",
    actor: { id: "user:oncall", method: "session" },
    approvers: ["oncall@bank.example"],
  });

  out(
    `  ${c.green(g.pass)} prompt change, two approvers    → ${c.bold(approved.decision)} ${c.faint(
      `(${approved.rule})`,
    )}`,
  );
  out(
    `  ${c.yellow(g.warn)} widening an agent's permissions → ${c.bold(refused.decision)} ${c.faint(
      `(${refused.rule})`,
    )}`,
  );
  out();
  say(c.faint(`Why: ${DEFAULT_POLICY.rules.find((r) => r.id === refused.rule)?.because ?? ""}`));
  say(
    "The strictest matching rule wins, so a permissive rule added later cannot quietly " +
      "override a restrictive one. `cool policy` prints the whole set.",
  );
  out();
  await step.next("open one field without revealing the rest");

  /* ── 5 · disclose ── */
  rule("5 of 6 · selective disclosure");
  say(
    "The receipt contains no plaintext, which is what lets you publish it. So when a " +
      "regulator asks what the prompt actually said, you disclose one field: the text plus " +
      "its salt. Anyone can recompute the commitment and check.",
  );
  out();
  const disclosure = disclose(receipt, "change.after", after);
  const disclosureVerdict = verifyDisclosure(receipt, disclosure);
  out(`  ${c.grey("field")}      ${disclosure.field}`);
  out(`  ${c.grey("value")}      ${c.bold(after.split("\n")[0] ?? "")}`);
  out(`  ${c.grey("salt")}       ${c.faint(disclosure.salt)}`);
  out(`  ${c.grey("commitment")} ${c.faint(disclosure.commitment)}`);
  out();
  out(
    disclosureVerdict.ok
      ? `  ${c.green(`${g.pass} ${disclosureVerdict.detail}`)}`
      : `  ${c.red(`${g.fail} ${disclosureVerdict.detail}`)}`,
  );
  out();
  say(
    "One field opened. The `before` text, and every other record, stay closed — salts " +
      "are per field and per record.",
  );
  out();
  await step.next("finish with the artefact an auditor asks for");

  /* ── 6 · pack ── */
  rule("6 of 6 · the audit pack");
  say(
    "Everything so far, in one self-contained file: the receipts, the keys to check " +
      "them, the measurement, and the clause mapping. It verifies offline, and the verifier " +
      "re-derives the summary rather than trusting it.",
  );
  out();
  const { loadReceipts } = await import("./workspace");
  const all = loadReceipts(workspace.root).map((entry) => entry.receipt);
  const pack = buildAuditPack(all, {
    subject: `walkthrough — ${workspace.root}`,
    enclave: {
      vendor: workspace.info.vendor,
      mode: workspace.info.mode,
      app_id: workspace.info.appId,
      measurement: workspace.info.measurement,
    },
  });
  const packVerdict = await verifyAuditPack(pack);
  out(`  ${c.grey("records")}      ${packVerdict.total}`);
  out(
    `  ${c.grey("verified")}     ${
      packVerdict.failed === 0
        ? c.green(String(packVerdict.verified))
        : `${c.green(String(packVerdict.verified))} ${c.red(`· ${packVerdict.failed} failed`)}`
    }`,
  );
  out(
    `  ${c.grey("obligations")}  ${packVerdict.obligationsCovered} of ${packVerdict.obligationsTotal} covered by evidence`,
  );
  out();
  say(c.faint("Build one any time with `cool pack build --out audit.json`."));
  out();

  rule("done");
  say(
    `${c.bold("That is the whole model.")} Records that fail loudly when they are wrong, ` +
      "governance that cannot be edited after the fact, one field openable without opening " +
      "the rest, and a verifier that trusts nothing but the bytes.",
  );
  out();
  out(`  ${c.faint("Next:")} ${c.brand("cool help concepts")}  ${c.faint("·")}  ${c.brand("cool records")}  ${c.faint("·")}  ${c.brand("cool help production")}`);
  out();
  step.close();
}
