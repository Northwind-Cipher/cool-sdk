/**
 * The features added in 2.2.0, each tested against the reason it exists.
 *
 * Policy is only worth something if it cannot be edited after the fact, a
 * disclosure is only worth something if a wrong one is rejected, a witness is
 * only worth something if the count refuses to include the operator, and a
 * persistent log is only worth something if the tree actually grows. So each
 * block below asserts the property, then attacks it.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CoolTee,
  DEFAULT_POLICY,
  SimulatedDstackClient,
  attachWitness,
  buildAuditPack,
  cosign,
  countWitnesses,
  coverage,
  disclosableFields,
  disclose,
  evaluate,
  policyHash,
  query,
  summarise,
  verifyAuditPack,
  verifyDisclosure,
  sealedKeyset,
  verifyReceiptV2,
} from "../src/phala/index";
import type { PolicySet, ReceiptV2 } from "../src/phala/index";
import { FileLog } from "../src/phala/log-file";
import { generateKeypair } from "../src/keys";

const workspace = () => mkdtempSync(join(tmpdir(), "cool-feat-"));

/**
 * A plane wired the way the CLI wires one.
 *
 * The log key matters: an STH is verified against the key directory the receipt
 * carries, so a file log must be signed by the SAME sealed key the plane
 * derives. Handing it an unrelated key produces receipts whose inclusion proof
 * cannot be checked — which is exactly the bug this helper existing prevents.
 */
async function plane(options: { dir?: string; policy?: PolicySet } = {}) {
  const client = new SimulatedDstackClient({
    appName: "features",
    imageDigest: "sha256:features",
  });
  const keys = await sealedKeyset(client);
  return CoolTee.connect({
    dstack: client,
    capture: { flushMs: 1 },
    ...(options.policy ? { governance: options.policy } : {}),
    ...(options.dir
      ? {
          log: new FileLog({
            dir: join(options.dir, "log"),
            logId: "test-log",
            logKey: keys.log,
          }),
        }
      : {}),
  });
}

/* ── policy ───────────────────────────────────────────────────────────── */

test("policy: the strictest matching rule wins, not the first", () => {
  const permissiveLast: PolicySet = {
    id: "test",
    rules: [
      { id: "STRICT", title: "no", when: { kinds: ["agent-permission"] }, decision: "rejected" },
      { id: "LOOSE", title: "yes", when: {}, decision: "auto-approved" },
    ],
  };
  const outcome = evaluate(permissiveLast, {
    kind: "agent-permission",
    ref: "app#tools",
    environment: "prod",
    actor: { id: "u", method: "cli" },
    approvers: [],
  });
  assert.equal(outcome.decision, "rejected");
  assert.equal(outcome.rule, "STRICT");
  assert.equal(outcome.considered.length, 2, "both rules are recorded, not just the winner");
});

test("policy: unmatched changes escalate rather than slide through", () => {
  const outcome = evaluate(
    { id: "empty", rules: [] },
    { kind: "prompt", ref: "x", environment: "prod", actor: { id: "u", method: "cli" }, approvers: [] },
  );
  assert.equal(outcome.decision, "escalate");
  assert.equal(outcome.rule, null);
});

test("policy: the default set approves with two and escalates with one", () => {
  const base = {
    kind: "prompt" as const,
    ref: "billing/agent#system",
    environment: "prod",
    actor: { id: "user:a", method: "session" },
  };
  assert.equal(evaluate(DEFAULT_POLICY, { ...base, approvers: ["a", "b"] }).decision, "approved");
  assert.equal(evaluate(DEFAULT_POLICY, { ...base, approvers: ["a"] }).decision, "escalate");
  // Widening an agent's permissions is never automatic, whatever the environment.
  assert.equal(
    evaluate(DEFAULT_POLICY, { ...base, kind: "agent-permission", environment: "dev", approvers: ["a", "b"] })
      .decision,
    "escalate",
  );
});

test("policy: the decision is sealed, so editing it breaks the signature", async () => {
  const cool = await plane({ policy: DEFAULT_POLICY });
  const receipt = await cool.change({
    kind: "agent-permission",
    ref: "support/copilot#tools",
    environment: "prod",
    after: "read:tickets\nrefund:initiate",
    actor: { id: "user:oncall", method: "session" },
    approvers: ["oncall@x"],
  });

  assert.equal(receipt.record.schema, "cool.change.v2");
  const approval =
    receipt.record.schema === "cool.change.v2" ? receipt.record.change.approval : null;
  assert.equal(approval?.decision, "rejected", "escalate is sealed as 'did not have authority'");
  assert.equal(approval?.policy_id, "POL-031");
  assert.equal((await verifyReceiptV2(receipt)).ok, true);

  const forged = JSON.parse(JSON.stringify(receipt)) as ReceiptV2;
  (forged.record as unknown as { change: { approval: { decision: string } } }).change.approval.decision =
    "approved";
  const verdict = await verifyReceiptV2(forged);
  assert.equal(verdict.checks.signature.status, "fail");
  await cool.close();
});

test("policy: a rule set hashes deterministically", () => {
  assert.equal(policyHash(DEFAULT_POLICY), policyHash(DEFAULT_POLICY));
  assert.notEqual(policyHash(DEFAULT_POLICY), policyHash({ id: "other", rules: [] }));
});

/* ── selective disclosure ─────────────────────────────────────────────── */

test("disclosure: the right text opens a field, the wrong text cannot", async () => {
  const cool = await plane();
  const after = "Approve refunds up to $500.";
  const receipt = await cool.change({
    kind: "prompt",
    ref: "app#system",
    environment: "dev",
    before: "Approve refunds up to $50.",
    after,
    actor: { id: "u", method: "cli" },
  });

  assert.deepEqual(disclosableFields(receipt), ["change.before", "change.after"]);

  const disclosure = disclose(receipt, "change.after", after);
  const verdict = verifyDisclosure(receipt, disclosure);
  assert.equal(verdict.ok, true);

  // A disclosure claiming different text must be refused at creation…
  assert.throws(() => disclose(receipt, "change.after", "something else"), /does not match/);

  // …and a hand-edited one must fail verification.
  const forged = { ...disclosure, value: "something else" };
  assert.equal(verifyDisclosure(receipt, forged).ok, false);

  // The receipt itself still contains no plaintext.
  assert.ok(!JSON.stringify(receipt).includes(after));
  await cool.close();
});

test("disclosure: a disclosure for one record does not open another", async () => {
  const cool = await plane();
  const a = await cool.change({
    kind: "prompt",
    ref: "app#a",
    environment: "dev",
    after: "text A",
    actor: { id: "u", method: "cli" },
  });
  const b = await cool.change({
    kind: "prompt",
    ref: "app#b",
    environment: "dev",
    after: "text B",
    actor: { id: "u", method: "cli" },
  });
  const disclosure = disclose(a, "change.after", "text A");
  assert.equal(verifyDisclosure(b, disclosure).ok, false);
  await cool.close();
});

/* ── witnesses ────────────────────────────────────────────────────────── */

test("witnesses: an independent co-signature makes the domain pass", async () => {
  const cool = await plane();
  const receipt = await cool.change({
    kind: "prompt",
    ref: "app#system",
    environment: "dev",
    after: "hello",
    actor: { id: "u", method: "cli" },
  });

  assert.equal((await verifyReceiptV2(receipt)).checks.witnesses.status, "absent");

  const auditor = generateKeypair("witness-auditor", { seed: new Uint8Array(32).fill(3) });
  const witnessed = attachWitness(receipt, cosign(receipt.sth!, auditor));

  const verdict = await verifyReceiptV2(witnessed);
  assert.equal(verdict.checks.witnesses.status, "pass");
  assert.match(verdict.checks.witnesses.detail, /1 independent/);
  assert.match(verdict.checks.witnesses.detail, /not counted/, "the self-signature is still shown");

  const counts = countWitnesses(witnessed);
  assert.equal(counts.external, 1);
  assert.equal(counts.self, 1);
  await cool.close();
});

test("witnesses: a statement about a different tree head is refused", async () => {
  const cool = await plane();
  const first = await cool.change({
    kind: "prompt",
    ref: "app#a",
    environment: "dev",
    after: "a",
    actor: { id: "u", method: "cli" },
  });
  const second = await cool.change({
    kind: "prompt",
    ref: "app#b",
    environment: "dev",
    after: "b",
    actor: { id: "u", method: "cli" },
  });
  const auditor = generateKeypair("witness-auditor", { seed: new Uint8Array(32).fill(3) });
  assert.throws(() => attachWitness(second, cosign(first.sth!, auditor)), /witness statement is for/);
  await cool.close();
});

test("witnesses: a forged co-signature is counted as invalid, never as independent", async () => {
  const cool = await plane();
  const receipt = await cool.change({
    kind: "prompt",
    ref: "app#system",
    environment: "dev",
    after: "hello",
    actor: { id: "u", method: "cli" },
  });
  const auditor = generateKeypair("witness-auditor", { seed: new Uint8Array(32).fill(3) });
  const witnessed = attachWitness(receipt, cosign(receipt.sth!, auditor));

  const tampered = JSON.parse(JSON.stringify(witnessed)) as ReceiptV2;
  const external = tampered.sth!.witnesses.find((w) => w.external)!;
  // Flip the first base64 char after the `base64:` prefix — it always carries
  // significant bits, so the decoded signature bytes are guaranteed to change
  // (a trailing base64 char can be altered without changing the bytes it
  // decodes to, which would make this a no-op tamper).
  const sig = external.ed25519;
  const at = "base64:".length;
  (external as { ed25519: string }).ed25519 =
    sig.slice(0, at) + (sig[at] === "A" ? "B" : "A") + sig.slice(at + 1);

  assert.equal(countWitnesses(tampered).external, 0);
  assert.equal(countWitnesses(tampered).invalid, 1);
  assert.equal((await verifyReceiptV2(tampered)).checks.witnesses.status, "absent");
  await cool.close();
});

/* ── the persistent log ───────────────────────────────────────────────── */

test("log: one tree grows across processes instead of many trees of one", async () => {
  const dir = workspace();
  try {
    const first = await plane({ dir });
    await first.change({
      kind: "prompt",
      ref: "app#a",
      environment: "dev",
      after: "a",
      actor: { id: "u", method: "cli" },
    });
    await first.close();

    // A completely separate client, as a second CLI invocation would be.
    const second = await plane({ dir });
    const receipt = await second.change({
      kind: "prompt",
      ref: "app#b",
      environment: "dev",
      after: "b",
      actor: { id: "u", method: "cli" },
    });

    assert.equal(receipt.inclusion?.tree_size, 2, "the second record joins the first one's tree");
    assert.equal(receipt.inclusion?.leaf_index, 1);
    assert.equal((await verifyReceiptV2(receipt)).checks.inclusion.status, "pass");
    await second.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("log: a corrupt leaf file refuses to start rather than silently reindexing", () => {
  const dir = workspace();
  try {
    const key = generateKeypair("k", { seed: new Uint8Array(32).fill(1) });
    const log = new FileLog({ dir, logId: "l", logKey: key });
    log.append(new Uint8Array(32).fill(9));
    const path = join(dir, "leaves.log");
    writeFileSync(path, `${readFileSync(path, "utf8")}not-a-digest\n`);
    assert.throws(() => new FileLog({ dir, logId: "l", logKey: key }), /corrupt log/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("log: consistency proves the tree only grew", () => {
  const dir = workspace();
  try {
    const key = generateKeypair("k", { seed: new Uint8Array(32).fill(1) });
    const log = new FileLog({ dir, logId: "l", logKey: key });
    for (let i = 0; i < 5; i++) log.append(new Uint8Array(32).fill(i));
    const proof = log.consistency(2);
    assert.ok(proof.length > 0);
    assert.equal(log.consistency(5).length, 0, "no proof needed when nothing changed");
    assert.equal(log.size, 5);
    assert.ok(log.lastCheckpoint() === null || log.lastCheckpoint()!.tree_size <= 5);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/* ── compliance, packs and queries ────────────────────────────────────── */

test("compliance: coverage is counted from receipts, never assumed", async () => {
  const cool = await plane({ policy: DEFAULT_POLICY });
  const empty = coverage([]);
  assert.ok(empty.every((row) => row.records === 0 && !row.covered), "nothing is covered by nothing");

  const receipt = await cool.record({ type: "model.execution", metadata: { model: "m@1" }, payloads: { input: "p" } });
  const approved = await cool.change({
    kind: "prompt",
    ref: "app#system",
    environment: "prod",
    after: "x",
    actor: { id: "u", method: "cli" },
    approvers: ["a@x", "b@x"],
  });

  const rows = coverage([receipt, approved]);
  const article12 = rows.find((row) => row.obligation.id === "eu-ai-act-12")!;
  const article14 = rows.find((row) => row.obligation.id === "eu-ai-act-14")!;
  assert.equal(article12.records, 1, "one inference record");
  assert.equal(article14.records, 1, "one change with named approvers");
  await cool.close();
});

test("pack: verification re-derives the summary rather than trusting it", async () => {
  const cool = await plane();
  const a = await cool.change({
    kind: "prompt",
    ref: "app#a",
    environment: "dev",
    after: "a",
    actor: { id: "u", method: "cli" },
  });
  const b = await cool.change({
    kind: "prompt",
    ref: "app#b",
    environment: "dev",
    after: "b",
    actor: { id: "u", method: "cli" },
  });

  const pack = buildAuditPack([a, b], { subject: "test" });
  const clean = await verifyAuditPack(pack);
  assert.equal(clean.ok, true);
  assert.equal(clean.verified, 2);

  // Edit one record inside the pack; the pack's own counts are irrelevant.
  const tampered = JSON.parse(JSON.stringify(pack)) as typeof pack;
  const record = tampered.records[0]!.receipt.record as unknown as { change: { after_hash: string } };
  record.change.after_hash = record.change.after_hash.replace(/.$/, (ch) => (ch === "0" ? "1" : "0"));

  const verdict = await verifyAuditPack(tampered);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.failed, 1);
  assert.equal(verdict.failures[0]?.record_id, pack.records[0]?.record_id);
  await cool.close();
});

test("query: filters and summaries over receipts alone", async () => {
  const cool = await plane({ policy: DEFAULT_POLICY });
  await cool.change({
    kind: "prompt",
    ref: "billing/agent#system",
    environment: "prod",
    after: "a",
    actor: { id: "ci:github", method: "oidc" },
    approvers: ["a@x", "b@x"],
  });
  await cool.change({
    kind: "agent-permission",
    ref: "support/copilot#tools",
    environment: "dev",
    after: "b",
    actor: { id: "user:dev", method: "session" },
  });
  await cool.record({ type: "model.execution", metadata: { model: "m@1" } });
  // `cool.receipts` already retains everything sealed on this client, including
  // the inference — appending it again would double-count it.
  const all = [...cool.receipts];

  assert.equal(query(all, { kind: "change" }).length, 2);
  assert.equal(query(all, { environment: "prod" }).length, 1);
  assert.equal(query(all, { actor: "ci:" }).length, 1);
  assert.equal(query(all, { changeKinds: ["agent-permission"] }).length, 1);
  assert.equal(query(all, { subject: "billing" }).length, 1);
  assert.equal(query(all, { limit: 1 }).length, 1);

  const summary = summarise(all);
  assert.equal(summary.changes, 2);
  assert.equal(summary.evidence, 1);
  assert.equal(summary.needingReview, 1, "the escalated agent-permission change");
  await cool.close();
});
