/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/** Enforcement: disabled and dry-run by default, idempotent, confirmed externally. */
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  EnforcementCoordinator,
  LocalDirectoryTarget,
  evaluatePolicy,
  fileDigest,
  type EnforcementAdapter,
  type PolicyDocument,
} from "../src/platform/index";

const ENFORCE: PolicyDocument = { schema: "cool.policy.v1", id: "p", version: "1", mode: "enforce", default: "allow", rules: [] };
const allow = evaluatePolicy(ENFORCE, {}, { now: new Date(0) });
const observed = evaluatePolicy({ ...ENFORCE, mode: "observe" }, {}, { now: new Date(0) });

function artifact(content = "release v1\n") {
  const dir = mkdtempSync(join(tmpdir(), "cool-enf-"));
  const path = join(dir, "app.tar");
  writeFileSync(path, content);
  return { dir, path, digest: fileDigest(path) };
}

function counting(behaviour: "complete" | "hang" | "throw"): EnforcementAdapter & { calls: number } {
  const a = {
    id: "fake", permissions: ["none"], actions: ["admit"], allowedDecisions: { admit: ["allow"] as const }, calls: 0,
    async execute(req: { request_id: string }, signal: AbortSignal) {
      a.calls++;
      if (behaviour === "throw") throw new Error("connection reset");
      if (behaviour === "hang") await new Promise((_, reject) => signal.addEventListener("abort", () => reject(new Error("aborted"))));
      return { request_id: req.request_id, adapter: "fake", state: "completed" as const, detail: "ok" };
    },
    async confirm() { return { confirmed: true, detail: "seen" }; },
  };
  return a;
}

test("enforcement: disabled by default — nothing executes, and the result says why", async () => {
  const a = artifact();
  const target = new LocalDirectoryTarget(join(a.dir, "deploy"));
  const r = await new EnforcementCoordinator().request(allow, target, "admit", "prod", { requestId: "r1", dryRun: false, params: { artifact_path: a.path, artifact_digest: a.digest } });
  assert.equal(r.state, "not_executed");
  assert.match(r.detail, /disabled/);
  assert.equal(existsSync(join(a.dir, "deploy", "app.tar")), false);
});

test("enforcement: enabled is still a dry run unless asked, and observe-mode decisions never execute", async () => {
  const a = artifact();
  const c = new EnforcementCoordinator({ enabled: true });
  const target = new LocalDirectoryTarget(join(a.dir, "deploy"));
  const params = { artifact_path: a.path, artifact_digest: a.digest };
  assert.match((await c.request(allow, target, "admit", "prod", { requestId: "dry", params })).detail, /dry run/);
  assert.match((await c.request(observed, target, "admit", "prod", { requestId: "obs", dryRun: false, params })).detail, /observe mode/);
  assert.equal(existsSync(join(a.dir, "deploy", "app.tar")), false);
});

test("enforcement: a live admit is executed by the target and independently confirmed", async () => {
  const a = artifact();
  const audit: string[] = [];
  const c = new EnforcementCoordinator({ enabled: true, audit: (e) => audit.push(e.kind) });
  const r = await c.request(allow, new LocalDirectoryTarget(join(a.dir, "deploy")), "admit", "prod", { requestId: "live", dryRun: false, params: { artifact_path: a.path, artifact_digest: a.digest } });
  assert.equal(r.state, "completed");
  assert.equal(r.confirmed, true);
  assert.ok(existsSync(join(a.dir, "deploy", "app.tar")));
  assert.deepEqual(audit, ["requested", "result"]);
});

test("enforcement: the TARGET refuses bytes that do not match the approved digest", async () => {
  const a = artifact();
  writeFileSync(a.path, "release v1 + backdoor\n");
  const c = new EnforcementCoordinator({ enabled: true });
  const r = await c.request(allow, new LocalDirectoryTarget(join(a.dir, "deploy")), "admit", "prod", { requestId: "tampered", dryRun: false, params: { artifact_path: a.path, artifact_digest: a.digest } });
  assert.equal(r.state, "rejected");
  assert.match(r.detail, /target recomputed/);
  assert.equal(existsSync(join(a.dir, "deploy", "app.tar")), false);
});

test("enforcement: a request id is an idempotency key — the adapter runs once", async () => {
  const fake = counting("complete");
  const c = new EnforcementCoordinator({ enabled: true });
  const first = await c.request(allow, fake, "admit", "prod", { requestId: "same", dryRun: false });
  const second = await c.request(allow, fake, "admit", "prod", { requestId: "same", dryRun: false });
  assert.equal(fake.calls, 1);
  assert.deepEqual(first, second);
});

test("enforcement: a timeout is unknown until reconciled; an adapter error is unknown, not success", async () => {
  const hang = counting("hang");
  const c = new EnforcementCoordinator({ enabled: true, timeoutMs: 30 });
  const t = await c.request(allow, hang, "admit", "prod", { requestId: "slow", dryRun: false });
  assert.equal(t.state, "timed_out");
  assert.equal(t.confirmed, false);
  const rec = await c.reconcile("slow", hang);
  assert.equal(rec.state, "completed");
  assert.equal(rec.confirmed, true);

  const boom = await c.request(allow, counting("throw"), "admit", "prod", { requestId: "boom", dryRun: false });
  assert.equal(boom.state, "unknown");
  assert.match(boom.detail, /connection reset/);
});

test("enforcement: a decision that does not permit the action is rejected before any call", async () => {
  const fake = counting("complete");
  const deny = evaluatePolicy({ ...ENFORCE, default: "deny" }, {}, { now: new Date(0) });
  const r = await new EnforcementCoordinator({ enabled: true }).request(deny, fake, "admit", "prod", { requestId: "d", dryRun: false });
  assert.equal(r.state, "rejected");
  assert.equal(fake.calls, 0);
  const unsupported = await new EnforcementCoordinator({ enabled: true }).request(allow, fake, "delete-cluster", "prod", { requestId: "x", dryRun: false });
  assert.match(unsupported.detail, /does not support/);
});
