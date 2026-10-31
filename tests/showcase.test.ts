/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/** The showcase is also a test: every claim it prints must hold, on every run. */
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runShowcase } from "../scripts/showcase";

test("showcase: every claim holds and the artifacts are written", async () => {
  const dir = join(mkdtempSync(join(tmpdir(), "cool-showcase-test-")), "out");
  const outcome = await runShowcase({ dir, quiet: true });
  const failed = outcome.results.filter((r) => !r.ok).map((r) => `${r.chapter}: ${r.claim}`);
  assert.deepEqual(failed, []);
  assert.ok(outcome.passed >= 40, `only ${outcome.passed} claims ran`);
  assert.equal(new Set(outcome.results.map((r) => r.chapter)).size, 12);
  for (const f of ["release-bundle.json", "incident-bundle.json", "trust.json", "showcase-report.json"]) assert.ok(existsSync(join(dir, f)), f);
});
