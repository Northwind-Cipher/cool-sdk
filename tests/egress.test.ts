/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * No phone-home: the open SDK's end-to-end paths make no network calls.
 *
 * Every outbound primitive Node offers — TCP/TLS sockets, DNS, http(s)
 * requests and fetch — is wrapped to record any attempt, then the full open
 * showcase and the agent demo run. The assertion is zero attempts. (Only the
 * opt-in OpenTimestamps anchoring touches the network, and neither run uses it.)
 */
import test from "node:test";
import assert from "node:assert/strict";
import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runShowcase } from "../scripts/showcase";
import { runAgentDemo } from "../scripts/demo-agent";

test("egress: the showcase and the agent demo make no network calls", async () => {
  const attempts: string[] = [];
  const restore: Array<() => void> = [];
  const wrap = <T extends object>(obj: T, key: keyof T, label: string) => {
    const original = obj[key];
    (obj as Record<string, unknown>)[key as string] = (...args: unknown[]) => {
      attempts.push(`${label} ${JSON.stringify(args[0])?.slice(0, 80)}`);
      throw new Error(`network call blocked by egress test: ${label}`);
    };
    restore.push(() => { (obj as Record<string, unknown>)[key as string] = original; });
  };
  wrap(net.Socket.prototype, "connect", "net.connect");
  wrap(dns, "lookup", "dns.lookup");
  wrap(http, "request", "http.request");
  wrap(https, "request", "https.request");
  wrap(globalThis as Record<string, unknown>, "fetch", "fetch");
  try {
    const dir = mkdtempSync(join(tmpdir(), "cool-egress-"));
    const s = await runShowcase({ dir: join(dir, "showcase"), quiet: true });
    const d = await runAgentDemo({ dir: join(dir, "demo"), quiet: true });
    assert.equal(s.failed + d.failed, 0, "both runs must still succeed with the network blocked");
  } finally {
    for (const r of restore) r();
  }
  assert.deepEqual(attempts, []);
});
