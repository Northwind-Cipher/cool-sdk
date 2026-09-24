/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Runtime status: REAL vs SIMULATED vs UNAVAILABLE vs FAILED.
 *
 * What is under test is the DECISION — which evidence makes a runtime show as
 * REAL — not silicon. The dstack agent here is a fixture that speaks the real
 * protocol shape (tcb_info as a JSON string, MRTD + RTMR0-3, agent identity, a
 * quote), and the "vendor root" is a mock verifier. A fixture cannot be real
 * TDX, so these tests never claim it is: they prove that the SDK refuses to say
 * REAL unless every piece of evidence it requires is present and verified, and
 * that the real-hardware path on an actual Phala CVM is covered separately by
 * artifacts/final-evidence.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  CoolTee,
  HttpDstackClient,
  SimulatedDstackClient,
  remoteQuoteVerifier,
  verifyReceiptV2,
} from "../src/phala/index";
import { CooL } from "../src/index";
import { DstackUnavailableError, HardwareRequiredError } from "../src/errors";
import { DEFAULT_DSTACK_SOCKET, openWorkspace } from "../src/cli/workspace";
import type { Measurement } from "../src/phala/types";
import { startMockAgent, startMockQuoteVerifier } from "./support/servers";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(root, "src", "cli", "index.ts");
const LOADER = pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;

function pin(m: Record<string, string>) {
  return Object.fromEntries(Object.entries(m).map(([k, v]) => [k, `hex:${v}`])) as unknown as Measurement;
}

async function withEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T>): Promise<T> {
  const saved: Record<string, string | undefined> = {};
  for (const k of Object.keys(vars)) saved[k] = process.env[k];
  for (const [k, v] of Object.entries(vars)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return await fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

async function tmp<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "cool-runtime-"));
  try {
    return await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const NO_ENDPOINT = {
  DSTACK_ENDPOINT: undefined,
  DSTACK_SIMULATOR_ENDPOINT: undefined,
  QUOTE_VERIFIER_URL: undefined,
  COOL_REQUIRE_HARDWARE: undefined,
  COOL_EXPECTED_MEASUREMENT: undefined,
};

/* 1 */
test("1: SimulatedDstackClient => SIMULATED, never REAL, even when everything says intel-tdx", async () => {
  const pinned = await new SimulatedDstackClient({ appName: "s", imageDigest: "sha256:s" }).info();
  const cool = await CoolTee.connect({
    dstack: new SimulatedDstackClient({ appName: "s", imageDigest: "sha256:s" }),
    expectedMeasurement: pinned.measurement,
    policy: { expectedMeasurement: pinned.measurement, requireVendor: ["intel-tdx"] },
    capture: { flushMs: 1 },
  });
  const rt = cool.runtime;
  assert.equal(rt.state, "simulated");
  assert.equal(rt.label, "SIMULATED");
  assert.match(rt.display, /intel-tdx · SIMULATED/);
  assert.match(rt.reason, /no dstack hardware agent detected/);
  const receipt = await cool.record({ type: "model.execution", metadata: { a: 1 } });
  assert.equal(receipt.record.runtime.mode, "simulated", "the receipt itself says simulated");
  const verdict = await verifyReceiptV2(receipt, {});
  assert.equal(verdict.checks.attestation.status, "simulated");
  assert.match(verdict.subject?.tee ?? "", /simulated/);
  await cool.close();
});

/* 2 */
test("2: no dstack + allowSimulated:false => FAIL (no silent simulator fallback)", async () => {
  // Library path: the simulator is refused outright.
  const cool = await CoolTee.connect({
    app: { name: "n", imageDigest: "sha256:n" },
    policy: { allowSimulated: false },
    capture: { flushMs: 1 },
  });
  assert.equal(cool.handshake.ok, false);
  await assert.rejects(() => cool.record({ type: "model.execution", metadata: { a: 1 } }));
  await cool.close();

  // Public API: requireAttestation with an unreachable agent throws, never degrades.
  const client = new CooL({
    attestation: { provider: "dstack", endpoint: "http://127.0.0.1:1" },
    security: { requireAttestation: true },
  });
  await assert.rejects(() => client.ready(), (e: unknown) => e instanceof DstackUnavailableError);
  // And requireAttestation with the local simulator is a configuration error.
  await assert.rejects(() => new CooL({ security: { requireAttestation: true } }).ready());
});

/* 3 */
test("3: no dstack + requireHardware => FAIL, and an unreachable configured agent never falls back", async () => {
  if (existsSync(DEFAULT_DSTACK_SOCKET)) return; // a real agent is present on this machine
  await tmp(async (dir) => {
    await withEnv(NO_ENDPOINT, async () => {
      await assert.rejects(
        () => openWorkspace(dir, { requireHardware: true }),
        (e: unknown) => e instanceof HardwareRequiredError && /no dstack guest agent/.test((e as Error).message),
      );
      // Environment switch is equivalent.
      await withEnv({ COOL_REQUIRE_HARDWARE: "1" }, async () => {
        await assert.rejects(() => openWorkspace(dir), (e: unknown) => e instanceof HardwareRequiredError);
      });
      // Even WITHOUT requireHardware, an endpoint that was configured but does not
      // answer is an error, not a quiet switch to the simulator.
      await withEnv({ DSTACK_ENDPOINT: "http://127.0.0.1:1" }, async () => {
        await assert.rejects(() => openWorkspace(dir), (e: unknown) => e instanceof DstackUnavailableError);
      });
    });
  });
});

/* 4 */
test("4: incomplete dstack Info (no TCB block, no identity) => NOT REAL", async () => {
  for (const incompleteInfo of ["no-tcb", "no-identity"] as const) {
    const agent = await startMockAgent({ incompleteInfo });
    const dcap = await startMockQuoteVerifier({ accept: true });
    try {
      const cool = await CoolTee.connect({
        dstack: new HttpDstackClient({ endpoint: agent.url }),
        policy: { verifier: remoteQuoteVerifier({ endpoint: dcap.url, root: "intel-dcap" }) },
        capture: { flushMs: 1 },
      });
      assert.equal(cool.handshake.ok, false, `${incompleteInfo}: channel must close`);
      assert.notEqual(cool.runtime.state, "real");
      assert.equal(cool.runtime.state, "failed");
      assert.equal(cool.runtime.label, "EVIDENCE INCOMPLETE");
      await cool.close();
    } finally {
      await agent.close();
      await dcap.close();
    }
  }
});

/* 5 */
test("5: all-zero measurement => NOT REAL", async () => {
  const agent = await startMockAgent({ incompleteInfo: "zero-measurement", tcbInfoAsString: true });
  const dcap = await startMockQuoteVerifier({ accept: true });
  try {
    const cool = await CoolTee.connect({
      dstack: new HttpDstackClient({ endpoint: agent.url }),
      policy: { verifier: remoteQuoteVerifier({ endpoint: dcap.url, root: "intel-dcap" }) },
      capture: { flushMs: 1 },
    });
    assert.equal(cool.handshake.ok, false);
    assert.equal(cool.runtime.state, "failed");
    assert.match(cool.runtime.reason, /mrtd is missing or all-zero/);
    assert.match(cool.runtime.reason, /rtmr3 is missing or all-zero/);
    await cool.close();
  } finally {
    await agent.close();
    await dcap.close();
  }
});

/* 6 */
test("6: a real-looking vendor string, a pin and a reachable agent WITHOUT a verifier => NOT REAL", async () => {
  const agent = await startMockAgent({ tcbInfoAsString: true });
  try {
    const cool = await CoolTee.connect({
      dstack: new HttpDstackClient({ endpoint: agent.url, vendor: "intel-tdx" }),
      expectedMeasurement: pin(agent.measurement),
      policy: { expectedMeasurement: pin(agent.measurement), requireVendor: ["intel-tdx"], requireVerifiedRoot: false },
      capture: { flushMs: 1 },
    });
    assert.equal(cool.handshake.ok, true, "the channel may open when the operator allowed an unverified root");
    assert.equal(cool.handshake.rootVerified, false);
    assert.equal(cool.runtime.state, "unverified");
    assert.notEqual(cool.runtime.state, "real");
    assert.match(cool.runtime.display, /UNVERIFIED/);
    assert.equal(cool.runtime.display.includes("REAL"), false);
    const receipt = await cool.record({ type: "model.execution", metadata: { a: 1 } });
    const verdict = await verifyReceiptV2(receipt, {});
    assert.match(verdict.subject?.tee ?? "", /NOT verified/);
    await cool.close();
  } finally {
    await agent.close();
  }
});

/* 7 + 10 */
test("7/10: complete evidence + verified quote + matching pin + hardware policy => REAL", async () => {
  const agent = await startMockAgent({ tcbInfoAsString: true });
  const dcap = await startMockQuoteVerifier({ accept: true });
  try {
    const verifier = remoteQuoteVerifier({ endpoint: dcap.url, root: "intel-dcap" });
    const cool = await CoolTee.connect({
      dstack: new HttpDstackClient({ endpoint: agent.url }),
      expectedMeasurement: pin(agent.measurement),
      policy: {
        allowSimulated: false,
        requireVendor: ["intel-tdx"],
        requireVerifiedRoot: true,
        expectedMeasurement: pin(agent.measurement),
        verifier,
      },
      capture: { flushMs: 1 },
    });
    assert.equal(cool.handshake.ok, true, cool.handshake.reasons.join("; "));
    assert.equal(cool.handshake.rootVerified, true);
    assert.equal(cool.runtime.state, "real");
    assert.equal(cool.runtime.display, "intel-tdx · REAL");
    assert.deepEqual(cool.runtime.findings, []);
    const receipt = await cool.record({ type: "model.execution", metadata: { a: 1 } });
    const verdict = await verifyReceiptV2(receipt, { quoteVerifier: verifier, requireHardware: true });
    assert.equal(verdict.ok, true, verdict.reasons.join("; "));
    assert.equal(verdict.subject?.tee, "intel-tdx · hardware");
    await cool.close();
  } finally {
    await agent.close();
    await dcap.close();
  }
});

/* 8 */
test("8: measurement mismatch => FAIL, labelled MEASUREMENT MISMATCH", async () => {
  const running = await startMockAgent({ imageSeed: "running", tcbInfoAsString: true });
  const approved = await startMockAgent({ imageSeed: "approved" });
  const dcap = await startMockQuoteVerifier({ accept: true });
  try {
    const cool = await CoolTee.connect({
      dstack: new HttpDstackClient({ endpoint: running.url }),
      policy: {
        allowSimulated: false,
        expectedMeasurement: pin(approved.measurement),
        verifier: remoteQuoteVerifier({ endpoint: dcap.url, root: "intel-dcap" }),
      },
      capture: { flushMs: 1 },
    });
    assert.equal(cool.handshake.ok, false);
    assert.equal(cool.runtime.state, "failed");
    assert.equal(cool.runtime.label, "MEASUREMENT MISMATCH");
    await cool.close();
  } finally {
    await running.close();
    await approved.close();
    await dcap.close();
  }
});

/* 9 */
test("9: attestation failure + requireHardware => FAIL (library and CLI path)", async () => {
  const agent = await startMockAgent({ tcbInfoAsString: true });
  const dcap = await startMockQuoteVerifier({ accept: false });
  try {
    const cool = await CoolTee.connect({
      dstack: new HttpDstackClient({ endpoint: agent.url }),
      policy: { allowSimulated: false, verifier: remoteQuoteVerifier({ endpoint: dcap.url, root: "intel-dcap" }) },
      capture: { flushMs: 1 },
    });
    assert.equal(cool.runtime.state, "failed");
    assert.equal(cool.runtime.label, "ATTESTATION FAILED");
    await cool.close();

    await tmp(async (dir) => {
      await withEnv(
        { ...NO_ENDPOINT, DSTACK_ENDPOINT: agent.url, QUOTE_VERIFIER_URL: dcap.url },
        async () => {
          await assert.rejects(
            () => openWorkspace(dir, { requireHardware: true }),
            (e: unknown) => e instanceof HardwareRequiredError && /ATTESTATION FAILED/.test((e as Error).message),
          );
        },
      );
    });
  } finally {
    await agent.close();
    await dcap.close();
  }
});

test("requireHardware with an agent but NO verifier is refused, not downgraded", async () => {
  const agent = await startMockAgent({ tcbInfoAsString: true });
  try {
    await tmp(async (dir) => {
      await withEnv({ ...NO_ENDPOINT, DSTACK_ENDPOINT: agent.url }, async () => {
        await assert.rejects(
          () => openWorkspace(dir, { requireHardware: true }),
          (e: unknown) => e instanceof HardwareRequiredError && /no quote verifier/.test((e as Error).message),
        );
      });
    });
  } finally {
    await agent.close();
  }
});

test("CLI workspace: agent + verifier + pin + requireHardware => REAL; without hardware required and no verifier => UNVERIFIED", async () => {
  const agent = await startMockAgent({ tcbInfoAsString: true });
  const dcap = await startMockQuoteVerifier({ accept: true });
  try {
    await tmp(async (dir) => {
      await withEnv(
        {
          ...NO_ENDPOINT,
          DSTACK_ENDPOINT: agent.url,
          QUOTE_VERIFIER_URL: dcap.url,
          COOL_EXPECTED_MEASUREMENT: JSON.stringify(pin(agent.measurement)),
        },
        async () => {
          const ws = await openWorkspace(dir, { requireHardware: true });
          assert.equal(ws.runtime.state, "real");
          assert.equal(ws.hardwareRequired, true);
          await ws.cool.close();
        },
      );
      await withEnv({ ...NO_ENDPOINT, DSTACK_ENDPOINT: agent.url }, async () => {
        const ws = await openWorkspace(dir);
        assert.equal(ws.runtime.state, "unverified");
        await ws.cool.close();
      });
      // A wrong pin from the environment is a hard failure when hardware is required.
      await withEnv(
        {
          ...NO_ENDPOINT,
          DSTACK_ENDPOINT: agent.url,
          QUOTE_VERIFIER_URL: dcap.url,
          COOL_EXPECTED_MEASUREMENT: JSON.stringify({ ...pin(agent.measurement), rtmr3: `hex:${"ab".repeat(48)}` }),
        },
        async () => {
          await assert.rejects(
            () => openWorkspace(dir, { requireHardware: true }),
            (e: unknown) => e instanceof HardwareRequiredError && /MEASUREMENT MISMATCH/.test((e as Error).message),
          );
        },
      );
    });
  } finally {
    await agent.close();
    await dcap.close();
  }
});

/* local machine: the CLI itself */
test("local CLI on a machine with no dstack agent says SIMULATED and why; hardware-required exits non-zero", () => {
  if (existsSync(DEFAULT_DSTACK_SOCKET)) return;
  const dir = mkdtempSync(join(tmpdir(), "cool-cli-runtime-"));
  try {
    const env = { ...process.env, NO_COLOR: "1" } as Record<string, string | undefined>;
    for (const k of Object.keys(NO_ENDPOINT)) delete env[k];
    const run = (args: string[], extra: Record<string, string> = {}) => {
      try {
        const stdout = execFileSync(process.execPath, ["--import", LOADER, CLI, ...args], {
          cwd: dir,
          encoding: "utf8",
          env: { ...env, ...extra },
          stdio: ["pipe", "pipe", "pipe"],
        });
        return { stdout, code: 0 };
      } catch (error) {
        const err = error as { stdout?: string; status?: number };
        return { stdout: err.stdout ?? "", code: err.status ?? 1 };
      }
    };

    const status = run(["status"]);
    assert.equal(status.code, 0);
    assert.match(status.stdout, /intel-tdx · SIMULATED/);
    assert.match(status.stdout, /no dstack hardware agent detected/);
    assert.equal(/intel-tdx · REAL/.test(status.stdout), false);

    const strict = run(["status", "--require-hardware"]);
    assert.notEqual(strict.code, 0);
    const viaEnv = run(["status"], { COOL_REQUIRE_HARDWARE: "1" });
    assert.notEqual(viaEnv.code, 0);

    const repl = run(["repl"], {}); // the banner
    assert.match(repl.stdout, /enclave\s+intel-tdx · SIMULATED/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
