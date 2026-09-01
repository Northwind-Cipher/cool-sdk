/**
 * `remoteQuoteVerifier` and the attestation domain.
 *
 * This is the seam where "hardware said so" enters the system, and the only
 * place where CooL depends on somebody else's answer. The tests therefore care
 * less about the happy path than about every way the answer can go wrong: a
 * rejection, an HTTP error, an unreachable service, an unexpected response
 * shape, and a quote with nothing to submit. In each case the domain must end
 * up somewhere honest — `fail` or `absent` — and never at `pass`.
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  CoolTee,
  HttpDstackClient,
  remoteQuoteVerifier,
  verifyReceiptV2,
} from "../src/phala/index";
import type { ReceiptV2 } from "../src/phala/index";
import { startMockAgent, startMockQuoteVerifier } from "./support/servers";

async function hardwareReceipt(agentUrl: string): Promise<ReceiptV2> {
  const cool = await CoolTee.connect({
    dstack: new HttpDstackClient({ endpoint: agentUrl }),
    policy: { requireVerifiedRoot: false },
    capture: { flushMs: 1 },
  });
  const receipt = await cool.change({
    kind: "prompt",
    ref: "test#system",
    after: "hello",
    environment: "test",
    actor: { id: "test", method: "session" },
  });
  await cool.close();
  return receipt;
}

test("a rejected quote fails the attestation domain", async () => {
  const agent = await startMockAgent();
  const dcap = await startMockQuoteVerifier({ accept: false, tcbStatus: "OutOfDate" });
  try {
    const receipt = await hardwareReceipt(agent.url);
    const verdict = await verifyReceiptV2(receipt, {
      quoteVerifier: remoteQuoteVerifier({ endpoint: dcap.url, root: "intel-dcap" }),
    });
    assert.equal(verdict.checks.attestation.status, "fail");
    assert.equal(verdict.ok, false);
    assert.match(verdict.reasons.join(" "), /TCB out of date/);
  } finally {
    await agent.close();
    await dcap.close();
  }
});

test("an attestation service that errors or vanishes never yields a pass", async () => {
  const agent = await startMockAgent();
  const broken = await startMockQuoteVerifier({ httpError: 429 });
  try {
    const receipt = await hardwareReceipt(agent.url);

    const httpFail = await verifyReceiptV2(receipt, {
      quoteVerifier: remoteQuoteVerifier({ endpoint: broken.url, root: "intel-dcap" }),
    });
    assert.equal(httpFail.checks.attestation.status, "fail");
    assert.match(httpFail.checks.attestation.detail, /HTTP 429/);

    const unreachable = await verifyReceiptV2(receipt, {
      quoteVerifier: remoteQuoteVerifier({ endpoint: "http://127.0.0.1:1", root: "intel-dcap" }),
    });
    assert.equal(unreachable.checks.attestation.status, "fail");
    assert.match(unreachable.checks.attestation.detail, /unreachable/);
  } finally {
    await agent.close();
    await broken.close();
  }
});

test("no verifier means reported, not verified — an absent domain, not a pass", async () => {
  const agent = await startMockAgent();
  try {
    const receipt = await hardwareReceipt(agent.url);
    const verdict = await verifyReceiptV2(receipt);
    assert.equal(verdict.checks.attestation.status, "absent");
    assert.match(verdict.checks.attestation.detail, /REPORTED, not verified/);
    // The binding between quote, measurement and key is pure maths, so it still
    // holds — but it is reported as `pass` only because the quote structure and
    // key binding checked out, not because anyone vouched for the silicon.
    assert.equal(verdict.checks.enclave.status, "pass");
    assert.equal(verdict.ok, true);
    // …and a deployment that demands hardware refuses it.
    const strict = await verifyReceiptV2(receipt, { requireHardware: true });
    assert.equal(strict.ok, false);
  } finally {
    await agent.close();
  }
});

test("a service with its own response shape is handled by `decode`", async () => {
  const agent = await startMockAgent();
  const intel = await startMockQuoteVerifier({ shape: "intel" });
  try {
    const receipt = await hardwareReceipt(agent.url);
    const verdict = await verifyReceiptV2(receipt, {
      quoteVerifier: remoteQuoteVerifier({
        endpoint: intel.url,
        root: "intel-dcap",
        name: "intel-trust-authority",
        decode: (response) => {
          const r = response as { attestation_result?: string; tcb?: { status?: string } };
          return {
            ok: r.attestation_result === "PASSED",
            ...(r.tcb?.status === undefined ? {} : { tcb_status: r.tcb.status }),
          };
        },
      }),
    });
    assert.equal(verdict.checks.attestation.status, "pass");
    assert.match(verdict.checks.attestation.detail, /UpToDate/);
  } finally {
    await agent.close();
    await intel.close();
  }
});

test("a simulated quote is never upgraded by a hardware verifier", async () => {
  const dcap = await startMockQuoteVerifier({ accept: true });
  try {
    const cool = await CoolTee.connect({
      app: { name: "sim", imageDigest: "sha256:sim" },
      capture: { flushMs: 1 },
    });
    const receipt = await cool.change({
      kind: "prompt",
      ref: "test#system",
      after: "hello",
      environment: "test",
      actor: { id: "test", method: "session" },
    });
    await cool.close();

    // Even handed a verifier that says yes to everything, a simulated quote
    // carries no vendor bytes — so the verifier has nothing to check and the
    // domain reports what it is.
    const verdict = await verifyReceiptV2(receipt, {
      quoteVerifier: remoteQuoteVerifier({ endpoint: dcap.url, root: "intel-dcap" }),
    });
    assert.notEqual(verdict.checks.attestation.status, "pass");
    assert.equal(verdict.checks.attestation.status, "fail");
    assert.match(verdict.checks.attestation.detail, /not from hardware/);
  } finally {
    await dcap.close();
  }
});
