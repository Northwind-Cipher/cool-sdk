/**
 * `HttpDstackClient` — the path that talks to a real confidential VM.
 *
 * Until these tests existed this class had never executed. That is the most
 * dangerous kind of code: it looks reviewed, and its first run is in front of a
 * customer. What follows drives it against a guest agent that answers the way
 * the real one does, in each of the encodings real ones use, and asserts the
 * things that would otherwise fail silently — a report_data of the wrong
 * length, a `0x` prefix, a key longer than a signing seed, a renamed RPC.
 *
 * It also produces the first **hardware-rooted** verdict this project has ever
 * seen: a quote with `root: intel-dcap` and vendor bytes, checked through
 * `remoteQuoteVerifier` against an attestation service, arriving at
 * `attestation: pass`. The silicon is still simulated — no test can conjure a
 * TDX module — but every line of our code between the API and the wire now runs.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import {
  CoolTee,
  HttpDstackClient,
  enclaveReportData,
  remoteQuoteVerifier,
  verifyReceiptV2,
} from "../src/phala/index";
import { startMockAgent, startMockQuoteVerifier } from "./support/servers";

test("info() parses the guest agent's TCB report", async () => {
  const agent = await startMockAgent();
  try {
    const client = new HttpDstackClient({ endpoint: agent.url });
    const info = await client.info();

    assert.equal(info.vendor, "intel-tdx");
    assert.equal(info.mode, "hardware");
    assert.equal(info.appId, "a1b2c3d4e5f60718");
    assert.equal(info.instanceId, "i-0d5e74639e89ccc1");
    assert.equal(info.appUrl, "https://cool-evidence-plane.dstack-prod.phala.network");
    assert.equal(info.measurement.mrtd, `hex:${agent.measurement.mrtd}`);
    assert.equal(info.measurement.rtmr3, `hex:${agent.measurement.rtmr3}`);
    assert.equal(info.eventLog.length, 2);
    assert.equal(info.eventLog[0]?.event, "app-id");
    assert.equal(info.eventLog[0]?.imr, 3);
  } finally {
    await agent.close();
  }
});

test("quote bytes survive every encoding a real agent uses", async () => {
  for (const encoding of ["hex", "hex0x", "base64"] as const) {
    const agent = await startMockAgent({ encoding });
    try {
      const client = new HttpDstackClient({ endpoint: agent.url });
      const commitment = "mh:sha256:" + "ab".repeat(32);
      const quote = await client.getQuote(commitment as `mh:sha256:${string}`);

      assert.equal(quote.format, "dstack.tdx.v4");
      assert.equal(quote.root, "intel-dcap");
      assert.equal(quote.body.tcb_status, "UpToDate");
      assert.equal(quote.body.report_data, commitment, "the commitment must round-trip");
      assert.ok(quote.raw?.startsWith("base64:"), `raw not normalised for ${encoding}`);

      const raw = Buffer.from(quote.raw!.slice("base64:".length), "base64");
      assert.deepEqual(
        new Uint8Array(raw),
        new Uint8Array(agent.quoteBytes),
        `bytes mangled for ${encoding}`,
      );

      // The agent rejects anything that is not 64 bytes, so reaching here also
      // asserts the client padded the 32-byte commitment correctly.
      const call = agent.calls.find((c) => c.path === "/prpc/GetQuote");
      assert.equal((call?.body as { report_data: string }).report_data.length, 128);
    } finally {
      await agent.close();
    }
  }
});

test("deriveKey compresses KMS material to a 32-byte seed, per path", async () => {
  const agent = await startMockAgent();
  try {
    const client = new HttpDstackClient({ endpoint: agent.url });
    const record = await client.deriveKey("cool/evidence/record/v2");
    const log = await client.deriveKey("cool/evidence/log/v2");
    const again = await client.deriveKey("cool/evidence/record/v2");

    assert.equal(record.length, 32, "signing seeds are 32 bytes");
    assert.deepEqual(record, again, "derivation must be deterministic");
    assert.notDeepEqual(record, log, "paths must be domain-separated");
  } finally {
    await agent.close();
  }
});

test("renamed RPCs and POST-only Info are configurable, not fatal", async () => {
  const agent = await startMockAgent({
    infoRequiresPost: true,
    paths: { info: "/prpc/Tappd.Info", quote: "/prpc/Tappd.TdxQuote", key: "/prpc/Tappd.DeriveKey" },
  });
  try {
    const strict = new HttpDstackClient({
      endpoint: agent.url,
      infoMethod: "POST",
      paths: {
        info: "/prpc/Tappd.Info",
        quote: "/prpc/Tappd.TdxQuote",
        key: "/prpc/Tappd.DeriveKey",
      },
    });
    const info = await strict.info();
    assert.equal(info.appName, "cool-evidence-plane");

    // The default GET must fail loudly against that agent rather than hang or
    // return something empty — this is the misconfiguration to catch at boot.
    const lazy = new HttpDstackClient({
      endpoint: agent.url,
      paths: { info: "/prpc/Tappd.Info" },
    });
    await assert.rejects(() => lazy.info(), /HTTP 405/);
  } finally {
    await agent.close();
  }
});

test("an unreachable or broken agent fails loudly", async () => {
  const agent = await startMockAgent({ broken: true });
  try {
    const client = new HttpDstackClient({ endpoint: agent.url });
    await assert.rejects(() => client.info(), /HTTP 503/);
  } finally {
    await agent.close();
  }

  const dead = new HttpDstackClient({ endpoint: "http://127.0.0.1:1" });
  await assert.rejects(() => dead.info());
});

test("a vendor quote with no verifier configured closes the channel", async () => {
  const agent = await startMockAgent();
  try {
    const cool = await CoolTee.connect({
      dstack: new HttpDstackClient({ endpoint: agent.url }),
      capture: { flushMs: 1 },
    });

    assert.equal(cool.handshake.ok, false);
    const root = cool.handshake.steps.find((s) => s.label === "root of trust");
    assert.equal(root?.ok, false);
    assert.match(root?.detail ?? "", /refusing to transmit/);

    // Fail-open toward the application: capture must not throw.
    cool.capture({
      kind: "change",
      changeKind: "prompt",
      ref: "x#y",
      environment: "prod",
      after: "hello",
      actor: { id: "test", method: "session" },
    });
    await cool.flush();
    assert.equal(cool.stats().sent, 0);
    assert.ok(cool.stats().dropped > 0, "loss must be counted");
    await cool.close();
  } finally {
    await agent.close();
  }
});

test("requireVerifiedRoot=false reports the root without pretending to check it", async () => {
  const agent = await startMockAgent();
  try {
    const cool = await CoolTee.connect({
      dstack: new HttpDstackClient({ endpoint: agent.url }),
      policy: { requireVerifiedRoot: false },
      capture: { flushMs: 1 },
    });
    assert.equal(cool.handshake.ok, true);
    const root = cool.handshake.steps.find((s) => s.label === "root of trust");
    assert.match(root?.detail ?? "", /REPORTED, NOT VERIFIED/);
    await cool.close();
  } finally {
    await agent.close();
  }
});

test("end to end on the hardware path: attestation and enclave both PASS", async () => {
  const agent = await startMockAgent();
  const dcap = await startMockQuoteVerifier({ accept: true });
  try {
    const dstack = new HttpDstackClient({ endpoint: agent.url });
    const verifier = remoteQuoteVerifier({ endpoint: dcap.url, root: "intel-dcap" });
    const pinned = {
      mrtd: `hex:${agent.measurement.mrtd}`,
      rtmr0: `hex:${agent.measurement.rtmr0}`,
      rtmr1: `hex:${agent.measurement.rtmr1}`,
      rtmr2: `hex:${agent.measurement.rtmr2}`,
      rtmr3: `hex:${agent.measurement.rtmr3}`,
    } as const;

    const cool = await CoolTee.connect({
      dstack,
      expectedMeasurement: pinned,
      policy: {
        expectedMeasurement: pinned,
        allowSimulated: false,
        requireVendor: ["intel-tdx"],
        verifier,
      },
      capture: { flushMs: 1 },
    });

    assert.equal(cool.handshake.ok, true, cool.handshake.reasons.join("; "));
    assert.equal(cool.handshake.mode, "hardware");

    const receipt = await cool.record({ type: "model.execution", metadata: { model: "phala/deepseek-v4-pro@2026.07" }, payloads: { input: "assess application A-40182", } });

    assert.equal(receipt.record.runtime.mode, "hardware");
    assert.equal(receipt.record.runtime.tee_vendor, "intel-tdx");
    assert.equal(receipt.attestation.quote?.root, "intel-dcap");
    assert.ok(receipt.attestation.quote?.raw, "a hardware receipt carries vendor bytes");

    const verdict = await verifyReceiptV2(receipt, {
      quoteVerifier: verifier,
      expectedMeasurement: pinned,
      requireHardware: true,
    });

    assert.equal(verdict.checks.attestation.status, "pass", verdict.checks.attestation.detail);
    assert.equal(verdict.checks.enclave.status, "pass", verdict.checks.enclave.detail);
    assert.equal(verdict.checks.binding.status, "pass");
    assert.equal(verdict.checks.signature.status, "pass");
    assert.equal(verdict.checks.inclusion.status, "pass");
    assert.equal(verdict.ok, true, verdict.reasons.join("; "));

    // The key that signed is the key the quote attests — the property the whole
    // integration exists for, asserted rather than assumed.
    const entry = receipt.key_directory[receipt.record.signature.key_id];
    assert.ok(entry);
    assert.equal(receipt.attestation.quote?.body.report_data, enclaveReportData(entry));

    await cool.close();
  } finally {
    await agent.close();
    await dcap.close();
  }
});

test("a receipt from the wrong image fails the pin, even on hardware", async () => {
  const approved = await startMockAgent({ imageSeed: "approved-build" });
  const patched = await startMockAgent({ imageSeed: "patched-build" });
  const dcap = await startMockQuoteVerifier({ accept: true });
  try {
    const verifier = remoteQuoteVerifier({ endpoint: dcap.url, root: "intel-dcap" });
    const cool = await CoolTee.connect({
      dstack: new HttpDstackClient({ endpoint: patched.url }),
      policy: { verifier },
      capture: { flushMs: 1 },
    });
    const receipt = await cool.record({ type: "model.execution", metadata: { model: "m@1" }, payloads: { input: "p" } });

    const verdict = await verifyReceiptV2(receipt, {
      quoteVerifier: verifier,
      expectedMeasurement: {
        mrtd: `hex:${approved.measurement.mrtd}`,
        rtmr0: `hex:${approved.measurement.rtmr0}`,
        rtmr1: `hex:${approved.measurement.rtmr1}`,
        rtmr2: `hex:${approved.measurement.rtmr2}`,
        rtmr3: `hex:${approved.measurement.rtmr3}`,
      },
    });

    assert.equal(verdict.ok, false);
    assert.equal(verdict.checks.enclave.status, "fail");
    assert.match(verdict.checks.enclave.detail, /mrtd/);
    await cool.close();
  } finally {
    await approved.close();
    await patched.close();
    await dcap.close();
  }
});
