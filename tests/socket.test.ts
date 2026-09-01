/**
 * The unix-socket transport — the difference between "supports dstack" and
 * "runs inside a CVM".
 *
 * `DSTACK_ENDPOINT=/var/run/dstack.sock` is the configuration every real
 * deployment uses, and it could not have worked before this transport existed,
 * because `fetch` cannot open a unix socket. So this stands up a guest agent on
 * a real socket — a named pipe on Windows, an AF_UNIX socket everywhere else —
 * and drives the whole evidence plane through it.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CoolTee, HttpDstackClient, verifyReceiptV2 } from "../src/phala/index";
import { isSocketPath, unixFetch } from "../src/phala/unix";

const WINDOWS = process.platform === "win32";

/** A socket path that works on both Windows and everything else. */
function socketPath(seed: string): { path: string; cleanup: () => void } {
  if (WINDOWS) {
    return { path: String.raw`\\.\pipe\cool-test-` + seed, cleanup: () => {} };
  }
  const dir = mkdtempSync(join(tmpdir(), "cool-sock-"));
  return {
    path: join(dir, "dstack.sock"),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

const hex48 = (seed: string) => createHash("sha384").update(seed).digest("hex");
const quoteBytes = randomBytes(256);

/** A guest agent that can only be reached over the socket. */
async function agentOnSocket(path: string): Promise<() => Promise<void>> {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const url = (req.url ?? "").split("?")[0];
      const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString()) : {};
      const send = (payload: unknown) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(payload));
      };
      if (url === "/prpc/Info") {
        send({
          app_id: "socket-app",
          instance_id: "socket-instance",
          app_name: "cool-evidence",
          tcb_info: {
            mrtd: hex48("mrtd"),
            rtmr0: hex48("r0"),
            rtmr1: hex48("r1"),
            rtmr2: hex48("r2"),
            rtmr3: hex48("r3"),
            event_log: [],
          },
        });
      } else if (url === "/prpc/GetQuote") {
        // 64 bytes of report_data, hex-encoded — the key binding.
        assert.equal((body as { report_data: string }).report_data.length, 128);
        send({ quote: quoteBytes.toString("hex"), tcb_status: "UpToDate" });
      } else if (url === "/prpc/GetKey") {
        send({
          key: createHash("sha512").update(String((body as { path: string }).path)).digest("hex"),
        });
      } else {
        res.writeHead(404).end("{}");
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(path, resolve));
  return () => new Promise<void>((resolve) => server.close(() => resolve()));
}

test("socket paths are recognised, URLs are left alone", () => {
  assert.equal(isSocketPath("/var/run/dstack.sock"), true);
  assert.equal(isSocketPath("/tmp/dstack.sock"), true);
  assert.equal(isSocketPath(String.raw`\\.\pipe\dstack`), true);
  assert.equal(isSocketPath("http://localhost:8090"), false);
  assert.equal(isSocketPath("https://agent.internal/prpc"), false);
});

test("the whole evidence plane runs over a socket", async () => {
  const { path, cleanup } = socketPath("plane");
  const close = await agentOnSocket(path);
  try {
    const client = new HttpDstackClient({
      endpoint: path,
      fetchImpl: unixFetch(path) as unknown as typeof fetch,
    });

    const info = await client.info();
    assert.equal(info.appId, "socket-app");
    assert.equal(info.mode, "hardware", "a real agent means a hardware-mode plane");
    assert.equal(info.measurement.mrtd, `hex:${hex48("mrtd")}`);

    const cool = await CoolTee.connect({
      dstack: client,
      policy: { requireVerifiedRoot: false },
      capture: { flushMs: 1 },
    });

    const receipt = await cool.change({
      kind: "prompt",
      ref: "socket#system",
      environment: "prod",
      after: "sealed over a socket",
      actor: { id: "test", method: "cli" },
    });

    assert.equal(receipt.record.runtime.mode, "hardware");
    assert.equal(receipt.attestation.quote?.root, "intel-dcap");
    assert.ok(receipt.record.runtime.tee_quote, "the record commits to the vendor bytes");

    // Without a verifier the attestation is reported, never verified — the same
    // honesty rule applies on hardware as anywhere else.
    const verdict = await verifyReceiptV2(receipt);
    assert.equal(verdict.checks.attestation.status, "absent");
    assert.equal(verdict.checks.enclave.status, "pass", "the key binding still holds");
    assert.equal(verdict.checks.binding.status, "pass");
    await cool.close();
  } finally {
    await close();
    cleanup();
  }
});

test("a missing agent says what is actually wrong", async () => {
  const dead = WINDOWS ? String.raw`\\.\pipe\cool-absent` : "/tmp/cool-does-not-exist.sock";
  await assert.rejects(
    () => unixFetch(dead)("/prpc/Info"),
    /dstack|ENOENT|EPIPE|not found|refused/i,
  );
});
