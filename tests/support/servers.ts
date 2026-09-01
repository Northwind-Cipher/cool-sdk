/**
 * Faithful stand-ins for the three services the SDK talks to.
 *
 * The point of these is narrow and important: until now the hardware code paths
 * — `HttpDstackClient`, `remoteQuoteVerifier`, `PhalaPrivateLLM` — had never
 * executed. Not "were untested"; had never run at all. A mock server does not
 * conjure silicon, but it does execute every line between our API and the wire,
 * which is where integration bugs actually live: encodings, path names, error
 * shapes, and what happens when a service answers slowly, wrongly or not at all.
 *
 * Each server mirrors the real thing's observed wire format and is deliberately
 * configurable in the ways the real ones vary (hex vs base64, `0x` prefixes,
 * `Info` over GET or POST), so the tests pin behaviour we would otherwise
 * discover on a customer's cluster.
 */
import { createHash, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

/** A running mock, plus a transcript of what it was asked. */
export interface MockServer {
  readonly url: string;
  readonly calls: { method: string; path: string; body: unknown }[];
  close(): Promise<void>;
}

function listen(handler: (req: IncomingMessage, res: ServerResponse, body: unknown) => void): Promise<{
  server: Server;
  url: string;
  calls: { method: string; path: string; body: unknown }[];
}> {
  const calls: { method: string; path: string; body: unknown }[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      let body: unknown = null;
      if (raw) {
        try {
          body = JSON.parse(raw);
        } catch {
          body = raw;
        }
      }
      calls.push({ method: req.method ?? "GET", path: (req.url ?? "").split("?")[0] ?? "", body });
      handler(req, res, body);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({ server, url: `http://127.0.0.1:${port}`, calls });
    });
  });
}

const closeLater = (server: Server) => (): Promise<void> =>
  new Promise((resolve) => server.close(() => resolve()));

function json(res: ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(body);
}

/* ── 1 · the dstack guest agent ───────────────────────────────────────── */

const HEX48 = (seed: string) => createHash("sha384").update(seed).digest("hex");

export interface MockAgentOptions {
  /** How the agent encodes quote and key bytes. Real agents differ. */
  readonly encoding?: "hex" | "hex0x" | "base64";
  /** Reject GET on `Info`, the way a strict prpc endpoint would. */
  readonly infoRequiresPost?: boolean;
  /** Override the RPC paths, as the tappd→dstack rename did. */
  readonly paths?: { info?: string; quote?: string; key?: string };
  /** Fail every call, to exercise the error path. */
  readonly broken?: boolean;
  readonly appId?: string;
  readonly imageSeed?: string;
}

export interface MockAgent extends MockServer {
  /** The measurement this agent reports — what a test pins against. */
  readonly measurement: {
    mrtd: string;
    rtmr0: string;
    rtmr1: string;
    rtmr2: string;
    rtmr3: string;
  };
  /** The raw quote bytes it hands out, for byte-level assertions. */
  readonly quoteBytes: Buffer;
}

export async function startMockAgent(options: MockAgentOptions = {}): Promise<MockAgent> {
  const encoding = options.encoding ?? "hex";
  const seed = options.imageSeed ?? "mock-image-1";
  const appId = options.appId ?? "a1b2c3d4e5f60718";
  const paths = {
    info: options.paths?.info ?? "/prpc/Info",
    quote: options.paths?.quote ?? "/prpc/GetQuote",
    key: options.paths?.key ?? "/prpc/GetKey",
  };

  const measurement = {
    mrtd: HEX48(`${seed}/mrtd`),
    rtmr0: HEX48(`${seed}/rtmr0`),
    rtmr1: HEX48(`${seed}/rtmr1`),
    rtmr2: HEX48(`${seed}/rtmr2`),
    rtmr3: HEX48(`${seed}/rtmr3`),
  };
  // Stands in for a TDX v4 quote: opaque bytes we only ever forward.
  const quoteBytes = randomBytes(512);

  const encode = (bytes: Buffer): string =>
    encoding === "base64"
      ? bytes.toString("base64")
      : encoding === "hex0x"
        ? `0x${bytes.toString("hex")}`
        : bytes.toString("hex");

  const { server, url, calls } = await listen((req, res, body) => {
    if (options.broken) {
      json(res, 503, { error: "guest agent unavailable" });
      return;
    }
    const path = (req.url ?? "").split("?")[0];

    if (path === paths.info) {
      if (options.infoRequiresPost && req.method !== "POST") {
        json(res, 405, { error: "method not allowed" });
        return;
      }
      json(res, 200, {
        app_id: appId,
        instance_id: "i-0d5e74639e89ccc1",
        app_name: "cool-evidence-plane",
        app_url: "https://cool-evidence-plane.dstack-prod.phala.network",
        tcb_info: {
          mrtd: measurement.mrtd,
          rtmr0: measurement.rtmr0,
          rtmr1: measurement.rtmr1,
          rtmr2: measurement.rtmr2,
          rtmr3: measurement.rtmr3,
          event_log: [
            { imr: 3, event: "app-id", digest: HEX48("event/app-id") },
            { imr: 3, event: "compose-hash", digest: HEX48("event/compose") },
          ],
        },
      });
      return;
    }

    if (path === paths.quote) {
      const reportData = (body as { report_data?: string } | null)?.report_data;
      if (typeof reportData !== "string" || reportData.length !== 128) {
        // The agent takes 64 bytes; anything else is a client bug and should
        // surface here rather than silently producing a useless quote.
        json(res, 400, { error: `report_data must be 64 bytes, got ${reportData?.length ?? 0}/2` });
        return;
      }
      json(res, 200, {
        quote: encode(quoteBytes),
        tcb_status: "UpToDate",
        event_log: "[]",
      });
      return;
    }

    if (path === paths.key) {
      const derivation = (body as { path?: string } | null)?.path ?? "";
      // Real KMS material is longer than a signing seed and deterministic for a
      // given (measurement, path). Both properties matter to the client.
      const material = createHash("sha512")
        .update(`${seed}|${measurement.mrtd}|${derivation}`)
        .digest();
      json(res, 200, { key: encode(material), signature_chain: [] });
      return;
    }

    json(res, 404, { error: `no such method: ${path}` });
  });

  return { url, calls, measurement, quoteBytes, close: closeLater(server) };
}

/* ── 2 · an attestation verification service ──────────────────────────── */

export interface MockVerifierOptions {
  readonly accept?: boolean;
  readonly tcbStatus?: string;
  /** Answer with a non-2xx, the way a rate-limited or misconfigured one would. */
  readonly httpError?: number;
  /** Answer in an alternative shape, to exercise a custom `decode`. */
  readonly shape?: "default" | "intel";
}

export async function startMockQuoteVerifier(
  options: MockVerifierOptions = {},
): Promise<MockServer> {
  const accept = options.accept ?? true;
  const { server, url, calls } = await listen((_req, res, body) => {
    if (options.httpError) {
      json(res, options.httpError, { error: "nope" });
      return;
    }
    const quote = (body as { quote?: string } | null)?.quote;
    if (typeof quote !== "string" || quote.length === 0) {
      json(res, 400, { error: "no quote submitted" });
      return;
    }
    if (options.shape === "intel") {
      json(res, 200, {
        attestation_result: accept ? "PASSED" : "FAILED",
        tcb: { status: options.tcbStatus ?? "UpToDate" },
      });
      return;
    }
    json(res, 200, {
      ok: accept,
      tcb_status: options.tcbStatus ?? "UpToDate",
      detail: accept ? "quote verified against Intel DCAP collateral" : "TCB out of date",
    });
  });
  return { url, calls, close: closeLater(server) };
}

/* ── 3 · Phala's confidential inference endpoint ──────────────────────── */

export interface MockLLMOptions {
  /** Serve `/attestation/report`. When false, the SDK must degrade cleanly. */
  readonly withAttestation?: boolean;
  readonly completionStatus?: number;
  readonly content?: string;
}

export async function startMockPhalaLLM(options: MockLLMOptions = {}): Promise<MockServer> {
  const withAttestation = options.withAttestation ?? true;
  const { server, url, calls } = await listen((req, res, body) => {
    const path = (req.url ?? "").split("?")[0];

    if (path === "/attestation/report") {
      if (!withAttestation) {
        json(res, 404, { error: "not enabled for this endpoint" });
        return;
      }
      json(res, 200, {
        signing_address: "0x9f2c1e6b4d8a3f57c0b1e2d3a4f5968708192a3b",
        nvidia_payload: { evidence: "AgABAL8LAAAMAAsA", gpu: "H200" },
        intel_quote: "0400020081000000",
      });
      return;
    }

    if (path === "/chat/completions") {
      if (options.completionStatus && options.completionStatus !== 200) {
        json(res, options.completionStatus, { error: { message: "upstream failure" } });
        return;
      }
      const model = (body as { model?: string } | null)?.model ?? "unknown";
      json(res, 200, {
        id: "chatcmpl-mock",
        model,
        choices: [
          {
            index: 0,
            message: { role: "assistant", content: options.content ?? "Score 62/100. Decline." },
            finish_reason: "stop",
          },
        ],
      });
      return;
    }

    json(res, 404, { error: `no such path: ${path}` });
    void req;
  });
  return { url, calls, close: closeLater(server) };
}
