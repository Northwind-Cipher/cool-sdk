/**
 * CooL independent witness, run as its OWN Phala CVM.
 *
 * What makes this a separate witness rather than a second key held by the log:
 *
 *   - It is a different confidential VM with its own app_id. dstack derives keys
 *     per app, so the witness key (path cool/witness/v1) exists only inside this
 *     enclave and cannot be obtained by the primary log workload.
 *   - It does not trust what it is handed. It pulls the primary log's receipts
 *     itself over the network, verifies each one (signature, inclusion, real
 *     TDX quote through Phala's verification service, and the primary's pinned
 *     measurement), re-derives the whole history, checks every consistency step,
 *     and only then signs. It remembers what it signed and refuses a log that
 *     forks or rolls back.
 *   - Its own key is attested: /identity carries a TDX quote whose report_data
 *     commits to the witness public key, so a verifier can trust the key because
 *     of the measured witness code, not because of who holds an account.
 *
 * Limit, stated plainly: the account that deployed both CVMs is the same. This
 * demonstrates separated key custody, separated process and environment, and a
 * verifying witness. It does not demonstrate a different organization.
 */
import http from "node:http";
import {
  HttpDstackClient,
  Witness,
  enclaveReportData,
  phalaQuoteVerifier,
  sealedKeypair,
  verifyReceiptV2,
} from "cool-nwc/phala";
import { unixFetch, isSocketPath } from "cool-nwc/node";

const PORT = process.env.PORT ?? 8080;
const DSTACK_ENDPOINT = process.env.COOL_DSTACK_ENDPOINT ?? "/var/run/dstack.sock";
const PRIMARY_URL = (process.env.PRIMARY_URL ?? "").replace(/\/$/, "");
const PRIMARY_PIN = process.env.PRIMARY_MEASUREMENT ? JSON.parse(process.env.PRIMARY_MEASUREMENT) : null;
const IMAGE_DIGEST = process.env.COOL_IMAGE_DIGEST ?? null;

if (!PRIMARY_URL) throw new Error("PRIMARY_URL is required");
if (!PRIMARY_PIN) throw new Error("PRIMARY_MEASUREMENT is required: a witness must pin the log it witnesses");
if (!isSocketPath(DSTACK_ENDPOINT)) throw new Error("the witness runs only against the real dstack socket");

const client = new HttpDstackClient({
  endpoint: DSTACK_ENDPOINT,
  vendor: "intel-tdx",
  fetchImpl: unixFetch(DSTACK_ENDPOINT),
  paths: { info: "/Info", quote: "/GetQuote", key: "/GetKey" },
});
const verifier = phalaQuoteVerifier();

let state = { status: "starting" };
const decisions = [];
let witness = null;

async function init() {
  try {
    const key = await sealedKeypair(client, { path: "cool/witness/v1", role: "witness" });
    const info = await client.info();
    const quote = await client.getQuote(enclaveReportData(key.directoryEntry));
    witness = new Witness(key, {
      verifyReceipt: async (receipt) => {
        const v = await verifyReceiptV2(receipt, { requireHardware: true, quoteVerifier: verifier, expectedMeasurement: PRIMARY_PIN });
        return { ok: v.ok, reasons: v.reasons };
      },
    });
    state = {
      status: "ready",
      identity: {
        key_id: key.keyId,
        key_directory: { [key.keyId]: key.directoryEntry },
        quote,
        app_id: info.appId,
        instance_id: info.instanceId,
        measurement: info.measurement,
        image_digest: IMAGE_DIGEST,
        primary_url: PRIMARY_URL,
        primary_measurement_pin: PRIMARY_PIN,
      },
    };
    console.log("[witness] ready", key.keyId);
  } catch (error) {
    state = { status: "error", error: String(error?.stack ?? error) };
    console.error("[witness] FATAL", state.error);
  }
}

async function primaryReceipts() {
  const res = await fetch(`${PRIMARY_URL}/receipts`);
  if (!res.ok) throw new Error(`primary /receipts -> HTTP ${res.status}`);
  return res.json();
}

function record(kind, request, decision) {
  const entry = { at: new Date().toISOString(), kind, request, ok: decision.ok, reasons: decision.reasons, checks: decision.checks, statement: decision.statement };
  decisions.push(entry);
  return entry;
}

function send(res, code, body) {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(body, null, 2));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://witness");
  try {
    if (url.pathname === "/health") return send(res, state.status === "ready" ? 200 : 503, { status: state.status });
    if (state.status !== "ready") return send(res, 503, state);
    if (url.pathname === "/identity") return send(res, 200, state.identity);
    if (url.pathname === "/decisions") return send(res, 200, decisions);
    if (url.pathname === "/cosign" && req.method === "GET") {
      const size = Number(url.searchParams.get("size"));
      const receipts = await primaryReceipts();
      const d = await witness.observe(receipts, size);
      const entry = record("observe", { size }, d);
      return send(res, d.ok ? 200 : 409, entry);
    }
    if (url.pathname === "/cosign-presented" && req.method === "POST") {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const presented = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const receipts = await primaryReceipts();
      const d = await witness.cosignPresented(presented, receipts);
      const entry = record("presented", { tree_size: presented.tree_size, root_hash: presented.root_hash }, d);
      return send(res, d.ok ? 200 : 409, entry);
    }
    return send(res, 404, { error: "not found" });
  } catch (error) {
    return send(res, 500, { error: String(error?.message ?? error) });
  }
});

server.listen(PORT, () => {
  console.log(`[witness] listening on :${PORT}`);
  init();
});
