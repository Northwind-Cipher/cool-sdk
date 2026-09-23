/**
 * CooL x Phala Cloud real-TDX validation workload.
 *
 * Runs inside a real Phala Cloud Intel TDX confidential VM. Uses the advanced
 * `CoolTee` API (not the top-level `CooL` convenience class) because reaching
 * `attestation: pass` requires wiring a real QuoteVerifier into the RA-TLS
 * handshake policy — an option the top-level class does not expose.
 *
 * Real dstack, real quote, real verification against Phala Cloud's own
 * attestation-verification API (POST /api/v1/attestations/verify). No
 * simulator fallback: policy.allowSimulated is hard-false.
 *
 * WORKLOAD_MARKER exists solely to produce a different, immutable image digest
 * for the workload-change / measurement-pin test.
 */
import http from "node:http";
import { CoolTee, HttpDstackClient, remoteQuoteVerifier, verifyReceiptV2 } from "cool-nwc/phala";
import { unixFetch, isSocketPath } from "cool-nwc/node";

const WORKLOAD_MARKER = process.env.WORKLOAD_MARKER ?? "v1";
const PORT = process.env.PORT ?? 8080;
const DSTACK_ENDPOINT = process.env.COOL_DSTACK_ENDPOINT ?? "/var/run/dstack.sock";
const RAW_IMAGE_DIGEST = process.env.COOL_IMAGE_DIGEST ?? "sha256:unpinned-development-image";
// cool.evidence.v1's software.digest is a multihash (`mh:sha256:<hex>`), not a
// bare OCI digest string (`sha256:<hex>`) — reformat rather than guess a field.
const IMAGE_DIGEST_MULTIHASH = /^sha256:[0-9a-f]{64}$/.test(RAW_IMAGE_DIGEST)
  ? `mh:${RAW_IMAGE_DIGEST}`
  : null;

const PHALA_ATTESTATION_API = "https://cloud-api.phala.com/api/v1/attestations/verify";

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Phala Cloud's own quote-verification service: real DCAP check against real Intel hardware. */
function phalaQuoteVerifier() {
  return remoteQuoteVerifier({
    endpoint: PHALA_ATTESTATION_API,
    root: "intel-dcap",
    name: "phala-cloud-attestation-api",
    encode: (rawQuoteBase64) => {
      const bytes = Uint8Array.from(atob(rawQuoteBase64), (c) => c.charCodeAt(0));
      return { hex: bytesToHex(bytes) };
    },
    decode: (response) => {
      const r = response ?? {};
      const verified = r?.quote?.verified === true;
      return { ok: verified, detail: verified ? "verified by Phala Cloud attestation API (real Intel DCAP check)" : `Phala Cloud attestation API returned: ${JSON.stringify(r)}` };
    },
  });
}

const dstackClient = isSocketPath(DSTACK_ENDPOINT)
  ? new HttpDstackClient({
      endpoint: DSTACK_ENDPOINT,
      vendor: "intel-tdx",
      fetchImpl: unixFetch(DSTACK_ENDPOINT),
      paths: { info: "/Info", quote: "/GetQuote", key: "/GetKey" },
    })
  : undefined;

let state = { status: "starting" };

async function init() {
  try {
    const tee = await CoolTee.connect({
      dstack: dstackClient,
      app: { name: "cool-phala-validation", imageDigest: RAW_IMAGE_DIGEST },
      policy: {
        allowSimulated: false,
        requireVerifiedRoot: true,
        requireVendor: ["intel-tdx"],
        verifier: phalaQuoteVerifier(),
      },
    });

    // Six synthetic events so the transparency log reaches tree size 6 and the
    // final receipt carries a non-trivial inclusion path; heads at sizes 1..6 are
    // all served so consistency can be checked between signed heads.
    const receipts = [];
    for (let i = 0; i < 6; i++) {
      receipts.push(
        await tee.record({
          type: "model.execution",
          metadata: { model: "demo-model", version: "1.0.0", policy: "policy-v1", workload_marker: WORKLOAD_MARKER, seq: i },
          payloads: { input: "synthetic-input", output: "synthetic-output" },
          software: {
            name: "cool-phala-validation",
            version: "0.1.0",
            ...(IMAGE_DIGEST_MULTIHASH ? { digest: IMAGE_DIGEST_MULTIHASH } : {}),
          },
        }),
      );
    }
    const receipt = receipts[receipts.length - 1];

    const verdict = await verifyReceiptV2(receipt, {
      requireHardware: true,
      quoteVerifier: phalaQuoteVerifier(),
    });

    state = {
      status: "ready",
      handshake: tee.handshake,
      keyDirectory: tee.keyDirectory,
      receipt,
      receipts,
      verdict,
      workload_marker: WORKLOAD_MARKER,
      image_digest: RAW_IMAGE_DIGEST,
    };
    console.log("[cool-phala-validation] ready. handshake ok:", tee.handshake.ok, "verdict ok:", verdict.ok);
    console.log("[cool-phala-validation] verdict:", JSON.stringify(verdict.checks));
  } catch (error) {
    state = {
      status: "error",
      error: {
        name: error?.name,
        code: error?.code,
        message: String(error?.message ?? error),
        action: error?.action,
        cause: error?.cause ? String(error.cause?.message ?? error.cause) : null,
        stack: String(error?.stack ?? "").split("\n").slice(0, 8),
      },
    };
    console.error("[cool-phala-validation] FATAL:", JSON.stringify(state.error));
  }
}

const server = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url === "/health") {
    res.writeHead(state.status === "ready" ? 200 : 503);
    res.end(JSON.stringify({ status: state.status, workload_marker: WORKLOAD_MARKER }));
    return;
  }
  if (req.url === "/receipt") {
    if (state.status !== "ready") { res.writeHead(503); res.end(JSON.stringify(state)); return; }
    res.writeHead(200);
    res.end(JSON.stringify(state.receipt, null, 2));
    return;
  }
  if (req.url === "/receipts") {
    if (state.status !== "ready") { res.writeHead(503); res.end(JSON.stringify(state)); return; }
    res.writeHead(200);
    res.end(JSON.stringify(state.receipts, null, 2));
    return;
  }
  if (req.url === "/verdict") {
    if (state.status !== "ready") { res.writeHead(503); res.end(JSON.stringify(state)); return; }
    res.writeHead(200);
    res.end(JSON.stringify(state.verdict, null, 2));
    return;
  }
  if (req.url === "/handshake") {
    if (state.status !== "ready") { res.writeHead(503); res.end(JSON.stringify(state)); return; }
    res.writeHead(200);
    res.end(JSON.stringify(state.handshake, null, 2));
    return;
  }
  if (req.url === "/environment") {
    if (state.status !== "ready") { res.writeHead(503); res.end(JSON.stringify(state)); return; }
    res.writeHead(200);
    res.end(JSON.stringify({ keyDirectory: state.keyDirectory, image_digest: state.image_digest, workload_marker: state.workload_marker }, null, 2));
    return;
  }
  if (req.url === "/") {
    res.writeHead(state.status === "ready" ? 200 : 503);
    res.end(JSON.stringify({ status: state.status, workload_marker: WORKLOAD_MARKER, error: state.error ?? null, routes: ["/health", "/receipt", "/receipts", "/verdict", "/handshake", "/environment"] }));
    return;
  }
  res.writeHead(404);
  res.end(JSON.stringify({ error: "not found" }));
});

server.listen(PORT, () => {
  console.log(`[cool-phala-validation] listening on :${PORT}, marker=${WORKLOAD_MARKER}`);
  init();
});
