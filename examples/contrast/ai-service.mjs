/**
 * An AI service that runs inside a Contrast confidential workload and seals
 * verifiable evidence of everything that changes about it.
 *
 * The integration is the first six lines of `start()`. Nothing else in this
 * file knows it is running confidentially — which is the point: adopting
 * Contrast under CooL is a runtime swap, not a rewrite.
 *
 * Endpoints:
 *
 *   GET  /healthz      liveness
 *   GET  /identity     what Contrast says this workload is
 *   POST /infer        run the "model", seal an execution-evidence record
 *   POST /change       record a change to the AI system (model, prompt, policy,
 *                      permission, params) and seal it
 *   GET  /receipts     every receipt this pod has sealed, newest last
 *   GET  /verify       the pod's own verdict on its own evidence (a self-check,
 *                      not a substitute for an independent verifier)
 *
 * Run it locally against the test fixtures, with no cluster:
 *
 *     COOL_CONTRAST_ROOT=$(node --import tsx pod.mjs ai-service) node ai-service.mjs
 */
import { createServer } from "node:http";
import { CooL } from "cool-nwc";
import { verifyEvidence, formatVerdict } from "cool-nwc/verify";
import { ContrastWorkload } from "cool-nwc/contrast";

const PORT = Number(process.env.PORT ?? 8080);

/* ── the integration ─────────────────────────────────────────────────── */

const runtime = await ContrastWorkload.open({
  // In production, make this fatal rather than discovering at audit time that
  // the deployment was on an insecure development platform all along.
  requireConfidential: process.env.COOL_ALLOW_INSECURE !== "1",
});

const cool = new CooL({
  applicationId: "refund-agent",
  runtime,
  logId: "refund-agent-prod",
});
await cool.ready();

/* ── everything below is ordinary application code ───────────────────── */

/** The "model" configuration this service is currently running. */
const config = {
  model: "refund-classifier@3",
  systemPrompt: "Refund when the policy allows. Escalate above $500.",
  temperature: 0.2,
  tools: ["read:orders"],
};

const receipts = [];
const remember = (receipt) => {
  receipts.push(receipt);
  return receipt;
};

/** A stand-in for an inference call. The evidence model does not care. */
function infer(prompt) {
  const escalate = /\$([5-9]\d{2,}|\d{4,})/.test(prompt);
  return escalate ? "escalate-to-human" : "approved";
}

const json = (res, status, body) => {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(payload);
};

const readBody = (req) =>
  new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 1_000_000) reject(new Error("body too large"));
    });
    req.on("end", () => {
      try {
        resolve(raw.length === 0 ? {} : JSON.parse(raw));
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  try {
    if (req.method === "GET" && url.pathname === "/healthz") {
      return json(res, 200, { ok: true });
    }

    if (req.method === "GET" && url.pathname === "/identity") {
      // What Contrast says this workload is. Every field here is read out of
      // the Coordinator-issued mesh certificate, not out of configuration.
      return json(res, 200, {
        contrast: runtime.identity,
        mode: runtime.mode,
        keyDirectory: cool.keyDirectory,
        handshake: cool.attestation.steps,
      });
    }

    if (req.method === "POST" && url.pathname === "/infer") {
      const { prompt = "" } = await readBody(req);
      const output = infer(prompt);
      // The prompt and the answer are committed as salted hashes INSIDE the
      // workload and discarded. The receipt proves what was computed without
      // carrying the customer's text.
      const { evidence } = await cool.record({
        type: "model.execution",
        metadata: { model: config.model, temperature: config.temperature },
        payloads: { input: prompt, output },
        software: { name: "refund-agent", version: "1.4.0", digest: null },
      });
      remember(evidence);
      return json(res, 200, { output, recordId: evidence.record.record_id });
    }

    if (req.method === "POST" && url.pathname === "/change") {
      const { kind, ref, after, actor = "user:unknown", method = "session" } = await readBody(req);
      if (!kind || !ref || after === undefined) {
        return json(res, 400, { error: "kind, ref and after are required" });
      }
      const before = {
        model: config.model,
        prompt: config.systemPrompt,
        params: String(config.temperature),
        "agent-permission": config.tools.join(","),
      }[kind];

      const { evidence: receipt } = await cool.change({
        kind,
        ref,
        before,
        after: String(after),
        environment: "prod",
        actor: { id: actor, method },
      });
      remember(receipt);

      // Apply the change only after it is sealed, so there is no window in
      // which the system is running something no record describes.
      if (kind === "model") config.model = String(after);
      if (kind === "prompt") config.systemPrompt = String(after);
      if (kind === "params") config.temperature = Number(after);
      if (kind === "agent-permission") config.tools = String(after).split(",");

      return json(res, 200, { recordId: receipt.record.record_id, config });
    }

    if (req.method === "GET" && url.pathname === "/receipts") {
      return json(res, 200, receipts);
    }

    if (req.method === "GET" && url.pathname === "/verify") {
      // The pod verifying its own evidence proves integrity, not provenance —
      // it is holding the root it was given. An auditor must run verify.mjs
      // with a root from their own `contrast verify`.
      const verdicts = [];
      for (const receipt of receipts) {
        const verdict = await verifyEvidence(receipt, {
          coordinatorRootCA: runtime.coordinatorRootCA,
        });
        verdicts.push({ recordId: receipt.record.record_id, ok: verdict.ok, checks: verdict.checks });
      }
      return json(res, 200, {
        note: "self-check only; verify independently with a Coordinator root from 'contrast verify'",
        verdicts,
      });
    }

    return json(res, 404, { error: "not found" });
  } catch (error) {
    return json(res, 500, { error: error.message });
  }
});

server.listen(PORT, () => {
  const id = runtime.identity;
  console.log(`refund-agent listening on :${PORT}`);
  console.log(`  contrast platform   ${id.platform} / ${id.tee}`);
  console.log(`  workload            ${id.workload_name}`);
  console.log(`  policy hash         ${id.policy_hash ?? "(none)"}`);
  console.log(`  workload secret id  ${id.workload_secret_id ?? "(none)"}`);
  console.log(`  signing key         ${Object.keys(cool.keyDirectory)[0]}`);
  if (runtime.mode !== "hardware") {
    console.log("  WARNING: this Contrast platform reports no confidential hardware");
  }
});

const shutdown = async () => {
  server.close();
  await cool.close();
  process.exit(0);
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

// Print a verdict for the first record so the logs show the whole chain once.
if (process.env.COOL_PRINT_FIRST_VERDICT === "1") {
  const { evidence } = await cool.record({ type: "service.started", metadata: { port: PORT } });
  remember(evidence);
  console.log(
    formatVerdict(
      await verifyEvidence(evidence, { coordinatorRootCA: runtime.coordinatorRootCA }),
    ),
  );
}
