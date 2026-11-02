/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The Nitro Enclaves deployment kit: the enclave-side server and the
 * host-side collector that together produce a VALIDATION ARTIFACT — the record
 * that CooL sealed receipts inside a real enclave and that they verify against
 * the pinned AWS root.
 *
 *   enclave:  serveEnclave({ nsm: new CommandNsmSource("/app/nsm-helper") })
 *             listens on 127.0.0.1:5005; socat bridges VSOCK-LISTEN:5005 to it
 *   host:     collectFromEnclave({ port, policy })   (socat bridges TCP → VSOCK)
 *
 * Wire protocol: CooL frames (./vsock), JSON payloads.
 *   host → hello {nonce}             enclave → register {key_id, entry, attestation}
 *   host → register {epoch}          enclave → ack {epoch}
 *   host → receipt {input}           enclave → receipt {envelope}
 *   either → error {message}
 *
 * The collector trusts NOTHING the enclave says until the attestation verifies:
 * chain to the AWS root, PCR policy, the nonce it just sent, and user_data
 * binding the receipt key. Only then is that key trusted for the receipts.
 *
 * examples/nitro-enclave/ packages this for nitro-cli. Exercised here with a
 * synthetic NSM (tests/nitro-kit.test.ts); a run on real hardware is recorded
 * only when an artifact with `synthetic: false` exists in artifacts/.
 */
import { createServer, connect, type Server, type Socket } from "node:net";
import { randomBytes } from "node:crypto";
import { encodeFrame, FrameDecoder, FrameType, type Frame } from "./vsock";
import { NitroReceiptSealer, type NsmSource } from "./receipt";
import { verifyNitroAttestation, type NitroPcrPolicy, type NitroAttestationReport } from "./attestation";
import { AWS_NITRO_TRUST_BUNDLE, type NitroTrustBundle } from "./trust-root";
import { PayloadRegistry } from "../platform/payloads";
import { TrustStore } from "../platform/trust";
import { verifyEnvelope, type EnvelopeInput, type SignedEnvelope, type VerificationReport } from "../platform/envelope";
import type { DirectoryEntry } from "../types";

const enc = (v: unknown) => new TextEncoder().encode(JSON.stringify(v));
const dec = (f: Frame) => JSON.parse(new TextDecoder().decode(f.payload)) as Record<string, unknown>;

/* ── enclave side ─────────────────────────────────────────────────────── */

export interface EnclaveServer { readonly port: number; close(): Promise<void> }

/**
 * Serve the sealer. ONE key per enclave instance: the first `hello` starts the
 * sealer with that verifier's nonce; later hellos are refused, so a single
 * enclave run cannot present two different keys.
 */
export async function serveEnclave(options: { readonly nsm: NsmSource; readonly registry?: PayloadRegistry; readonly host?: string; readonly port?: number; readonly log?: (m: string) => void }): Promise<EnclaveServer> {
  const registry = options.registry ?? PayloadRegistry.standard();
  const log = options.log ?? (() => {});
  let sealer: NitroReceiptSealer | undefined;
  let starting: Promise<NitroReceiptSealer> | undefined;
  const server: Server = createServer((sock) => {
    const decoder = new FrameDecoder();
    const send = (type: number, v: unknown) => sock.write(encodeFrame(type, enc(v)));
    sock.on("data", async (chunk: Buffer) => {
      let frames: Frame[];
      try { frames = decoder.push(new Uint8Array(chunk)); } catch (err) { send(FrameType.error, { message: (err as Error).message }); sock.destroy(); return; }
      for (const f of frames) {
        try {
          const body = dec(f);
          if (f.type === FrameType.hello) {
            if (starting) throw new Error("this enclave instance already has a key; restart the enclave for a new attestation");
            const nonce = Buffer.from(String(body["nonce"] ?? ""), "base64");
            if (nonce.length < 16) throw new Error("hello needs a nonce of at least 16 bytes");
            starting = NitroReceiptSealer.start({ nsm: options.nsm, registry, nonce: new Uint8Array(nonce) });
            sealer = await starting;
            log(`sealer started: ${sealer.keyId}`);
            send(FrameType.register, { key_id: sealer.keyId, entry: sealer.publicEntry, attestation: Buffer.from(sealer.attestation).toString("base64") });
          } else if (f.type === FrameType.register) {
            if (!sealer) throw new Error("hello first");
            sealer.acceptEpoch({ registration: { epoch: Number(body["epoch"]), key_id: sealer.keyId } });
            send(FrameType.ack, { epoch: Number(body["epoch"]) });
          } else if (f.type === FrameType.receipt) {
            if (!sealer) throw new Error("hello first");
            send(FrameType.receipt, { envelope: sealer.seal(body["input"] as EnvelopeInput & { event_id: string }) });
          } else throw new Error(`unexpected frame type ${f.type}`);
        } catch (err) {
          send(FrameType.error, { message: (err as Error).message });
        }
      }
    });
    sock.on("error", () => sock.destroy());
  });
  await new Promise<void>((resolve) => server.listen(options.port ?? 5005, options.host ?? "127.0.0.1", () => resolve()));
  const port = (server.address() as { port: number }).port;
  log(`CooL enclave server on ${options.host ?? "127.0.0.1"}:${port}`);
  return { port, close: () => new Promise<void>((r) => server.close(() => r())) };
}

/* ── host side ────────────────────────────────────────────────────────── */

export interface ValidationArtifact {
  readonly schema: "cool.nitro-validation.v1";
  readonly recorded_at: string;
  /** True unless the attestation chained to the pinned AWS root. */
  readonly synthetic: boolean;
  readonly trust_bundle: { readonly id: string; readonly version: string };
  readonly policy: { readonly id: string; readonly version: string; readonly source: string; readonly pcrs: Readonly<Record<number, string>> };
  readonly nonce: string;
  readonly enclave: { readonly key_id: string; readonly entry: DirectoryEntry; readonly module_id?: string; readonly attestation_b64: string };
  readonly attestation: Pick<NitroAttestationReport, "overall_status" | "document_sha256" | "reasons"> & { readonly checks: Record<string, { status: string; reason: string }> };
  readonly receipts: readonly { readonly envelope: SignedEnvelope; readonly overall_status: VerificationReport["overall_status"]; readonly outcome: VerificationReport["outcome"]; readonly reasons: readonly string[] }[];
  readonly passed: boolean;
  readonly environment?: Readonly<Record<string, string>>;
}

class Session {
  readonly #decoder = new FrameDecoder();
  readonly #waiting: Array<(f: Frame) => void> = [];
  readonly #queue: Frame[] = [];
  constructor(readonly sock: Socket, readonly timeoutMs: number) {
    sock.on("data", (c: Buffer) => {
      for (const f of this.#decoder.push(new Uint8Array(c))) {
        const w = this.#waiting.shift();
        if (w) w(f); else this.#queue.push(f);
      }
    });
  }
  async request(type: number, body: unknown, expect: number): Promise<Record<string, unknown>> {
    this.sock.write(encodeFrame(type, enc(body)));
    const f = this.#queue.shift() ?? await new Promise<Frame>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("enclave did not answer in time")), this.timeoutMs);
      this.#waiting.push((fr) => { clearTimeout(t); resolve(fr); });
    });
    const b = dec(f);
    if (f.type === FrameType.error) throw new Error(`enclave error: ${String(b["message"])}`);
    if (f.type !== expect) throw new Error(`unexpected frame type ${f.type}`);
    return b;
  }
}

/** Sample events sealed during validation: commitments only, no plaintext. */
export const VALIDATION_EVENTS = (n: number, at = Date.now()): Array<EnvelopeInput & { event_id: string }> =>
  Array.from({ length: n }, (_, i) => ({
    event_id: `nitro-validation-${i}`,
    event_type: "ai.inference",
    occurred_at: new Date(at + i).toISOString(),
    observed_at: new Date(at + i).toISOString(),
    source: { system: "cool-nitro-validation", instance: "enclave" },
    actor: { id: "workload:cool-nitro-validation", type: "workload" as const },
    action: "infer",
    resource: { type: "model", ref: "validation/echo@1" },
    payload: { model: "validation/echo", model_version: "1", input_commitment: `mh:sha256:${randomBytes(32).toString("hex")}`, output_commitment: `mh:sha256:${randomBytes(32).toString("hex")}` },
  }));

/**
 * Connect, challenge, verify the attestation BEFORE trusting the key, seal
 * `count` receipts, verify each, and return the artifact. Throws only on
 * transport failure; verification failures are recorded with `passed: false`.
 */
export async function collectFromEnclave(options: {
  readonly host?: string;
  readonly port?: number;
  readonly policy: NitroPcrPolicy;
  readonly trustBundle?: NitroTrustBundle;
  readonly count?: number;
  readonly timeoutMs?: number;
  readonly environment?: Readonly<Record<string, string>>;
  readonly now?: () => number;
}): Promise<ValidationArtifact> {
  const now = options.now ?? Date.now;
  const bundle = options.trustBundle ?? AWS_NITRO_TRUST_BUNDLE;
  const registry = PayloadRegistry.standard();
  const sock = connect({ host: options.host ?? "127.0.0.1", port: options.port ?? 5005 });
  await new Promise<void>((resolve, reject) => { sock.once("connect", () => resolve()); sock.once("error", reject); });
  const session = new Session(sock, options.timeoutMs ?? 30_000);
  try {
    const nonce = new Uint8Array(randomBytes(32));
    const reg = await session.request(FrameType.hello, { nonce: Buffer.from(nonce).toString("base64") }, FrameType.register);
    const keyId = String(reg["key_id"]);
    const entry = reg["entry"] as DirectoryEntry;
    const document = new Uint8Array(Buffer.from(String(reg["attestation"]), "base64"));
    const report = verifyNitroAttestation(document, { trustBundle: bundle, policy: options.policy, receiptKey: { keyId, entry }, freshness: { mode: "nonce", expected: nonce }, now: now() });
    const base = {
      schema: "cool.nitro-validation.v1" as const,
      recorded_at: new Date(now()).toISOString(),
      synthetic: bundle.id !== AWS_NITRO_TRUST_BUNDLE.id,
      trust_bundle: { id: bundle.id, version: bundle.version },
      policy: { id: options.policy.id, version: options.policy.version, source: options.policy.source, pcrs: options.policy.pcrs },
      nonce: Buffer.from(nonce).toString("hex"),
      enclave: { key_id: keyId, entry, ...(report.claims?.module_id ? { module_id: report.claims.module_id } : {}), attestation_b64: Buffer.from(document).toString("base64") },
      attestation: { overall_status: report.overall_status, document_sha256: report.document_sha256, reasons: report.reasons, checks: Object.fromEntries(Object.entries(report.checks).map(([k, c]) => [k, { status: c.status, reason: c.reason }])) },
      ...(options.environment ? { environment: options.environment } : {}),
    };
    if (report.overall_status !== "pass") return { ...base, receipts: [], passed: false };

    // Only now is the enclave's key trusted — because the attestation bound it.
    const trust = new TrustStore({ schema: "cool.trust-snapshot.v1", id: "attested-enclave-key", as_of: new Date(now()).toISOString(), keys: [{ key_id: keyId, entry, purposes: ["evidence"], owner: `nitro enclave ${report.claims?.module_id ?? ""}`.trim(), valid_from: new Date(now() - 60_000).toISOString(), status: "active" }] });
    await session.request(FrameType.register, { epoch: 1 }, FrameType.ack);
    const receipts = [];
    for (const input of VALIDATION_EVENTS(options.count ?? 3, now())) {
      const out = await session.request(FrameType.receipt, { input }, FrameType.receipt);
      const envelope = out["envelope"] as SignedEnvelope;
      const r = verifyEnvelope(envelope, { registry, trust, now: now(), nitro: { trustBundle: bundle, policy: options.policy, freshness: { mode: "nonce", expected: nonce } } });
      receipts.push({ envelope, overall_status: r.overall_status, outcome: r.outcome, reasons: r.reasons });
    }
    return { ...base, receipts, passed: receipts.length > 0 && receipts.every((r) => r.overall_status === "pass") };
  } finally {
    sock.destroy();
  }
}
