/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * CoolClient: the open evidence client.
 *
 *   const cool = new CoolClient({ project, signer, trust });
 *   const core = cool.evidence.create(input);   // validate, no side effects
 *   const env  = cool.evidence.sign(core);       // local signature
 *   const pub  = cool.evidence.publish(env);     // append to the configured log
 *   const rep  = cool.evidence.verify(pub);      // offline, per-check report
 *
 * Every method does what its name says and nothing else — there is no
 * secure() or protect(). The client is offline: it makes no network calls;
 * only connectors you run may.
 *
 * Configuration is explicit. The client reads no environment variables, so
 * nothing in the environment can silently change trust settings.
 * `inspectConfig()` explains the effective settings with secrets redacted.
 *
 * Policy, enforcement, incident reconstruction and the operational modules
 * build on this client in the commercial CooL platform.
 */
import { CooLError } from "../errors";
import type { KeyPair } from "../types";
import { exportBundle, verifyBundle, type DecisionRecord, type EvidenceBundle } from "./bundle";
import { runConnector, type Connector } from "./connectors";
import {
  canonicalize,
  commit,
  createEnvelope,
  inspectEnvelope,
  localSigner,
  signEnvelope,
  verifyEnvelope,
  type EnvelopeCore,
  type EnvelopeInput,
  type Signer,
  type SignedEnvelope,
  type VerifyEnvelopeOptions,
} from "./envelope";
import { PayloadRegistry } from "./payloads";
import type { TransparencyLog } from "./transparency";
import type { TrustStore } from "./trust";

export interface CoolClientConfig {
  readonly project: string;
  readonly signer: Signer | KeyPair;
  readonly trust: TrustStore;
  /** Where `evidence.publish` appends. Absent → publish throws. */
  readonly log?: TransparencyLog;
  readonly registry?: PayloadRegistry;
  readonly verify?: Omit<VerifyEnvelopeOptions, "registry" | "trust">;
  readonly logger?: (level: "debug" | "info" | "warn", message: string, fields?: Record<string, unknown>) => void;
  readonly clock?: () => Date;
}

const SENSITIVE = /(secret|password|passphrase|token|private|credential|ml_dsa_secret|ed25519_secret|mlDsaSecret|ed25519Secret)/i;

/** Deep-copy with sensitive members replaced. Used for every log line and the config inspector. */
export function redact(value: unknown): unknown {
  if (value instanceof Uint8Array) return `[${value.length} bytes]`;
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, SENSITIVE.test(k) ? "[redacted]" : redact(v)]));
  }
  return value;
}

export class CoolClient {
  readonly #config: CoolClientConfig;
  readonly #signer: Signer;
  readonly #registry: PayloadRegistry;
  #closed = false;

  constructor(config: CoolClientConfig) {
    if (!config.project) throw new CooLError("COOL_CONFIGURATION_INVALID", "project is required");
    if (!config.signer) throw new CooLError("COOL_CONFIGURATION_INVALID", "a signer is required", { action: "pass signer: generateKeypair(...) or a KMS-backed Signer" });
    if (!config.trust) throw new CooLError("COOL_CONFIGURATION_INVALID", "a trust store is required");
    this.#config = config;
    this.#signer = "sign" in config.signer && typeof config.signer.sign === "function" ? (config.signer as Signer) : localSigner(config.signer as KeyPair);
    this.#registry = config.registry ?? PayloadRegistry.standard();
  }

  #live(): void {
    if (this.#closed) throw new CooLError("COOL_CLOSED", "this CoolClient has been closed");
  }

  #log(level: "debug" | "info" | "warn", message: string, fields?: Record<string, unknown>): void {
    this.#config.logger?.(level, message, fields ? (redact(fields) as Record<string, unknown>) : undefined);
  }

  #verifyOptions(extra: Partial<VerifyEnvelopeOptions> = {}): VerifyEnvelopeOptions {
    return { ...(this.#config.verify ?? {}), ...extra, registry: this.#registry, trust: this.#config.trust };
  }

  /** The registry this client validates payloads against. */
  get registry(): PayloadRegistry {
    return this.#registry;
  }

  /** Effective settings, explained, with nothing secret in them. */
  inspectConfig(): Record<string, unknown> {
    const snap = this.#config.trust.snapshot();
    return redact({
      project: this.#config.project,
      signer: { key_id: this.#signer.keyId, kind: "sign" in this.#config.signer ? "provider" : "local keypair (in memory)" },
      trust: { snapshot: snap.id, as_of: snap.as_of, max_age_ms: snap.max_age_ms ?? "none stated", keys: snap.keys.length },
      transparency: this.#config.log ? { configured: true, size: this.#config.log.size } : { configured: false },
      network: "the client makes no outbound calls; connectors you run may (see their declared permissions)",
      environment_variables_read: "none",
      payload_schemas: this.#registry.eventTypes().length,
    }) as Record<string, unknown>;
  }

  readonly evidence = {
    create: (input: EnvelopeInput): EnvelopeCore => (this.#live(), createEnvelope(input, this.#registry, this.#config.clock)),
    canonicalize: (core: EnvelopeCore) => canonicalize(core),
    commit: (bytes: Uint8Array) => commit(bytes),
    sign: (core: EnvelopeCore, attestation?: EnvelopeInput["attestation"]): SignedEnvelope => (this.#live(), signEnvelope(core, this.#signer, attestation)),
    /** create + sign in one step, for callers that want both and nothing more. */
    record: (input: EnvelopeInput): SignedEnvelope => (this.#live(), signEnvelope(createEnvelope(input, this.#registry, this.#config.clock), this.#signer, input.attestation)),
    publish: (env: SignedEnvelope): SignedEnvelope => {
      this.#live();
      if (!this.#config.log) throw new CooLError("COOL_TRANSPARENCY_FAILED", "no transparency log configured", { action: "pass log: new TransparencyLog(...)" });
      const out = this.#config.log.publish(env);
      this.#log("debug", "published", { digest: env.digest, leaf: out.checkpoint?.leaf_index });
      return out;
    },
    verify: (env: SignedEnvelope, extra: Partial<VerifyEnvelopeOptions> = {}) => verifyEnvelope(env, this.#verifyOptions(extra)),
    inspect: (env: SignedEnvelope) => inspectEnvelope(env),
    exportBundle: (title: string, envelopes: readonly SignedEnvelope[], decisions: readonly DecisionRecord[] = [], exporter?: KeyPair): EvidenceBundle => {
      this.#live();
      const key = exporter ?? ("mlDsaSecret" in this.#config.signer ? (this.#config.signer as KeyPair) : undefined);
      if (!key) throw new CooLError("COOL_CONFIGURATION_INVALID", "bundle export needs a local exporter keypair");
      return exportBundle({ title, envelopes, decisions, trust: this.#config.trust, exporter: key, ...(this.#config.clock ? { now: this.#config.clock() } : {}) });
    },
    verifyBundle: (bundle: EvidenceBundle) => verifyBundle(bundle, { ...this.#verifyOptions(), trust: this.#config.trust }),
  };

  readonly trust = {
    evaluate: (keyId: string, purpose: Parameters<TrustStore["evaluate"]>[0]["purpose"]) => this.#config.trust.evaluate({ keyId, purpose, now: (this.#config.clock?.() ?? new Date()).getTime() }),
    snapshot: () => this.#config.trust.snapshot(),
  };

  readonly connectors = {
    run: (c: Connector, options?: Parameters<typeof runConnector>[1]) => (this.#live(), runConnector(c, options)),
  };

  /** Release resources. Idempotent; every later call throws COOL_CLOSED. */
  close(): void {
    this.#closed = true;
  }
}
