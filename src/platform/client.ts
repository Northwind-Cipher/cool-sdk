/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * CoolClient: one entry point, one namespace per module.
 *
 *   const cool = new CoolClient({ project, signer, trust });
 *   const core = cool.evidence.create(input);   // validate, no side effects
 *   const env  = cool.evidence.sign(core);       // local signature
 *   const pub  = cool.evidence.publish(env);     // append to the configured log
 *   const rep  = cool.evidence.verify(pub);      // offline, per-check report
 *
 * Every method does what its name says and nothing else — there is no
 * secure() or protect(). Defaults are the safe ones: offline (the client makes
 * no network calls; only connectors you run and adapters you call may), policy
 * in `audit` mode (decisions are advisory), enforcement disabled.
 *
 * Configuration is explicit. The client reads no environment variables, so
 * nothing in the environment can silently change trust settings.
 * `inspectConfig()` explains the effective settings with secrets redacted.
 */
import { CooLError } from "../errors";
import { exportBundle, verifyBundle, type EvidenceBundle } from "./bundle";
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
import { EnforcementCoordinator } from "./enforcement";
import { PayloadRegistry } from "./payloads";
import { evaluatePolicy, simulatePolicy, PolicyRegistry, type Facts, type PolicyDocument, type PolicyDecisionRecord } from "./policy";
import type { TransparencyLog } from "./transparency";
import type { TrustStore } from "./trust";
import type { KeyPair } from "../types";
import * as supplyChain from "./modules/supply-chain";
import * as identity from "./modules/identity";
import * as changeControl from "./modules/change-control";
import * as runtime from "./modules/runtime-guard";
import { IncidentCase, type Severity } from "./modules/incidents";

export type PolicyMode = "disabled" | "audit" | "enforce";

export interface CoolClientConfig {
  readonly project: string;
  readonly signer: Signer | KeyPair;
  readonly trust: TrustStore;
  /** Where `evidence.publish` appends. Absent → publish throws. */
  readonly log?: TransparencyLog;
  readonly registry?: PayloadRegistry;
  /** disabled: no evaluation · audit (default): advisory · enforce: as each policy says. */
  readonly policyMode?: PolicyMode;
  /** Off unless set. Even then each request is a dry run unless asked otherwise. */
  readonly enforcement?: { readonly enabled: boolean; readonly timeoutMs?: number };
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
  readonly #coordinator: EnforcementCoordinator;
  readonly #policies: PolicyRegistry;
  #closed = false;

  constructor(config: CoolClientConfig) {
    if (!config.project) throw new CooLError("COOL_CONFIGURATION_INVALID", "project is required");
    if (!config.signer) throw new CooLError("COOL_CONFIGURATION_INVALID", "a signer is required", { action: "pass signer: generateKeypair(...) or a KMS-backed Signer" });
    if (!config.trust) throw new CooLError("COOL_CONFIGURATION_INVALID", "a trust store is required");
    this.#config = config;
    this.#signer = "sign" in config.signer && typeof config.signer.sign === "function" ? (config.signer as Signer) : localSigner(config.signer as KeyPair);
    this.#registry = config.registry ?? PayloadRegistry.standard();
    this.#coordinator = new EnforcementCoordinator({
      enabled: config.enforcement?.enabled ?? false,
      ...(config.enforcement?.timeoutMs ? { timeoutMs: config.enforcement.timeoutMs } : {}),
      audit: (e) => this.#log("info", `enforcement ${e.kind}`, { request_id: e.request.request_id, adapter: e.request.adapter, state: e.result?.state }),
      ...(config.clock ? { clock: config.clock } : {}),
    });
    this.#policies = new PolicyRegistry({ ...(config.clock ? { clock: config.clock } : {}) });
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

  /** Effective settings, explained, with nothing secret in them. */
  inspectConfig(): Record<string, unknown> {
    const snap = this.#config.trust.snapshot();
    return redact({
      project: this.#config.project,
      signer: { key_id: this.#signer.keyId, kind: "sign" in this.#config.signer ? "provider" : "local keypair (in memory)" },
      trust: { snapshot: snap.id, as_of: snap.as_of, max_age_ms: snap.max_age_ms ?? "none stated", keys: snap.keys.length },
      transparency: this.#config.log ? { configured: true, size: this.#config.log.size } : { configured: false },
      policy_mode: this.#config.policyMode ?? "audit",
      enforcement: { enabled: this.#coordinator.enabled, default: "dry run" },
      network: "the client makes no outbound calls; connectors and adapters you run may (see their declared permissions)",
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
    exportBundle: (title: string, envelopes: readonly SignedEnvelope[], decisions: readonly PolicyDecisionRecord[] = [], exporter?: KeyPair): EvidenceBundle => {
      this.#live();
      const key = exporter ?? ("mlDsaSecret" in this.#config.signer ? (this.#config.signer as KeyPair) : undefined);
      if (!key) throw new CooLError("COOL_CONFIGURATION_INVALID", "bundle export needs a local exporter keypair");
      return exportBundle({ title, envelopes, decisions, trust: this.#config.trust, exporter: key, ...(this.#config.clock ? { now: this.#config.clock() } : {}) });
    },
    verifyBundle: (bundle: EvidenceBundle) => verifyBundle(bundle, { ...this.#verifyOptions(), trust: this.#config.trust }),
  };

  readonly policy = {
    registry: () => this.#policies,
    /** Evaluate under the client's policy mode. Returns null when policy is disabled. */
    evaluate: (p: PolicyDocument, facts: Facts, inputRefs: readonly string[] = []): PolicyDecisionRecord | null => {
      this.#live();
      const mode = this.#config.policyMode ?? "audit";
      if (mode === "disabled") return null;
      const doc = mode === "audit" ? { ...p, mode: "observe" as const } : p;
      return evaluatePolicy(doc, facts, { inputRefs, ...(this.#config.clock ? { now: this.#config.clock() } : {}) });
    },
    simulate: simulatePolicy,
  };

  readonly trust = {
    evaluate: (keyId: string, purpose: Parameters<TrustStore["evaluate"]>[0]["purpose"]) => this.#config.trust.evaluate({ keyId, purpose, now: (this.#config.clock?.() ?? new Date()).getTime() }),
    snapshot: () => this.#config.trust.snapshot(),
  };

  readonly connectors = {
    run: (c: Connector, options?: Parameters<typeof runConnector>[1]) => (this.#live(), runConnector(c, options)),
  };

  readonly supply_chain = {
    buildProvenance: supplyChain.buildProvenance,
    artifactFacts: supplyChain.artifactFacts,
    releasePolicy: supplyChain.RELEASE_POLICY,
    gate: (input: Omit<Parameters<typeof supplyChain.gateDeployment>[0], "coordinator">) => {
      this.#live();
      const policy = input.policy ?? supplyChain.RELEASE_POLICY;
      const mode = this.#config.policyMode ?? "audit";
      const effective = mode === "enforce" ? policy : { ...policy, mode: "observe" as const };
      return supplyChain.gateDeployment({ ...input, policy: effective, coordinator: this.#coordinator, ...(this.#config.clock ? { now: this.#config.clock } : {}) });
    },
  };

  readonly identity = {
    credential: (ref: string, provider: string, subject: string) => new identity.CredentialLifecycle(ref, provider, subject),
    matrix: (grants: readonly identity.Grant[]) => new identity.AuthorizationMatrix(grants),
    replayGuard: (ttlMs: number) => new identity.ReplayGuard(ttlMs),
  };

  readonly change_control = {
    facts: changeControl.changeFacts,
    policy: changeControl.CHANGE_POLICY,
    detectDrift: changeControl.detectDrift,
    rollout: (id: string, digest: `mh:sha256:${string}`, stages: ReadonlyArray<{ name: string; percent: number }>) => new changeControl.RolloutController(id, digest, stages),
  };

  readonly runtime = {
    guard: (options?: ConstructorParameters<typeof runtime.RuntimeGuard>[0]) => new runtime.RuntimeGuard(options),
    coordinator: () => this.#coordinator,
  };

  readonly incidents = {
    open: (id: string, title: string, severity: Severity) => new IncidentCase(id, title, severity),
  };

  /** Release resources. Idempotent; every later call throws COOL_CLOSED. */
  close(): void {
    this.#closed = true;
  }
}
