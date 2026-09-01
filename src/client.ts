/**
 * `CooL` — the client an application imports.
 *
 *     import { CooL } from "cool-nwc";
 *
 *     const cool = new CooL({ applicationId: "my-app" });
 *     const { evidence } = await cool.record({
 *       type: "model.execution",
 *       metadata: { model: "my-model", version: "1.0.0" },
 *     });
 *     const verdict = await cool.verify(evidence);
 *
 * Construction does no I/O. The first `record()` / `verify()` / `ready()` call
 * connects the evidence plane: it reads the runtime's measurement, derives a
 * signing key sealed to it, and completes an RA-TLS handshake before a byte of
 * caller data is transmitted. With no `attestation.provider` set — or `"local"`
 * — that plane is the built-in simulator: the same code path, clearly labelled
 * `simulated` in every receipt and every verdict, never `pass` on a
 * hardware-dependent domain.
 *
 * Advanced wiring (a pinned measurement, a custom transparency backend, direct
 * dstack client construction, the change-record model) lives one layer down, in
 * `cool-nwc/phala`.
 */
import { CoolTee, type RecordRequest } from "./phala/client";
import { HttpDstackClient } from "./phala/dstack";
import type { DstackClient, EnclaveInfo } from "./phala/dstack";
import type { AttestationHandshake } from "./phala/ratls";
import type { Measurement, ReceiptV2, TeeVendor } from "./phala/types";
import { verifyEvidence, type Verdict, type VerifyOptions } from "./verify";
import type { KeyDirectory, Multihash } from "./types";
import {
  AttestationRequiredError,
  ClosedError,
  ConfigurationError,
  DstackUnavailableError,
  EvidenceError,
} from "./errors";

/** Where the evidence plane runs. */
export interface AttestationConfig {
  /**
   * `"local"` (default) runs the built-in simulator — no hardware, clearly
   * labelled. `"dstack"` talks to a Phala dstack guest agent.
   */
  readonly provider?: "local" | "dstack";
  /**
   * dstack guest-agent endpoint. Inside a dstack CVM this is the unix socket
   * `/var/run/dstack.sock`; over TCP (the dstack simulator) an `http://` URL.
   * Defaults to `$COOL_DSTACK_ENDPOINT`, then `/var/run/dstack.sock`.
   */
  readonly endpoint?: string;
  /** Host silicon vendor, recorded in the runtime block. Default `intel-tdx`. */
  readonly vendor?: TeeVendor;
}

/** Security policy. Explicit by design — nothing here has a surprising default. */
export interface SecurityConfig {
  /**
   * Require a verified hardware root of trust. When `true`, connecting fails
   * (rather than silently downgrading) if the plane is simulated, and a
   * simulated receipt can never verify `ok`. The setting a regulated deployment
   * turns on and never turns off again.
   */
  readonly requireAttestation?: boolean;
  /** Pin the measurement of the image you approved. Any mismatch fails. */
  readonly expectedMeasurement?: Measurement;
  /** Restrict acceptable silicon vendors. */
  readonly requireVendor?: readonly TeeVendor[];
}

/** Options for {@link CooL}. */
export interface CooLOptions {
  /** Identity of the application producing evidence. Default `"cool-app"`. */
  readonly applicationId?: string;
  /** Where and how the evidence plane runs. */
  readonly attestation?: AttestationConfig;
  /** Security policy. */
  readonly security?: SecurityConfig;
  /** Stable transparency-log id recorded in every signed tree head. */
  readonly logId?: string;
  /** Called with each sealed evidence record, in order. */
  readonly onEvidence?: (evidence: Evidence) => void;
  /** Called when an async `recordAsync` event is dropped (queue overflow, etc). */
  readonly onDrop?: (reason: string) => void;
  /** Inject a dstack client directly (tests, non-standard transports). */
  readonly dstackClient?: DstackClient;
  /** RFC 3339 clock. Inject for deterministic vectors and tests. */
  readonly clock?: () => string;
  /** Record-id generator. Inject for deterministic vectors and tests. */
  readonly newId?: () => string;
  /** Monotone sequence generator. Inject for deterministic vectors and tests. */
  readonly seq?: () => number;
}

/** A record request handed to {@link CooL.record}. */
export type RecordInput = RecordRequest;

/** A single piece of verifiable execution evidence. */
export type Evidence = ReceiptV2;

/** What {@link CooL.record} returns. */
export interface EvidenceResult {
  /** The self-contained, offline-verifiable evidence record. */
  readonly evidence: Evidence;
  /** The record's ULID. */
  readonly recordId: string;
  /** The execution/session id this evidence belongs to. */
  readonly executionId: string;
  /** The binding commitment over the record core. */
  readonly digest: Multihash;
}

/** A summary of the connected runtime. */
export interface Environment {
  readonly provider: "local" | "dstack";
  readonly mode: EnclaveInfo["mode"];
  readonly vendor: EnclaveInfo["vendor"];
  readonly appId: string;
  readonly instanceId: string;
  readonly measurement: Measurement;
  /** True only when a verified hardware quote backs this plane. */
  readonly hardware: boolean;
}

const DEFAULT_SOCKET = "/var/run/dstack.sock";

function resolveProvider(config: AttestationConfig): "local" | "dstack" {
  if (config.provider) return config.provider;
  if (config.endpoint) return "dstack";
  if (typeof process !== "undefined" && process.env?.["COOL_DSTACK_ENDPOINT"]) return "dstack";
  return "local";
}

export class CooL {
  private readonly options: CooLOptions;
  private readonly applicationId: string;
  private readonly provider: "local" | "dstack";
  private connecting: Promise<CoolTee> | null = null;
  private tee: CoolTee | null = null;
  private closed = false;

  constructor(options: CooLOptions = {}) {
    this.options = options;
    this.applicationId = options.applicationId ?? "cool-app";
    this.provider = resolveProvider(options.attestation ?? {});

    if (this.applicationId.length === 0) {
      throw new ConfigurationError(
        "applicationId must not be empty",
        "pass a non-empty applicationId, e.g. new CooL({ applicationId: 'billing-api' })",
      );
    }
    if (options.attestation?.provider === "local" && options.security?.requireAttestation) {
      throw new ConfigurationError(
        "security.requireAttestation is set but attestation.provider is 'local' (the simulator)",
        "set attestation.provider to 'dstack', or drop security.requireAttestation for local development",
      );
    }
  }

  /** Force the connection now. Optional — `record()` does it on first use. */
  async ready(): Promise<void> {
    await this.connect();
  }

  private connect(): Promise<CoolTee> {
    if (this.closed) return Promise.reject(new ClosedError());
    if (this.tee) return Promise.resolve(this.tee);
    if (this.connecting) return this.connecting;
    this.connecting = this.openPlane()
      .then((tee) => {
        this.tee = tee;
        return tee;
      })
      .catch((error) => {
        this.connecting = null;
        throw error;
      });
    return this.connecting;
  }

  private async openPlane(): Promise<CoolTee> {
    const security = this.options.security ?? {};
    const attestation = this.options.attestation ?? {};

    let client: DstackClient | undefined = this.options.dstackClient;
    if (!client && this.provider === "dstack") {
      const endpoint =
        attestation.endpoint ??
        (typeof process !== "undefined" ? process.env?.["COOL_DSTACK_ENDPOINT"] : undefined) ??
        DEFAULT_SOCKET;
      try {
        client = new HttpDstackClient({
          endpoint,
          vendor: attestation.vendor ?? "intel-tdx",
        });
      } catch (error) {
        throw new DstackUnavailableError(
          `could not construct a dstack client for '${endpoint}'`,
          {
            cause: error,
            action:
              "check attestation.endpoint, or run with attestation.provider: 'local' for development",
          },
        );
      }
    }

    let tee: CoolTee;
    try {
      tee = await CoolTee.connect({
        ...(client ? { dstack: client } : {}),
        app: {
          name: this.applicationId,
          imageDigest:
            typeof process !== "undefined"
              ? (process.env?.["COOL_IMAGE_DIGEST"] ?? "sha256:unpinned-development-image")
              : "sha256:unpinned-development-image",
        },
        ...(this.options.logId === undefined ? {} : { logId: this.options.logId }),
        ...(this.options.clock === undefined ? {} : { clock: this.options.clock }),
        ...(this.options.newId === undefined ? {} : { newId: this.options.newId }),
        ...(this.options.seq === undefined ? {} : { seq: this.options.seq }),
        ...(security.expectedMeasurement === undefined
          ? {}
          : { expectedMeasurement: security.expectedMeasurement }),
        policy: {
          allowSimulated: !security.requireAttestation,
          ...(security.expectedMeasurement === undefined
            ? {}
            : { expectedMeasurement: security.expectedMeasurement }),
          ...(security.requireVendor === undefined
            ? {}
            : { requireVendor: security.requireVendor }),
        },
        ...(this.options.onEvidence ? { onReceipt: this.options.onEvidence } : {}),
        ...(this.options.onDrop
          ? { onDrop: (_event: unknown, reason: string) => this.options.onDrop?.(reason) }
          : {}),
      });
    } catch (error) {
      if (this.provider === "dstack") {
        throw new DstackUnavailableError(
          `CooL could not reach the dstack guest agent`,
          {
            cause: error,
            action:
              "run the application inside a dstack CVM with /var/run/dstack.sock mounted, start the dstack simulator, or use attestation.provider: 'local'",
          },
        );
      }
      throw error;
    }

    if (security.requireAttestation && !tee.handshake.ok) {
      throw new AttestationRequiredError(
        `security.requireAttestation is set and the attestation handshake did not pass: ${tee.handshake.reasons.join("; ")}`,
        "deploy inside attested hardware, or remove security.requireAttestation",
      );
    }

    return tee;
  }

  /**
   * Record an execution-evidence event. The metadata and any `payloads` are
   * committed as salted hashes inside the evidence plane and discarded — the
   * returned evidence never carries raw application data.
   */
  async record(input: RecordInput): Promise<EvidenceResult> {
    if (!input || typeof input.type !== "string" || input.type.length === 0) {
      throw new EvidenceError("record() requires a non-empty `type`", {
        action: "pass { type: 'model.execution', metadata: { ... } }",
      });
    }
    const tee = await this.connect();
    let evidence: Evidence;
    try {
      evidence = await tee.record(input);
    } catch (error) {
      throw new EvidenceError("failed to seal the evidence record", { cause: error });
    }
    return {
      evidence,
      recordId: evidence.record.record_id,
      executionId:
        evidence.record.schema === "cool.evidence.v1"
          ? evidence.record.event.execution_id
          : evidence.record.record_id,
      digest: evidence.binding_hash,
    };
  }

  /** Verify a piece of CooL evidence. Delegates to the standalone verifier. */
  verify(evidence: unknown, options: VerifyOptions = {}): Promise<Verdict> {
    const security = this.options.security ?? {};
    return verifyEvidence(evidence, {
      ...options,
      ...(security.requireAttestation ? { requireHardware: true } : {}),
      ...(options.expectedMeasurement === undefined && security.expectedMeasurement !== undefined
        ? { expectedMeasurement: security.expectedMeasurement }
        : {}),
    });
  }

  /** The RA-TLS attestation transcript — render it; it is your proof. */
  get attestation(): AttestationHandshake {
    if (!this.tee) {
      throw new ConfigurationError(
        "attestation transcript is not available until the plane is connected",
        "await cool.ready() or cool.record(...) first",
      );
    }
    return this.tee.handshake;
  }

  /** Public keys any verifier needs — publish this next to your evidence. */
  get keyDirectory(): KeyDirectory {
    if (!this.tee) {
      throw new ConfigurationError(
        "keyDirectory is not available until the plane is connected",
        "await cool.ready() or cool.record(...) first",
      );
    }
    return this.tee.keyDirectory;
  }

  /** A summary of the connected runtime. Throws until connected. */
  get environment(): Environment {
    if (!this.tee) {
      throw new ConfigurationError(
        "environment is not available until the plane is connected",
        "await cool.ready() or cool.record(...) first",
      );
    }
    const info = this.tee.plane.info;
    return {
      provider: this.provider,
      mode: info.mode,
      vendor: info.vendor,
      appId: info.appId,
      instanceId: info.instanceId,
      measurement: info.measurement,
      hardware: info.mode === "hardware" && this.tee.handshake.ok,
    };
  }

  /** Evidence records retained in memory for inspection, newest last. */
  get evidence(): readonly Evidence[] {
    return this.tee?.receipts ?? [];
  }

  /** Flush any queued async events. Call before the process exits. */
  async flush(): Promise<void> {
    if (this.tee) await this.tee.flush();
  }

  /** Stop accepting work and drain. Idempotent. */
  async close(): Promise<void> {
    this.closed = true;
    if (this.tee) await this.tee.close();
  }
}
