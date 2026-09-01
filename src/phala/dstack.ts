/**
 * The dstack client — CooL's only touch-point with the confidential VM.
 *
 * Phala's dstack is "Docker for TEEs": you hand it a compose file, it measures
 * the image into the TD, and a guest agent inside the VM exposes three things
 * over a local socket — the TCB info (what am I?), quotes (prove it), and
 * measurement-bound key derivation (give me a secret only this code can have).
 * Those three calls are the entire integration surface, which is why this file
 * is small and why moving between Intel TDX, AMD SEV-SNP and a laptop costs
 * nothing above it.
 *
 * Two implementations:
 *
 *   {@link HttpDstackClient}      talks to the real guest agent inside a CVM.
 *   {@link SimulatedDstackClient} reproduces the same three calls with real
 *                                 cryptography over a CooL-held root, so the
 *                                 whole pipeline — including key sealing and
 *                                 quote verification — runs in a browser, in CI,
 *                                 and on a developer laptop with no TEE at all.
 *
 * The simulator is honest in the way that matters: keys really are derived from
 * the measurement, so changing the deployed image really does change the key and
 * really does break every record signed by the old one. That failure is the
 * property customers are buying; it should be demonstrable without a data centre.
 */
import { sha256, sha384 } from "@noble/hashes/sha2";
import type { Base64Field, HexField, KeyDirectory, KeyPair, Multihash } from "../types";
import { concatBytes, toBase64Field, toHexField, utf8 } from "../codec";
import { generateKeypair } from "../keys";
import { multihashDigest } from "../multihash";
import type { Measurement, QuoteBody, QuoteEnvelope, RuntimeMode, TeeVendor } from "./types";
import { SIM_ROOT_KEY_ID, signSimulatedQuote } from "./quote";

/** One entry of the RTMR event log — what was extended, and with what. */
export interface EnclaveEvent {
  /** Which measurement register the event extended (0–3). */
  readonly imr: 0 | 1 | 2 | 3;
  readonly event: string;
  readonly digest: HexField;
}

/** Everything the guest agent knows about the VM it is running in. */
export interface EnclaveInfo {
  readonly appId: string;
  readonly instanceId: string;
  readonly appName: string;
  readonly vendor: TeeVendor;
  readonly mode: RuntimeMode;
  readonly measurement: Measurement;
  readonly tcbStatus: string;
  readonly eventLog: readonly EnclaveEvent[];
  /** Digest of the deployed compose/image — the input MRTD is derived from. */
  readonly imageDigest: string;
  /** Public ingress for the CVM, when dstack-gateway has published one. */
  readonly appUrl: string | null;
}

/**
 * The three calls CooL makes into the enclave. Anything that can satisfy this
 * interface — the real agent, the simulator, a test double — can host the
 * evidence plane, which is what keeps the SDK free of TEE-specific branches.
 */
export interface DstackClient {
  readonly mode: RuntimeMode;
  /** Who am I, and what is my measurement? */
  info(): Promise<EnclaveInfo>;
  /** Ask the hardware to sign a quote binding `reportData` to this measurement. */
  getQuote(reportData: Multihash): Promise<QuoteEnvelope>;
  /** Derive a 32-byte secret that only this measurement can obtain (dstack-KMS). */
  deriveKey(path: string): Promise<Uint8Array>;
  /**
   * Public keys a verifier needs that are not otherwise in the receipt. Empty on
   * hardware (Intel's roots are not ours to publish); the simulator returns its
   * root's public half so simulated receipts stay offline-verifiable.
   */
  directory(): KeyDirectory;
}

/* ── the real guest agent ─────────────────────────────────────────────── */

/** Wire-level options for {@link HttpDstackClient}. */
export interface HttpDstackOptions {
  /**
   * Guest-agent endpoint. Inside a dstack CVM this is the unix socket
   * `/var/run/dstack.sock`; over TCP (dev, or the dstack simulator binary) it is
   * an http:// URL. Node reaches the socket with `undici`'s socketPath or via
   * `DSTACK_SIMULATOR_ENDPOINT`; both arrive here as a base URL.
   */
  readonly endpoint: string;
  /**
   * RPC paths. dstack renamed these between the `tappd` generation and the
   * current agent, so they are overridable rather than hard-coded — confirm the
   * pair for your image before shipping.
   */
  readonly paths?: {
    readonly info?: string;
    readonly quote?: string;
    readonly key?: string;
  };
  readonly headers?: Readonly<Record<string, string>>;
  /** Vendor of the host silicon. Recorded in the runtime block. */
  readonly vendor?: TeeVendor;
  /**
   * `Info` takes no arguments, so it is a GET by default. Strict prpc endpoints
   * answer 405 to that and want a POST with an empty body — hence the switch,
   * which is cheaper than discovering the difference in a customer's cluster.
   */
  readonly infoMethod?: "GET" | "POST";
  /** Purpose string passed to the key provider. */
  readonly keyPurpose?: string;
  readonly fetchImpl?: typeof fetch;
}

interface AgentInfoResponse {
  app_id?: string;
  instance_id?: string;
  app_name?: string;
  tcb_info?: {
    mrtd?: string;
    rtmr0?: string;
    rtmr1?: string;
    rtmr2?: string;
    rtmr3?: string;
    event_log?: { imr?: number; event?: string; digest?: string }[];
  };
  app_url?: string;
}

interface AgentQuoteResponse {
  quote?: string;
  event_log?: string;
  tcb_status?: string;
}

interface AgentKeyResponse {
  key?: string;
}

function hexField(value: string | undefined, fallback: HexField): HexField {
  if (!value) return fallback;
  const clean = value.startsWith("0x") ? value.slice(2) : value;
  return `hex:${clean.toLowerCase()}`;
}

const ZERO_48: HexField = `hex:${"0".repeat(96)}`;

/**
 * Talks to the dstack guest agent inside a confidential VM.
 *
 * Nothing here is Phala-proprietary: the same shape works against any agent that
 * can answer "what is my measurement", "quote these 64 bytes" and "derive a key
 * bound to me". That portability is deliberate — it is also what stops this
 * integration from becoming a lock-in.
 */
export class HttpDstackClient implements DstackClient {
  readonly mode: RuntimeMode = "hardware";
  private readonly endpoint: string;
  private readonly vendor: TeeVendor;
  private readonly fetchImpl: typeof fetch;
  private readonly infoPath: string;
  private readonly quotePath: string;
  private readonly keyPath: string;
  private readonly headers: Readonly<Record<string, string>>;
  private readonly infoMethod: "GET" | "POST";
  private readonly keyPurpose: string;

  constructor(options: HttpDstackOptions) {
    // A socket path is an address, not a URL prefix. `/var/run/dstack.sock` and
    // `\\.\pipe\dstack` both reach the agent through the transport, so the
    // request itself is just the path — gluing the socket in front of it would
    // produce a nonsense URL and a puzzling 404.
    const endpoint = options.endpoint.replace(/\/$/, "");
    this.endpoint = /^https?:\/\//i.test(endpoint) ? endpoint : "";
    this.vendor = options.vendor ?? "intel-tdx";
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.infoPath = options.paths?.info ?? "/prpc/Info";
    this.quotePath = options.paths?.quote ?? "/prpc/GetQuote";
    this.keyPath = options.paths?.key ?? "/prpc/GetKey";
    this.infoMethod = options.infoMethod ?? "GET";
    this.keyPurpose = options.keyPurpose ?? "cool-evidence";
    this.headers = { "content-type": "application/json", ...(options.headers ?? {}) };
  }

  private async rpc<T>(path: string, body?: unknown, method?: "GET" | "POST"): Promise<T> {
    const verb = method ?? (body === undefined ? "GET" : "POST");
    const response = await this.fetchImpl(`${this.endpoint}${path}`, {
      method: verb,
      headers: this.headers,
      ...(verb === "GET" ? {} : { body: JSON.stringify(body ?? {}) }),
    });
    if (!response.ok) {
      throw new Error(`dstack agent ${path} → HTTP ${response.status}`);
    }
    return (await response.json()) as T;
  }

  async info(): Promise<EnclaveInfo> {
    const raw = await this.rpc<AgentInfoResponse>(this.infoPath, undefined, this.infoMethod);
    const tcb = raw.tcb_info ?? {};
    const measurement: Measurement = {
      mrtd: hexField(tcb.mrtd, ZERO_48),
      rtmr0: hexField(tcb.rtmr0, ZERO_48),
      rtmr1: hexField(tcb.rtmr1, ZERO_48),
      rtmr2: hexField(tcb.rtmr2, ZERO_48),
      rtmr3: hexField(tcb.rtmr3, ZERO_48),
    };
    return {
      appId: raw.app_id ?? "unknown",
      instanceId: raw.instance_id ?? "unknown",
      appName: raw.app_name ?? "cool-evidence-plane",
      vendor: this.vendor,
      mode: "hardware",
      measurement,
      tcbStatus: "Unknown",
      eventLog: (tcb.event_log ?? []).map((e) => ({
        imr: ((e.imr ?? 3) % 4) as 0 | 1 | 2 | 3,
        event: e.event ?? "unknown",
        digest: hexField(e.digest, ZERO_48),
      })),
      imageDigest: hexField(tcb.mrtd, ZERO_48).slice("hex:".length),
      appUrl: raw.app_url ?? null,
    };
  }

  async getQuote(reportData: Multihash): Promise<QuoteEnvelope> {
    const info = await this.info();
    const hex = Array.from(multihashDigest(reportData))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    // The agent takes 64 bytes; the commitment is 32, zero-padded on the right.
    const raw = await this.rpc<AgentQuoteResponse>(this.quotePath, {
      report_data: `${hex}${"0".repeat(64)}`,
    });
    if (!raw.quote) throw new Error("dstack agent returned no quote");

    const body: QuoteBody = {
      vendor: this.vendor,
      measurement: info.measurement,
      report_data: reportData,
      tcb_status: raw.tcb_status ?? "Unknown",
      app_id: info.appId,
      instance_id: info.instanceId,
      issued_at: new Date().toISOString(),
    };
    const quoteBytes = raw.quote.startsWith("0x") ? raw.quote.slice(2) : raw.quote;
    return {
      format: this.vendor === "amd-sev-snp" ? "dstack.sevsnp.v1" : "dstack.tdx.v4",
      root: this.vendor === "amd-sev-snp" ? "amd-kds" : "intel-dcap",
      body,
      signature: null,
      raw: (/^[0-9a-f]+$/i.test(quoteBytes)
        ? toBase64Field(hexToBytes(quoteBytes))
        : `base64:${quoteBytes}`) as Base64Field,
    };
  }

  async deriveKey(path: string): Promise<Uint8Array> {
    const raw = await this.rpc<AgentKeyResponse>(this.keyPath, {
      path,
      purpose: this.keyPurpose,
    });
    if (!raw.key) throw new Error("dstack KMS returned no key material");
    const bytes = /^[0-9a-f]+$/i.test(raw.key)
      ? hexToBytes(raw.key)
      : Uint8Array.from(atob(raw.key), (c) => c.charCodeAt(0));
    // The agent's key material is longer than a signing seed; compress it to 32
    // bytes with a domain-separated hash rather than truncating.
    return sha256(concatBytes(utf8("cool/kms/seed/v2"), bytes));
  }

  directory(): KeyDirectory {
    return {};
  }
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/* ── the simulator ────────────────────────────────────────────────────── */

/** Options for {@link SimulatedDstackClient}. */
export interface SimulatedDstackOptions {
  readonly appName: string;
  /**
   * Digest of the deployed image / compose file. THE input: everything the
   * simulator derives — measurement, keys, quotes — hangs off this value, so
   * "someone shipped different code" is expressed by changing one string.
   */
  readonly imageDigest: string;
  readonly instanceId?: string;
  readonly vendor?: TeeVendor;
  /** Root secret for the simulated attestation authority. Deterministic if fixed. */
  readonly rootSeed?: string;
  readonly clock?: () => string;
  readonly appUrl?: string;
}

function reg(tag: string, ...parts: string[]): HexField {
  return toHexField(sha384(utf8([tag, ...parts].join(" ")))) as HexField;
}

/**
 * A dstack guest agent that runs anywhere.
 *
 * The measurement is a SHA-384 chain over the image digest and the same event
 * sequence a real dstack CVM extends into RTMR3 (app id, compose digest,
 * instance id, key provider). Key derivation mixes the measurement in, so the
 * sealing property is structural and not a claim in a comment.
 */
export class SimulatedDstackClient implements DstackClient {
  readonly mode: RuntimeMode = "simulated";
  private readonly options: SimulatedDstackOptions;
  private readonly rootKey: KeyPair;
  private readonly appId: string;
  private readonly instanceId: string;
  private readonly clock: () => string;

  constructor(options: SimulatedDstackOptions) {
    this.options = options;
    this.clock = options.clock ?? (() => new Date().toISOString());
    this.appId = toHexField(sha256(utf8(`dstack/app-id ${options.appName}`)))
      .slice("hex:".length, "hex:".length + 40);
    this.instanceId =
      options.instanceId ??
      toHexField(sha256(utf8(`dstack/instance ${options.imageDigest}`))).slice(
        "hex:".length,
        "hex:".length + 32,
      );
    const rootSeed = sha256(utf8(`cool/sim-attestation-root ${options.rootSeed ?? "cool"}`));
    this.rootKey = generateKeypair(SIM_ROOT_KEY_ID, { seed: rootSeed });
  }

  /** The measurement set this image produces. Pure function of the options. */
  measurement(): Measurement {
    const { imageDigest, appName } = this.options;
    return {
      // Build-time measurement of the TD image.
      mrtd: reg("dstack/mrtd", imageDigest),
      // Virtual hardware configuration.
      rtmr0: reg("dstack/rtmr0", "tdx-virtual-firmware", appName),
      // Kernel + initrd.
      rtmr1: reg("dstack/rtmr1", "dstack-os-0.5.3"),
      // Kernel command line.
      rtmr2: reg("dstack/rtmr2", "console=ttyS0 dstack.rootfs_hash=verity"),
      // Application events — the register that moves when YOUR code moves.
      rtmr3: reg("dstack/rtmr3", this.appId, imageDigest, this.instanceId, "kms-onchain"),
    };
  }

  async info(): Promise<EnclaveInfo> {
    const measurement = this.measurement();
    return {
      appId: this.appId,
      instanceId: this.instanceId,
      appName: this.options.appName,
      vendor: this.options.vendor ?? "intel-tdx",
      mode: "simulated",
      measurement,
      tcbStatus: "UpToDate (simulated)",
      eventLog: [
        { imr: 3, event: "app-id", digest: reg("event/app-id", this.appId) },
        { imr: 3, event: "compose-hash", digest: reg("event/compose", this.options.imageDigest) },
        { imr: 3, event: "instance-id", digest: reg("event/instance", this.instanceId) },
        { imr: 3, event: "key-provider", digest: reg("event/kms", "kms-onchain") },
      ],
      imageDigest: this.options.imageDigest,
      appUrl: this.options.appUrl ?? null,
    };
  }

  async getQuote(reportData: Multihash): Promise<QuoteEnvelope> {
    const info = await this.info();
    const body: QuoteBody = {
      vendor: info.vendor,
      measurement: info.measurement,
      report_data: reportData,
      tcb_status: info.tcbStatus,
      app_id: info.appId,
      instance_id: info.instanceId,
      issued_at: this.clock(),
    };
    return {
      format: "cool.sim.v1",
      root: "cool-sim-root",
      body,
      signature: signSimulatedQuote(body, this.rootKey),
      raw: null,
    };
  }

  /**
   * The sealing property, in one line: the seed is a function of the
   * measurement. Ship different code → different MRTD/RTMR3 → different seed →
   * a different signing key, and every record the old key signed now verifies
   * against a key this deployment can no longer produce.
   */
  async deriveKey(path: string): Promise<Uint8Array> {
    const m = this.measurement();
    return sha256(
      utf8(
        [
          "cool/kms/seed/v2",
          this.options.rootSeed ?? "cool",
          m.mrtd,
          m.rtmr3,
          this.appId,
          path,
        ].join(" "),
      ),
    );
  }

  directory(): KeyDirectory {
    return { [this.rootKey.keyId]: this.rootKey.directoryEntry };
  }
}
