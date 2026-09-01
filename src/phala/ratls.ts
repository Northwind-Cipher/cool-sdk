/**
 * RA-TLS: attest first, then speak.
 *
 * Ordinary TLS answers "am I talking to the right host?". RA-TLS answers the
 * question that actually matters here — "am I talking to the right *code*?" —
 * by carrying the enclave's attestation quote in the handshake and binding it to
 * the key on the other end of the channel. The CooL SDK refuses to emit a single
 * event before that check passes, so prompts and evidence never reach an
 * endpoint that has not proven what it is.
 *
 * Two rules govern failure, and they pull in opposite directions on purpose:
 *
 *   • REFUSE to send. An unattested or mismatched endpoint gets nothing. There
 *     is no "degrade to plaintext" path, because a fallback that leaks is worse
 *     than no capture at all.
 *   • NEVER block the application. Attestation failing is CooL's problem, not
 *     the caller's request. The channel reports itself closed and
 *     the capture queue drops on the floor, loudly, in the caller's metrics.
 *
 * Those two together are what "async, fail-open, out-of-band" means in practice:
 * fail-open toward the application, fail-closed toward the network.
 */
import type { DirectoryEntry, KeyDirectory } from "../types";
import type { DstackClient, EnclaveInfo } from "./dstack";
import {
  checkQuoteStructure,
  enclaveReportData,
  measurementDiff,
  measurementEquals,
  simulatedQuoteVerifier,
} from "./quote";
import type { QuoteVerifier } from "./quote";
import type { Measurement, QuoteEnvelope, RuntimeMode, TeeVendor } from "./types";

/** What the client demands of the endpoint before it will transmit. */
export interface AttestationPolicy {
  /**
   * The measurement this deployment approved. Set it in production: without a
   * pin, a quote only proves "some TEE", not "the code you reviewed".
   */
  readonly expectedMeasurement?: Measurement;
  /** Accept the simulator. Must be false in production. Default true. */
  readonly allowSimulated?: boolean;
  /** Restrict to specific silicon, e.g. `["intel-tdx"]`. */
  readonly requireVendor?: readonly TeeVendor[];
  /** Root-of-trust checker. Defaults to the simulator's for simulated quotes. */
  readonly verifier?: QuoteVerifier;
  /**
   * Close the channel when a quote's root cannot be checked — no verifier
   * configured for a vendor root. Default true, because an unverifiable quote
   * proves nothing about the endpoint and sending to it anyway would make the
   * handshake decorative.
   *
   * Set false only where the quote is verified out of band (a sidecar, a
   * gateway, an operator's own pipeline). The step then records what it saw and
   * says plainly that it did not verify it.
   */
  readonly requireVerifiedRoot?: boolean;
}

/** One line of the handshake transcript — the UI renders these verbatim. */
export interface HandshakeStep {
  readonly label: string;
  readonly ok: boolean;
  readonly detail: string;
}

/** The full result of attesting an endpoint. */
export interface AttestationHandshake {
  readonly ok: boolean;
  readonly mode: RuntimeMode;
  readonly info: EnclaveInfo;
  readonly quote: QuoteEnvelope;
  readonly directory: KeyDirectory;
  readonly steps: readonly HandshakeStep[];
  readonly reasons: readonly string[];
  readonly at: string;
}

/**
 * Run the attestation handshake against an enclave endpoint.
 *
 * `expectedKey` is the public half of the key the endpoint claims to sign
 * records with. Binding it into the quote's `report_data` is what makes the
 * channel meaningful: a valid quote for the wrong key is rejected here, before
 * any data moves, rather than being discovered later by an auditor.
 */
export async function attestEndpoint(
  client: DstackClient,
  expectedKey: DirectoryEntry,
  policy: AttestationPolicy = {},
): Promise<AttestationHandshake> {
  const steps: HandshakeStep[] = [];
  const reasons: string[] = [];
  const step = (label: string, ok: boolean, detail: string) => {
    steps.push({ label, ok, detail });
    if (!ok) reasons.push(`${label}: ${detail}`);
    return ok;
  };

  const info = await client.info();
  step(
    "enclave info",
    true,
    `${info.appName} · app ${info.appId.slice(0, 12)} · instance ${info.instanceId.slice(0, 12)}`,
  );

  const expectedReportData = enclaveReportData(expectedKey);
  const quote = await client.getQuote(expectedReportData);
  const directory = { ...client.directory() };
  step("quote fetched", true, `${quote.format} · TCB ${quote.body.tcb_status}`);

  const structural = checkQuoteStructure(quote);
  step("quote structure", structural === null, structural?.detail ?? "well-formed");

  const allowSimulated = policy.allowSimulated ?? true;
  const simulated = quote.root === "cool-sim-root";
  if (simulated && !allowSimulated) {
    step("root of trust", false, "simulated quote rejected — policy requires hardware");
  } else {
    const verifier = policy.verifier ?? (simulated ? simulatedQuoteVerifier(directory) : null);
    if (!verifier) {
      const required = policy.requireVerifiedRoot ?? true;
      step(
        "root of trust",
        !required,
        required
          ? `no verifier configured for root '${quote.root}' — refusing to transmit`
          : `root '${quote.root}' REPORTED, NOT VERIFIED (policy.requireVerifiedRoot = false)`,
      );
    } else {
      const verification = await verifier.verify(quote);
      step("root of trust", verification.ok, verification.detail);
    }
  }

  if (policy.requireVendor && policy.requireVendor.length > 0) {
    const ok = policy.requireVendor.includes(quote.body.vendor);
    step(
      "vendor",
      ok,
      ok
        ? `${quote.body.vendor} permitted`
        : `${quote.body.vendor} not in [${policy.requireVendor.join(", ")}]`,
    );
  }

  if (policy.expectedMeasurement) {
    const ok = measurementEquals(policy.expectedMeasurement, quote.body.measurement);
    step(
      "measurement pin",
      ok,
      ok
        ? `matches the pinned image (${quote.body.measurement.mrtd.slice(4, 16)}…)`
        : `MISMATCH in ${measurementDiff(policy.expectedMeasurement, quote.body.measurement).join(", ")} — the endpoint is not running the approved image`,
    );
  } else {
    step("measurement pin", true, "no pin configured (development posture)");
  }

  const bindingOk = quote.body.report_data === expectedReportData;
  step(
    "key binding",
    bindingOk,
    bindingOk
      ? "quote report_data commits to the endpoint's signing key"
      : "quote is for a DIFFERENT key — refusing to transmit",
  );

  const ok = steps.every((s) => s.ok);
  step(
    "channel",
    ok,
    ok ? "open — events may be transmitted" : "CLOSED — no data will be sent",
  );

  return {
    ok,
    mode: client.mode,
    info,
    quote,
    directory,
    steps,
    reasons,
    at: new Date().toISOString(),
  };
}

/** Thrown when a caller tries to transmit over a channel that never attested. */
export class ChannelClosedError extends Error {
  constructor(reasons: readonly string[]) {
    super(`RA-TLS channel closed: ${reasons.join("; ") || "attestation failed"}`);
    this.name = "ChannelClosedError";
  }
}

/**
 * An attested transport. Construct it with {@link AttestedChannel.connect} — the
 * constructor is private precisely so an unattested channel cannot exist.
 */
export class AttestedChannel<T> {
  private constructor(
    readonly handshake: AttestationHandshake,
    private readonly sink: (batch: readonly T[]) => Promise<void>,
  ) {}

  static async connect<T>(args: {
    client: DstackClient;
    expectedKey: DirectoryEntry;
    sink: (batch: readonly T[]) => Promise<void>;
    policy?: AttestationPolicy;
  }): Promise<AttestedChannel<T>> {
    const handshake = await attestEndpoint(args.client, args.expectedKey, args.policy ?? {});
    return new AttestedChannel(handshake, args.sink);
  }

  get open(): boolean {
    return this.handshake.ok;
  }

  /** Transmit a batch. Rejects — never silently drops — on a closed channel. */
  async send(batch: readonly T[]): Promise<void> {
    if (!this.handshake.ok) throw new ChannelClosedError(this.handshake.reasons);
    if (batch.length === 0) return;
    await this.sink(batch);
  }
}
