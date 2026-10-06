/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

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
import { bindingMessage, bindingStatement } from "../contrast/identity";
import { parseCertificates, verifyChain, verifyEcdsa } from "../contrast/x509";
import { fromBase64Field } from "../codec";
import type { AttestationSource, EnclaveInfo } from "./dstack";
import {
  checkQuoteStructure,
  enclaveReportData,
  measurementDiff,
  measurementEquals,
  simulatedQuoteVerifier,
} from "./quote";
import type { QuoteVerifier } from "./quote";
import { hardwareEvidenceIssues } from "./runtime";
import type {
  Measurement,
  QuoteEnvelope,
  RuntimeMode,
  TeeVendor,
  WorkloadBinding,
} from "./types";

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
  /**
   * Coordinator root CA, PEM, to check a Contrast workload credential against.
   *
   * Inside a Contrast pod the honest default is the root the Coordinator itself
   * delivered over aTLS (`/contrast/tls-config/coordinator-root-ca.pem`), which
   * is what `ContrastWorkload` supplies. That confirms the pod's own files are
   * coherent — it is NOT a substitute for a reader pinning the root out of band
   * with `contrast verify`, and the transcript says so.
   */
  readonly coordinatorRootCA?: string;
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
  /** The vendor quote, when the platform issues one. `null` under Contrast. */
  readonly quote: QuoteEnvelope | null;
  /** The orchestrator-issued credential, when the platform issues one. */
  readonly workload: WorkloadBinding | null;
  readonly directory: KeyDirectory;
  readonly steps: readonly HandshakeStep[];
  readonly reasons: readonly string[];
  /**
   * True only when a configured verifier actually chained the quote to a vendor
   * root during this handshake. `ok` alone does not imply it: with
   * `requireVerifiedRoot: false` a channel can open on a quote nobody checked.
   */
  readonly rootVerified: boolean;
  /**
   * True when an orchestrator-issued credential was checked against a
   * Coordinator root the CALLER pinned, rather than the root the pod itself was
   * handed. The pod's own root establishes that its files are coherent and
   * nothing more, so this is the flag that separates "self-consistent" from
   * "checked against a deployment someone attested".
   */
  readonly workloadRootPinned: boolean;
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
  client: AttestationSource,
  expectedKey: DirectoryEntry,
  policy: AttestationPolicy = {},
  workload: WorkloadBinding | null = null,
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

  // Contrast issues no quote to the workload: the Coordinator consumed the
  // attestation report and answered with a certificate. So the handshake takes
  // the credential route instead, and refuses to open the channel on exactly
  // the same terms -- a credential that does not check out sends nothing.
  if (!quote) {
    const pinned = attestWorkloadCredential(step, expectedKey, policy, workload, info, client);
    const openOnCredential = steps.every((s) => s.ok);
    step(
      "channel",
      openOnCredential,
      openOnCredential ? "open — events may be transmitted" : "CLOSED — no data will be sent",
    );
    return {
      ok: openOnCredential,
      mode: client.mode,
      info,
      quote: null,
      workload,
      directory,
      steps,
      reasons,
      // No vendor quote was chained to anything, so this is false by
      // construction. The credential's standing is `workloadRootPinned`.
      rootVerified: false,
      workloadRootPinned: pinned,
      at: new Date().toISOString(),
    };
  }

  step("quote fetched", true, `${quote.format} · TCB ${quote.body.tcb_status}`);

  if (client.mode === "hardware") {
    // A hardware-mode client must present real evidence: a complete, non-zero
    // measurement and an agent identity. An agent that answers with an empty
    // TCB block is not a TDX guest, and its receipts must not claim to be.
    const issues = hardwareEvidenceIssues(info);
    step(
      "hardware evidence",
      issues.length === 0,
      issues.length === 0 ? "complete non-zero MRTD/RTMR0-3 and agent identity" : issues.join("; "),
    );
  }

  const structural = checkQuoteStructure(quote);
  step("quote structure", structural === null, structural?.detail ?? "well-formed");

  let rootVerified = false;
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
      rootVerified = verification.ok && !simulated && verification.root !== "cool-sim-root";
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
    workload,
    directory,
    steps,
    reasons,
    rootVerified,
    workloadRootPinned: false,
    at: new Date().toISOString(),
  };
}

/**
 * The Contrast half of the handshake.
 *
 * Three checks, each refusing the channel on failure:
 *
 *   • the credential exists and names a workload;
 *   • its chain verifies to a Coordinator root CA (the pod's own, by default);
 *   • its binding signature covers the very key the plane will sign with.
 *
 * Plus the confidentiality posture: a Contrast `insecure` platform issues a
 * certificate with no attestation claims, and under `allowSimulated: false`
 * that closes the channel rather than quietly transmitting to a pod whose
 * hardware nobody checked.
 */
function attestWorkloadCredential(
  step: (label: string, ok: boolean, detail: string) => boolean,
  expectedKey: DirectoryEntry,
  policy: AttestationPolicy,
  workload: WorkloadBinding | null,
  info: EnclaveInfo,
  client: AttestationSource,
): boolean {
  // Returns whether the credential was checked against a root the CALLER
  // pinned, which is the only form of this check that means anything to a
  // third party.
  if (!workload) {
    step(
      "workload credential",
      false,
      "this runtime issues no quote and produced no workload credential — nothing attests it",
    );
    return false;
  }
  const identity = workload.identity;
  step(
    "workload credential",
    true,
    `Contrast ${identity.tee} · '${identity.workload_name ?? "unnamed"}' · policy ${(identity.policy_hash ?? "hex:none").slice(4, 16)}…`,
  );

  // The reader's pinned root wins. Falling back to the root the pod itself was
  // handed keeps the self-check meaningful without ever pretending it is
  // independent -- the step label says which one was used.
  const pinnedByPolicy = policy.coordinatorRootCA !== undefined;
  const rootPem = policy.coordinatorRootCA ?? client.coordinatorRootCA;
  const chainLabel = pinnedByPolicy
    ? "coordinator chain"
    : "coordinator chain (pod's own root)";
  try {
    const chain = parseCertificates(workload.attestation.cert_chain);
    const leaf = chain[0];
    if (!leaf) {
      step(chainLabel, false, "credential carries no leaf certificate");
      return false;
    }
    if (rootPem) {
      const result = verifyChain(chain, parseCertificates(rootPem), new Date(workload.attestation.issued_at));
      step(
        chainLabel,
        result.ok,
        pinnedByPolicy
          ? result.detail
          : `${result.detail} — self-check only; an independent reader must pin a root from 'contrast verify'`,
      );
    } else {
      step(
        chainLabel,
        false,
        "no Coordinator root CA available — refusing to transmit on an uncheckable credential",
      );
    }

    const statement = bindingStatement(
      workload.attestation.bound_key_id,
      expectedKey,
      workload.attestation.issued_at,
    );
    const bound = verifyEcdsa(
      bindingMessage(statement),
      fromBase64Field(workload.attestation.binding_signature),
      leaf.publicKey,
      workload.attestation.binding_alg,
    );
    step(
      "key binding",
      bound,
      bound
        ? "the Coordinator-issued credential signed this endpoint's signing key"
        : "the credential attests a DIFFERENT key — refusing to transmit",
    );
  } catch (error) {
    step(chainLabel, false, `credential unreadable: ${(error as Error).message}`);
    return false;
  }

  if (policy.expectedMeasurement) {
    const pinned = policy.expectedMeasurement;
    const registers = identity.registers;
    const drift = (["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"] as const).filter(
      (name) => pinned[name] !== registers[name],
    );
    step(
      "measurement pin",
      drift.length === 0,
      drift.length === 0
        ? `matches the pinned image (${(registers["mrtd"] ?? "hex:none").slice(4, 16)}…)`
        : `MISMATCH in ${drift.join(", ")} — the workload is not running the approved image`,
    );
  } else {
    step("measurement pin", true, "no pin configured (development posture)");
  }

  const confidential = identity.tee !== "insecure";
  const allowSimulated = policy.allowSimulated ?? true;
  step(
    "confidentiality",
    confidential || allowSimulated,
    confidential
      ? `Contrast reports ${identity.tee}; the Coordinator verified the report against the manifest`
      : "Contrast INSECURE platform — no confidential-computing hardware; rejected because policy.allowSimulated is false",
  );

  if (policy.requireVendor && policy.requireVendor.length > 0) {
    const ok = policy.requireVendor.includes(info.vendor);
    step("vendor", ok, ok ? `${info.vendor} permitted` : `${info.vendor} not in [${policy.requireVendor.join(", ")}]`);
  }

  return pinnedByPolicy;
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
    client: AttestationSource;
    expectedKey: DirectoryEntry;
    sink: (batch: readonly T[]) => Promise<void>;
    policy?: AttestationPolicy;
    /**
     * The credential the evidence plane already obtained, when the platform
     * issues one. Passed in rather than re-fetched so the channel attests the
     * same binding the records will carry — a second call would produce a second
     * signature and leave the two halves free to differ.
     */
    workload?: WorkloadBinding | null;
  }): Promise<AttestedChannel<T>> {
    const handshake = await attestEndpoint(
      args.client,
      args.expectedKey,
      args.policy ?? {},
      args.workload ?? null,
    );
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
