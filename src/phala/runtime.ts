/**
 * Runtime status: what this process can HONESTLY say about where it is running.
 *
 * `DstackClient.mode` only says which client class is in use — `HttpDstackClient`
 * is always "hardware", whatever answers on the other end (a real confidential
 * VM, Phala's dstack simulator, a half-working agent that returns an empty TCB
 * block). Showing that label as if it were a finding is how a simulator gets
 * mistaken for silicon. Status is therefore derived from evidence, never from
 * configuration:
 *
 *   REAL         a dstack agent answered, its measurement is complete and
 *                non-zero, a quote was obtained, the quote was chained to a
 *                vendor root by a configured verifier, the key binding and any
 *                pin held, and the channel opened.
 *   UNVERIFIED   a dstack agent answered with complete evidence but nothing
 *                verified the quote. It cannot be told apart from a protocol
 *                simulator, so it is NOT shown as real.
 *   SIMULATED    CooL's in-process simulator (or a quote under the simulator's
 *                root). Never hardware evidence.
 *   UNAVAILABLE  no dstack agent could be reached.
 *   FAILED       an agent answered but its evidence is incomplete, or the
 *                handshake (quote, root, vendor, pin, key binding) failed.
 *
 * `real` requires all of the above; nothing here reads a vendor string,
 * a Docker digest or an expected measurement as proof of hardware.
 */
import type { EnclaveInfo } from "./dstack";
import type { AttestationHandshake } from "./ratls";
import type { Measurement } from "./types";

export type RuntimeState = "real" | "unverified" | "simulated" | "unavailable" | "failed";

export interface RuntimeStatus {
  readonly state: RuntimeState;
  /** Short upper-case tag for a status line: REAL, SIMULATED, ... */
  readonly label: string;
  /** `intel-tdx · REAL`, ready to print. */
  readonly display: string;
  /** One sentence a developer can act on. */
  readonly reason: string;
  /** Every finding that kept the state from being `real`. Empty when real. */
  readonly findings: readonly string[];
  readonly vendor: string;
}

const REGISTERS = ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"] as const;

/** True for a register that is absent or all zero — the parser's fallback value. */
export function isZeroRegister(value: string | undefined): boolean {
  if (!value) return true;
  const hex = value.startsWith("hex:") ? value.slice(4) : value;
  return hex.length === 0 || /^0+$/.test(hex);
}

/** Registers that are missing or zero. A real TDX guest has none. */
export function measurementIssues(m: Measurement): string[] {
  return REGISTERS.filter((r) => isZeroRegister(m[r])).map((r) => `${r} is missing or all-zero`);
}

/** What a hardware-mode agent must have told us before we believe it. */
export function hardwareEvidenceIssues(info: EnclaveInfo): string[] {
  const issues = measurementIssues(info.measurement);
  if (!info.appId || info.appId === "unknown") issues.push("agent returned no app_id");
  if (!info.instanceId || info.instanceId === "unknown") issues.push("agent returned no instance_id");
  return issues;
}

function status(
  state: RuntimeState,
  label: string,
  vendor: string,
  reason: string,
  findings: readonly string[],
): RuntimeStatus {
  return { state, label, display: `${vendor} · ${label}`, reason, findings, vendor };
}

/** No dstack agent was reachable (nothing to derive a status from). */
export function unavailableRuntime(vendor: string, reason: string): RuntimeStatus {
  return status("unavailable", "UNAVAILABLE", vendor, reason, [reason]);
}

/**
 * Derive the status of a connected evidence plane.
 *
 * `handshake` is the RA-TLS transcript; `null` means none exists yet, which can
 * never be REAL.
 */
export function assessRuntime(info: EnclaveInfo, handshake: AttestationHandshake | null): RuntimeStatus {
  const vendor = info.vendor;

  if (info.mode === "simulated" || handshake?.quote.root === "cool-sim-root") {
    return status(
      "simulated",
      "SIMULATED",
      vendor,
      "no dstack hardware agent detected — this is CooL's in-process simulator and is not hardware evidence",
      ["running under the simulator"],
    );
  }

  const incomplete = hardwareEvidenceIssues(info);
  if (incomplete.length > 0) {
    return status(
      "failed",
      "EVIDENCE INCOMPLETE",
      vendor,
      `the dstack agent answered but did not supply real TDX evidence: ${incomplete.join("; ")}`,
      incomplete,
    );
  }

  if (!handshake) {
    return status("failed", "NOT ATTESTED", vendor, "no attestation handshake has run", ["no handshake"]);
  }

  if (!handshake.ok) {
    const pin = handshake.steps.find((s) => s.label === "measurement pin" && !s.ok);
    const label = pin ? "MEASUREMENT MISMATCH" : "ATTESTATION FAILED";
    return status("failed", label, vendor, handshake.reasons.join("; ") || "attestation handshake failed", [
      ...handshake.reasons,
    ]);
  }

  if (!handshake.rootVerified) {
    return status(
      "unverified",
      "UNVERIFIED",
      vendor,
      "a dstack agent answered with a complete measurement, but no verifier chained the quote to a vendor root — this cannot be told apart from a protocol simulator (set QUOTE_VERIFIER_URL)",
      ["quote not chained to a vendor root"],
    );
  }

  return status("real", "REAL", vendor, "dstack evidence complete; quote verified against a vendor root", []);
}

/** One line for a terminal: the display, plus the reason unless the state is real. */
export function describe(status_: RuntimeStatus): string {
  return status_.state === "real" ? status_.display : `${status_.display} — ${status_.reason}`;
}
