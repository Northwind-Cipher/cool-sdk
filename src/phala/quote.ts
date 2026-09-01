/**
 * Quotes: building them, hashing them into the record, and checking them.
 *
 * A quote is the only thing in CooL that cannot be verified by pure maths. Every
 * other domain — binding, signature, inclusion — is self-contained: you check it
 * with the bytes in front of you. A quote is a statement by silicon, and
 * believing it means chaining to a vendor root (Intel DCAP, AMD KDS, NVIDIA
 * NRAS). This module keeps that boundary explicit:
 *
 *   • Everything that CAN be checked offline is checked offline, always — the
 *     quote's structure, the measurement pin, and the binding between the quote
 *     and the key that signed the record.
 *   • Chaining to a vendor root is delegated to a pluggable {@link QuoteVerifier}.
 *     No verifier attached → the domain reports what it saw and stops. It never
 *     upgrades itself to `pass` out of optimism.
 *
 * The simulator's root is a CooL-held key. Its quotes are structurally complete
 * and cryptographically real, and they still mean nothing about confidentiality,
 * which is why they are reported as `simulated` for as long as they exist.
 */
import type { DirectoryEntry, KeyDirectory, KeyPair, Multihash, SignatureBlock } from "../types";
import { canonicalCbor } from "../canonical";
import { concatBytes, fromHexField, utf8 } from "../codec";
import { mhSha256 } from "../multihash";
import { hybridSign, hybridVerify } from "../sign";
import type {
  AttestationRoot,
  DomainCheckV2,
  Measurement,
  QuoteBody,
  QuoteEnvelope,
} from "./types";

/** Key id under which the simulator's attestation root is published in receipts. */
export const SIM_ROOT_KEY_ID = "cool-sim-attestation-root-01";

/** Domain-separation tag for the 64 bytes bound into a quote's `report_data`. */
const REPORT_DATA_TAG = "cool/report-data/v2";

/* ── measurements ─────────────────────────────────────────────────────── */

/** Field-by-field equality. Used for the measurement pin. */
export function measurementEquals(a: Measurement, b: Measurement): boolean {
  return (
    a.mrtd === b.mrtd &&
    a.rtmr0 === b.rtmr0 &&
    a.rtmr1 === b.rtmr1 &&
    a.rtmr2 === b.rtmr2 &&
    a.rtmr3 === b.rtmr3
  );
}

/** A single short digest over a measurement set — for display and comparison. */
export function measurementDigest(m: Measurement): Multihash {
  return mhSha256(canonicalCbor(m));
}

/** The first `n` hex characters of a measurement register, for compact display. */
export function shortMeasurement(m: Measurement, n = 12): string {
  return m.mrtd.slice("hex:".length, "hex:".length + n);
}

/** Which register(s) differ — so a mismatch says *what* changed, not just "no". */
export function measurementDiff(a: Measurement, b: Measurement): string[] {
  const fields: (keyof Measurement)[] = ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"];
  return fields.filter((f) => a[f] !== b[f]);
}

/* ── the key ↔ enclave binding ────────────────────────────────────────── */

/**
 * The commitment placed in a quote's `report_data`.
 *
 * This is the hinge of the whole design. The hardware attests to a measurement
 * AND to 64 bytes of our choosing; we spend those bytes on the public half of
 * the key the enclave signs with. A verifier recomputes this from the receipt's
 * own `key_directory` and compares. If they match, "attested code" and "signing
 * key" are the same entity — which is precisely what stops a real quote from
 * being stapled onto a record signed somewhere else.
 */
export function enclaveReportData(entry: DirectoryEntry): Multihash {
  return mhSha256(
    concatBytes(
      utf8(REPORT_DATA_TAG),
      canonicalCbor({ ed25519_pub: entry.ed25519_pub, ml_dsa_pub: entry.ml_dsa_pub }),
    ),
  );
}

/** The 64 raw bytes to hand a TDX `GetQuote` call, derived from the commitment. */
export function reportDataBytes(commitment: Multihash): Uint8Array {
  const digest = fromHexField(`hex:${commitment.slice("mh:sha256:".length)}`);
  const out = new Uint8Array(64);
  out.set(digest, 0);
  return out;
}

/* ── envelope helpers ─────────────────────────────────────────────────── */

/** The exact bytes a quote signature (or the silicon) covers. */
export function quoteSigningMessage(body: QuoteBody): Uint8Array {
  return canonicalCbor(body);
}

/**
 * The digest that goes into the record's signed core (`runtime.tee_quote`).
 * Hashing the whole envelope — signature and raw bytes included — is what makes
 * the record signature cover the quote, so neither can be swapped for the other.
 */
export function quoteDigest(quote: QuoteEnvelope): Multihash {
  return mhSha256(canonicalCbor(quote));
}

/** Sign a simulated quote body with the simulator's root key. */
export function signSimulatedQuote(body: QuoteBody, rootKey: KeyPair): SignatureBlock {
  return hybridSign(quoteSigningMessage(body), rootKey);
}

/* ── verification ─────────────────────────────────────────────────────── */

/** The outcome of chaining a quote to its root of trust. */
export interface QuoteVerification {
  readonly ok: boolean;
  readonly root: AttestationRoot;
  readonly tcb_status: string;
  readonly detail: string;
}

/**
 * A root-of-trust checker. Two implementations ship here — the simulator's, and
 * a remote DCAP/NRAS client. A customer running on Phala Cloud can supply their
 * own (Intel Trust Authority, Phala's verifier service, an in-house DCAP setup)
 * without touching anything else in the pipeline.
 */
export interface QuoteVerifier {
  readonly root: AttestationRoot;
  readonly name: string;
  verify(quote: QuoteEnvelope): Promise<QuoteVerification>;
}

/**
 * Verifier for simulator-issued quotes.
 *
 * It performs a genuine hybrid-signature check against the simulator root key
 * carried in the receipt — so a tampered simulated quote is still caught — and
 * then reports `ok: true` with a root of `cool-sim-root`. Callers translate that
 * into the `simulated` status; nothing here ever claims a vendor root.
 */
export function simulatedQuoteVerifier(directory: KeyDirectory): QuoteVerifier {
  return {
    root: "cool-sim-root",
    name: "cool-simulator",
    async verify(quote: QuoteEnvelope): Promise<QuoteVerification> {
      if (!quote.signature) {
        return {
          ok: false,
          root: "cool-sim-root",
          tcb_status: quote.body.tcb_status,
          detail: "simulated quote carries no signature",
        };
      }
      const entry = directory[quote.signature.key_id];
      if (!entry) {
        return {
          ok: false,
          root: "cool-sim-root",
          tcb_status: quote.body.tcb_status,
          detail: `no public key for simulator root '${quote.signature.key_id}'`,
        };
      }
      const ok = hybridVerify(quoteSigningMessage(quote.body), quote.signature, entry).ok;
      return {
        ok,
        root: "cool-sim-root",
        tcb_status: quote.body.tcb_status,
        detail: ok
          ? "simulated quote signature valid under the CooL simulator root (NOT a vendor root)"
          : "simulated quote signature does not verify",
      };
    },
  };
}

/** Configuration for {@link remoteQuoteVerifier}. */
export interface RemoteVerifierOptions {
  /**
   * Attestation-verification endpoint. Phala's verifier, Intel Trust Authority
   * and a self-hosted DCAP service all accept a raw quote and return a verdict;
   * the exact URL and payload shape is per-service, hence `encode`/`decode`.
   */
  readonly endpoint: string;
  readonly root: AttestationRoot;
  readonly name?: string;
  readonly headers?: Readonly<Record<string, string>>;
  /** Build the request body from the raw quote. Defaults to `{ quote }`. */
  readonly encode?: (rawQuoteBase64: string, quote: QuoteEnvelope) => unknown;
  /** Read the service's verdict. Defaults to `{ ok|verified, tcb_status }`. */
  readonly decode?: (response: unknown) => { ok: boolean; tcb_status?: string; detail?: string };
}

/**
 * Verifier that posts the vendor-native quote bytes to an attestation service.
 *
 * This is the hardware path. It is a network call by construction — DCAP
 * collateral is not something a browser or an air-gapped verifier can synthesise
 * — so it is opt-in, and its absence degrades to "reported, not verified" rather
 * than to a silent pass.
 */
export function remoteQuoteVerifier(options: RemoteVerifierOptions): QuoteVerifier {
  const encode = options.encode ?? ((raw: string) => ({ quote: raw }));
  const decode =
    options.decode ??
    ((response: unknown) => {
      const r = (response ?? {}) as Record<string, unknown>;
      const ok = r["ok"] === true || r["verified"] === true || r["success"] === true;
      const tcb = typeof r["tcb_status"] === "string" ? r["tcb_status"] : undefined;
      const detail = typeof r["detail"] === "string" ? r["detail"] : undefined;
      return tcb === undefined
        ? detail === undefined
          ? { ok }
          : { ok, detail }
        : detail === undefined
          ? { ok, tcb_status: tcb }
          : { ok, tcb_status: tcb, detail };
    });

  return {
    root: options.root,
    name: options.name ?? "remote-attestation-service",
    async verify(quote: QuoteEnvelope): Promise<QuoteVerification> {
      if (!quote.raw) {
        return {
          ok: false,
          root: options.root,
          tcb_status: quote.body.tcb_status,
          detail: "no raw vendor quote bytes to submit (this receipt is not from hardware)",
        };
      }
      try {
        const raw = quote.raw.slice("base64:".length);
        const response = await fetch(options.endpoint, {
          method: "POST",
          headers: { "content-type": "application/json", ...(options.headers ?? {}) },
          body: JSON.stringify(encode(raw, quote)),
        });
        if (!response.ok) {
          return {
            ok: false,
            root: options.root,
            tcb_status: quote.body.tcb_status,
            detail: `attestation service returned HTTP ${response.status}`,
          };
        }
        const verdict = decode(await response.json());
        return {
          ok: verdict.ok,
          root: options.root,
          tcb_status: verdict.tcb_status ?? quote.body.tcb_status,
          detail:
            verdict.detail ??
            (verdict.ok
              ? `quote verified against ${options.root}`
              : `quote rejected by ${options.root}`),
        };
      } catch (error) {
        return {
          ok: false,
          root: options.root,
          tcb_status: quote.body.tcb_status,
          detail: `attestation service unreachable: ${(error as Error).message}`,
        };
      }
    },
  };
}

/* ── structural checks (always offline, always run) ───────────────────── */

const HEX32 = /^hex:[0-9a-f]{96}$|^hex:[0-9a-f]{64}$/;

/** Reject a quote whose shape is wrong before any root is consulted. */
export function checkQuoteStructure(quote: QuoteEnvelope): DomainCheckV2 | null {
  const m = quote.body.measurement;
  for (const [name, value] of Object.entries(m)) {
    if (!HEX32.test(value)) {
      return { status: "fail", detail: `FAILED — malformed measurement register '${name}'` };
    }
  }
  if (!/^mh:sha256:[0-9a-f]{64}$/.test(quote.body.report_data)) {
    return { status: "fail", detail: "FAILED — malformed report_data commitment" };
  }
  if (quote.root === "cool-sim-root" && quote.raw !== null) {
    return { status: "fail", detail: "FAILED — a simulated quote must not carry vendor bytes" };
  }
  if (quote.root !== "cool-sim-root" && quote.raw === null) {
    return {
      status: "fail",
      detail: `FAILED — quote claims root '${quote.root}' but carries no vendor bytes`,
    };
  }
  return null;
}
