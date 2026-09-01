/**
 * The independent verifier — the whole product, from the reader's side.
 *
 * `verifyEvidence` takes bytes and returns a structured {@link Verdict}. It
 * never throws on a malformed or tampered receipt; problems surface as failed
 * domains. No network access is required for any domain except chaining a
 * hardware quote to its vendor root (pass a `quoteVerifier`) or checking a
 * Bitcoin anchor against a block header (pass `blockHeaders`).
 *
 * This module is also the entry point behind `cool verify <file>` and the
 * `cool-nwc/verify` subpath, so a verifier can be shipped without the rest of
 * the SDK.
 */
import {
  domainOrder,
  verifyReceiptV2,
  withTrustedKeys,
  type VerifyArgsV2,
} from "./phala/verify";
import type {
  DomainCheckV2,
  DomainStatusV2,
  ReceiptV2,
  VerdictChecksV2,
  VerdictSubjectV2,
  VerdictV2,
} from "./phala/types";

/** A piece of verifiable execution evidence. Alias of the receipt envelope. */
export type Evidence = ReceiptV2;

/** A structured verification verdict. `ok` is never a bare boolean elsewhere. */
export type Verdict = VerdictV2;
export type VerdictChecks = VerdictChecksV2;
export type VerdictCheck = DomainCheckV2;
export type VerdictSubject = VerdictSubjectV2;
export type DomainStatus = DomainStatusV2;

/** Options for {@link verifyEvidence}. */
export type VerifyOptions = VerifyArgsV2;

export { domainOrder, withTrustedKeys };

/**
 * Verify a piece of CooL evidence, fully offline against the keys it carries.
 *
 * @param evidence a `cool.receipt.v2` value (from `record()` or a file)
 * @param options  pin a measurement, require hardware, supply a quote verifier
 */
export function verifyEvidence(
  evidence: unknown,
  options: VerifyOptions = {},
): Promise<Verdict> {
  return verifyReceiptV2(evidence, options);
}

const GLYPH: Record<DomainStatusV2, string> = {
  pass: "OK ",
  fail: "X  ",
  absent: "-  ",
  mock: "-  ",
  simulated: "~  ",
  pending: "...",
};

const LABEL: Record<DomainStatusV2, string> = {
  pass: "valid",
  fail: "FAILED",
  absent: "absent",
  mock: "absent",
  simulated: "simulated",
  pending: "pending",
};

/** Width of the boxed report, in characters. */
const WIDTH = 60;

function line(text = ""): string {
  const trimmed = text.length > WIDTH - 4 ? `${text.slice(0, WIDTH - 7)}...` : text;
  return `| ${trimmed.padEnd(WIDTH - 4)} |`;
}

/**
 * Render a verdict as a human-readable block. Plain ASCII, no colour, no
 * dependencies — safe to print anywhere, including CI logs.
 */
export function formatVerdict(verdict: Verdict): string {
  const rule = `+${"-".repeat(WIDTH - 2)}+`;
  const rows: string[] = [rule, line("COOL VERIFIER"), rule];

  if (verdict.subject) {
    rows.push(
      line(`subject     ${verdict.subject.subject}`),
      line(`record id   ${verdict.subject.record_id}`),
      line(`signer      ${verdict.subject.key_id}`),
      line(`runtime     ${verdict.subject.tee}`),
      line(),
    );
  }

  for (const domain of domainOrder()) {
    const check = verdict.checks[domain];
    rows.push(line(`${GLYPH[check.status]} ${domain.padEnd(12)} ${LABEL[check.status]}`));
  }

  rows.push(rule);
  rows.push(line(verdict.ok ? "RESULT      VERIFIED" : "RESULT      FAILED"));
  rows.push(rule);

  if (!verdict.ok && verdict.reasons.length > 0) {
    rows.push("", "Failures:");
    for (const reason of verdict.reasons) rows.push(`  - ${reason}`);
  }

  return rows.join("\n");
}
