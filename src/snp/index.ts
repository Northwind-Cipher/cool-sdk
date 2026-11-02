/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * `cool-nwc/snp` — offline verification of AMD SEV-SNP attestation reports.
 *
 * Layout per AMD's "SEV Secure Nested Paging Firmware ABI Specification"
 * (ATTESTATION_REPORT, 0x4A0 bytes; report versions 2–5 accepted).
 *
 * Checks, each reported separately:
 *   structure     1184 bytes, known version, signature_algo = 1 (ECDSA P-384 / SHA-384)
 *   chain         VCEK ← ASK ← ARK (or VLEK ← ASVK ← ARK), ARK PINNED (./roots), valid now
 *   signature     ECDSA P-384 over bytes 0x000–0x29F, verified with the VCEK/VLEK key
 *   tcb_binding   the certificate's TCB extensions equal REPORTED_TCB; for a VCEK,
 *                 its hwID equals CHIP_ID — so a certificate for one chip or TCB
 *                 cannot vouch for another
 *   debug         guest policy DEBUG bit clear (unless explicitly allowed)
 *   measurement   equals the pinned launch measurement            (required for `verified`)
 *   report_data   equals the expected 64 bytes (key/nonce binding), when given
 *   tcb_minimum   every TCB component ≥ the minimum, when given
 *   vmpl          equals the expected VMPL, when given
 *
 * Not checked: VCEK revocation (AMD publishes a CRL per product at KDS — fetch
 * it yourself and pass `revokedSerials`), and the ID block / author key.
 * A report has no timestamp: freshness must come from a nonce in report_data.
 */
import { X509Certificate, createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { check, type Check } from "../platform/status";
import { classifyOutcome, type Outcome } from "../platform/outcome";
import { DerError, TAG, certificateExtensions, integerValue, parseDer } from "../platform/der";
import { AMD_SNP_ROOTS, type SnpProduct } from "./roots";

export { AMD_SNP_ROOTS } from "./roots";
export type { SnpProduct, SnpProductRoots } from "./roots";

export const SNP_REPORT_SIZE = 0x4a0;
const SIGNED_LEN = 0x2a0;

export interface SnpTcb {
  readonly fmc?: number;
  readonly bootloader: number;
  readonly tee: number;
  readonly snp: number;
  readonly microcode: number;
}

export interface SnpReport {
  readonly version: number;
  readonly guest_svn: number;
  readonly policy: { readonly raw: string; readonly debug: boolean; readonly smt: boolean; readonly migrate_ma: boolean; readonly single_socket: boolean };
  readonly family_id: string;
  readonly image_id: string;
  readonly vmpl: number;
  readonly signature_algo: number;
  readonly current_tcb_raw: string;
  readonly reported_tcb_raw: string;
  readonly signing_key: "vcek" | "vlek" | "none" | "unknown";
  readonly report_data: string;
  readonly measurement: string;
  readonly host_data: string;
  readonly id_key_digest: string;
  readonly author_key_digest: string;
  readonly report_id: string;
  readonly chip_id: string;
  readonly cpuid?: { readonly family: number; readonly model: number; readonly stepping: number };
  readonly signature: { readonly r: Uint8Array; readonly s: Uint8Array };
}

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** Parse a report. Throws on wrong size only; field validation happens in verification. */
export function parseSnpReport(bytes: Uint8Array): SnpReport {
  if (bytes.length !== SNP_REPORT_SIZE) throw new DerError(`an SEV-SNP report is ${SNP_REPORT_SIZE} bytes, got ${bytes.length}`);
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u32 = (o: number) => v.getUint32(o, true);
  const policy = v.getBigUint64(0x08, true);
  const bit = (n: number) => ((policy >> BigInt(n)) & 1n) === 1n;
  const flags = u32(0x48);
  const signingKey = (flags >> 2) & 0x7;
  const version = u32(0);
  const leToBe = (b: Uint8Array) => Uint8Array.from(b).reverse();
  return {
    version,
    guest_svn: u32(0x04),
    policy: { raw: `0x${policy.toString(16)}`, debug: bit(19), smt: bit(16), migrate_ma: bit(18), single_socket: bit(20) },
    family_id: hex(bytes.subarray(0x10, 0x20)),
    image_id: hex(bytes.subarray(0x20, 0x30)),
    vmpl: u32(0x30),
    signature_algo: u32(0x34),
    current_tcb_raw: hex(bytes.subarray(0x38, 0x40)),
    reported_tcb_raw: hex(bytes.subarray(0x180, 0x188)),
    signing_key: signingKey === 0 ? "vcek" : signingKey === 1 ? "vlek" : signingKey === 7 ? "none" : "unknown",
    report_data: hex(bytes.subarray(0x50, 0x90)),
    measurement: hex(bytes.subarray(0x90, 0xc0)),
    host_data: hex(bytes.subarray(0xc0, 0xe0)),
    id_key_digest: hex(bytes.subarray(0xe0, 0x110)),
    author_key_digest: hex(bytes.subarray(0x110, 0x140)),
    report_id: hex(bytes.subarray(0x140, 0x160)),
    chip_id: hex(bytes.subarray(0x1a0, 0x1e0)),
    ...(version >= 3 ? { cpuid: { family: bytes[0x188]!, model: bytes[0x189]!, stepping: bytes[0x18a]! } } : {}),
    // r and s are 72-byte little-endian fields; P-384 uses the low 48 bytes.
    signature: { r: leToBe(bytes.subarray(0x2a0, 0x2a0 + 48)), s: leToBe(bytes.subarray(0x2e8, 0x2e8 + 48)) },
  };
}

/** r and s are 72-byte fields holding 48-byte P-384 values; the padding and the reserved tail must be zero. */
function unsignedBytesZero(b: Uint8Array): boolean {
  const zero = (from: number, to: number) => b.subarray(from, to).every((x) => x === 0);
  return zero(0x2a0 + 48, 0x2a0 + 72) && zero(0x2e8 + 48, 0x2e8 + 72) && zero(0x330, SNP_REPORT_SIZE);
}

/** Decode a TCB_VERSION. Milan/Genoa: [bl, tee, -, -, -, -, snp, ucode]; Turin: [fmc, bl, tee, snp, -, -, -, ucode]. */
export function decodeTcb(rawHex: string, product: SnpProduct): SnpTcb {
  const b = Buffer.from(rawHex, "hex");
  return product === "Turin"
    ? { fmc: b[0]!, bootloader: b[1]!, tee: b[2]!, snp: b[3]!, microcode: b[7]! }
    : { bootloader: b[0]!, tee: b[1]!, snp: b[6]!, microcode: b[7]! };
}

const EXT = {
  bootloader: "1.3.6.1.4.1.3704.1.3.1",
  tee: "1.3.6.1.4.1.3704.1.3.2",
  snp: "1.3.6.1.4.1.3704.1.3.3",
  microcode: "1.3.6.1.4.1.3704.1.3.8",
  fmc: "1.3.6.1.4.1.3704.1.3.9",
  hwid: "1.3.6.1.4.1.3704.1.4",
  productName: "1.3.6.1.4.1.3704.1.2",
} as const;

export interface SnpChecks {
  readonly structure: Check;
  readonly chain: Check;
  readonly signature: Check;
  readonly tcb_binding: Check;
  readonly debug: Check;
  readonly measurement: Check;
  readonly report_data: Check;
  readonly tcb_minimum: Check;
  readonly vmpl: Check;
}

export interface SnpVerification {
  readonly outcome: Outcome;
  readonly checks: SnpChecks;
  readonly reasons: readonly string[];
  readonly product?: SnpProduct;
  readonly report?: SnpReport;
  readonly tcb?: SnpTcb;
  readonly limitations: readonly string[];
}

export interface VerifySnpOptions {
  /** The VCEK (or VLEK) certificate, DER — from AMD KDS or the host's certificate table. */
  readonly certificate: Uint8Array;
  /** Pin the product line; otherwise inferred from the certificate issuer. */
  readonly product?: SnpProduct;
  /** Hex, 96 chars. Without it the outcome is at best `indeterminate`. */
  readonly expectedMeasurement?: string;
  /** Hex, 128 chars: the exact REPORT_DATA expected (e.g. sha512 of a key ‖ nonce). */
  readonly expectedReportData?: string;
  readonly minimumTcb?: Partial<SnpTcb>;
  readonly expectedVmpl?: number;
  readonly allowDebug?: boolean;
  /** Serial numbers (hex) revoked by AMD's CRL, if you fetched it. */
  readonly revokedSerials?: readonly string[];
  /** Verification time for certificate validity, ms. */
  readonly now?: number;
}

const LIMITS = [
  "VCEK/VLEK revocation is checked only against revokedSerials you supply (AMD KDS CRL, fetched separately)",
  "the ID block and author key are not evaluated",
  "a report carries no timestamp: freshness requires a verifier nonce inside REPORT_DATA",
  "attestation shows a measured launch state under AMD's root of trust; it does not prove the guest software is correct",
];

const NOT = (why: string) => check("not_checked", "prerequisite_failed", why);

function productFromCert(cert: X509Certificate): SnpProduct | undefined {
  const issuerCn = cert.issuer.split("\n").find((l) => l.startsWith("CN="))?.slice(3) ?? "";
  const m = issuerCn.match(/^SEV-(?:VLEK-)?(Milan|Genoa|Turin)$/);
  return m ? (m[1] as SnpProduct) : undefined;
}

/** Verify a report offline. Never throws on malformed input: it fails. */
export function verifySnpReport(reportBytes: Uint8Array, o: VerifySnpOptions): SnpVerification {
  let report: SnpReport;
  try {
    report = parseSnpReport(reportBytes);
  } catch (err) {
    const c = check("fail", "malformed", (err as Error).message);
    return done({ structure: c, chain: NOT("structure"), signature: NOT("structure"), tcb_binding: NOT("structure"), debug: NOT("structure"), measurement: NOT("structure"), report_data: NOT("structure"), tcb_minimum: NOT("structure"), vmpl: NOT("structure") }, {});
  }
  const structure = report.version < 2 || report.version > 5
    ? check("fail", "unsupported_version", `report version ${report.version} (supported: 2–5)`)
    : report.signature_algo !== 1
      ? check("fail", "unsupported_algorithm", `signature_algo ${report.signature_algo}; only 1 (ECDSA P-384 with SHA-384) is defined`)
      : !unsignedBytesZero(reportBytes)
        ? check("fail", "malformed", "non-zero bytes in the signature padding or reserved area: the unsigned part of the report was altered")
      : report.signing_key === "none" || report.signing_key === "unknown"
        ? check("fail", "unsupported_algorithm", `report signed with key selector ${report.signing_key}`)
        : check("pass", "well_formed", `version ${report.version}, signed by ${report.signing_key.toUpperCase()}`);

  let cert: X509Certificate;
  try { cert = new X509Certificate(o.certificate); } catch (err) {
    const c = check("fail", "malformed", `the ${report.signing_key.toUpperCase()} certificate does not parse: ${(err as Error).message}`);
    return done({ structure, chain: c, signature: NOT("certificate"), tcb_binding: NOT("certificate"), debug: NOT("certificate"), measurement: NOT("certificate"), report_data: NOT("certificate"), tcb_minimum: NOT("certificate"), vmpl: NOT("certificate") }, { report });
  }
  const product = o.product ?? productFromCert(cert);
  const now = o.now ?? Date.now();

  /* chain */
  let chain: Check;
  if (!product) chain = check("fail", "unsupported_platform", `cannot tell the product line from issuer "${cert.issuer.replace(/\n/g, ", ")}"; pass options.product`);
  else {
    const roots = AMD_SNP_ROOTS[product];
    const ark = new X509Certificate(roots.ark);
    const signerCa = new X509Certificate(report.signing_key === "vlek" ? roots.asvk : roots.ask);
    const validAt = (c: X509Certificate) => now >= Date.parse(c.validFrom) && now <= Date.parse(c.validTo);
    if (!(signerCa.checkIssued(ark) && signerCa.verify(ark.publicKey))) chain = check("fail", "chain_invalid", `pinned ${report.signing_key === "vlek" ? "ASVK" : "ASK"}-${product} is not signed by ARK-${product}`);
    else if (!(cert.checkIssued(signerCa) && cert.verify(signerCa.publicKey))) chain = check("fail", "untrusted_root", `the ${report.signing_key.toUpperCase()} certificate is not signed by AMD's ${report.signing_key === "vlek" ? "ASVK" : "ASK"}-${product}`);
    else if (!validAt(cert)) chain = check("fail", "certificate_expired", `the ${report.signing_key.toUpperCase()} certificate is not valid at ${new Date(now).toISOString()}`);
    else if (o.revokedSerials?.map((s) => s.toLowerCase()).includes(cert.serialNumber.toLowerCase())) chain = check("fail", "certificate_revoked", `serial ${cert.serialNumber} is on the supplied CRL`);
    else chain = check("pass", "chain_valid", `${report.signing_key.toUpperCase()} → ${report.signing_key === "vlek" ? "ASVK" : "ASK"}-${product} → ARK-${product} (pinned ${roots.arkSha256.slice(0, 16)}…)`);
  }

  /* signature */
  let signature: Check;
  try {
    const key = createPublicKey(cert.publicKey.export({ type: "spki", format: "pem" }));
    const details = key.asymmetricKeyDetails;
    if (key.asymmetricKeyType !== "ec" || details?.namedCurve !== "secp384r1") signature = check("fail", "unsupported_algorithm", "the certificate key is not ECDSA P-384");
    else {
      const sig = Buffer.concat([report.signature.r, report.signature.s]);
      const ok = cryptoVerify("sha384", reportBytes.subarray(0, SIGNED_LEN), { key, dsaEncoding: "ieee-p1363" }, sig);
      signature = ok ? check("pass", "signature_valid", "ECDSA P-384 / SHA-384 over bytes 0x000–0x29F") : check("fail", "signature_invalid", "the report signature does not verify with this certificate — altered report or wrong certificate");
    }
  } catch (err) {
    signature = check("fail", "signature_invalid", `signature check failed: ${(err as Error).message}`);
  }

  /* TCB and chip binding */
  let tcb: SnpTcb | undefined;
  let tcb_binding: Check;
  if (!product) tcb_binding = NOT("unknown product");
  else {
    tcb = decodeTcb(report.reported_tcb_raw, product);
    try {
      const exts = certificateExtensions(o.certificate);
      const intExt = (oid: string): number | undefined => {
        const e = exts.get(oid);
        return e ? integerValue(parseDer(e.value)) : undefined;
      };
      const problems: string[] = [];
      for (const k of ["bootloader", "tee", "snp", "microcode", ...(product === "Turin" ? ["fmc"] : [])] as const) {
        const certVal = intExt(EXT[k as keyof typeof EXT]);
        const repVal = tcb[k as keyof SnpTcb];
        if (certVal === undefined) problems.push(`certificate lacks ${k} SPL`);
        else if (certVal !== repVal) problems.push(`${k}: certificate ${certVal} ≠ report ${repVal}`);
      }
      if (report.signing_key === "vcek") {
        const hw = exts.get(EXT.hwid);
        let hwBytes: Uint8Array | undefined;
        if (hw) {
          // Encoded either as the raw 64 bytes or as a DER OCTET STRING containing them.
          if (hw.value.length === 64) hwBytes = hw.value;
          else { const n = parseDer(hw.value); if (n.tag === TAG.OCTET_STRING) hwBytes = n.content; }
        }
        if (!hwBytes) problems.push("VCEK lacks hwID");
        else if (hex(hwBytes) !== report.chip_id) problems.push("VCEK hwID ≠ report CHIP_ID (certificate for a different chip)");
      }
      tcb_binding = problems.length ? check("fail", "tcb_mismatch", problems.join("; ")) : check("pass", "tcb_bound", `certificate TCB = reported TCB ${JSON.stringify(tcb)}${report.signing_key === "vcek" ? "; hwID = CHIP_ID" : ""}`);
    } catch (err) {
      tcb_binding = check("fail", "malformed", `certificate extensions unreadable: ${(err as Error).message}`);
    }
  }

  const debug = report.policy.debug && !o.allowDebug
    ? check("fail", "debug_enabled", "guest policy allows DEBUG: the hypervisor can read and alter guest memory")
    : check("pass", report.policy.debug ? "debug_allowed_by_option" : "debug_disabled", `policy ${report.policy.raw}`);

  const measurement = o.expectedMeasurement === undefined
    ? check("unknown", "no_measurement_policy", `measurement ${report.measurement} is not pinned; pass expectedMeasurement`)
    : o.expectedMeasurement.toLowerCase() === report.measurement ? check("pass", "measurement_matches", report.measurement) : check("fail", "measurement_mismatch", `got ${report.measurement}`);

  const report_data = o.expectedReportData === undefined
    ? check("not_applicable", "no_report_data_expected", "REPORT_DATA not compared")
    : o.expectedReportData.toLowerCase() === report.report_data ? check("pass", "report_data_matches", "REPORT_DATA binds the expected key/nonce") : check("fail", "report_data_mismatch", "REPORT_DATA differs: not bound to this key or nonce");

  let tcb_minimum: Check;
  if (!o.minimumTcb) tcb_minimum = check("not_applicable", "no_minimum", "no TCB minimum set");
  else if (!tcb) tcb_minimum = NOT("TCB unknown");
  else {
    const low = Object.entries(o.minimumTcb).filter(([k, min]) => (tcb![k as keyof SnpTcb] ?? 0) < (min as number));
    tcb_minimum = low.length ? check("fail", "tcb_below_minimum", low.map(([k, min]) => `${k} ${tcb![k as keyof SnpTcb]} < ${min}`).join("; ")) : check("pass", "tcb_meets_minimum", JSON.stringify(tcb));
  }

  const vmpl = o.expectedVmpl === undefined ? check("not_applicable", "no_vmpl_expected", `VMPL ${report.vmpl}`)
    : o.expectedVmpl === report.vmpl ? check("pass", "vmpl_matches", `VMPL ${report.vmpl}`) : check("fail", "vmpl_mismatch", `VMPL ${report.vmpl} ≠ ${o.expectedVmpl}`);

  return done({ structure, chain, signature, tcb_binding, debug, measurement, report_data, tcb_minimum, vmpl }, { report, ...(product ? { product } : {}), ...(tcb ? { tcb } : {}) });
}

function done(checks: SnpChecks, extra: { report?: SnpReport; product?: SnpProduct; tcb?: SnpTcb }): SnpVerification {
  const { outcome, reasons } = classifyOutcome(checks as unknown as Record<string, Check>, Object.keys(checks));
  return { outcome, checks, reasons, ...extra, limitations: LIMITS };
}

/** Digest of a report, for evidence envelopes (`attestation.recorded.document_digest`). */
export const snpReportDigest = (bytes: Uint8Array) => `mh:sha256:${createHash("sha256").update(bytes).digest("hex")}`;
