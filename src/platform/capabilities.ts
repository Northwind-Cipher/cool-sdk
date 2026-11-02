/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The single source of truth for what CooL can and cannot do.
 *
 * Every capability has exactly one label and the evidence behind it. Docs are
 * generated from this table (docs/capabilities.md, `npm run docs:capabilities`)
 * and tests/capabilities.test.ts fails CI when a doc drifts from it, when a TEE
 * adapter's `support` disagrees with it, or when a known stale claim reappears.
 *
 *   implemented   built, tested, and validated against GENUINE evidence or a real service
 *   experimental  built and tested, but not yet validated against the real thing (hardware, cloud)
 *   partial       built with documented gaps
 *   planned       designed, not built
 *   unsupported   deliberately not supported; the verifier says so instead of guessing
 */

export type CapabilityLabel = "implemented" | "experimental" | "partial" | "planned" | "unsupported";

export interface Capability {
  readonly id: string;
  readonly area: "evidence" | "authorization" | "tee" | "keys" | "time" | "replay" | "transparency" | "assurance";
  readonly name: string;
  readonly label: CapabilityLabel;
  /** What the label rests on: tests, genuine fixtures, CI jobs, artifacts. */
  readonly evidence: string;
  /** What it does not do, or what would move it up a label. */
  readonly limits: string;
}

export const CAPABILITIES: readonly Capability[] = [
  { id: "envelope", area: "evidence", name: "Evidence envelope, schemas, canonical CBOR, hybrid ML-DSA-65 + Ed25519 signatures", label: "implemented", evidence: "platform-envelope, evidence-v2, test vectors", limits: "a signature says who signed, not that the statement is true" },
  { id: "bundle", area: "evidence", name: "Bundles with attachments, sequence-gap detection, six outcomes", label: "implemented", evidence: "evidence-v2, demo:agent G", limits: "a dropped final event is undetectable until a later one arrives" },
  { id: "legacy-receipts", area: "evidence", name: "cool.receipt.v2 wrapped in the envelope unchanged", label: "implemented", evidence: "evidence-v2", limits: "—" },
  { id: "authz-protocol", area: "authorization", name: "Principals, delegation, committed requests, signed decisions, replayable policy", label: "implemented", evidence: "authz, authz-schemas, demo:agent A–C", limits: "intent is not proven; only signatures are" },
  { id: "gateway", area: "authorization", name: "ToolGateway enforcement with signed external confirmations", label: "implemented", evidence: "authz-gateway, demo:agent B/D/E", limits: "actions outside the gateway are not covered" },
  { id: "replay-local", area: "replay", name: "Replay protection on one host (memory, O_EXCL file store)", label: "implemented", evidence: "authz (25-way race), demo:agent D", limits: "one host only" },
  { id: "replay-redis", area: "replay", name: "Replay protection across machines: RedisNonceStore (RESP over TCP/TLS, SET NX PX)", label: "implemented", evidence: "replay-shared (protocol, races, faults) + CI job `redis` against a real redis:7 server", limits: "Redis must be configured for durability you accept; a failover that loses writes can forget nonces within the TTL" },
  { id: "replay-sql-dynamo", area: "replay", name: "Replay protection on Postgres / DynamoDB (SharedNonceStore backends)", label: "experimental", evidence: "replay-shared (semantics with emulated backends)", limits: "not yet run against a live Postgres or DynamoDB" },
  { id: "nitro-verifier", area: "tee", name: "AWS Nitro attestation verification", label: "implemented", evidence: "GENUINE AWS document + 600 corruption cases (nitro-attestation)", limits: "no revocation (AWS publishes no CRL)" },
  { id: "nitro-runtime", area: "tee", name: "CooL sealer inside a Nitro Enclave on AWS hardware", label: "experimental", evidence: "deployment kit (examples/nitro-enclave), nitro-kit tests over real sockets with a synthetic NSM, CI builds the image and compiles the NSM helper", limits: "not yet run on AWS hardware: becomes implemented when artifacts/nitro-validation/ holds a passing, non-synthetic artifact" },
  { id: "tdx", area: "tee", name: "Intel TDX via Phala dstack", label: "implemented", evidence: "hardware validation on Phala Cloud tdx.small (artifacts/closure-verification-matrix.md)", limits: "TCB recorded as Unknown; quote freshness not checked on this path" },
  { id: "dstack-kms", area: "tee", name: "Phala dstack KMS / runtime evidence", label: "partial", evidence: "real-tee-validation", limits: "keys follow app identity, not the image; the KMS's own attestation is not verified" },
  { id: "sev-snp", area: "tee", name: "AMD SEV-SNP report verification (VCEK/VLEK → ASK/ASVK → pinned ARK, TCB and chip binding)", label: "implemented", evidence: "GENUINE Milan report + VCEK (snp), AMD roots fetched from KDS and pinned, 300-case fuzz", limits: "CRL only if you supply revoked serials; ID block not evaluated" },
  { id: "nvidia-cc", area: "tee", name: "NVIDIA Confidential Computing: NRAS result verification, CPU binding", label: "experimental", evidence: "nvidia (real NRAS JWKS chains to pinned intermediates; tokens synthetic)", limits: "no result from a real CC GPU yet; raw SPDM evidence is appraised by NRAS, not here" },
  { id: "kms-aws", area: "keys", name: "AWS KMS signer (ML_DSA_65 + ECC_NIST_EDWARDS25519)", label: "experimental", evidence: "signers (provider emulator enforcing AWS API rules)", limits: "becomes implemented with a passing `npm run validate:kms -- aws` artifact" },
  { id: "kms-gcp", area: "keys", name: "Google Cloud KMS signer (PQ_SIGN_ML_DSA_65 + EC_SIGN_ED25519)", label: "experimental", evidence: "signers (provider emulator)", limits: "becomes implemented with a passing `npm run validate:kms -- gcp` artifact" },
  { id: "kms-pkcs11", area: "keys", name: "PKCS#11 HSM component signer (CKM_ML_DSA, CKM_EDDSA)", label: "experimental", evidence: "signers (emulated session)", limits: "not run against a physical HSM; needs an HSM supporting both mechanisms" },
  { id: "kms-azure", area: "keys", name: "Azure Key Vault signer", label: "unsupported", evidence: "—", limits: "Key Vault offers neither Ed25519 nor ML-DSA, so it cannot hold either half of the hybrid" },
  { id: "rfc3161", area: "time", name: "RFC 3161 trusted timestamps (request, offline verification, pinned TSA anchors)", label: "implemented", evidence: "GENUINE DigiCert token; exhaustive single-bit flips (timestamp)", limits: "TSA revocation not checked offline; RSASSA-PSS tokens unsupported" },
  { id: "opentimestamps", area: "time", name: "OpenTimestamps anchoring", label: "implemented", evidence: "anchor", limits: "opt-in and networked" },
  { id: "transparency", area: "transparency", name: "RFC 6962 log, consistency proofs, witness verification", label: "implemented", evidence: "platform-envelope, witness-consistency", limits: "a log can still withhold entries; witnesses detect forks, not omissions" },
  { id: "internal-review", area: "assurance", name: "Internal adversarial security review", label: "implemented", evidence: "docs/security-review/internal-review-2026-11.md", limits: "performed by the maintainers (AI-assisted); not independent" },
  { id: "external-review", area: "assurance", name: "Independent third-party security review", label: "planned", evidence: "review package ready: docs/security-review/", limits: "not commissioned: requires engaging an external firm; no audit is claimed" },
];

export function capability(id: string): Capability {
  const c = CAPABILITIES.find((x) => x.id === id);
  if (!c) throw new Error(`unknown capability ${id}`);
  return c;
}

/** The generated markdown table (docs/capabilities.md). */
export function capabilitiesMarkdown(): string {
  const rows = CAPABILITIES.map((c) => `| ${c.area} | ${c.name} | **${c.label}** | ${c.evidence} | ${c.limits} |`);
  return [
    "# Capabilities and their labels",
    "",
    "<!-- GENERATED from src/platform/capabilities.ts by `npm run docs:capabilities`. Do not edit by hand: tests/capabilities.test.ts fails if this file drifts. -->",
    "",
    "| Label | Meaning |",
    "|---|---|",
    "| **implemented** | built, tested, and validated against genuine evidence or a real service |",
    "| **experimental** | built and tested, not yet validated against the real thing (hardware, cloud) |",
    "| **partial** | built with documented gaps |",
    "| **planned** | designed, not built |",
    "| **unsupported** | deliberately not supported; the verifier says so |",
    "",
    "| Area | Capability | Label | Evidence | Limits / what moves it up |",
    "|---|---|---|---|---|",
    ...rows,
    "",
    "Run `cool capabilities` to print this table from the installed package.",
    "",
  ].join("\n");
}
