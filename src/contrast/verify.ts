/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * The `workload` verdict domain: does this record really come from the Contrast
 * workload it claims?
 *
 * Six checks, in the order that makes failures diagnostic rather than merely
 * negative. Each one closes a specific substitution:
 *
 *   1. SHAPE        the credential parses and carries a leaf certificate.
 *   2. KEY BINDING  the binding statement is recomputed from the receipt's OWN
 *                   key directory and the signature over it is checked under
 *                   the leaf certificate's public key. This is what stops a
 *                   genuine credential being stapled to a record signed by some
 *                   other key — the attacker would need the pod's mesh key.
 *   3. IDENTITY     the identity recomputed from the certificate must equal the
 *                   identity sealed inside the signed record core. This is what
 *                   stops workload A's receipt being presented as workload B's:
 *                   swap the credential and the recomputed identity diverges;
 *                   edit the sealed identity and the record signature breaks.
 *   4. CHAIN        the chain must verify to a Coordinator root the VERIFIER
 *                   pinned. Not a root the receipt carried — a pod can mint its
 *                   own CA, so an unpinned chain proves only self-consistency
 *                   and is reported, never passed.
 *   5. MANIFEST     the policy hash must be one the pinned manifest authorises,
 *                   and the sealed manifest digest must match the pinned bytes.
 *   6. REGISTERS    the attestation registers must match what was pinned.
 *
 * The honesty rule that governs the whole domain: `pass` requires a pinned
 * Coordinator root AND a credential that actually carries measurements. A
 * Contrast `insecure` deployment issues certificates with no attestation claims
 * at all (`internal/attestation/insecure/validator.go` returns no extensions),
 * and such a credential reports `simulated` — a real signature by a real
 * Coordinator over a workload whose hardware nobody checked. It is never
 * rounded up, because that distinction is the product.
 */
import type { DomainCheckV2, ReceiptV2, VerifyOptionsV2, WorkloadIdentityV1 } from "../phala/types";
import { canonicalCbor } from "../canonical";
import { fromBase64Field, utf8 } from "../codec";
import { mhSha256 } from "../multihash";
import {
  bindingCommitment,
  bindingMessage,
  bindingStatement,
  identityFromCertificate,
  pinnedRegisterDiff,
  registerDiff,
  registersDigest,
} from "./identity";
import { parseManifest, policyFor, workloadPolicyHashes } from "./manifest";
import { parseCertificates, verifyChain, verifyEcdsa, type Certificate } from "./x509";

/** Options the workload domain reads. A subset of the verifier's own options. */
export type WorkloadVerifyOptions = Pick<
  VerifyOptionsV2,
  "coordinatorRootCA" | "allowedPolicyHashes" | "expectedManifest" | "expectedRegisters"
>;

function fail(detail: string): DomainCheckV2 {
  return { status: "fail", detail };
}

/** Normalise a hex-ish value for comparison: drop any `hex:` prefix, lowercase. */
function hex(value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  return value.replace(/^hex:/, "").toLowerCase();
}

/**
 * Verify the Contrast workload binding of a receipt.
 *
 * Never throws: a malformed credential is a failed domain, not an exception,
 * because a verifier is often looking at bytes an adversary chose.
 *
 * @param reasons appended to with human-readable failures, as the other domains do
 */
export function verifyWorkloadDomain(
  receipt: ReceiptV2,
  options: WorkloadVerifyOptions,
  reasons: string[],
): DomainCheckV2 {
  const credential = receipt.attestation.workload;
  const sealed = receipt.record.runtime.workload;

  if (!credential && !sealed) {
    return {
      status: "absent",
      detail: "no orchestrator-issued workload credential in this receipt",
    };
  }
  // Half a binding is worse than none: it means someone removed the other half.
  if (!credential) {
    reasons.push("workload: the record seals a workload identity but the receipt carries no credential");
    return fail("FAILED — sealed workload identity with no credential to check it against");
  }
  if (!sealed) {
    reasons.push("workload: a credential is attached but the signed record seals no workload identity");
    return fail("FAILED — credential present but nothing in the signed core binds to it");
  }

  /* 1 · shape */
  let chain: Certificate[];
  try {
    chain = parseCertificates(credential.cert_chain);
  } catch (error) {
    reasons.push(`workload: credential could not be parsed (${(error as Error).message})`);
    return fail(`FAILED — unreadable credential: ${(error as Error).message}`);
  }
  const leaf = chain[0];
  if (!leaf) {
    reasons.push("workload: credential contains no leaf certificate");
    return fail("FAILED — credential contains no leaf certificate");
  }

  /* 2 · key binding */
  const boundKeyId = credential.bound_key_id;
  const entry = receipt.key_directory[boundKeyId];
  if (!entry) {
    reasons.push(`workload: key_directory has no entry for the bound key '${boundKeyId}'`);
    return fail(`FAILED — no public key for bound key_id '${boundKeyId}'`);
  }
  if (boundKeyId !== receipt.record.signature.key_id) {
    reasons.push("workload: the credential binds a different key than the one that signed the record");
    return fail(
      `FAILED — credential binds '${boundKeyId}' but the record was signed by '${receipt.record.signature.key_id}'`,
    );
  }

  const statement = bindingStatement(boundKeyId, entry, credential.issued_at);
  const recomputed = bindingCommitment(statement);
  if (recomputed !== credential.key_binding) {
    reasons.push("workload: the binding commitment does not match the signing key in this receipt");
    return fail("FAILED — key_binding does not commit to the key that signed this record");
  }

  let bindingOk = false;
  try {
    bindingOk = verifyEcdsa(
      bindingMessage(statement),
      fromBase64Field(credential.binding_signature),
      leaf.publicKey,
      credential.binding_alg,
    );
  } catch {
    bindingOk = false;
  }
  if (!bindingOk) {
    reasons.push("workload: the workload credential did not sign this record's key");
    return fail(
      "FAILED — the binding signature does not verify under the credential; this credential attests a DIFFERENT key",
    );
  }

  /* 3 · identity */
  // No operator inputs here: only the fields the certificate itself states are
  // compared against the signed core.
  //
  // Wrapped because a certificate can parse as X.509 and still carry a
  // malformed attestation extension -- a claim that is not an OCTET STRING, say.
  // `verifyEvidence` promises never to throw on adversarial bytes, and the bytes
  // here were chosen by whoever produced the receipt.
  let observed: WorkloadIdentityV1;
  try {
    observed = identityFromCertificate(leaf);
  } catch (error) {
    reasons.push(`workload: the credential's attestation claims are malformed (${(error as Error).message})`);
    return fail(`FAILED — malformed attestation claim in the credential: ${(error as Error).message}`);
  }
  const identityProblem = compareIdentity(sealed, observed);
  if (identityProblem) {
    reasons.push(`workload: ${identityProblem}`);
    return fail(`FAILED — ${identityProblem}`);
  }

  /* 4 · chain */
  let roots: Certificate[] = [];
  if (options.coordinatorRootCA) {
    try {
      roots = parseCertificates(options.coordinatorRootCA);
    } catch (error) {
      reasons.push(`workload: the pinned Coordinator root CA could not be parsed (${(error as Error).message})`);
      return fail(`FAILED — unreadable Coordinator root CA: ${(error as Error).message}`);
    }
  }

  const issuedAt = new Date(credential.issued_at);
  const at = Number.isNaN(issuedAt.getTime()) ? new Date() : issuedAt;

  let chainDetail: string;
  let pinned = false;
  if (roots.length === 0) {
    chainDetail = "chain NOT checked — no Coordinator root CA pinned by the verifier";
  } else {
    // If the record sealed which root it expected, say so plainly when the
    // verifier is holding a different one. Without this the failure would
    // surface as an opaque "no issuer found", which sends the reader looking
    // for a forgery instead of for the right PEM file.
    const sealedRootPresent =
      sealed.coordinator_root !== null &&
      roots.some((root) => mhSha256(root.der) === sealed.coordinator_root);
    if (sealed.coordinator_root !== null && !sealedRootPresent) {
      reasons.push("workload: the record was produced against a different Coordinator root than the one pinned here");
      return fail(
        "FAILED — the pinned Coordinator root CA is not the one this record sealed; you are verifying against the wrong deployment",
      );
    }
    const result = verifyChain(chain, roots, at);
    if (!result.ok) {
      reasons.push(`workload: ${result.detail}`);
      return fail(`FAILED — ${result.detail}`);
    }
    chainDetail = result.detail;
    pinned = true;
  }

  /* 5 · manifest */
  let manifestDetail = "no manifest pinned by the verifier";
  if (options.expectedManifest !== undefined) {
    let manifest: ReturnType<typeof parseManifest>;
    try {
      manifest = parseManifest(options.expectedManifest);
    } catch (error) {
      // This one is the VERIFIER's own input, not the receipt's, so say whose
      // file is at fault rather than implying the evidence is bad.
      reasons.push(`workload: the manifest supplied to the verifier could not be parsed (${(error as Error).message})`);
      return fail(`FAILED — the manifest YOU supplied is not a Contrast manifest: ${(error as Error).message}`);
    }
    if (sealed.manifest_digest !== null && sealed.manifest_digest !== manifest.digest) {
      reasons.push("workload: the record was produced under a different manifest than the one pinned here");
      return fail(
        `FAILED — this record was produced under a different manifest: it sealed ${sealed.manifest_digest.slice(10, 22)}…, the pinned manifest is ${manifest.digest.slice(10, 22)}…`,
      );
    }
    const policy = sealed.policy_hash ? policyFor(manifest, sealed.policy_hash) : undefined;
    if (!policy) {
      reasons.push("workload: the credential's policy hash is not in the pinned manifest's Policies");
      return fail(
        `FAILED — policy hash ${hex(sealed.policy_hash)?.slice(0, 16) ?? "(absent)"}… is not authorised by the pinned manifest`,
      );
    }
    if (
      policy.workloadSecretId !== null &&
      sealed.workload_secret_id !== null &&
      policy.workloadSecretId !== sealed.workload_secret_id
    ) {
      reasons.push("workload: the credential's workload secret id disagrees with the manifest entry");
      return fail(
        `FAILED — manifest entry expects workload secret id '${policy.workloadSecretId}', credential says '${sealed.workload_secret_id}'`,
      );
    }
    manifestDetail = `policy hash authorised by the pinned manifest (${workloadPolicyHashes(manifest).length} workload polic${workloadPolicyHashes(manifest).length === 1 ? "y" : "ies"})`;
  }

  if (options.allowedPolicyHashes && options.allowedPolicyHashes.length > 0) {
    const allowed = new Set(options.allowedPolicyHashes.map((value) => hex(value)));
    if (!allowed.has(hex(sealed.policy_hash))) {
      reasons.push("workload: the credential's policy hash is not in the verifier's allow-list");
      return fail(
        `FAILED — policy hash ${hex(sealed.policy_hash)?.slice(0, 16) ?? "(absent)"}… is not in the allowed set`,
      );
    }
  }

  /* 6 · registers */
  let registerDetail = "no registers pinned by the verifier";
  if (options.expectedRegisters) {
    const expected: Record<string, string> = {};
    for (const [name, value] of Object.entries(options.expectedRegisters)) {
      expected[name] = `hex:${hex(value)}`;
    }
    const drift = pinnedRegisterDiff(expected, sealed.registers);
    if (drift.length > 0) {
      reasons.push("workload: the workload's measurements differ from the pinned ones");
      return fail(`FAILED — running workload differs from the approved one in ${drift.join(", ")}`);
    }
    registerDetail = `matches the pinned registers (${Object.keys(expected).length})`;
  }

  /* verdict */
  const name = sealed.workload_name ?? "(unnamed)";
  const policyShort = hex(sealed.policy_hash)?.slice(0, 12) ?? "none";
  const summary = `Contrast workload '${name}' · policy ${policyShort}… · ${chainDetail}; ${manifestDetail}; ${registerDetail}`;

  if (sealed.tee === "insecure") {
    return {
      status: "simulated",
      detail: `${summary} — the Coordinator issued this credential on an INSECURE (non-CC) platform, so it carries no measurements and is NOT evidence of confidential execution`,
    };
  }
  if (!pinned) {
    return {
      status: "absent",
      detail: `${summary} — the binding is valid and self-consistent, but with no pinned Coordinator root it is REPORTED, not verified`,
    };
  }
  return { status: "pass", detail: summary };
}

/**
 * Compare the identity sealed in the signed core against the identity recovered
 * from the credential, and name the first field that disagrees.
 *
 * `coordinator_root` and `manifest_digest` are operator inputs rather than
 * certificate contents, so they are not compared here — they are checked
 * against what the VERIFIER pinned, above, which is the only comparison that
 * means anything.
 */
function compareIdentity(
  sealed: WorkloadIdentityV1,
  observed: WorkloadIdentityV1,
): string | null {
  if (sealed.schema !== "cool.workload.v1") {
    return `unknown workload identity schema '${String(sealed.schema)}'`;
  }
  if (sealed.platform !== observed.platform) {
    return `record claims platform '${sealed.platform}', credential is '${observed.platform}'`;
  }
  if (sealed.tee !== observed.tee) {
    return `record claims ${sealed.tee}, but the credential's claims are ${observed.tee}`;
  }
  if (hex(sealed.policy_hash) !== hex(observed.policy_hash)) {
    return "the record's policy hash is not the one in the credential";
  }
  if (sealed.workload_secret_id !== observed.workload_secret_id) {
    return "the record's workload secret id is not the one in the credential";
  }
  if (sealed.workload_name !== observed.workload_name) {
    return `record names workload '${sealed.workload_name}', credential names '${observed.workload_name}'`;
  }
  if (canonicalCborHex(sealed.sans) !== canonicalCborHex(observed.sans)) {
    return "the record's subject alternative names are not the credential's";
  }
  const drift = registerDiff(sealed.registers, observed.registers);
  if (drift.length > 0) {
    return `record and credential disagree on ${drift.join(", ")}`;
  }
  if (sealed.registers_digest !== registersDigest(sealed.registers)) {
    return "the record's registers_digest does not commit to its own registers";
  }
  if (observed.registers_digest !== sealed.registers_digest) {
    return "the credential's registers do not produce the record's registers_digest";
  }
  return null;
}

function canonicalCborHex(value: unknown): string {
  return mhSha256(canonicalCbor(value));
}

/** Convenience: the digest a deployment should pin for a Coordinator root CA PEM. */
export function coordinatorRootDigest(pem: string): string {
  const roots = parseCertificates(pem);
  const first = roots[0];
  if (!first) throw new Error("no certificate in the supplied Coordinator root CA PEM");
  return mhSha256(first.der);
}

/** Convenience: the digest a deployment should pin for a manifest. */
export function manifestDigest(source: string | Uint8Array): string {
  return mhSha256(typeof source === "string" ? utf8(source) : source);
}
