/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * The Contrast manifest, read as a pinning input.
 *
 * `manifest.json` is the Coordinator's configuration: which pods are allowed
 * (`Policies`, keyed by policy hash), what their hardware must look like
 * (`ReferenceValues.snp` / `.tdx`), and who may change it later
 * (`WorkloadOwnerPubKeys`, `SeedshareOwnerPubKeys`). CooL does not interpret the
 * reference values — enforcing them is the Coordinator's job and duplicating
 * that logic here would create a second, divergent opinion about what is
 * acceptable. What CooL does is narrower and complementary:
 *
 *   • pin the manifest by digest, so a record states which manifest governed it;
 *   • read the `Policies` keys, so a verifier can require that the policy hash
 *     in a workload credential is one the manifest actually authorises.
 *
 * Field names are taken from `internal/manifest/manifest.go`, where `Policies`
 * is documented as "a map from policy hash (HOSTDATA) to policy entry" — which
 * is precisely the value CooL reads out of the mesh certificate.
 *
 * Parsing is tolerant by design: an unknown field is not an error, because the
 * manifest gains fields as Contrast gains platforms and a CooL upgrade should
 * not be required to keep verifying.
 */
import { canonicalCbor } from "../canonical";
import { concatBytes, utf8 } from "../codec";
import { mhSha256 } from "../multihash";
import type { Multihash } from "../types";

/** One entry of the manifest's `Policies` map. */
export interface ManifestPolicy {
  /** Subject alternative names the Coordinator puts in this workload's cert. */
  readonly sans: readonly string[];
  /** Label used to derive the workload secret. */
  readonly workloadSecretId: string | null;
  /** `coordinator` for the Coordinator's own entry; absent for workloads. */
  readonly role: string | null;
}

/** A parsed Contrast manifest. */
export interface ContrastManifest {
  /** `mh:sha256` over the exact bytes supplied — the pinnable identity. */
  readonly digest: Multihash;
  /** Policy hash → entry. Keys are lowercase hex, as the manifest writes them. */
  readonly policies: Readonly<Record<string, ManifestPolicy>>;
  /** Platforms the manifest carries reference values for. */
  readonly platforms: readonly ("snp" | "tdx")[];
  /** Commitment over the reference values, for change detection. */
  readonly referenceValuesDigest: Multihash | null;
  /** True when the manifest pins no owner keys, i.e. updates are disabled. */
  readonly updatesDisabled: boolean;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/**
 * Parse a Contrast `manifest.json`.
 *
 * @param source the exact bytes or text of the manifest. Bytes are preferred:
 *   the digest must be over what the Coordinator serves, and re-serialising
 *   parsed JSON would change it.
 */
export function parseManifest(source: string | Uint8Array): ContrastManifest {
  const bytes = typeof source === "string" ? utf8(source) : source;
  const text = typeof source === "string" ? source : new TextDecoder().decode(source);

  let root: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("manifest is not a JSON object");
    }
    root = parsed as Record<string, unknown>;
  } catch (error) {
    throw new Error(`could not parse Contrast manifest: ${(error as Error).message}`);
  }

  const policies: Record<string, ManifestPolicy> = {};
  const rawPolicies = root["Policies"];
  if (typeof rawPolicies === "object" && rawPolicies !== null) {
    for (const [hash, entry] of Object.entries(rawPolicies as Record<string, unknown>)) {
      const e = (typeof entry === "object" && entry !== null ? entry : {}) as Record<string, unknown>;
      policies[hash.toLowerCase()] = {
        sans: asStringArray(e["SANs"]),
        workloadSecretId:
          typeof e["WorkloadSecretID"] === "string" ? e["WorkloadSecretID"] : null,
        role: typeof e["Role"] === "string" ? e["Role"] : null,
      };
    }
  }

  const referenceValues = root["ReferenceValues"];
  const platforms: ("snp" | "tdx")[] = [];
  let referenceValuesDigest: Multihash | null = null;
  if (typeof referenceValues === "object" && referenceValues !== null) {
    const rv = referenceValues as Record<string, unknown>;
    for (const platform of ["snp", "tdx"] as const) {
      const list = rv[platform];
      if (Array.isArray(list) && list.length > 0) platforms.push(platform);
    }
    referenceValuesDigest = mhSha256(
      concatBytes(utf8("cool/contrast/reference-values/v1"), canonicalCbor(referenceValues)),
    );
  }

  const ownerKeys = asStringArray(root["WorkloadOwnerPubKeys"]);

  return {
    digest: mhSha256(bytes),
    policies,
    platforms,
    referenceValuesDigest,
    updatesDisabled: ownerKeys.length === 0,
  };
}

/** The policy hashes a manifest authorises, excluding the Coordinator's own. */
export function workloadPolicyHashes(manifest: ContrastManifest): string[] {
  return Object.entries(manifest.policies)
    .filter(([, entry]) => entry.role !== "coordinator")
    .map(([hash]) => hash)
    .sort();
}

/** Look up the manifest entry a policy hash refers to. */
export function policyFor(
  manifest: ContrastManifest,
  policyHash: string,
): ManifestPolicy | undefined {
  return manifest.policies[policyHash.replace(/^hex:/, "").toLowerCase()];
}
