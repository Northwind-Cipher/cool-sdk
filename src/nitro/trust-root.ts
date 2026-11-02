/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The pinned AWS Nitro Enclaves root.
 *
 * The certificate below was downloaded from
 * https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
 * (zip SHA-256 8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c)
 * and checked against the fingerprint AWS publishes on "Verifying the root of
 * trust" in the Nitro Enclaves user guide. The fingerprint is pinned twice — as
 * a constant here and in the docs — and the module refuses to load if the
 * embedded PEM ever stops matching it, so an edit to one cannot go unnoticed.
 *
 * A trust bundle is versioned data, not code: callers can pass their own (for a
 * different partition, or a test PKI), and every report names the bundle and
 * root it was checked against. A caller-supplied bundle is never merged with
 * this one implicitly.
 */
import { X509Certificate, createHash } from "node:crypto";

/** One trusted root inside a bundle. */
export interface NitroTrustRoot {
  readonly name: string;
  /** DER bytes of the root certificate. */
  readonly der: Uint8Array;
  /** Lowercase hex SHA-256 of {@link der}. */
  readonly fingerprintSha256: string;
}

/** A versioned set of roots a verifier is willing to chain to. */
export interface NitroTrustBundle {
  readonly id: string;
  readonly version: string;
  /** Where the roots were obtained, for the report. */
  readonly source: string;
  readonly roots: readonly NitroTrustRoot[];
  /**
   * Optional review deadline. After it, the verifier reports the trust root as
   * `unknown` ("trust_bundle_stale") instead of passing: the bundle may still be
   * correct, but nobody has confirmed it recently enough to say so.
   */
  readonly expiresAt?: string;
}

/** AWS-published SHA-256 fingerprint of AWS_NitroEnclaves_Root-G1. */
export const AWS_NITRO_ROOT_G1_FINGERPRINT =
  "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b";

const AWS_NITRO_ROOT_G1_PEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`;

function rootFromPem(name: string, pem: string, pinned: string): NitroTrustRoot {
  const der = new Uint8Array(new X509Certificate(pem).raw);
  const fingerprintSha256 = createHash("sha256").update(der).digest("hex");
  if (fingerprintSha256 !== pinned) {
    throw new Error(
      `embedded ${name} does not match its pinned fingerprint (${fingerprintSha256} ≠ ${pinned}); refusing to load`,
    );
  }
  return { name, der, fingerprintSha256 };
}

/** The default bundle: the AWS commercial-partition Nitro root, G1. */
export const AWS_NITRO_TRUST_BUNDLE: NitroTrustBundle = {
  id: "aws-nitro-enclaves-root-g1",
  version: "2019-10-28",
  source: "https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip",
  roots: [rootFromPem("AWS_NitroEnclaves_Root-G1", AWS_NITRO_ROOT_G1_PEM, AWS_NITRO_ROOT_G1_FINGERPRINT)],
};

/** Build a bundle from DER roots (a test PKI, or another partition's root). */
export function trustBundleFromDer(
  id: string,
  version: string,
  source: string,
  roots: ReadonlyArray<{ readonly name: string; readonly der: Uint8Array }>,
  expiresAt?: string,
): NitroTrustBundle {
  return {
    id,
    version,
    source,
    roots: roots.map((r) => ({
      name: r.name,
      der: r.der,
      fingerprintSha256: createHash("sha256").update(r.der).digest("hex"),
    })),
    ...(expiresAt ? { expiresAt } : {}),
  };
}
