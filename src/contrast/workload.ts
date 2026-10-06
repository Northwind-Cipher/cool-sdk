/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * `ContrastWorkload` — CooL's only touch-point with a Contrast deployment.
 *
 * The integration surface is a directory, not an RPC. Contrast's initializer
 * runs as an init container, attests the pod to the Coordinator over aTLS, and
 * writes the results into the shared `contrast-secrets` volume mounted at
 * `/contrast` (`initializer/main.go`):
 *
 *   /contrast/tls-config/certChain.pem            leaf mesh cert ‖ intermediate
 *   /contrast/tls-config/key.pem                  the pod's P-256 key (0400)
 *   /contrast/tls-config/mesh-ca.pem              the mesh CA
 *   /contrast/tls-config/coordinator-root-ca.pem  the Coordinator root CA
 *   /contrast/secrets/workload-secret-seed        hex workload secret (0400)
 *
 * By the time the application container starts, those files exist or the pod
 * never got past its init container. So CooL needs no Contrast client library,
 * no sidecar and no network call — which is also why this adds no dependency to
 * the SDK and why the whole thing can be exercised from fixtures on a laptop.
 *
 * This class satisfies the same {@link AttestationSource} contract the dstack
 * clients do, so everything above it — the evidence plane, the capture queue,
 * the transparency log, the verifier — is unchanged. The one thing it does
 * differently is the attestation shape: Contrast has no raw quote to return, so
 * `getQuote` is `null` and `attestWorkload` produces a Coordinator-issued
 * credential instead. That asymmetry is the integration, stated in two methods.
 *
 * Node-only, by nature: it reads files. The VERIFIER half
 * (`./verify`, `./x509`) deliberately stays browser-safe.
 */
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import type { KeyDirectory, Multihash } from "../types";
import type {
  QuoteEnvelope,
  RuntimeMode,
  TeeVendor,
  WorkloadBinding,
  WorkloadIdentityV1,
} from "../phala/types";
import type { AttestationSource, EnclaveInfo } from "../phala/dstack";
import { fromHex, utf8 } from "../codec";
import { mhSha256 } from "../multihash";
import {
  CONTRAST_KEY_PATH,
  bindingCommitment,
  bindingMessage,
  bindingStatement,
  identityFromCertificate,
} from "./identity";
import { bindingAlgorithm, parsePrivateKey, signBinding, type PrivateKey } from "./key";
import { parseManifest, type ContrastManifest } from "./manifest";
import { parseCertificates, type Certificate } from "./x509";

/** Where Contrast mounts its shared volume inside a workload container. */
export const CONTRAST_ROOT = "/contrast";

/** The files CooL reads, relative to the Contrast root. */
export const CONTRAST_FILES = {
  certChain: "tls-config/certChain.pem",
  key: "tls-config/key.pem",
  meshCa: "tls-config/mesh-ca.pem",
  coordinatorRootCa: "tls-config/coordinator-root-ca.pem",
  workloadSecret: "secrets/workload-secret-seed",
} as const;

/** Raised when a Contrast deployment is not where CooL was told to look. */
export class ContrastUnavailableError extends Error {
  readonly action: string;
  constructor(message: string, action: string) {
    super(message);
    this.name = "ContrastUnavailableError";
    this.action = action;
  }
}

/** The minimal file reader `ContrastWorkload` needs. Injectable for tests. */
export interface FileReader {
  read(path: string): Promise<string>;
}

/** Options for {@link ContrastWorkload.open}. */
export interface ContrastWorkloadOptions {
  /**
   * The Contrast volume root. Defaults to `$COOL_CONTRAST_ROOT`, then
   * `/contrast`. Point it at a fixture directory to exercise the whole path
   * without a cluster.
   */
  readonly root?: string;
  /**
   * The `manifest.json` the deployment approved, as bytes or text. Sealed into
   * every record by digest, so a receipt states which manifest governed it.
   * Defaults to `$COOL_CONTRAST_MANIFEST` read as a file path, when set.
   */
  readonly manifest?: string | Uint8Array;
  /** RFC 3339 clock. Inject for deterministic tests. */
  readonly clock?: () => string;
  /** Override file access. Defaults to `node:fs/promises`. */
  readonly files?: FileReader;
  /**
   * Treat a credential with no attestation claims as fatal rather than
   * reporting it. Contrast issues such certificates on `insecure` development
   * platforms; a production deployment should set this and never unset it.
   */
  readonly requireConfidential?: boolean;
}

async function nodeFiles(): Promise<FileReader> {
  const fs = await import("node:fs/promises");
  return {
    async read(path: string): Promise<string> {
      return fs.readFile(path, "utf8");
    },
  };
}

function join(root: string, relative: string): string {
  return `${root.replace(/[/\\]$/, "")}/${relative}`;
}

/**
 * A CooL attestation source backed by a live Contrast workload.
 *
 * Construction is `open()` rather than `new` because the useful object is the
 * one that has already read and validated the pod's credential — an instance
 * that exists but has not confirmed where it is running would be a trap.
 */
export class ContrastWorkload implements AttestationSource {
  readonly mode: RuntimeMode;

  private constructor(
    private readonly leaf: Certificate,
    private readonly chainPem: string,
    private readonly meshKey: PrivateKey,
    private readonly workloadSecret: Uint8Array,
    readonly identity: WorkloadIdentityV1,
    readonly manifest: ContrastManifest | null,
    private readonly coordinatorRootPem: string,
    private readonly clock: () => string,
  ) {
    // A Contrast credential with real measurements is hardware-backed from the
    // Coordinator's point of view; one without is not, and says so here rather
    // than at the end of a verification nobody ran.
    this.mode = identity.tee === "insecure" ? "simulated" : "hardware";
  }

  /** Read the pod's Contrast credential and prepare to seal evidence with it. */
  static async open(options: ContrastWorkloadOptions = {}): Promise<ContrastWorkload> {
    const env = typeof process !== "undefined" ? process.env : undefined;
    const root = options.root ?? env?.["COOL_CONTRAST_ROOT"] ?? CONTRAST_ROOT;
    const files = options.files ?? (await nodeFiles());

    const read = async (relative: string, what: string): Promise<string> => {
      const path = join(root, relative);
      try {
        return await files.read(path);
      } catch (error) {
        throw new ContrastUnavailableError(
          `could not read ${what} at ${path}: ${(error as Error).message}`,
          "run this container inside a Contrast deployment (the initializer writes these files), or point COOL_CONTRAST_ROOT at a directory that has them",
        );
      }
    };

    const chainPem = await read(CONTRAST_FILES.certChain, "the workload certificate chain");
    const keyPem = await read(CONTRAST_FILES.key, "the workload mesh key");
    const coordinatorRootPem = await read(
      CONTRAST_FILES.coordinatorRootCa,
      "the Coordinator root CA",
    );
    // Read separately from the TLS files: a MISSING workload secret is not a
    // "you are not in a Contrast pod" problem, it is a manifest problem, and
    // the two need different advice. Contrast only releases a workload secret
    // for a policy entry that sets WorkloadSecretID.
    let secretHex: string;
    try {
      secretHex = await files.read(join(root, CONTRAST_FILES.workloadSecret));
    } catch (error) {
      throw new ContrastUnavailableError(
        `the Coordinator released no workload secret to this pod (${join(root, CONTRAST_FILES.workloadSecret)}: ${(error as Error).message})`,
        "set WorkloadSecretID on this pod's entry in the Contrast manifest, or add the 'contrast.edgeless.systems/workload-secret-id' annotation to the pod template — without one there is no measurement-released secret for CooL to seal its signing key to",
      );
    }

    const chain = parseCertificates(chainPem);
    const leaf = chain[0];
    if (!leaf) {
      throw new ContrastUnavailableError(
        `${join(root, CONTRAST_FILES.certChain)} contains no leaf certificate`,
        "check that the Contrast initializer completed; its log ends with 'Initializer done'",
      );
    }
    const meshKey = parsePrivateKey(keyPem);
    if (meshKey.curve !== leaf.publicKey.curve) {
      throw new ContrastUnavailableError(
        `the mesh key is ${meshKey.curve} but the certificate's subject key is ${leaf.publicKey.curve}`,
        "the key and certificate are from different pods; check the contrast-secrets volume mount",
      );
    }

    const workloadSecret = fromHex(secretHex.trim());
    if (workloadSecret.length === 0) {
      throw new ContrastUnavailableError(
        `${join(root, CONTRAST_FILES.workloadSecret)} is empty`,
        "set WorkloadSecretID for this pod in the Contrast manifest — without one the Coordinator releases no workload secret and CooL has nothing to seal its key to",
      );
    }

    let manifestBytes: Uint8Array | undefined;
    let manifest: ContrastManifest | null = null;
    const manifestSource =
      options.manifest ??
      (env?.["COOL_CONTRAST_MANIFEST"]
        ? await files.read(env["COOL_CONTRAST_MANIFEST"])
        : undefined);
    if (manifestSource !== undefined) {
      manifestBytes = typeof manifestSource === "string" ? utf8(manifestSource) : manifestSource;
      manifest = parseManifest(manifestBytes);
    }

    const rootCerts = parseCertificates(coordinatorRootPem);
    const identity = identityFromCertificate(leaf, {
      ...(rootCerts[0] ? { coordinatorRootDer: rootCerts[0].der } : {}),
      ...(manifestBytes ? { manifest: manifestBytes } : {}),
    });

    if (identity.tee === "insecure" && options.requireConfidential) {
      throw new ContrastUnavailableError(
        "this Contrast deployment issued a credential with no attestation claims (an 'insecure', non-CC platform)",
        "deploy on a Contrast runtime backed by Intel TDX or AMD SEV-SNP, or drop requireConfidential for development",
      );
    }

    return new ContrastWorkload(
      leaf,
      chainPem,
      meshKey,
      workloadSecret,
      identity,
      manifest,
      coordinatorRootPem,
      options.clock ?? (() => new Date().toISOString()),
    );
  }

  /**
   * What CooL reports as the runtime it is in.
   *
   * The measurement is only populated for TDX, where Contrast's registers are
   * exactly CooL's `Measurement` shape. For SNP there is a single measurement
   * register and no RTMRs, so padding it into that struct would invent four
   * values; the real registers live in `identity.registers` and are what the
   * verifier compares.
   */
  async info(): Promise<EnclaveInfo> {
    const registers = this.identity.registers;
    const zero = `hex:${"0".repeat(96)}` as const;
    const measurement =
      this.identity.tee === "intel-tdx"
        ? {
            mrtd: registers["mrtd"] ?? zero,
            rtmr0: registers["rtmr0"] ?? zero,
            rtmr1: registers["rtmr1"] ?? zero,
            rtmr2: registers["rtmr2"] ?? zero,
            rtmr3: registers["rtmr3"] ?? zero,
          }
        : { mrtd: zero, rtmr0: zero, rtmr1: zero, rtmr2: zero, rtmr3: zero };

    const vendor: TeeVendor =
      this.identity.tee === "intel-tdx"
        ? "intel-tdx"
        : this.identity.tee === "amd-sev-snp"
          ? "amd-sev-snp"
          : "none";

    return {
      // The policy hash is Contrast's stable workload identity across restarts
      // and image upgrades, which is exactly what dstack's app id means.
      appId: this.identity.policy_hash?.slice("hex:".length) ?? "unknown",
      // The certificate serial changes every time the Coordinator issues one,
      // i.e. once per pod -- the closest honest analogue of an instance id.
      instanceId: this.leaf.serial,
      appName: this.identity.workload_name ?? "contrast-workload",
      vendor,
      mode: this.mode,
      measurement,
      tcbStatus:
        this.identity.tee === "insecure"
          ? "Unknown (Contrast insecure platform)"
          : "Verified by the Contrast Coordinator against the manifest",
      eventLog: [],
      imageDigest: this.identity.registers_digest,
      appUrl: null,
    };
  }

  /**
   * Contrast issues no raw vendor quote to the workload.
   *
   * The Coordinator consumed the pod's attestation report during the aTLS
   * handshake and expressed its verdict as the mesh certificate instead. So
   * there is nothing to return here, and returning something anyway — a
   * synthesised quote, a re-labelled certificate — would be the one genuinely
   * dishonest move available in this integration. `null` is the honest answer,
   * and {@link attestWorkload} carries the real evidence.
   */
  async getQuote(_commitment: Multihash): Promise<QuoteEnvelope | null> {
    return null;
  }

  /**
   * Derive a 32-byte seed from the Contrast workload secret.
   *
   * HKDF-SHA256 with the derivation path as `info`, so CooL's record key and log
   * key are independent even though one secret backs both. The secret itself is
   * released by the Coordinator only to a pod whose attestation report matched
   * the manifest, which is what makes the resulting signing key unobtainable
   * outside the attested workload — the same property CooL gets from dstack-KMS,
   * sourced from Contrast's key release instead.
   */
  async deriveKey(path: string): Promise<Uint8Array> {
    return hkdf(sha256, this.workloadSecret, utf8("cool/contrast/kms/v1"), utf8(path), 32);
  }

  /**
   * Sign a commitment to CooL's signing identity with the pod's mesh key, and
   * return it with the certificate chain that names the pod.
   */
  async attestWorkload(keyId: string, entry: KeyDirectory[string]): Promise<WorkloadBinding> {
    const issuedAt = this.clock();
    const statement = bindingStatement(keyId, entry, issuedAt);
    return {
      // The identity goes into the signed core; the attestation into the
      // envelope. They are returned together because only this object can
      // produce them consistently — the identity was read out of the very
      // certificate whose key is making the signature below.
      identity: this.identity,
      attestation: {
        schema: "cool.workload.attestation.v1",
        platform: "contrast",
        cert_chain: this.chainPem,
        key_binding: bindingCommitment(statement),
        bound_key_id: keyId,
        // Signed over exactly the bytes the verifier recomputes — one
        // definition, in identity.ts, used by both halves.
        binding_signature: signBinding(bindingMessage(statement), this.meshKey),
        binding_alg: bindingAlgorithm(this.meshKey.curve),
        issued_at: issuedAt,
      },
    };
  }

  /**
   * The key id CooL stamps into signatures.
   *
   * Derived from the Contrast WORKLOAD identity, not from the image. Two pods
   * built from the same image share an MRTD but get different workload secrets
   * and therefore different keys, so an image-derived id would file two distinct
   * public keys under one name. The policy hash is the right discriminator: it
   * is the manifest entry that authorised the pod, and Contrast keeps both it
   * and the workload secret stable across restarts — so the signing identity
   * survives pod churn without ever being shared between workloads.
   */
  keyId(role: string): string {
    const basis =
      this.identity.policy_hash?.slice("hex:".length) ??
      // An insecure platform has no policy hash in the certificate; fall back to
      // the secret id, which is what the key was actually derived from.
      this.identity.workload_secret_id ??
      this.identity.registers_digest;
    const label = /^[0-9a-f]+$/.test(basis)
      ? basis.slice(0, 12)
      : mhSha256(utf8(basis)).slice("mh:sha256:".length, "mh:sha256:".length + 12);
    return `cool-contrast-${role}-${label}`;
  }

  /** Public keys a verifier needs beyond the receipt. Contrast adds none. */
  directory(): KeyDirectory {
    return {};
  }

  /**
   * The Coordinator root CA this pod was given, PEM.
   *
   * Publish it next to the evidence for convenience, but a verifier should
   * obtain its own copy with `contrast verify` — a root a pod handed you proves
   * nothing, which is why the workload domain will not pass on it.
   */
  get coordinatorRootCA(): string {
    return this.coordinatorRootPem;
  }

  /** Derivation paths this source uses. */
  static readonly KEY_PATH = CONTRAST_KEY_PATH;
}
