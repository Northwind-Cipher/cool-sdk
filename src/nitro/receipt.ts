/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The in-enclave half of the Nitro path: key, attestation, sealed receipts.
 *
 * On start the sealer generates a FRESH hybrid keypair (per enclave instance),
 * asks the Nitro Security Module for an attestation document whose user_data
 * binds that key (ADR 0002) and whose public_key carries its Ed25519 half, and
 * then seals receipts as ordinary `cool.envelope.v1` envelopes carrying
 * `[epoch].[sequence]`. The private key lives in a private field with no
 * accessor; nothing outside the sealer can read it.
 *
 * The sequence number is allocated BEFORE signing and bound into the signed
 * core. Sealing the same event id again returns the same envelope, so a retry
 * after a lost acknowledgement never consumes a new sequence.
 *
 * NSM access is behind `NsmSource`. `CommandNsmSource` delegates to a helper
 * binary that must run INSIDE the enclave and talk to /dev/nsm (for example
 * one built on aws-nitro-enclaves-nsm-api). That helper is not part of this
 * package, and nothing here has run inside a real enclave.
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { generateKeypair } from "../keys";
import type { KeyPair } from "../types";
import { createEnvelope, signEnvelope, type EnvelopeInput, type SignedEnvelope } from "../platform/envelope";
import type { PayloadRegistry } from "../platform/payloads";
import { ed25519Spki, keyBindingUserData } from "./attestation";

/**
 * The part of a log's signed epoch registration the sealer needs. Verifying
 * the registration's signature is the log operator's and the verifier's job;
 * the log server itself is part of the commercial CooL platform.
 */
export interface EpochAssignment {
  readonly registration: { readonly epoch: number; readonly key_id: string };
}

export interface NsmRequest {
  readonly nonce?: Uint8Array;
  readonly user_data: Uint8Array;
  readonly public_key?: Uint8Array;
}

/** Something that can return a Nitro attestation document from inside an enclave. */
export interface NsmSource {
  attest(request: NsmRequest): Promise<Uint8Array>;
}

/**
 * NSM via an external helper: writes `{nonce, user_data, public_key}` (base64)
 * as JSON to the helper's stdin and reads a base64 attestation document from
 * its stdout. Fails loudly if the helper is missing or returns nothing.
 */
export class CommandNsmSource implements NsmSource {
  constructor(readonly command: string, readonly args: readonly string[] = [], readonly timeoutMs = 10_000) {}

  attest(request: NsmRequest): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      const child = spawn(this.command, this.args, { stdio: ["pipe", "pipe", "pipe"], timeout: this.timeoutMs });
      let out = "";
      let err = "";
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (err += d));
      child.on("error", (e) => reject(new Error(`NSM helper ${this.command} failed to start: ${e.message}`)));
      child.on("close", (code) => {
        const doc = Buffer.from(out.trim(), "base64");
        if (code !== 0 || doc.length === 0) reject(new Error(`NSM helper exited ${code}: ${err.trim() || "no document"}`));
        else resolve(new Uint8Array(doc));
      });
      const b64 = (b?: Uint8Array) => (b ? Buffer.from(b).toString("base64") : null);
      child.stdin.end(JSON.stringify({ nonce: b64(request.nonce), user_data: b64(request.user_data), public_key: b64(request.public_key) }));
    });
  }
}

export class NitroReceiptSealer {
  readonly #key: KeyPair;
  readonly #registry: PayloadRegistry;
  readonly #issued = new Map<string, SignedEnvelope>();
  #epoch: number | null = null;
  #next = 0;

  private constructor(key: KeyPair, readonly attestation: Uint8Array, registry: PayloadRegistry) {
    this.#key = key;
    this.#registry = registry;
  }

  /** Generate a fresh key inside the enclave and attest to it. */
  static async start(options: { readonly nsm: NsmSource; readonly registry: PayloadRegistry; readonly nonce?: Uint8Array; readonly keyIdPrefix?: string }): Promise<NitroReceiptSealer> {
    const keyId = `${options.keyIdPrefix ?? "cool-nitro"}-${randomBytes(6).toString("hex")}`;
    const key = generateKeypair(keyId, { seed: new Uint8Array(randomBytes(32)) });
    const document = await options.nsm.attest({
      ...(options.nonce ? { nonce: options.nonce } : {}),
      user_data: keyBindingUserData(keyId, key.directoryEntry),
      public_key: ed25519Spki(key.ed25519Public),
    });
    return new NitroReceiptSealer(key, document, options.registry);
  }

  get keyId(): string {
    return this.#key.keyId;
  }

  get publicEntry(): KeyPair["directoryEntry"] {
    return this.#key.directoryEntry;
  }

  /** Accept the log's epoch assignment for this key. */
  acceptEpoch(signed: EpochAssignment): void {
    if (signed.registration.key_id !== this.#key.keyId) throw new Error("registration is for a different key");
    if (this.#epoch !== null && this.#epoch !== signed.registration.epoch) throw new Error("this key already has an epoch");
    this.#epoch = signed.registration.epoch;
  }

  /** Seal one event. Requires an epoch. Idempotent by event_id. */
  seal(input: EnvelopeInput & { readonly event_id: string }): SignedEnvelope {
    if (this.#epoch === null) throw new Error("no epoch assigned yet: register with the log first");
    const prior = this.#issued.get(input.event_id);
    if (prior) return prior;
    const sequence = { epoch: this.#epoch, number: this.#next++ };
    const attestation = { platform: "aws-nitro" as const, document: this.attestation };
    const core = createEnvelope({ ...input, sequence, attestation }, this.#registry);
    const env = signEnvelope(core, this.#key, attestation);
    this.#issued.set(input.event_id, env);
    return env;
  }
}
