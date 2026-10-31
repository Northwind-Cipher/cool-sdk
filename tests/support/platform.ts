/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/** Shared fixtures for platform tests: deterministic keys, a trust snapshot, a registry. */
import { generateKeypair } from "../../src/keys";
import type { KeyPair } from "../../src/types";
import { PayloadRegistry, TrustStore, type EnvelopeInput, type KeyPurpose, type KeyRecord } from "../../src/platform/index";

export const key = (id: string, fill: number): KeyPair => generateKeypair(id, { seed: new Uint8Array(32).fill(fill) });

export const KEYS = {
  source: key("source-1", 1),
  builder: key("builder-1", 2),
  log: key("log-1", 3),
  witness: key("witness-1", 4),
  rogue: key("rogue-1", 5),
  exporter: key("exporter-1", 6),
  sensor: key("sensor-1", 7),
};

export const T0 = Date.parse("2026-10-31T12:00:00Z");
export const iso = (offsetMs = 0) => new Date(T0 + offsetMs).toISOString();

export function record(k: KeyPair, purposes: KeyPurpose[], extra: Partial<KeyRecord> = {}): KeyRecord {
  return { key_id: k.keyId, entry: k.directoryEntry, purposes, owner: "test", valid_from: "2026-01-01T00:00:00Z", status: "active", ...extra };
}

export function trust(extra: KeyRecord[] = [], options: { maxAgeMs?: number; asOf?: string } = {}): TrustStore {
  return new TrustStore({
    schema: "cool.trust-snapshot.v1",
    id: "test-trust",
    as_of: options.asOf ?? iso(-60_000),
    ...(options.maxAgeMs ? { max_age_ms: options.maxAgeMs } : {}),
    keys: [
      record(KEYS.source, ["evidence"]),
      record(KEYS.builder, ["builder", "evidence"]),
      record(KEYS.log, ["log"]),
      record(KEYS.witness, ["witness"]),
      record(KEYS.exporter, ["evidence"]),
      record(KEYS.sensor, ["evidence"]),
      ...extra,
    ],
  });
}

export const registry = PayloadRegistry.standard();

export const commitInput = (overrides: Partial<EnvelopeInput> = {}): EnvelopeInput => ({
  event_type: "scm.commit",
  occurred_at: iso(-30_000),
  observed_at: iso(-20_000),
  source: { system: "git", instance: "acme/api", event_id: "c0ffee" },
  actor: { id: "user:dev", type: "human" },
  action: "commit",
  resource: { type: "repository", ref: "acme/api" },
  payload: { repository: "acme/api", commit: "c0ffee", author: "dev", signed: true },
  event_id: "evt-commit-1",
  ...overrides,
});
