/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/** A small, deterministic authorization world for tests and the agent demo. */
import { generateKeypair } from "../../src/keys";
import type { KeyPair } from "../../src/types";
import { PrincipalDirectory, enrollPrincipal, grantDelegation, type Delegation, type Signed } from "../../src/authz/index";
import { TrustStore, type PolicyDocument } from "../../src/platform/index";

export const T0 = Date.parse("2026-11-02T09:00:00Z");
export const at = (offsetMs = 0) => new Date(T0 + offsetMs).toISOString();
const k = (id: string, fill: number): KeyPair => generateKeypair(id, { seed: new Uint8Array(32).fill(fill) });

export const KEYS = {
  issuer: k("idp-acme", 21),
  evaluator: k("pdp-acme", 22),
  gateway: k("tool-gateway", 23),
  owner: k("asha-key-1", 24),
  agent: k("refund-bot-key-1", 25),
  agentRotated: k("refund-bot-key-2", 26),
  child: k("refund-helper-key-1", 27),
  rogue: k("rogue-key", 28),
};

export function world(now = T0) {
  const trust = new TrustStore({
    schema: "cool.trust-snapshot.v1", id: "authz-test", as_of: at(-60_000),
    keys: [
      { key_id: KEYS.issuer.keyId, entry: KEYS.issuer.directoryEntry, purposes: ["identity_issuer"], owner: "acme IdP", valid_from: "2026-01-01T00:00:00Z", status: "active" },
      { key_id: KEYS.evaluator.keyId, entry: KEYS.evaluator.directoryEntry, purposes: ["evaluator"], owner: "acme PDP", valid_from: "2026-01-01T00:00:00Z", status: "active" },
      { key_id: KEYS.gateway.keyId, entry: KEYS.gateway.directoryEntry, purposes: ["enforcement"], owner: "acme tool gateway", valid_from: "2026-01-01T00:00:00Z", status: "active" },
    ],
  });
  const directory = new PrincipalDirectory(trust, () => now);
  const enroll = (principal_id: string, kind: "agent" | "human", key: KeyPair, extra: Record<string, unknown> = {}) =>
    directory.enroll(enrollPrincipal({ principal_id, kind, issuer: KEYS.issuer.keyId, owner: "acme", tenant: "acme", basis: "issuer_attested", created_at: at(-86_400_000), keys: [{ key_id: key.keyId, entry: key.directoryEntry }], ...extra }, KEYS.issuer));
  enroll("user:asha", "human", KEYS.owner);
  enroll("agent:refund-bot", "agent", KEYS.agent, { sponsor: "user:asha", workload_id: "refund-bot" });
  enroll("agent:refund-helper", "agent", KEYS.child, { sponsor: "user:asha", parent: "agent:refund-bot" });
  return { trust, directory };
}

export const ROOT_DELEGATION = (overrides: Partial<Delegation> = {}): Signed<Delegation> => grantDelegation({
  delegation_id: "del-root",
  delegator: "user:asha",
  delegate: "agent:refund-bot",
  scope: { actions: ["refund"], resources: ["order:*"], max_amount: 500 },
  audience: "acme-payments",
  not_before: at(-3_600_000),
  expires_at: at(86_400_000),
  nonce: "n-root",
  issued_at: at(-3_600_000),
  ...overrides,
}, KEYS.owner);

export const REFUND_POLICY: PolicyDocument = {
  schema: "cool.policy.v1",
  id: "refunds",
  version: "1",
  mode: "enforce",
  default: "deny",
  on_unknown: "deny",
  rules: [
    { id: "small-refund", when: { all: [{ fact: "request.action", op: "eq", value: "refund" }, { fact: "refund.amount", op: "lte", value: 500 }] }, decision: "allow", reason: "within_refund_limit" },
    { id: "large-refund", when: { fact: "refund.amount", op: "gt", value: 500 }, decision: "deny", reason: "exceeds_refund_limit" },
  ],
};
