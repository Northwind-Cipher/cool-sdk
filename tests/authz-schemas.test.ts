/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/** The authorization schemas in spec/schemas/ describe what the code emits. */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { MemoryNonceStore, ToolGateway, createAuthorizationRequest, decide, enrollPrincipal } from "../src/authz/index";
import { KEYS, REFUND_POLICY, ROOT_DELEGATION, T0, world } from "./support/authz";

type Schema = Record<string, unknown>;
const load = (name: string): Schema => JSON.parse(readFileSync(join(import.meta.dirname, "..", "spec", "schemas", name), "utf8"));
const json = <T>(v: T): T => JSON.parse(JSON.stringify(v));

/** The same small subset validator as platform-schemas.test.ts: required, properties, additionalProperties, const, enum, type, pattern, items. */
function validate(value: unknown, schema: Schema, path = "$"): string[] {
  const errors: string[] = [];
  if ("const" in schema && value !== schema["const"]) errors.push(`${path}: const`);
  if (Array.isArray(schema["enum"]) && !(schema["enum"] as unknown[]).includes(value)) errors.push(`${path}: enum`);
  const t = schema["type"] as string | undefined;
  if (t) {
    const actual = value === null ? "null" : Array.isArray(value) ? "array" : Number.isInteger(value) ? "integer" : typeof value;
    if (actual !== t && !(t === "number" && actual === "integer")) errors.push(`${path}: ${actual} is not ${t}`);
  }
  if (typeof value === "string" && typeof schema["pattern"] === "string" && !new RegExp(schema["pattern"] as string).test(value)) errors.push(`${path}: pattern`);
  if (Array.isArray(value) && schema["items"]) value.forEach((v, i) => errors.push(...validate(v, schema["items"] as Schema, `${path}[${i}]`)));
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const o = value as Record<string, unknown>;
    for (const r of (schema["required"] as string[] | undefined) ?? []) if (!(r in o)) errors.push(`${path}: missing ${r}`);
    const props = (schema["properties"] as Record<string, Schema> | undefined) ?? {};
    for (const [k, v] of Object.entries(o)) {
      if (props[k]) errors.push(...validate(v, props[k]!, `${path}.${k}`));
      else if (schema["additionalProperties"] === false) errors.push(`${path}: unexpected ${k}`);
    }
  }
  return errors;
}

test("schemas: request, decision, delegation, confirmation and principal conform; a broken one does not", async () => {
  const { trust, directory } = world();
  const { request, secrets } = createAuthorizationRequest({ principal: "agent:refund-bot", action: "refund", resource: "order:1", audience: "acme-payments", policy_selector: "refunds", params: { order: "1", amount: 10 }, delegation: "del-root", now: T0 });
  const decision = decide({ request, policy: REFUND_POLICY, facts: { "refund.amount": 10 }, evaluatorKey: KEYS.evaluator, now: T0 });
  const gw = new ToolGateway({ id: "gw", audience: "acme-payments", key: KEYS.gateway, trust, nonces: new MemoryNonceStore(), directory, roots: ["user:asha"], now: () => T0 });
  gw.register("refund", { action: "refund", resource: "order:*", async execute() { return { response: { ok: 1 } }; } });
  const { confirmation } = await gw.invoke({ tool: "refund", request, params: secrets.params, params_salt: secrets.params_salt, decision, delegation: [ROOT_DELEGATION()] });
  const principal = enrollPrincipal({ principal_id: "agent:x", kind: "agent", issuer: KEYS.issuer.keyId, owner: "acme", basis: "issuer_attested", created_at: new Date(T0).toISOString(), keys: [{ key_id: KEYS.agent.keyId, entry: KEYS.agent.directoryEntry }] }, KEYS.issuer);

  assert.deepEqual(validate(json(request), load("cool.authz-request.v1.schema.json")), []);
  assert.deepEqual(validate(json(decision), load("cool.authz-decision.v1.schema.json")), []);
  assert.deepEqual(validate(json(ROOT_DELEGATION()), load("cool.delegation.v1.schema.json")), []);
  assert.deepEqual(validate(json(confirmation), load("cool.external-confirmation.v1.schema.json")), []);
  assert.deepEqual(validate(json(principal), load("cool.principal.v1.schema.json")), []);
  assert.ok(validate({ ...json(request), params: { amount: 10 } }, load("cool.authz-request.v1.schema.json")).some((e) => e.includes("unexpected params")), "plaintext params are not allowed in a request");
});
