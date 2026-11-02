/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The published JSON Schemas (spec/schemas/) describe what the code actually
 * emits. A small validator for the subset the schemas use keeps this free of
 * new dependencies; a real envelope, report, policy, bundle and trust snapshot
 * must each conform, and a broken one must not.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { TransparencyLog, exportBundle, verifyEnvelope } from "../src/platform/index";
import { createEnvelope, signEnvelope } from "../src/platform/envelope";
import { KEYS, T0, commitInput, registry, trust } from "./support/platform";

type Schema = Record<string, unknown>;
const load = (name: string): Schema => JSON.parse(readFileSync(join(import.meta.dirname, "..", "spec", "schemas", name), "utf8"));

function validate(value: unknown, schema: Schema, root: Schema = schema, path = "$"): string[] {
  if (typeof schema["$ref"] === "string") {
    const name = (schema["$ref"] as string).replace("#/$defs/", "");
    return validate(value, (root["$defs"] as Record<string, Schema>)[name]!, root, path);
  }
  const errors: string[] = [];
  if ("const" in schema && value !== schema["const"]) errors.push(`${path}: expected ${JSON.stringify(schema["const"])}`);
  if (Array.isArray(schema["enum"]) && !(schema["enum"] as unknown[]).includes(value)) errors.push(`${path}: not in enum`);
  if (Array.isArray(schema["oneOf"])) {
    const ok = (schema["oneOf"] as Schema[]).filter((s) => validate(value, s, root, path).length === 0).length;
    if (ok !== 1) errors.push(`${path}: matches ${ok} of oneOf`);
  }
  const t = schema["type"];
  if (t) {
    const types = Array.isArray(t) ? (t as string[]) : [t as string];
    const actual = value === null ? "null" : Array.isArray(value) ? "array" : Number.isInteger(value) ? "integer" : typeof value;
    if (!types.includes(actual) && !(actual === "integer" && types.includes("number"))) errors.push(`${path}: ${actual} is not ${types.join("|")}`);
  }
  if (typeof value === "string" && typeof schema["pattern"] === "string" && !new RegExp(schema["pattern"] as string).test(value)) errors.push(`${path}: pattern`);
  if (Array.isArray(value)) {
    if (typeof schema["minItems"] === "number" && value.length < (schema["minItems"] as number)) errors.push(`${path}: too few items`);
    if (schema["items"]) value.forEach((v, i) => errors.push(...validate(v, schema["items"] as Schema, root, `${path}[${i}]`)));
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    for (const r of (schema["required"] as string[] | undefined) ?? []) if (!(r in obj)) errors.push(`${path}: missing ${r}`);
    const props = (schema["properties"] as Record<string, Schema> | undefined) ?? {};
    for (const [k, v] of Object.entries(obj)) {
      if (props[k]) errors.push(...validate(v, props[k]!, root, `${path}.${k}`));
      else if (schema["additionalProperties"] === false) errors.push(`${path}: unexpected ${k}`);
      else if (schema["additionalProperties"] && typeof schema["additionalProperties"] === "object") errors.push(...validate(v, schema["additionalProperties"] as Schema, root, `${path}.${k}`));
    }
  }
  return errors;
}

const json = <T>(v: T): T => JSON.parse(JSON.stringify(v));

test("schemas: a published envelope and its verification report conform", () => {
  const log = new TransparencyLog("l", KEYS.log, () => new Date(T0));
  const env = json(log.publish(signEnvelope(createEnvelope(commitInput(), registry), KEYS.source)));
  assert.deepEqual(validate(env, load("cool.envelope.v1.schema.json")), []);
  const report = json(verifyEnvelope(env, { registry, trust: trust(), now: T0 }));
  assert.deepEqual(validate(report, load("cool.verification-report.v1.schema.json")), []);
});

test("schemas: a bundle and a trust snapshot conform", () => {
  const env = signEnvelope(createEnvelope(commitInput(), registry), KEYS.source);
  const bundle = json(exportBundle({ title: "t", envelopes: [env], trust: trust(), exporter: KEYS.exporter, now: new Date(T0) }));
  assert.deepEqual(validate(bundle, load("cool.bundle.v1.schema.json")), []);
  assert.deepEqual(validate(json(trust().snapshot()), load("cool.trust-snapshot.v1.schema.json")), []);
});

test("schemas: the validator really rejects non-conforming documents", () => {
  const env = json(signEnvelope(createEnvelope(commitInput(), registry), KEYS.source)) as unknown as Record<string, unknown>;
  const errs = validate({ ...env, digest: "sha256:nope", surprise: 1 }, load("cool.envelope.v1.schema.json"));
  assert.ok(errs.some((e) => e.includes("pattern")));
  assert.ok(errs.some((e) => e.includes("unexpected surprise")));
});
