/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Typed, versioned payloads for every event family.
 *
 * The envelope is technology-neutral; domain fields live here. Each family has
 * a schema `<event_type>.v<n>` that the envelope names, so a verifier can tell
 * exactly which shape it is reading. Validation is strict: unknown fields,
 * wrong types and missing required fields are rejected, never ignored.
 *
 * Privacy rule enforced for every family: a field whose name says it holds a
 * secret, password, token, private key or credential VALUE must carry a digest
 * commitment (`mh:sha256:…`), never the value. Low-entropy values committed
 * without a secret salt can still be guessed, so the AI payload carries salted
 * commitments only.
 */
import { isMultihash } from "../multihash";

type FieldType = "string" | "digest" | "int" | "bool" | "timestamp" | "strings" | "digests" | `enum:${string}`;
interface FieldSpec {
  readonly type: FieldType;
  readonly required: boolean;
}
export interface PayloadSchema {
  readonly id: string;
  readonly event_type: string;
  readonly fields: Readonly<Record<string, FieldSpec>>;
}

const r = (type: FieldType): FieldSpec => ({ type, required: true });
const o = (type: FieldType): FieldSpec => ({ type, required: false });

const FAMILIES: Record<string, Record<string, FieldSpec>> = {
  // AI remains first-class (spec page 30).
  "ai.inference": { model: r("string"), model_version: r("string"), weights_digest: o("digest"), input_commitment: r("digest"), output_commitment: r("digest"), params_digest: o("digest") },
  // Supply chain.
  "scm.commit": { repository: r("string"), commit: r("string"), tree: o("string"), branch: o("string"), author: r("string"), committer: o("string"), signed: r("bool") },
  "build.started": { build_id: r("string"), builder_id: r("string"), source_repository: r("string"), source_commit: r("string") },
  "build.completed": { build_id: r("string"), builder_id: r("string"), source_repository: r("string"), source_commit: r("string"), result: r("enum:success|failure"), artifact_digests: r("digests") },
  "artifact.created": { artifact_name: r("string"), artifact_digest: r("digest"), build_id: o("string"), size_bytes: o("int") },
  "artifact.published": { artifact_name: r("string"), artifact_digest: r("digest"), registry: r("string"), reference: o("string") },
  "dependency.inventory": { artifact_digest: r("digest"), format: r("enum:spdx|cyclonedx|cool"), sbom_digest: r("digest"), component_count: r("int") },
  "release.approved": { release_id: r("string"), artifact_digest: r("digest"), approver: r("string"), policy_ref: o("string") },
  "release.rejected": { release_id: r("string"), artifact_digest: r("digest"), approver: r("string"), reason: r("string") },
  "deployment.requested": { deployment_id: r("string"), artifact_digest: r("digest"), environment: r("string"), target: r("string") },
  "deployment.completed": { deployment_id: r("string"), artifact_digest: r("digest"), environment: r("string"), target: r("string"), outcome: r("enum:succeeded|failed|rejected"), confirmed: r("bool") },
  // Identity & authority.
  "identity.authenticated": { subject: r("string"), issuer: r("string"), method: r("string"), assurance: o("string") },
  "identity.credential_used": { credential_ref: r("string"), subject: r("string"), issuer: r("string") },
  "authorization.evaluated": { subject: r("string"), permission: r("string"), resource_ref: r("string"), environment: o("string"), decision: r("enum:allow|deny") },
  "authorization.denied": { subject: r("string"), permission: r("string"), resource_ref: r("string"), reason: r("string") },
  "secret.accessed": { secret_ref: r("string"), accessor: r("string"), vault: r("string") },
  "key.used": { key_ref: r("string"), purpose: r("string"), operation: r("string") },
  "certificate.issued": { serial: r("string"), issuer: r("string"), subject: r("string"), fingerprint: r("digest"), not_after: r("timestamp") },
  "certificate.revoked": { serial: r("string"), issuer: r("string"), reason: r("string") },
  "credential.lifecycle": { credential_ref: r("string"), from_state: r("string"), to_state: r("string"), provider: r("string"), confirmed: r("bool") },
  // Change control.
  "configuration.changed": { config_ref: r("string"), before_digest: o("digest"), after_digest: r("digest"), change_id: o("string"), approval_ref: o("string") },
  "configuration.drift_detected": { config_ref: r("string"), expected_digest: r("digest"), observed_digest: r("digest") },
  "rollout.stage": { rollout_id: r("string"), artifact_digest: r("digest"), stage: r("string"), percent: r("int"), health: r("enum:pass|fail|unknown"), action: r("enum:promote|hold|rollback") },
  // Runtime.
  "runtime.process": { workload: r("string"), process: r("string"), executable_digest: o("digest"), pid: o("int") },
  "runtime.network": { workload: r("string"), destination: r("string"), port: r("int"), protocol: r("string") },
  "runtime.privilege_change": { workload: r("string"), from: r("string"), to: r("string") },
  "runtime.heartbeat": { source: r("string"), sequence: r("int") },
  // Incidents.
  "incident.opened": { incident_id: r("string"), title: r("string"), severity: r("enum:low|medium|high|critical") },
  "incident.evidence_added": { incident_id: r("string"), evidence_ref: r("digest"), label: r("enum:verified|source-asserted|inferred|unknown|contradicted|missing") },
  "incident.closed": { incident_id: r("string"), resolution: r("string") },
  // Agent identity, authority and authorization (cool-nwc/authz). Ids, digests and commitments only.
  "principal.enrolled": { principal_id: r("string"), kind: r("enum:agent|human|service|workload"), issuer: r("string"), basis: r("enum:self_asserted|issuer_attested|hardware_bound|federated"), record_digest: r("digest") },
  "principal.key_rotated": { principal_id: r("string"), key_id: r("string"), retired_key_id: o("string"), event_digest: r("digest") },
  "principal.status_changed": { principal_id: r("string"), status: r("enum:active|suspended|revoked|decommissioned"), reason: o("string"), event_digest: r("digest") },
  "delegation.granted": { delegation_id: r("string"), delegator: r("string"), delegate: r("string"), audience: r("string"), expires_at: r("timestamp"), parent: o("string"), delegation_digest: r("digest") },
  "delegation.revoked": { delegation_id: r("string"), revoked_by: r("string"), reason: r("string") },
  "authorization.requested": { request_id: r("string"), request_digest: r("digest"), principal: r("string"), action: r("string"), resource: r("string"), audience: r("string"), policy_selector: r("string"), params_commitment: r("digest"), expires_at: r("timestamp"), delegation: o("string") },
  "authorization.decided": { decision_id: r("string"), decision: r("enum:permit|deny|indeterminate|error"), request_id: r("string"), request_digest: r("digest"), policy_digest: r("digest"), evaluator: r("string"), assurance: r("enum:trusted|reproducible"), decision_digest: r("digest") },
  "policy.updated": { policy_id: r("string"), version: r("string"), policy_digest: r("digest"), previous_digest: o("digest") },
  "execution.started": { workload_id: r("string"), artifact_digest: r("digest"), config_digest: r("digest"), platform: r("string") },
  "tool.invoked": { tool: r("string"), request_id: r("string"), decision_id: o("string") },
  "external.confirmed": { confirmation_id: r("string"), target: r("string"), request_id: r("string"), decision_id: o("string"), outcome: r("enum:completed|rejected|failed|unknown|timed_out"), reason: r("string"), response_digest: o("digest"), confirmation_digest: r("digest") },
  "attestation.recorded": { platform: r("enum:aws-nitro|intel-tdx|amd-sev-snp|nvidia-cc|phala-dstack"), document_digest: r("digest"), outcome: r("enum:verified|invalid|unsupported|stale|incomplete|indeterminate") },
  "receipt.published": { receipt_digest: r("digest"), log_id: r("string"), leaf_index: r("int") },
  "checkpoint.signed": { log_id: r("string"), tree_size: r("int"), root_hash: r("digest") },
  "witness.signed": { witness_id: r("string"), log_id: r("string"), tree_size: r("int"), root_hash: r("digest") },
  // An analyst's note. Never a verified fact; carried so timelines can show it as an annotation.
  "incident.annotated": { incident_id: r("string"), annotation_digest: r("digest"), analyst: r("string") },
  // A cool.receipt.v2 wrapped without changing its semantics (see legacy.ts).
  "legacy.receipt": { legacy_schema: r("enum:cool.receipt.v2"), record_id: r("string"), receipt_digest: r("digest") },
  // Platform's own sensitive events.
  "policy.lifecycle": { policy_id: r("string"), version: r("string"), from_state: r("string"), to_state: r("string"), actor: r("string") },
  "enforcement.requested": { request_id: r("string"), adapter: r("string"), action: r("string"), target: r("string"), dry_run: r("bool"), decision_ref: r("digest") },
  "enforcement.result": { request_id: r("string"), adapter: r("string"), state: r("enum:not_executed|accepted|completed|failed|rejected|timed_out|unknown"), confirmed: r("bool"), external_ref: o("string") },
};

const SENSITIVE_NAME = /(secret|password|passphrase|token|private_?key|credential)(_value)?$/i;

export class PayloadRegistry {
  readonly #schemas = new Map<string, PayloadSchema>();

  static standard(): PayloadRegistry {
    const reg = new PayloadRegistry();
    for (const [type, fields] of Object.entries(FAMILIES)) reg.register({ id: `${type}.v1`, event_type: type, fields });
    return reg;
  }

  register(schema: PayloadSchema): void {
    if (this.#schemas.has(schema.id)) throw new Error(`payload schema ${schema.id} is already registered`);
    this.#schemas.set(schema.id, schema);
  }

  get(id: string): PayloadSchema | undefined {
    return this.#schemas.get(id);
  }

  /** The current schema id for an event type, or undefined. */
  schemaFor(eventType: string): string | undefined {
    const version = (id: string) => Number(/\.v(\d+)$/.exec(id)?.[1] ?? 0);
    let best: string | undefined;
    for (const s of this.#schemas.values()) {
      if (s.event_type === eventType && (!best || version(s.id) > version(best))) best = s.id;
    }
    return best;
  }

  eventTypes(): string[] {
    return [...new Set([...this.#schemas.values()].map((s) => s.event_type))].sort();
  }

  /** Validate a payload. Returns problems; empty means valid. */
  validate(schemaId: string, payload: unknown): string[] {
    const schema = this.#schemas.get(schemaId);
    if (!schema) return [`unknown payload schema ${schemaId}`];
    if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return ["payload must be an object"];
    const problems: string[] = [];
    const data = payload as Record<string, unknown>;
    for (const key of Object.keys(data)) {
      if (!(key in schema.fields)) problems.push(`unexpected field ${key}`);
    }
    for (const [name, spec] of Object.entries(schema.fields)) {
      const v = data[name];
      if (v === undefined || v === null) {
        if (spec.required) problems.push(`missing required field ${name}`);
        continue;
      }
      const bad = typeProblem(spec.type, v);
      if (bad) problems.push(`${name}: ${bad}`);
      if (SENSITIVE_NAME.test(name) && !(typeof v === "string" && isMultihash(v))) {
        problems.push(`${name}: looks like a secret value; commit it as a digest instead`);
      }
    }
    return problems;
  }
}

function typeProblem(type: FieldType, v: unknown): string | null {
  switch (type) {
    case "string": return typeof v === "string" && v.length > 0 ? null : "must be a non-empty string";
    case "digest": return typeof v === "string" && isMultihash(v) ? null : "must be a mh:sha256: digest";
    case "int": return typeof v === "number" && Number.isSafeInteger(v) ? null : "must be an integer";
    case "bool": return typeof v === "boolean" ? null : "must be a boolean";
    case "timestamp": return typeof v === "string" && !Number.isNaN(Date.parse(v)) ? null : "must be an ISO-8601 timestamp";
    case "strings": return Array.isArray(v) && v.every((x) => typeof x === "string") ? null : "must be an array of strings";
    case "digests": return Array.isArray(v) && v.every((x) => typeof x === "string" && isMultihash(x)) ? null : "must be an array of digests";
    default: {
      const allowed = type.slice("enum:".length).split("|");
      return typeof v === "string" && allowed.includes(v) ? null : `must be one of ${allowed.join(", ")}`;
    }
  }
}
