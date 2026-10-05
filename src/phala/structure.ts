/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Structural validation for `cool.receipt.v2`.
 *
 * v1 validates against the JSON Schema published in `cool-spec`. v2's schema is
 * still in flight, so this hand-written validator is the normative shape check
 * until it lands — it is deliberately exhaustive and its messages name the exact
 * field, because "malformed receipt" with no path is useless to whoever has to
 * work out why an auditor's copy will not verify.
 *
 * Shape only. Nothing here says a receipt is authentic; that is what the
 * hash, signature, log and attestation domains in `./verify.ts` are for.
 */
import type { ReceiptV2 } from "./types";

const MULTIHASH = /^mh:sha256:[0-9a-f]{64}$/;
const HEX_FIELD = /^hex:[0-9a-f]+$/;
const B64_FIELD = /^base64:[A-Za-z0-9+/]*={0,2}$/;
const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const OID = /^[0-9]+(\.[0-9]+)+$/;
const PEM_BEGIN = "-----BEGIN CERTIFICATE-----";
const PEM_END = "-----END CERTIFICATE-----";

/**
 * Does this look like a PEM certificate chain at all?
 *
 * Substring checks rather than a regular expression: the obvious pattern
 * (`/-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/`) backtracks
 * polynomially, and this runs on receipt bytes an attacker chose. Real parsing
 * happens in the verifier; all this has to decide is whether the field is
 * shaped like a chain.
 */
function looksLikePemChain(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const begin = value.indexOf(PEM_BEGIN);
  return begin !== -1 && value.indexOf(PEM_END, begin + PEM_BEGIN.length) !== -1;
}

const TEE_VENDORS = ["none", "intel-tdx", "amd-sev-snp", "nvidia-cc"];
const MODES = ["mock", "simulated", "hardware"];
const WORKLOAD_PLATFORMS = ["contrast"];
const WORKLOAD_TEES = ["intel-tdx", "amd-sev-snp", "insecure"];
const CHANGE_KINDS = ["prompt", "model", "params", "policy", "dataset", "agent-permission", "tool"];

type Bag = Record<string, unknown>;

class Checker {
  readonly errors: string[] = [];

  obj(path: string, value: unknown): Bag | null {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      this.errors.push(`${path}: expected an object`);
      return null;
    }
    return value as Bag;
  }

  str(path: string, value: unknown, pattern?: RegExp): boolean {
    if (typeof value !== "string" || value.length === 0) {
      this.errors.push(`${path}: expected a non-empty string`);
      return false;
    }
    if (pattern && !pattern.test(value)) {
      this.errors.push(`${path}: does not match ${pattern.source}`);
      return false;
    }
    return true;
  }

  oneOf(path: string, value: unknown, allowed: readonly string[]): boolean {
    if (typeof value !== "string" || !allowed.includes(value)) {
      this.errors.push(`${path}: expected one of [${allowed.join(", ")}]`);
      return false;
    }
    return true;
  }

  int(path: string, value: unknown, min = 0): boolean {
    if (typeof value !== "number" || !Number.isInteger(value) || value < min) {
      this.errors.push(`${path}: expected an integer ≥ ${min}`);
      return false;
    }
    return true;
  }

  signature(path: string, value: unknown): void {
    const s = this.obj(path, value);
    if (!s) return;
    if (s["alg"] !== "ml-dsa-65+ed25519") this.errors.push(`${path}.alg: expected ml-dsa-65+ed25519`);
    this.str(`${path}.key_id`, s["key_id"]);
    this.str(`${path}.ml_dsa`, s["ml_dsa"], B64_FIELD);
    this.str(`${path}.ed25519`, s["ed25519"], B64_FIELD);
  }

  measurement(path: string, value: unknown): void {
    const m = this.obj(path, value);
    if (!m) return;
    for (const field of ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]) {
      this.str(`${path}.${field}`, m[field], HEX_FIELD);
    }
  }

  runtime(path: string, value: unknown): void {
    const r = this.obj(path, value);
    if (!r) return;
    this.oneOf(`${path}.tee_vendor`, r["tee_vendor"], TEE_VENDORS);
    this.oneOf(`${path}.mode`, r["mode"], MODES);
    if (r["enclave_measurement"] !== null) this.measurement(`${path}.enclave_measurement`, r["enclave_measurement"]);
    if (r["tee_quote"] !== null) this.str(`${path}.tee_quote`, r["tee_quote"], MULTIHASH);
    const gpu = r["gpu"];
    if (gpu !== null) {
      const g = this.obj(`${path}.gpu`, gpu);
      if (g) {
        if (g["vendor"] !== "nvidia-cc") this.errors.push(`${path}.gpu.vendor: expected nvidia-cc`);
        this.str(`${path}.gpu.gpu_model`, g["gpu_model"]);
        this.str(`${path}.gpu.evidence_hash`, g["evidence_hash"], MULTIHASH);
        this.oneOf(`${path}.gpu.verdict`, g["verdict"], ["verified", "unverified", "simulated"]);
      }
    }
    if (r["workload"] !== undefined) this.workloadIdentity(`${path}.workload`, r["workload"]);

    // A record may not claim hardware without carrying something that backs it:
    // either a vendor quote, or an orchestrator-issued workload credential.
    // Contrast is the second case — its Coordinator consumes the workload's
    // quote and issues a certificate instead, so there is no quote digest to
    // require and demanding one would make every Contrast receipt malformed.
    if (r["mode"] === "hardware" && r["tee_quote"] === null && r["workload"] === undefined) {
      this.errors.push(
        `${path}: mode 'hardware' requires either a tee_quote digest or a workload identity`,
      );
    }
  }

  /** `cool.workload.v1` — the orchestrator-issued identity inside the core. */
  workloadIdentity(path: string, value: unknown): void {
    const w = this.obj(path, value);
    if (!w) return;
    if (w["schema"] !== "cool.workload.v1") {
      this.errors.push(`${path}.schema: expected 'cool.workload.v1'`);
    }
    this.oneOf(`${path}.platform`, w["platform"], WORKLOAD_PLATFORMS);
    this.oneOf(`${path}.tee`, w["tee"], WORKLOAD_TEES);
    if (w["policy_hash"] !== null) this.str(`${path}.policy_hash`, w["policy_hash"], HEX_FIELD);
    if (w["workload_secret_id"] !== null) this.str(`${path}.workload_secret_id`, w["workload_secret_id"]);
    if (w["workload_name"] !== null) this.str(`${path}.workload_name`, w["workload_name"]);
    if (!Array.isArray(w["sans"])) this.errors.push(`${path}.sans: expected an array`);
    else w["sans"].forEach((san, i) => this.str(`${path}.sans[${i}]`, san));

    const registers = this.obj(`${path}.registers`, w["registers"]);
    if (registers) {
      for (const name of Object.keys(registers)) {
        this.str(`${path}.registers.${name}`, registers[name], HEX_FIELD);
      }
    }
    this.str(`${path}.registers_digest`, w["registers_digest"], MULTIHASH);
    if (w["coordinator_root"] !== null) {
      this.str(`${path}.coordinator_root`, w["coordinator_root"], MULTIHASH);
    }
    if (w["manifest_digest"] !== null) {
      this.str(`${path}.manifest_digest`, w["manifest_digest"], MULTIHASH);
    }

    // A credential with no attestation claims cannot carry measurements, and a
    // record that says otherwise is internally inconsistent -- which is exactly
    // the shape a "relabel the insecure deployment as TDX" edit would take.
    if (w["tee"] === "insecure" && registers && Object.keys(registers).length > 0) {
      this.errors.push(
        `${path}: tee 'insecure' cannot carry attestation registers (Contrast issues no claims on a non-CC platform)`,
      );
    }
  }
}

/** The outcome of a shape check. `receipt` is only set when `ok` is true. */
export interface ShapeResult {
  readonly ok: boolean;
  readonly errors: readonly string[];
  readonly receipt: ReceiptV2 | null;
}

/** Validate the shape of a `cool.receipt.v2` value. Never throws. */
export function validateReceiptV2Shape(value: unknown): ShapeResult {
  const c = new Checker();
  const root = c.obj("(root)", value);
  if (!root) return { ok: false, errors: c.errors, receipt: null };

  if (root["schema"] !== "cool.receipt.v2") {
    c.errors.push("(root).schema: expected 'cool.receipt.v2'");
  }
  // An anchor is attached after the fact — a head cannot be timestamped before
  // it exists — so it is null on a fresh receipt and an object once submitted.
  if (root["anchor"] !== null && root["anchor"] !== undefined) {
    const anchor = c.obj("anchor", root["anchor"]);
    if (anchor) {
      c.oneOf("anchor.kind", anchor["kind"], ["opentimestamps"]);
      c.oneOf("anchor.chain", anchor["chain"], ["bitcoin"]);
      c.str("anchor.target", anchor["target"], MULTIHASH);
      c.int("anchor.tree_size", anchor["tree_size"], 1);
      c.str("anchor.proof", anchor["proof"], /^[A-Za-z0-9+/]+={0,2}$/);
      c.str("anchor.submitted_at", anchor["submitted_at"]);
      if (!Array.isArray(anchor["calendars"])) c.errors.push("anchor.calendars: expected an array");
      if (!Array.isArray(anchor["heights"])) c.errors.push("anchor.heights: expected an array");
    }
  }
  c.str("(root).binding_hash", root["binding_hash"], MULTIHASH);

  /* record */
  const record = c.obj("record", root["record"]);
  if (record) {
    const schema = record["schema"];
    c.str("record.record_id", record["record_id"], ULID);
    c.signature("record.signature", record["signature"]);
    c.runtime("record.runtime", record["runtime"]);

    const time = c.obj("record.time", record["time"]);
    if (time) {
      c.str("record.time.issued_at", time["issued_at"]);
      c.int("record.time.seq", time["seq"]);
    }

    if (schema === "cool.evidence.v1") {
      const ev = c.obj("record.event", record["event"]);
      if (ev) {
        c.str("record.event.type", ev["type"]);
        c.str("record.event.application_id", ev["application_id"]);
        c.str("record.event.execution_id", ev["execution_id"]);
        c.str("record.event.metadata_hash", ev["metadata_hash"], MULTIHASH);
        c.str("record.event.metadata_salt", ev["metadata_salt"], HEX_FIELD);

        const com = c.obj("record.event.commitments", ev["commitments"]);
        if (com) {
          for (const field of ["input", "output", "state"] as const) {
            const hash = com[field];
            const salt = com[`${field}_salt`];
            if (hash !== null) {
              c.str(`record.event.commitments.${field}`, hash, MULTIHASH);
              c.str(`record.event.commitments.${field}_salt`, salt, HEX_FIELD);
            } else if (salt !== null) {
              c.errors.push(
                `record.event.commitments.${field}_salt: present without a ${field} commitment`,
              );
            }
          }
        }

        if (ev["software"] !== null) {
          const sw = c.obj("record.event.software", ev["software"]);
          if (sw) {
            c.str("record.event.software.name", sw["name"]);
            c.str("record.event.software.version", sw["version"]);
            if (sw["digest"] !== null) {
              c.str("record.event.software.digest", sw["digest"], MULTIHASH);
            }
          }
        }
      }
    } else if (schema === "cool.change.v2") {
      const change = c.obj("record.change", record["change"]);
      if (change) {
        c.oneOf("record.change.kind", change["kind"], CHANGE_KINDS);
        c.str("record.change.ref", change["ref"]);
        c.str("record.change.environment", change["environment"]);
        if (change["before_hash"] !== null) {
          c.str("record.change.before_hash", change["before_hash"], MULTIHASH);
          c.str("record.change.before_salt", change["before_salt"], HEX_FIELD);
        }
        c.str("record.change.after_hash", change["after_hash"], MULTIHASH);
        c.str("record.change.after_salt", change["after_salt"], HEX_FIELD);
        c.str("record.change.diff_hash", change["diff_hash"], MULTIHASH);
        const actor = c.obj("record.change.actor", change["actor"]);
        if (actor) {
          c.str("record.change.actor.id", actor["id"]);
          c.str("record.change.actor.method", actor["method"]);
        }
      }
    } else {
      c.errors.push("record.schema: expected 'cool.evidence.v1' or 'cool.change.v2'");
    }
  }

  /* inclusion + sth travel together or not at all */
  const inclusion = root["inclusion"];
  const sth = root["sth"];
  if ((inclusion === null) !== (sth === null)) {
    c.errors.push("(root): inclusion and sth must both be present or both absent");
  }
  if (inclusion !== null) {
    const inc = c.obj("inclusion", inclusion);
    if (inc) {
      c.int("inclusion.leaf_index", inc["leaf_index"]);
      c.int("inclusion.tree_size", inc["tree_size"], 1);
      if (!Array.isArray(inc["audit_path"])) c.errors.push("inclusion.audit_path: expected an array");
      else inc["audit_path"].forEach((h, i) => c.str(`inclusion.audit_path[${i}]`, h, MULTIHASH));
    }
  }
  if (sth !== null) {
    const s = c.obj("sth", sth);
    if (s) {
      c.str("sth.log_id", s["log_id"]);
      c.int("sth.tree_size", s["tree_size"], 1);
      c.str("sth.root_hash", s["root_hash"], MULTIHASH);
      c.str("sth.timestamp", s["timestamp"]);
      c.signature("sth.signature", s["signature"]);
      if (!Array.isArray(s["witnesses"])) c.errors.push("sth.witnesses: expected an array");
    }
  }

  /* attestation */
  const attestation = c.obj("attestation", root["attestation"]);
  if (attestation) {
    c.oneOf("attestation.mode", attestation["mode"], MODES);
    c.str("attestation.note", attestation["note"]);
    if (attestation["key_binding"] !== null) {
      c.str("attestation.key_binding", attestation["key_binding"], MULTIHASH);
    }
    if (attestation["expected_measurement"] !== null) {
      c.measurement("attestation.expected_measurement", attestation["expected_measurement"]);
    }
    if (attestation["workload"] !== undefined) {
      const w = c.obj("attestation.workload", attestation["workload"]);
      if (w) {
        if (w["schema"] !== "cool.workload.attestation.v1") {
          c.errors.push("attestation.workload.schema: expected 'cool.workload.attestation.v1'");
        }
        c.oneOf("attestation.workload.platform", w["platform"], WORKLOAD_PLATFORMS);
        if (!looksLikePemChain(w["cert_chain"])) {
          c.errors.push(
            "attestation.workload.cert_chain: expected at least one PEM CERTIFICATE block",
          );
        }
        c.str("attestation.workload.key_binding", w["key_binding"], MULTIHASH);
        c.str("attestation.workload.bound_key_id", w["bound_key_id"]);
        c.str("attestation.workload.binding_signature", w["binding_signature"], B64_FIELD);
        c.str("attestation.workload.binding_alg", w["binding_alg"], OID);
        c.str("attestation.workload.issued_at", w["issued_at"]);
      }
    }
    const quote = attestation["quote"];
    if (quote !== null) {
      const q = c.obj("attestation.quote", quote);
      if (q) {
        c.oneOf("attestation.quote.format", q["format"], [
          "dstack.tdx.v4",
          "dstack.sevsnp.v1",
          "nvidia.cc.v1",
          "cool.sim.v1",
        ]);
        c.oneOf("attestation.quote.root", q["root"], [
          "intel-dcap",
          "amd-kds",
          "nvidia-nras",
          "cool-sim-root",
          "none",
        ]);
        if (q["signature"] !== null) c.signature("attestation.quote.signature", q["signature"]);
        if (q["raw"] !== null) c.str("attestation.quote.raw", q["raw"], B64_FIELD);
        const body = c.obj("attestation.quote.body", q["body"]);
        if (body) {
          c.oneOf("attestation.quote.body.vendor", body["vendor"], TEE_VENDORS);
          c.measurement("attestation.quote.body.measurement", body["measurement"]);
          c.str("attestation.quote.body.report_data", body["report_data"], MULTIHASH);
          c.str("attestation.quote.body.tcb_status", body["tcb_status"]);
          c.str("attestation.quote.body.app_id", body["app_id"]);
          c.str("attestation.quote.body.instance_id", body["instance_id"]);
          c.str("attestation.quote.body.issued_at", body["issued_at"]);
        }
      }
    }
  }

  /* key directory */
  const directory = c.obj("key_directory", root["key_directory"]);
  if (directory) {
    const ids = Object.keys(directory);
    if (ids.length === 0) c.errors.push("key_directory: must carry at least one key");
    for (const id of ids) {
      const entry = c.obj(`key_directory.${id}`, directory[id]);
      if (entry) {
        c.str(`key_directory.${id}.ml_dsa_pub`, entry["ml_dsa_pub"], B64_FIELD);
        c.str(`key_directory.${id}.ed25519_pub`, entry["ed25519_pub"], B64_FIELD);
      }
    }
  }

  return c.errors.length === 0
    ? { ok: true, errors: [], receipt: value as ReceiptV2 }
    : { ok: false, errors: c.errors, receipt: null };
}
