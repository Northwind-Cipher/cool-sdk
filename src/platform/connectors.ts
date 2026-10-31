/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Connectors: bringing source-system facts in as envelope inputs.
 *
 * A connector declares its permissions and whether it touches the network,
 * then yields `EnvelopeInput`s. Vendor-specific shapes stop here — everything
 * downstream sees typed payloads. The runner applies bounded retries with
 * backoff, a timeout and cancellation, and reports `complete`, `partial` (some
 * records, then an error), `unavailable` (nothing) or `cancelled` — never an
 * empty success.
 *
 * Shipped connectors are read-only and offline: local git history and local
 * configuration files. SaaS connectors (GitHub, CI systems, registries, cloud
 * audit logs) are NOT included; they need credentials and network access this
 * package does not assume.
 */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { promisify } from "node:util";
import type { Multihash } from "../types";
import type { EnvelopeInput } from "./envelope";

const run = promisify(execFile);

export interface Connector {
  readonly id: string;
  readonly kind: string;
  readonly permissions: readonly string[];
  readonly network: "none" | "outbound";
  collect(context: { readonly signal: AbortSignal }): AsyncIterable<EnvelopeInput>;
}

export interface ConnectorRun {
  readonly connector: string;
  readonly status: "complete" | "partial" | "unavailable" | "cancelled";
  readonly collected: readonly EnvelopeInput[];
  readonly errors: readonly string[];
  readonly attempts: number;
}

export async function runConnector(
  connector: Connector,
  options: { readonly retries?: number; readonly backoffMs?: number; readonly timeoutMs?: number; readonly signal?: AbortSignal } = {},
): Promise<ConnectorRun> {
  const retries = options.retries ?? 2;
  const errors: string[] = [];
  let collected: EnvelopeInput[] = [];
  for (let attempt = 1; attempt <= retries + 1; attempt++) {
    if (options.signal?.aborted) return { connector: connector.id, status: "cancelled", collected, errors, attempts: attempt - 1 };
    const controller = new AbortController();
    const onAbort = () => controller.abort();
    options.signal?.addEventListener("abort", onAbort, { once: true });
    const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 30_000);
    const batch: EnvelopeInput[] = [];
    try {
      for await (const item of connector.collect({ signal: controller.signal })) {
        if (controller.signal.aborted) throw new Error("timed out or cancelled");
        batch.push(item);
      }
      return { connector: connector.id, status: "complete", collected: batch, errors, attempts: attempt };
    } catch (err) {
      errors.push(`attempt ${attempt}: ${(err as Error).message}`);
      if (batch.length > collected.length) collected = batch;
      if (options.signal?.aborted) return { connector: connector.id, status: "cancelled", collected, errors, attempts: attempt };
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
    }
    if (attempt <= retries) await new Promise((r) => setTimeout(r, (options.backoffMs ?? 200) * 2 ** (attempt - 1)));
  }
  return { connector: connector.id, status: collected.length ? "partial" : "unavailable", collected, errors, attempts: retries + 1 };
}

/**
 * Local git history → `scm.commit` inputs. Read-only; runs `git log` in the
 * repository. Records the author NAME only (not the e-mail address) to keep
 * personal data out of evidence by default.
 */
export class GitConnector implements Connector {
  readonly kind = "scm.git-local";
  readonly network = "none" as const;
  readonly permissions: readonly string[];
  readonly id: string;

  constructor(readonly repoPath: string, readonly options: { readonly repository: string; readonly ref?: string; readonly limit?: number }) {
    this.id = `git:${options.repository}`;
    this.permissions = [`read ${repoPath} (git log)`];
  }

  async *collect(context: { readonly signal: AbortSignal }): AsyncIterable<EnvelopeInput> {
    const ref = this.options.ref ?? "HEAD";
    const { stdout } = await run("git", ["-C", this.repoPath, "log", ref, `-n${this.options.limit ?? 50}`, "--format=%H%x1f%T%x1f%an%x1f%cn%x1f%cI%x1f%G?%x1e"], { signal: context.signal, maxBuffer: 16 * 1024 * 1024 });
    for (const record of stdout.split("\x1e")) {
      const parts = record.trim().split("\x1f");
      if (parts.length < 6) continue;
      const [commit, tree, author, committer, time, sig] = parts as [string, string, string, string, string, string];
      yield {
        event_type: "scm.commit",
        occurred_at: time,
        source: { system: "git", instance: this.options.repository, event_id: commit },
        actor: { id: `git-author:${author}`, type: "human" },
        action: "commit",
        resource: { type: "repository", ref: this.options.repository },
        provenance: { collection_method: "imported" },
        payload: { repository: this.options.repository, commit, tree, author, committer, signed: sig !== "N", ...(this.options.ref && this.options.ref !== "HEAD" ? { branch: this.options.ref } : {}) },
      };
    }
  }
}

export const fileDigest = (path: string): Multihash => `mh:sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;

/**
 * Local configuration files → `configuration.drift_detected` against an
 * approved baseline of digests. Read-only. The file contents never enter
 * evidence; only their digests do.
 */
export class FileConfigConnector implements Connector {
  readonly kind = "config.file-local";
  readonly network = "none" as const;
  readonly id = "config:files";
  readonly permissions: readonly string[];

  constructor(readonly baseline: Readonly<Record<string, Multihash>>, readonly clock: () => Date = () => new Date()) {
    this.permissions = Object.keys(baseline).map((p) => `read ${p}`);
  }

  async *collect(): AsyncIterable<EnvelopeInput> {
    for (const [path, expected] of Object.entries(this.baseline)) {
      const observed = fileDigest(path);
      if (observed === expected) continue;
      yield {
        event_type: "configuration.drift_detected",
        occurred_at: this.clock().toISOString(),
        source: { system: "file-config", instance: path },
        actor: { id: "cool:file-config-connector", type: "service" },
        action: "detect_drift",
        resource: { type: "configuration", ref: path },
        provenance: { collection_method: "observed" },
        payload: { config_ref: path, expected_digest: expected, observed_digest: observed },
      };
    }
  }
}
