/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Execution binding: the workload a request was authorised FOR, versus the
 * workload actually about to run it.
 *
 * The planned context travels inside the signed request; the observed context
 * comes from the runtime (attestation, deployment metadata, the process). Any
 * difference in artifact, configuration, workload, platform or measurement is
 * a mismatch — a substituted workload cannot borrow another's authorization.
 *
 * Hardware attestation, where present, supports the observed measurement under
 * its own verifier policy; it does not prove what the application does.
 */
import type { Multihash } from "../types";
import { check, type Check } from "../platform/status";

export interface ExecutionContext {
  readonly workload_id: string;
  readonly artifact_digest: Multihash;
  readonly config_digest: Multihash;
  readonly platform: string;
  readonly measurement?: string;
  readonly environment?: string;
}

const FIELDS = ["workload_id", "artifact_digest", "config_digest", "platform", "measurement", "environment"] as const;

export function compareExecution(planned: ExecutionContext | undefined, observed: ExecutionContext | undefined): Check {
  if (!planned) return check("not_applicable", "no_planned_execution", "the request did not bind an execution context");
  if (!observed) return check("unknown", "no_observed_execution", "the enforcement boundary could not observe the executing workload");
  const differ = FIELDS.filter((f) => (planned[f] ?? null) !== (observed[f] ?? null));
  return differ.length
    ? check("fail", "execution_mismatch", `observed workload differs in ${differ.join(", ")}`)
    : check("pass", "execution_bound", `${observed.workload_id} ${observed.artifact_digest.slice(0, 22)}… matches the authorised execution`);
}
