/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * CooL × Contrast: conformance, binding, and the substitutions that must fail.
 *
 * Every certificate these tests read was issued by Contrast's OWN code. The
 * fixtures in `tests/fixtures/contrast-fixtures.json` are produced by a Go program
 * (`tools/contrast-fixture/main.go`, run inside a Contrast checkout) that calls
 * `internal/seedengine`, `internal/ca.NewAttestedMeshCert`,
 * `internal/attestation/tdx.Report.ClaimsToCertExtension` and
 * `internal/oid` — the same functions the Coordinator calls in
 * `coordinator/internal/meshapi.NewMeshCert`. So when a test here asserts that
 * CooL recovered an MRTD or a policy hash, it is asserting cross-implementation
 * agreement between Contrast's Go encoder and CooL's TypeScript decoder, not
 * agreement with a fixture CooL wrote for itself.
 *
 * What is NOT real, stated plainly because it bounds every claim below: no
 * confidential hardware was involved. The TDX quote whose claims the fixture
 * certificates carry was constructed in-process. These tests therefore prove
 * that CooL binds to, parses and enforces Contrast's credential format
 * correctly — not that Intel attested anything. The parts that need real
 * silicon are listed in `docs/contrast.md`.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { CooL } from "../src/index";
import { verifyEvidence } from "../src/verify";
import type { Evidence } from "../src/client";
import {
  ContrastUnavailableError,
  ContrastWorkload,
  identityFromCertificate,
  parseCertificates,
  parseManifest,
  teeOfCertificate,
  verifyChain,
  workloadPolicyHashes,
} from "../src/contrast/index";

// `import.meta.dirname` would be shorter but needs Node >= 20.11, and the
// package supports Node >= 20.
import {
  cleanupContrastPods,
  contrastPod,
  coordinatorRootCA,
  fixtures,
  manifestBytes,
  missingPod,
} from "./support/contrast-pod";

const meta = { policy_hashes: fixtures.policyHashes, measurements: fixtures.measurements };

const genuineRoot = coordinatorRootCA("genuine");
const rogueRoot = coordinatorRootCA("rogue");

/** The pod directory for a fixture workload, materialised on first use. */
const pods = new Map<string, string>();
const pod = (name: string): string => {
  let path = pods.get(name);
  if (path === undefined) {
    path = contrastPod(name);
    pods.set(name, path);
  }
  return path;
};
const chainOf = (name: string): string =>
  readFileSync(join(pod(name), "tls-config", "certChain.pem"), "utf8");

after(cleanupContrastPods);

/** A recursively-mutable view — tests must corrupt fields the type marks readonly. */
type DeepMutable<T> = T extends object ? { -readonly [K in keyof T]: DeepMutable<T[K]> } : T;
const clone = (e: Evidence): DeepMutable<Evidence> =>
  JSON.parse(JSON.stringify(e)) as DeepMutable<Evidence>;

/** Seal one receipt inside a (fixture-backed) Contrast workload. */
async function sealedIn(
  workloadDir: string,
  options: { manifest?: Uint8Array } = {},
): Promise<Evidence> {
  const runtime = await ContrastWorkload.open({
    root: pod(workloadDir),
    ...(options.manifest === undefined ? {} : { manifest: options.manifest }),
  });
  const cool = new CooL({ applicationId: "refund-agent", runtime });
  const { evidence } = await cool.record({
    type: "model.execution",
    metadata: { model: "refund-classifier@3", temperature: 0.2 },
    payloads: { input: "customer asked for a refund", output: "approved" },
  });
  await cool.close();
  return evidence;
}

/** The verifier options an auditor would use: pinned root and pinned manifest. */
const audit = {
  coordinatorRootCA: genuineRoot,
  expectedManifest: manifestBytes,
} as const;

/* ══ conformance: does CooL read what Contrast wrote? ═════════════════ */

test("conformance: CooL recovers Contrast's own TDX claims from a mesh certificate", () => {
  const [leaf] = parseCertificates(chainOf("ai-service"));
  assert.ok(leaf);
  assert.equal(teeOfCertificate(leaf), "intel-tdx");
  assert.equal(leaf.publicKey.curve, "P-256", "the pod key the initializer generates");

  const identity = identityFromCertificate(leaf);
  // These values were encoded by Contrast's Go, decoded by CooL's TypeScript.
  assert.equal(identity.registers["mrtd"], `hex:${meta.measurements["approved_mrtd"]}`);
  assert.equal(identity.registers["rtmr0"], `hex:${meta.measurements["rtmr0"]}`);
  assert.equal(identity.registers["rtmr3"], `hex:${meta.measurements["rtmr3_ai"]}`);
  assert.equal(identity.registers["mrseam"], `hex:${meta.measurements["mrseam"]}`);
  // HostData is MRCONFIGID[:32] for TDX — the manifest's Policies key.
  assert.equal(identity.policy_hash, `hex:${meta.policy_hashes["ai-service"]}`);
  assert.equal(identity.workload_secret_id, "default/ai-service");
  assert.equal(identity.workload_name, "ai-service");
  assert.deepEqual([...identity.sans], ["ai-service", "10.42.0.11"]);
});

test("conformance: the chain verifies to the Coordinator root and nothing else", () => {
  const chain = parseCertificates(chainOf("ai-service"));
  assert.equal(chain.length, 2, "leaf ‖ intermediate, as the Coordinator sends it");
  assert.equal(chain[1]!.publicKey.curve, "P-384", "Contrast's CA keys are P-384");

  assert.equal(verifyChain(chain, parseCertificates(genuineRoot)).ok, true);
  assert.equal(verifyChain(chain, parseCertificates(rogueRoot)).ok, false);
  // An unpinned chain is self-consistent and still not trusted.
  assert.equal(verifyChain(chain, []).ok, false);
});

test("conformance: the policy hash in the certificate is a key of the manifest", () => {
  const manifest = parseManifest(manifestBytes);
  const [leaf] = parseCertificates(chainOf("ai-service"));
  const identity = identityFromCertificate(leaf!);
  const hashes = workloadPolicyHashes(manifest);
  assert.ok(hashes.includes(identity.policy_hash!.slice("hex:".length)));
  assert.equal(manifest.platforms.includes("tdx"), true);
});

test("conformance: an insecure Contrast platform carries no claims and says so", () => {
  const [leaf] = parseCertificates(chainOf("insecure-service"));
  assert.equal(teeOfCertificate(leaf!), "insecure");
  const identity = identityFromCertificate(leaf!);
  assert.deepEqual(identity.registers, {});
  assert.equal(identity.policy_hash, null);
});

/* ══ the happy path ══════════════════════════════════════════════════ */

test("CooL inside Contrast: a receipt verifies against a pinned Coordinator root", async () => {
  const evidence = await sealedIn("ai-service", { manifest: manifestBytes });
  const verdict = await verifyEvidence(evidence, audit);

  assert.equal(verdict.ok, true, verdict.reasons.join("; "));
  assert.equal(verdict.checks.workload.status, "pass", verdict.checks.workload.detail);
  assert.equal(verdict.checks.binding.status, "pass");
  assert.equal(verdict.checks.signature.status, "pass");
  assert.equal(verdict.checks.inclusion.status, "pass");
  // Contrast issues no vendor quote, so the quote-shaped domains are absent
  // rather than passing. Saying "pass" here would be the dishonest answer.
  assert.equal(verdict.checks.attestation.status, "mock");
  assert.equal(verdict.checks.enclave.status, "absent");
  assert.match(verdict.checks.workload.detail, /Contrast workload 'ai-service'/);
});

test("the sealed identity is inside the signature, not beside it", async () => {
  const evidence = await sealedIn("ai-service", { manifest: manifestBytes });
  const sealed = evidence.record.runtime.workload;
  assert.ok(sealed, "the record core carries the workload identity");
  assert.equal(sealed.platform, "contrast");
  assert.equal(sealed.tee, "intel-tdx");
  assert.equal(sealed.policy_hash, `hex:${meta.policy_hashes["ai-service"]}`);
  assert.equal(sealed.manifest_digest, parseManifest(manifestBytes).digest);
  assert.ok(evidence.attestation.workload, "the envelope carries the credential");
  assert.equal(evidence.attestation.workload.bound_key_id, evidence.record.signature.key_id);
});

test("requireHardware is satisfied by a pinned Contrast credential, not by an unpinned one", async () => {
  const evidence = await sealedIn("ai-service", { manifest: manifestBytes });

  const pinned = await verifyEvidence(evidence, { ...audit, requireHardware: true });
  assert.equal(pinned.ok, true, pinned.reasons.join("; "));

  // Same receipt, no pinned root: the credential is reported, never passed, and
  // a hardware requirement is therefore not met.
  const unpinned = await verifyEvidence(evidence, { requireHardware: true });
  assert.equal(unpinned.ok, false);
  assert.equal(unpinned.checks.workload.status, "absent");
  assert.match(unpinned.checks.workload.detail, /REPORTED, not verified/);
  assert.ok(unpinned.reasons.some((r) => /pinned Coordinator root/.test(r)));
});

test("an insecure Contrast deployment can never report as confidential", async () => {
  await assert.rejects(
    () => ContrastWorkload.open({ root: pod("insecure-service"), requireConfidential: true }),
    ContrastUnavailableError,
  );

  const evidence = await sealedIn("insecure-service");
  const verdict = await verifyEvidence(evidence, { coordinatorRootCA: genuineRoot });
  assert.equal(verdict.checks.workload.status, "simulated");
  assert.match(verdict.checks.workload.detail, /INSECURE \(non-CC\) platform/);

  const strict = await verifyEvidence(evidence, {
    coordinatorRootCA: genuineRoot,
    requireHardware: true,
  });
  assert.equal(strict.ok, false);
});

/* ══ substitution: the attacks the binding exists to stop ════════════ */

test("a receipt from one workload cannot be presented as another's", async () => {
  const evidence = await sealedIn("ai-service", { manifest: manifestBytes });

  // Swap in a genuine, currently-valid credential belonging to a different pod.
  const forged = clone(evidence);
  forged.attestation.workload!.cert_chain = chainOf("sidecar-service");

  const verdict = await verifyEvidence(forged as unknown, audit);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.checks.workload.status, "fail");
  // The binding signature is checked before the identity, so that is what trips.
  assert.match(verdict.checks.workload.detail, /attests a DIFFERENT key/);
});

test("rewriting the sealed identity to match a swapped credential breaks the signature", async () => {
  const mine = await sealedIn("ai-service", { manifest: manifestBytes });
  const theirs = await sealedIn("sidecar-service", { manifest: manifestBytes });

  // The complete substitution: take the other pod's credential AND its sealed
  // identity, and staple both onto my record. Both halves now agree with each
  // other — and the record signature, which covers the core, does not.
  const forged = clone(mine);
  forged.attestation.workload = clone(theirs).attestation.workload;
  forged.record.runtime.workload = clone(theirs).record.runtime.workload;

  const verdict = await verifyEvidence(forged as unknown, audit);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.checks.signature.status, "fail");
  assert.equal(verdict.checks.binding.status, "fail");
});

test("a credential from a Coordinator nobody approved is rejected", async () => {
  const runtime = await ContrastWorkload.open({ root: pod("ai-service-rogue-coordinator") });
  const cool = new CooL({ applicationId: "refund-agent", runtime });
  const { evidence } = await cool.record({ type: "model.execution", metadata: {} });
  await cool.close();

  // The receipt is internally perfect: real signatures, real chain, real
  // binding. It just chains to a CA the auditor never attested.
  const self = await verifyEvidence(evidence, { coordinatorRootCA: runtime.coordinatorRootCA });
  assert.equal(self.checks.workload.status, "pass", "coherent against its own root");

  const verdict = await verifyEvidence(evidence, { coordinatorRootCA: genuineRoot });
  assert.equal(verdict.ok, false);
  assert.equal(verdict.checks.workload.status, "fail");
  assert.match(verdict.checks.workload.detail, /wrong deployment|no issuer/);
});

test("stripping either half of the binding fails; a half-binding is not a weaker binding", async () => {
  const evidence = await sealedIn("ai-service", { manifest: manifestBytes });

  const noCredential = clone(evidence);
  delete noCredential.attestation.workload;
  const a = await verifyEvidence(noCredential as unknown, audit);
  assert.equal(a.ok, false);
  assert.match(a.checks.workload.detail, /no credential to check it against/);

  const noIdentity = clone(evidence);
  delete noIdentity.record.runtime.workload;
  const b = await verifyEvidence(noIdentity as unknown, audit);
  assert.equal(b.ok, false);
  // Removing a signed field also breaks the signature, which is the point.
  assert.equal(b.checks.signature.status, "fail");
});

test("a single flipped byte in the credential is caught", async () => {
  const evidence = await sealedIn("ai-service", { manifest: manifestBytes });
  const forged = clone(evidence);
  const chain = forged.attestation.workload!.cert_chain;
  const lines = chain.split("\n");
  const target = lines.findIndex((l) => l.length > 60 && !l.includes("-----"));
  // Deterministic single-character mutation inside the base64 body.
  lines[target] = `${lines[target]!.slice(0, 10)}${lines[target]![10] === "A" ? "B" : "A"}${lines[target]!.slice(11)}`;
  forged.attestation.workload!.cert_chain = lines.join("\n");

  const verdict = await verifyEvidence(forged as unknown, audit);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.checks.workload.status, "fail");
});

test("a forged binding signature does not verify", async () => {
  const evidence = await sealedIn("ai-service", { manifest: manifestBytes });
  const forged = clone(evidence);
  const sig = forged.attestation.workload!.binding_signature;
  const body = sig.slice("base64:".length);
  forged.attestation.workload!.binding_signature =
    `base64:${body.slice(0, 20)}${body[20] === "A" ? "B" : "A"}${body.slice(21)}` as typeof sig;

  const verdict = await verifyEvidence(forged as unknown, audit);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.checks.workload.status, "fail");
});

test("re-dating a binding breaks it, because the date is inside the signed statement", async () => {
  const evidence = await sealedIn("ai-service", { manifest: manifestBytes });
  const forged = clone(evidence);
  forged.attestation.workload!.issued_at = "2019-01-01T00:00:00.000Z";

  const verdict = await verifyEvidence(forged as unknown, audit);
  assert.equal(verdict.ok, false);
  assert.match(verdict.checks.workload.detail, /does not commit to the key/);
});

/* ══ pinning: manifest, policy, measurements ═════════════════════════ */

test("a workload the manifest does not authorise is rejected", async () => {
  // `upgraded-ai-service` keeps its policy hash but runs a different image;
  // `no-secret-service` has a policy hash that is not in the manifest at all.
  const evidence = await sealedIn("ai-service", { manifest: manifestBytes });
  const verdict = await verifyEvidence(evidence, {
    coordinatorRootCA: genuineRoot,
    allowedPolicyHashes: [meta.policy_hashes["sidecar-service"]!],
  });
  assert.equal(verdict.ok, false);
  assert.equal(verdict.checks.workload.status, "fail");
  assert.match(verdict.checks.workload.detail, /not in the allowed set/);
});

test("a pinned manifest catches a receipt produced under a different one", async () => {
  const evidence = await sealedIn("ai-service", { manifest: manifestBytes });
  const other = new TextEncoder().encode(
    JSON.stringify({ Policies: {}, ReferenceValues: { tdx: [] } }),
  );
  const verdict = await verifyEvidence(evidence, {
    coordinatorRootCA: genuineRoot,
    expectedManifest: other,
  });
  assert.equal(verdict.ok, false);
  assert.match(verdict.checks.workload.detail, /produced under a different manifest/);
});

test("a rebuilt image fails a register pin — redeployment is visible, not silent", async () => {
  const approved = { mrtd: meta.measurements["approved_mrtd"]! };

  const before = await sealedIn("ai-service", { manifest: manifestBytes });
  const ok = await verifyEvidence(before, { ...audit, expectedRegisters: approved });
  assert.equal(ok.ok, true, ok.reasons.join("; "));

  // Same policy hash, same manifest entry, new image.
  const after = await sealedIn("upgraded-ai-service", { manifest: manifestBytes });
  const drift = await verifyEvidence(after, { ...audit, expectedRegisters: approved });
  assert.equal(drift.ok, false);
  assert.match(drift.checks.workload.detail, /differs from the approved one in mrtd/);

  // And the old receipt keeps verifying, which is what an auditor needs: the
  // upgrade does not retroactively invalidate history.
  const stillOk = await verifyEvidence(before, { ...audit, expectedRegisters: approved });
  assert.equal(stillOk.ok, true);
});

/* ══ lifecycle: restart, upgrade, sealing ════════════════════════════ */

test("the signing key is sealed to the Contrast workload secret, not to the pod", async () => {
  const first = await sealedIn("ai-service", { manifest: manifestBytes });
  const restarted = await sealedIn("restarted-ai-service", { manifest: manifestBytes });
  const other = await sealedIn("sidecar-service", { manifest: manifestBytes });

  // A restart gets a fresh certificate from the Coordinator but the SAME
  // workload secret (Contrast derives it from the manifest's WorkloadSecretID),
  // so CooL's signing identity survives the restart. That is what makes a
  // continuous audit trail possible across pod churn.
  assert.equal(
    restarted.record.signature.key_id,
    first.record.signature.key_id,
    "same workload secret id → same sealed key",
  );
  assert.notEqual(
    restarted.attestation.workload!.cert_chain,
    first.attestation.workload!.cert_chain,
    "but a different certificate",
  );

  // A different workload gets a different workload secret and therefore a
  // different key -- and, because the key id is derived from the Contrast
  // policy hash rather than the image, a different key ID too. Both pods are
  // built from the same image, so an image-derived id would have collided.
  assert.notEqual(other.record.signature.key_id, first.record.signature.key_id);
  assert.match(first.record.signature.key_id, /^cool-contrast-enclave-/);

  for (const receipt of [first, restarted, other]) {
    const verdict = await verifyEvidence(receipt, audit);
    assert.equal(verdict.ok, true, verdict.reasons.join("; "));
  }
});

test("a pod with no WorkloadSecretID fails loudly, with the fix in the message", async () => {
  await assert.rejects(
    () => ContrastWorkload.open({ root: pod("no-secret-service") }),
    (error: unknown) => {
      assert.ok(error instanceof ContrastUnavailableError);
      assert.match(error.action, /WorkloadSecretID/);
      return true;
    },
  );
});

test("pointing CooL at a directory that is not a Contrast pod says exactly that", async () => {
  await assert.rejects(
    () => ContrastWorkload.open({ root: missingPod() }),
    (error: unknown) => {
      assert.ok(error instanceof ContrastUnavailableError);
      assert.match(error.message, /certificate chain/);
      assert.match(error.action, /COOL_CONTRAST_ROOT/);
      return true;
    },
  );
});

/* ══ the AI-governance payload: changes, inside a confidential workload ══ */

test("four kinds of AI change are sealed, bound to the workload, and verify", async () => {
  const runtime = await ContrastWorkload.open({
    root: pod("ai-service"),
    manifest: manifestBytes,
  });
  const { CoolTee } = await import("../src/phala/client");
  const cool = await CoolTee.connect({
    runtime,
    app: { name: "refund-agent", imageDigest: "unused-under-contrast" },
    policy: { coordinatorRootCA: runtime.coordinatorRootCA, allowSimulated: false },
  });

  assert.equal(cool.handshake.ok, true, cool.handshake.reasons.join("; "));
  assert.equal(cool.handshake.quote, null, "Contrast issues no quote to the workload");
  assert.ok(cool.handshake.workload, "it issues a credential instead");

  const receipts = [
    await cool.change({
      kind: "model",
      ref: "billing/refund-agent#model",
      before: "refund-classifier@2",
      after: "refund-classifier@3",
      actor: { id: "ci:github-actions", method: "oidc" },
    }),
    await cool.change({
      kind: "prompt",
      ref: "billing/refund-agent#system",
      before: "Refund when the policy allows.",
      after: "Refund when the policy allows. Escalate above $500.",
      actor: { id: "user:priya@bank.example", method: "session" },
    }),
    await cool.change({
      kind: "agent-permission",
      ref: "billing/refund-agent#tools",
      before: "read:orders",
      after: "read:orders,write:refunds",
      actor: { id: "user:priya@bank.example", method: "session" },
    }),
    await cool.change({
      kind: "params",
      ref: "billing/refund-agent#temperature",
      before: "0.2",
      after: "0.7",
      actor: { id: "ci:github-actions", method: "oidc" },
    }),
  ];
  await cool.close();

  for (const receipt of receipts) {
    const verdict = await verifyEvidence(receipt, audit);
    assert.equal(verdict.ok, true, verdict.reasons.join("; "));
    assert.equal(verdict.checks.workload.status, "pass");
    assert.equal(verdict.subject?.kind, "change");
    assert.equal(receipt.record.runtime.workload?.workload_name, "ai-service");
  }

  // One transparency log across all four, so order and completeness are provable.
  assert.deepEqual(
    receipts.map((r) => r.inclusion?.leaf_index),
    [0, 1, 2, 3],
  );
});

test("tampering with the change itself fails, inside Contrast as anywhere else", async () => {
  const runtime = await ContrastWorkload.open({ root: pod("ai-service"), manifest: manifestBytes });
  const cool = new CooL({ applicationId: "refund-agent", runtime });
  const { evidence } = await cool.record({
    type: "policy.decision",
    metadata: { decision: "approved", amount: 120 },
  });
  await cool.close();

  const forged = clone(evidence) as unknown as {
    record: { event: { metadata_hash: string } };
  };
  // Deterministic single-character mutation of the metadata commitment.
  const hash = forged.record.event.metadata_hash;
  forged.record.event.metadata_hash = `${hash.slice(0, -1)}${hash.endsWith("a") ? "b" : "a"}`;

  const verdict = await verifyEvidence(forged as unknown, audit);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.checks.binding.status, "fail");
  assert.equal(verdict.checks.signature.status, "fail");
  // The workload binding is unaffected — the credential is still genuine. The
  // verdict names which domain failed rather than collapsing to "invalid".
  assert.equal(verdict.checks.workload.status, "pass");
});

test("a replayed inclusion proof from another record fails the log, not the binding", async () => {
  const runtime = await ContrastWorkload.open({ root: pod("ai-service"), manifest: manifestBytes });
  const cool = new CooL({ applicationId: "refund-agent", runtime });
  const first = (await cool.record({ type: "a.event", metadata: { n: 1 } })).evidence;
  const second = (await cool.record({ type: "b.event", metadata: { n: 2 } })).evidence;
  await cool.close();

  const forged = clone(second);
  forged.inclusion = clone(first).inclusion;
  const verdict = await verifyEvidence(forged as unknown, audit);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.checks.inclusion.status, "fail");
  assert.equal(verdict.checks.workload.status, "pass");
});

/* ══ the verifier's own posture ══════════════════════════════════════ */

test("verification is entirely offline — no network is reachable from it", async () => {
  const evidence = await sealedIn("ai-service", { manifest: manifestBytes });
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async (...args: unknown[]) => {
    calls++;
    throw new Error(`the verifier must not make network calls (tried ${String(args[0])})`);
  }) as typeof fetch;
  try {
    const verdict = await verifyEvidence(evidence, { ...audit, requireHardware: true });
    assert.equal(verdict.ok, true, verdict.reasons.join("; "));
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("a malformed workload identity is a structural failure, never a throw", async () => {
  const evidence = await sealedIn("ai-service", { manifest: manifestBytes });

  const cases: ((e: DeepMutable<Evidence>) => void)[] = [
    (e) => {
      e.record.runtime.workload!.schema = "cool.workload.v99" as "cool.workload.v1";
    },
    (e) => {
      e.record.runtime.workload!.tee = "insecure";
    },
    (e) => {
      e.record.runtime.workload!.registers = { mrtd: "not-hex" } as never;
    },
    (e) => {
      e.attestation.workload!.cert_chain = "not a pem";
    },
    (e) => {
      e.attestation.workload!.binding_alg = "9.9.9";
    },
  ];

  for (const mutate of cases) {
    const forged = clone(evidence);
    mutate(forged);
    const verdict = await verifyEvidence(forged as unknown, audit);
    assert.equal(verdict.ok, false);
    assert.ok(verdict.reasons.length > 0);
  }
});

test("a certificate with a malformed attestation claim fails, it does not throw", async () => {
  // Build a certificate that parses as X.509 but whose MRTD extension payload
  // is not an OCTET STRING. Contrast would never emit this; an attacker can.
  const evidence = await sealedIn("ai-service", { manifest: manifestBytes });
  const [leaf] = parseCertificates(chainOf("ai-service"));
  const der = Buffer.from(leaf!.der);

  // The MRTD claim is encoded as 04 32 04 30 <48 bytes>: an extnValue OCTET
  // STRING wrapping a second OCTET STRING. Corrupt the inner tag to NULL so the
  // outer structure still parses and the payload no longer does.
  const mrtd = Buffer.from(
    (meta.measurements["approved_mrtd"] ?? "").slice(0, 32),
    "hex",
  );
  const at = der.indexOf(mrtd);
  assert.ok(at > 4, "found the MRTD claim inside the certificate");
  der[at - 2] = 0x05; // inner OCTET STRING → NULL

  const body = der.toString("base64");
  const wrapped: string[] = ["-----BEGIN CERTIFICATE-----"];
  for (let i = 0; i < body.length; i += 64) wrapped.push(body.slice(i, i + 64));
  wrapped.push("-----END CERTIFICATE-----", "");
  const reencoded = wrapped.join("\n");

  const forged = clone(evidence);
  forged.attestation.workload!.cert_chain = reencoded;

  const verdict = await verifyEvidence(forged as unknown, audit);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.checks.workload.status, "fail");
  assert.ok(verdict.reasons.length > 0);
});

test("a manifest the VERIFIER supplied badly is blamed on the verifier, not the evidence", async () => {
  const evidence = await sealedIn("ai-service", { manifest: manifestBytes });
  const verdict = await verifyEvidence(evidence, {
    coordinatorRootCA: genuineRoot,
    expectedManifest: "{ not json",
  });
  assert.equal(verdict.ok, false);
  assert.match(verdict.checks.workload.detail, /manifest YOU supplied/);
});

/* ══ runtime status: what the process may honestly say about itself ══ */

test("runtime status on Contrast is UNVERIFIED from inside the pod, REAL only with a pinned root", async () => {
  const { assessRuntime } = await import("../src/phala/runtime");
  const { CoolTee } = await import("../src/phala/client");

  const runtime = await ContrastWorkload.open({ root: pod("ai-service"), manifest: manifestBytes });

  // The pod checking its own credential against the root it was handed proves
  // coherence, not provenance -- so the ceiling is UNVERIFIED.
  const selfChecked = await CoolTee.connect({
    runtime,
    app: { name: "refund-agent", imageDigest: "unused" },
    policy: { allowSimulated: false },
  });
  assert.equal(selfChecked.handshake.ok, true, selfChecked.handshake.reasons.join("; "));
  const self = assessRuntime(selfChecked.plane.info, selfChecked.handshake);
  assert.equal(self.state, "unverified");
  assert.match(self.reason, /only checked against the root CA the pod itself was given/);
  await selfChecked.close();

  // An operator who pins a root out of band gets REAL.
  const pinnedRun = await CoolTee.connect({
    runtime,
    app: { name: "refund-agent", imageDigest: "unused" },
    policy: { allowSimulated: false, coordinatorRootCA: genuineRoot },
  });
  const pinned = assessRuntime(pinnedRun.plane.info, pinnedRun.handshake);
  assert.equal(pinned.state, "real", pinned.reason);
  assert.match(pinned.reason, /verified against a pinned Coordinator root/);
  await pinnedRun.close();

  // And a rogue root closes the channel rather than downgrading it.
  const rogueRun = await CoolTee.connect({
    runtime,
    app: { name: "refund-agent", imageDigest: "unused" },
    policy: { allowSimulated: false, coordinatorRootCA: rogueRoot },
  });
  assert.equal(rogueRun.handshake.ok, false);
  assert.equal(assessRuntime(rogueRun.plane.info, rogueRun.handshake).state, "failed");
  await rogueRun.close();
});

test("runtime status never calls an insecure Contrast platform hardware", async () => {
  const { assessRuntime } = await import("../src/phala/runtime");
  const { CoolTee } = await import("../src/phala/client");

  const runtime = await ContrastWorkload.open({ root: pod("insecure-service") });
  const run = await CoolTee.connect({
    runtime,
    app: { name: "insecure", imageDigest: "unused" },
    policy: { coordinatorRootCA: runtime.coordinatorRootCA },
  });
  const status = assessRuntime(run.plane.info, run.handshake);
  assert.equal(status.state, "simulated");
  assert.match(status.reason, /INSECURE \(non-CC\) platform/);
  await run.close();
});

test("the verdict's runtime label names the Contrast route, not a missing quote", async () => {
  const evidence = await sealedIn("ai-service", { manifest: manifestBytes });

  const verified = await verifyEvidence(evidence, audit);
  assert.equal(verified.subject?.tee, "intel-tdx · contrast workload credential verified");

  // Unpinned: the label must say the credential was not verified, and must not
  // claim a hardware quote failed -- there was never a quote.
  const unpinned = await verifyEvidence(evidence);
  assert.match(unpinned.subject?.tee ?? "", /contrast credential NOT verified \(workload absent\)/);
  assert.doesNotMatch(unpinned.subject?.tee ?? "", /quote/);
});

test("an adversarial PEM cannot stall the verifier (ReDoS regression)", async () => {
  // CodeQL `js/polynomial-redos` flagged the original regex-based PEM parser.
  // These are the shapes it backtracked on: a long run of BEGIN markers with no
  // matching END, and a huge body. Both must now be linear.
  const evidence = await sealedIn("ai-service", { manifest: manifestBytes });
  const hostile = [
    "-----BEGIN CERTIFICATE-----".repeat(20_000),
    `-----BEGIN CERTIFICATE-----${"a".repeat(400_000)}`,
    `${"-----BEGIN CERTIFICATE-----".repeat(5_000)}-----END CERTIFICATE-----`,
  ];

  for (const chain of hostile) {
    const forged = clone(evidence);
    forged.attestation.workload!.cert_chain = chain;
    const started = Date.now();
    const verdict = await verifyEvidence(forged as unknown, audit);
    const elapsed = Date.now() - started;
    assert.equal(verdict.ok, false);
    // Generous bound: the point is that it finishes, not that it is fast.
    assert.ok(elapsed < 5_000, `verification took ${elapsed}ms on an adversarial PEM`);
  }
});

test("a non-Contrast receipt is unaffected: the workload domain is simply absent", async () => {
  const cool = new CooL({ applicationId: "simulator-test" });
  const { evidence } = await cool.record({ type: "model.execution", metadata: {} });
  await cool.close();

  const verdict = await verifyEvidence(evidence, audit);
  assert.equal(verdict.checks.workload.status, "absent");
  assert.equal(verdict.ok, true, verdict.reasons.join("; "));
  assert.equal(evidence.record.runtime.workload, undefined, "the field is absent, not null");
  assert.equal("workload" in evidence.record.runtime, false, "so old receipts hash identically");
});
