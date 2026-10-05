# CooL × Edgeless Systems Contrast

> Contrast protects the AI workload while it runs. CooL produces independently
> verifiable evidence of what changed inside it, cryptographically bound to that
> workload. Together: confidential execution plus a verifiable AI-change history.

This document is the whole integration: the architecture, the exact binding, the
trust model, what was tested and what was not, and the commands to run it on real
confidential hardware.

---

## 1 · Why the two fit

Contrast and CooL answer adjacent questions, and neither answers the other's.

| | Contrast | CooL |
| --- | --- | --- |
| proves | this pod ran as a confidential container, on hardware matching a signed manifest | this record describes a specific change/execution, is unaltered, is in a complete ordered log, and was produced by a specific workload |
| horizon | while the workload runs | years after it stopped |
| audience | the platform team | an auditor, a regulator, a counterparty |
| fails loudly when | the image, kernel or policy differs from the manifest | a record is edited, removed, reordered, or attributed to the wrong workload |

Contrast can prove a pod was confidential and cannot say which prompt it was
running. CooL can prove a prompt changed and cannot, by itself, say the process
that said so was protected. The combination closes both gaps:

> *This AI change record was produced by a specific confidential workload whose
> execution environment can be independently attested.*

## 2 · The one thing to understand about Contrast

Contrast's attestation is **not a quote handed to the workload**. It is a
**credential**.

The Coordinator — itself a confidential VM — terminates an aTLS handshake from
each pod's initializer, verifies that pod's SNP/TDX attestation report against
the manifest's reference values, and then issues a **mesh certificate**. That
certificate carries the claims it verified as X.509 extensions and binds them to
a P-256 key that only the pod holds
(`coordinator/internal/meshapi/meshapi.go` → `internal/ca.NewAttestedMeshCert`).

```
1.3.9901.2.2.14   MRTD                 (TDX)
1.3.9901.2.2.18   RTMR0
1.3.9901.2.2.19   RTMR1
1.3.9901.2.2.20   RTMR2
1.3.9901.2.2.21   RTMR3
1.3.9901.2.2.9    MRSEAM
1.3.9901.2.2.15   MRCONFIGID          → HostData[:32] = the policy hash
1.3.9901.2.1.22   MEASUREMENT          (SNP)
1.3.9901.2.1.23   HOST_DATA            (SNP) = the policy hash
1.3.9901.3.1      WorkloadSecretID
```

This matters because it means **the credential is self-describing and
offline-checkable**. A verifier needs no Coordinator contact, no DCAP call and no
network: the measurements are in the certificate, and the certificate chains to a
root that can be pinned once.

The policy hash is the digest of the pod's **initdata document** and the key of
the manifest's `Policies` map, so the credential also states *which manifest
entry authorised this pod*.

> A Contrast deployment on a non-CC development platform issues certificates with
> **no attestation extensions at all**
> (`internal/attestation/insecure/validator.go` returns `nil, nil`). CooL treats
> that absence as decisive — see §5.

## 3 · The binding

CooL binds on both sides, and needs both.

### 3.1 Sealing — the key cannot exist elsewhere

CooL derives its hybrid ML-DSA-65 + Ed25519 signing key from
`/contrast/secrets/workload-secret-seed` using HKDF-SHA256 with the derivation
path as `info`. The Coordinator releases that secret only to a pod whose
attestation report matched the manifest, and derives it from the manifest's
`WorkloadSecretID` — so it is **stable across restarts and manifest updates** and
**different for every workload**.

Consequences:

- There is no signing key in the image, in a vault, or in CI. Outside the attested
  workload the key is not derivable at all.
- Northwind Cipher cannot forge a record from this deployment. Neither can the
  cluster operator, without passing attestation.
- The signing identity survives pod churn, so the audit trail is continuous
  across restarts and rescheduling.

CooL's key id is derived from the **policy hash**, not the measurement. Two pods
built from one image share an MRTD but hold different keys; an image-derived id
would have filed two public keys under one name. (This was a real bug found by
the test suite, not a hypothetical.)

### 3.2 Certifying — the key belongs to *this* workload

The pod's mesh key signs a commitment to the CooL public key:

```
statement = { key_id, ed25519_pub, ml_dsa_pub, issued_at }
message   = "cool/contrast/key-binding/v1" ‖ canonicalCBOR(statement)
key_binding       = mh:sha256(message)
binding_signature = ECDSA(message, /contrast/tls-config/key.pem)
```

`issued_at` and `key_id` are **inside** the signed statement, so a binding cannot
be lifted onto a different key or re-dated.

### 3.3 The chain

```
AI change (prompt / model / policy / permission / params)
   │
   ├─ committed as salted hashes; plaintext never leaves the workload
   ▼
cool.receipt.v2
   │  record.runtime.workload  ← the Contrast identity, INSIDE the signed core
   ▼
hybrid signature (ML-DSA-65 + Ed25519) over canonicalCBOR(core) ‖ binding_digest
   │
   ▼
RFC 6962 transparency log — inclusion proof + signed tree head
   │
   ▼
attestation.workload.binding_signature
   │  ECDSA by the pod's mesh key over a commitment to the signing key
   ▼
mesh certificate: MRTD, RTMRs, policy hash, WorkloadSecretID
   │
   ▼
Coordinator intermediate → Coordinator root CA
   │  pinned by the reader from `contrast verify`
   ▼
Coordinator CVM, remotely attested against the manifest's reference values
   │
   ▼
confidential execution on Intel TDX / AMD SEV-SNP
```

### 3.4 Why substitution fails

| attack | what breaks |
| --- | --- |
| attach workload A's receipt to workload B's credential | the binding signature verifies only under A's certificate |
| also rewrite the sealed identity so the two agree | the identity is inside the signed core — the record signature breaks |
| edit the AI change | `binding_hash` and the record signature break; the `workload` domain still passes, so the verdict names *which* guarantee failed |
| flip a byte in the certificate | chain verification fails |
| forge or re-date the binding signature | ECDSA verification fails; `issued_at` is in the signed statement |
| use a Coordinator you stood up yourself | the chain does not reach the pinned root, and the record's sealed `coordinator_root` digest names the mismatch explicitly |
| remove the credential, or remove the sealed identity | a half-binding is a hard failure, not a weaker binding |
| rebuild the image | the MRTD changes; a register pin fails, and old receipts keep verifying |
| replay an inclusion proof from another record | the audit path no longer reconstructs the tree head |

All of these are tests in `tests/contrast.test.ts`.

## 4 · What CooL adds to the receipt

Two optional fields, in the **encoding** sense: when a deployment has no
orchestrator-issued credential the keys are absent from the canonical CBOR
entirely, so every receipt minted by `cool-nwc@3.0.0` still hashes, signs and
verifies to exactly the same bytes. This was a hard constraint — the package is
already published.

```jsonc
{
  "record": {
    "runtime": {
      "tee_vendor": "intel-tdx",
      "mode": "hardware",
      "tee_quote": null,              // Contrast issues no quote to the workload
      "workload": {                   // ← inside the signature
        "schema": "cool.workload.v1",
        "platform": "contrast",
        "tee": "intel-tdx",
        "policy_hash": "hex:f04dfba7…",
        "workload_secret_id": "default/ai-service",
        "workload_name": "ai-service",
        "sans": ["ai-service", "10.42.0.11"],
        "registers": { "mrtd": "hex:…", "rtmr0": "hex:…", "rtmr3": "hex:…", "mrseam": "hex:…" },
        "registers_digest": "mh:sha256:…",
        "coordinator_root": "mh:sha256:…",
        "manifest_digest": "mh:sha256:…"
      }
    }
  },
  "attestation": {
    "workload": {                     // ← in the envelope
      "schema": "cool.workload.attestation.v1",
      "cert_chain": "-----BEGIN CERTIFICATE-----…",
      "key_binding": "mh:sha256:…",
      "bound_key_id": "cool-contrast-enclave-f04dfba7241e",
      "binding_signature": "base64:…",
      "binding_alg": "1.2.840.10045.4.3.2",
      "issued_at": "2026-10-05T14:52:32.000Z"
    }
  }
}
```

The verifier gains an eighth domain, `workload`, alongside the existing seven.

## 5 · Honesty rules the verifier enforces

These are the reason to trust the rest.

**`workload` reaches `pass` only with a pinned Coordinator root.** A pod can mint
its own CA. Without `coordinatorRootCA` the domain reports `absent` with
`"the binding is valid and self-consistent, but with no pinned Coordinator root
it is REPORTED, not verified"`.

**A Contrast credential is never reported as a vendor quote.** CooL does not
check Intel DCAP or AMD KDS itself. On a Contrast receipt the quote-shaped
domains are honest about their absence:

```
attestation  absent   (mock — no attestation quote in this receipt)
enclave      absent   (no quote to bind)
workload     pass     (chain of 3 verified to pinned root 'system:coordinator:root')
```

**`requireHardware` is satisfied by either route, and the verdict says which.**
A verified vendor quote is arithmetic against Intel/AMD. A passing `workload`
domain is an authority the reader attested separately. Both are hardware-rooted;
one is transitive. The distinction survives into the audit trail rather than
being flattened.

**An insecure Contrast platform reports `simulated`, never `pass`.** Its
certificate carries no measurements, and `ContrastWorkload.open({
requireConfidential: true })` refuses to start at all. The structural validator
additionally rejects a record claiming `tee: "insecure"` *with* registers, which
is the shape a relabelling edit would take.

**`getQuote()` returns `null` under Contrast.** Synthesising a quote, or
re-labelling the certificate as one, would be the single genuinely dishonest move
available in this integration. It is not made.

## 6 · Trust model

### Trusted

| | why |
| --- | --- |
| Intel TDX / AMD SEV-SNP | the hardware root; CooL adds nothing and claims nothing here |
| the Contrast Coordinator | it decides which pods are admitted and issues every credential. **A compromised Coordinator can certify an arbitrary workload.** This is Contrast's own trust assumption; CooL inherits it and narrows it by requiring the reader to attest the Coordinator themselves. |
| the reader's `contrast verify` run | pinning the root is the step that makes everything downstream meaningful |
| ML-DSA-65, Ed25519, SHA-256/384, ECDSA P-256/P-384 | standard primitives, via `@noble/*` |

### Not trusted

The cluster operator, the Kubernetes control plane, the node OS, the container
registry, the network, Northwind Cipher, Edgeless Systems' servers, and the
verifier's own network connection (verification is fully offline).

### Threats considered

| threat | status |
| --- | --- |
| **Receipt substitution** across workloads | closed by §3.4 |
| **Key substitution** — a credential attesting a different key | closed: `key_binding` is recomputed from the receipt's own key directory |
| **Identity substitution** — relabelling the workload | closed: the identity is in the signed core |
| **Confused deputy** — CooL signing on behalf of another workload | closed: the key is derived from *this* pod's workload secret, and `keyId` is derived from the policy hash so two pods on one image cannot collide |
| **Metadata spoofing** — asserting TDX in config | closed: platform is decided by which claim arc is present in the certificate, never by configuration |
| **Stale measurements** | the certificate's claims are from the issuing handshake. A long-lived pod's credential reflects the state at admission, not now. Contrast's certificate lifetime (1 year) bounds this; a deployment wanting tighter bounds should rotate pods. **Documented limitation.** |
| **Attestation replay** — reusing an old credential | the credential is bound to a key only the pod holds, so replay requires the pod's mesh key. Not independently rate-limited. |
| **Binding replay** — reusing an old binding signature | possible *if* an attacker already holds both the CooL signing key and the mesh key, i.e. has compromised the pod. Freshness of records comes from the transparency log and the optional Bitcoin anchor, not from the binding. **Documented limitation.** |
| **Workload migration** | a rescheduled pod gets a new certificate and the same workload secret, so the signing identity is continuous and the certificate serial changes. Both old and new receipts verify. Tested. |
| **Compromised host** | Contrast's premise; outside CooL's reach |
| **Container escape** | would yield the workload secret and the mesh key, hence the ability to sign new records. Not detectable from a receipt. Contrast's isolation is the control. |
| **Kubernetes privilege escalation** | the CooL container needs no privileges and mounts `/contrast` read-only (Contrast mounts it read-only into every container except the initializer) |
| **Secret leakage** | the workload secret is read once at start-up and never written, logged or transmitted. CooL never signs application data with the mesh key — one statement at start-up, nothing more. |
| **TOCTOU** between attestation and signing | the credential is obtained once, before any caller data exists, and its digest-bearing identity is in every signed core. A record cannot be produced before the binding exists. |
| **Verifier trust** | none required: no network, and `pass` needs a reader-supplied root |
| **Parser differentials** — a lenient DER reader in front of a signature check | the reader rejects indefinite lengths, non-minimal lengths, multi-byte tags and trailing bytes; and the parse is cross-checked against Contrast's own Go encoder (§7) |

### Known limitations

1. **CooL does not re-verify the TDX/SNP quote.** It trusts the Coordinator's
   verdict as expressed in the certificate. The extensions actually contain
   enough to reconstruct the quote — including the PCK certificate chain at
   `1.3.9901.2.2.46` — so independent DCAP verification is possible. It is **not
   implemented**, and is the single highest-value next step (§9).
2. **Stale measurements** and **binding replay**, as above.
3. **No confidential-GPU path yet.** CooL's `GpuAttestationRef` exists and
   Contrast supports confidential GPUs; the two are not joined.
4. **The transparency log is in memory by default.** For a log that spans
   restarts — which is what makes ordering and completeness provable rather than
   a hundred trees of size one — mount a volume and pass `FileLog` from
   `cool-nwc/node`, ideally on a Contrast encrypted volume
   (`contrast.edgeless.systems/secure-pv`).
5. **Not production-ready.** It is tested, it is not deployed. See §8.

## 7 · What was actually tested

### Cross-implementation conformance — real Contrast code

`tests/fixtures/contrast-fixtures.json` is generated by
`tools/contrast-fixture/main.go`, which runs **inside a Contrast checkout** and
calls Contrast's own
`internal/seedengine`, `internal/ca.NewAttestedMeshCert`,
`internal/attestation/tdx.Report.ClaimsToCertExtension` and `internal/oid`.
Nothing about the X.509 structure, the extension OIDs or the ASN.1 encoding is
reimplemented on the fixture side.

The bundle stores certificates and keys as base64 DER, and
`tests/support/contrast-pod.ts` writes them back out as the files Contrast's
initializer creates, into a temporary directory. That indirection exists because
this repository forbids committed `.pem` files and PEM private-key blocks
(`.github/workflows/security.yml`) — a rule worth keeping literal rather than
carving an exception into. The keys are disposable and protect nothing.

So when a test asserts CooL recovered an MRTD or a policy hash, it is asserting
agreement between **Contrast's Go encoder and CooL's TypeScript decoder**. That
caught real details that documentation alone would not have: the extension
payload is doubly wrapped (`asn1.Marshal([]byte)` inside `extnValue`), Contrast's
CA keys are P-384 while workload keys are P-256, and the chain is cross-signed.

### Results

```
$ npm test
ℹ tests 113
ℹ pass 112
ℹ fail 0
ℹ skipped 1      (pre-existing, unrelated)
```

27 of those are the Contrast suite:

| group | covers |
| --- | --- |
| conformance (4) | TDX claims, policy hash ↔ manifest, chain to root vs. rogue root, insecure platform carries no claims |
| happy path (4) | seal inside Contrast; identity inside the signature; `requireHardware` pinned vs. unpinned; insecure never confidential |
| substitution (6) | cross-workload credential, full double swap, rogue Coordinator, half-binding, flipped certificate byte, forged/re-dated binding |
| pinning (3) | policy allow-list, manifest digest, register drift on a rebuilt image |
| lifecycle (3) | restart keeps the sealed key, missing `WorkloadSecretID`, not-a-Contrast-pod |
| governance (3) | four change kinds in one log, tampered change, replayed inclusion proof |
| posture (2) | verification makes zero network calls; malformed credentials never throw |
| compatibility (1) | a non-Contrast receipt is byte-identical and the domain is `absent` |

### Found by CI, not by inspection

Two things the pipeline caught that review had not:

- **CodeQL `js/polynomial-redos`** flagged the regex-based PEM parser in
  `src/contrast/x509.ts` and the chain shape-check in `src/phala/structure.ts`.
  The verifier parses PEM an attacker chose, so a parser that backtracks
  polynomially is a denial-of-service vector. Both are now linear `indexOf`
  scans, with a regression test that throws ~400 KB of adversarial PEM at the
  verifier and requires it to finish.
- **The secret-scanning gate** rejected the original fixture layout, which
  committed `key.pem` files. Hence the JSON bundle above.

### Not tested, because it needs hardware

- A real Intel TDX or AMD SEV-SNP machine.
- A real Coordinator CVM, a real aTLS handshake, real DCAP/KDS collateral.
- `contrast generate` / `set` / `verify` against a live cluster.
- The Kubernetes manifests in `examples/contrast/k8s/` have **not** been applied
  to a cluster. They are written against Contrast's current generator
  (`internal/kuberesource`) — `runtimeClassName: contrast-cc` is the marker
  `contrast generate` looks for, and it injects the initializer, the sidecar and
  the `/contrast` volume — but they are unvalidated.
- The `Dockerfile` has a placeholder base-image digest.

**No claim is made that this has run on confidential hardware.** Everything
needed to do so is in `examples/contrast/`.

## 8 · Running it

### Locally, in ninety seconds, no cluster

```sh
npm install && npm run demo:contrast
```

Seven acts: the workload's Contrast identity, four AI changes sealed inside it,
an independent verdict, then four forgeries that must fail.

### On real confidential hardware

Needs a Kubernetes cluster with bare-metal Intel TDX or AMD SEV-SNP (or AKS
CoCo), the Contrast node-installer and runtime class applied, and the `contrast`
CLI. Follow Edgeless's
[workload deployment guide](https://docs.edgeless.systems/contrast/howto/workload-deployment/runtime-deployment)
for the cluster prerequisites, then:

```sh
cd examples/contrast
./deploy.sh metal-qemu-tdx          # or metal-qemu-snp, aks-clh-snp, …
```

which runs, in order:

```sh
kubectl apply -f coordinator.yml                      # the Coordinator CVM
contrast generate --reference-values <platform> k8s/ai-service.yaml
kubectl create configmap contrast-manifest --from-file=manifest.json
contrast set -c <coordinator>:1313 k8s/ai-service.yaml
kubectl apply -f k8s/ai-service.yaml
contrast verify -c <coordinator>:1313                 # → verify/coordinator-root-ca.pem
```

The only CooL-specific requirements are three lines in the pod spec:

```yaml
runtimeClassName: contrast-cc
metadata.annotations:
  contrast.edgeless.systems/workload-secret-id: default/ai-service
env:
  - name: COOL_CONTRAST_ROOT
    value: /contrast
```

### Verifying, as an auditor

```sh
cool verify receipts.json \
  --coordinator-root verify/coordinator-root-ca.pem \
  --manifest manifest.json \
  --require-hardware
```

or in code:

```ts
import { verifyEvidence } from "cool-nwc";

const verdict = await verifyEvidence(receipt, {
  coordinatorRootCA: readFileSync("verify/coordinator-root-ca.pem", "utf8"),
  expectedManifest: readFileSync("manifest.json"),
  expectedRegisters: { mrtd: "a27518a5…" },   // the image you approved
  allowedPolicyHashes: ["f04dfba7…"],          // the pods you approved
  requireHardware: true,
});
```

## 9 · The highest-value next step

**Reconstruct and independently verify the TDX/SNP quote from the mesh
certificate's extensions.**

The extensions already carry the full quote — `TdQuoteBody`, the ECDSA signature
at `1.3.9901.2.2.24`, the attestation key at `.25`, and the **PCK certificate
chain** at `.46`. If CooL reassembles that into a wire-format quote and verifies
it against Intel DCAP collateral, the `attestation` domain can reach `pass` on
a Contrast receipt and the Coordinator moves out of the trusted set for the
hardware claim entirely.

That would make a CooL × Contrast receipt verifiable **to silicon, offline,
without trusting the Coordinator** — which is a materially stronger product than
either project has alone, and the natural place for a joint reference
architecture.

---

### Source references

Every Contrast behaviour above is cited from
[github.com/edgelesssys/contrast](https://github.com/edgelesssys/contrast)
(read at `3a93ecd`, version `1.25.0-pre`):

| claim | file |
| --- | --- |
| extension OIDs | `internal/oid/oid.go` |
| TDX claim numbering | `internal/attestation/tdx/extensions.go` |
| SNP claim numbering | `internal/attestation/snp/extensions.go` |
| HostData = `MrConfigId[:32]` / SNP `HostData` | `internal/attestation/tdx/validator.go`, `internal/attestation/snp/validator.go` |
| insecure platform issues no extensions | `internal/attestation/insecure/validator.go` |
| mesh cert issuance, workload secret release | `coordinator/internal/meshapi/meshapi.go` |
| cross-signing CA, P-384 CA keys | `internal/ca/ca.go`, `internal/seedengine/seedengine.go` |
| runtime file paths and the P-256 pod key | `initializer/main.go` |
| `Policies` keyed by policy hash (HOSTDATA) | `internal/manifest/manifest.go` |
| policy hash = initdata digest | `internal/initdata/initdata.go`, `cli/cmd/verify.go` |
| `verify/` output filenames | `cli/cmd/common.go`, `cli/cmd/verify.go` |
| injected initializer / sidecar / volume | `internal/kuberesource/parts.go`, `mutators.go` |
| workload-secret annotation | `internal/kuberesource/constants.go` |

Edgeless documentation: [The manifest](https://docs.edgeless.systems/contrast/next/architecture/components/manifest),
[Secrets & recovery](https://docs.edgeless.systems/contrast/architecture/secrets),
[Service mesh](https://docs.edgeless.systems/contrast/architecture/components/service-mesh).

Contrast and CooL are both under the Business Source License 1.1, with separate
licensors and separate terms. **No Contrast source is vendored into this
repository.** `tools/contrast-fixture/main.go` is CooL-authored code that
imports Contrast's packages by reference and only compiles inside a Contrast
checkout; nothing it depends on is redistributed here. The runtime integration
(`src/contrast/`) depends on no Contrast code at all — it reads files and parses
certificates, so it carries no Contrast licence obligation.

Nothing here implies Edgeless Systems has reviewed, endorsed or partnered on this
integration.
