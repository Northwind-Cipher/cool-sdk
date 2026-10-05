<div align="center">

<!-- GitHub strips inline CSS and does not reliably align ASCII art beside images.
     Use actual logo images, identical cell sizing, and native GitHub-safe HTML. -->
<table align="center">
  <tr>
    <td align="center" valign="middle" width="390">
      <a href="https://github.com/Northwind-Cipher/cool-sdk">
        <img src="https://raw.githubusercontent.com/Northwind-Cipher/cool-sdk/main/assets/hero.svg" alt="CooL" width="350" />
      </a>
    </td>
    <td align="center" valign="middle" width="42">
      <strong>×</strong>
    </td>
    <td align="center" valign="middle" width="390">
      <a href="https://phala.com/">
        <img src="https://raw.githubusercontent.com/Phala-Network/phala-docs/main/images/phala-dark.png" alt="Phala" width="350" />
      </a>
    </td>
  </tr>
</table>

<!-- Matching lime/charcoal GitHub-safe branding, rendered as an image instead of
     inline HTML colors (which GitHub removes). -->
<a href="https://phala.com/">
  <img src="https://img.shields.io/badge/POWERED%20BY-PHALA-CDFA50?style=for-the-badge&labelColor=151B23&color=CDFA50" alt="Powered by Phala" />
</a>

# CooL × Phala

### The Black Box for AI · Confidential Execution

**Every AI change can be automatically captured, cryptographically recorded, and independently verified.**

[![POWERED BY PHALA](https://img.shields.io/badge/POWERED%20BY-PHALA-CDFA50?style=for-the-badge&labelColor=151B23&color=CDFA50)](https://phala.com/)

<sub>CONFIDENTIAL EXECUTION · HARDWARE-BACKED ATTESTATION · VERIFIABLE RUNTIME</sub>

<br/><br/>

[![CI](https://github.com/Northwind-Cipher/cool-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/Northwind-Cipher/cool-sdk/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-BUSL--1.1-151B23.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A5%2020-CDFA50.svg)](https://nodejs.org)
[![TEE](https://img.shields.io/badge/TEE-Intel%20TDX-CDFA50?style=flat-square&labelColor=151B23)](https://phala.com/)

</div>


---

<div align="center">

```text
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║                    CRYPTOGRAPHIC OBSERVABILITY                           ║
║                              FOR AI                                     ║
║                                                                          ║
║       EVIDENCE ── SIGN ── LOG ── WITNESS ── ATTEST ── VERIFY            ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

**Evidence over claims.**

</div>

---

## What CooL is

CooL is a developer SDK and command line for producing **independently verifiable evidence about what software did**.

Your application records an event; CooL returns a self-contained receipt that anyone can check later, with no account and no trust in CooL, proving:

- **which software** ran, including name, version and content digest,
- **which event** happened,
- that the record has not been altered through a deterministic cryptographic commitment,
- authenticity through a hybrid **ML-DSA-65 + Ed25519** signature,
- that it sits in an **append-only RFC 6962 Merkle log**,
- and, through the Phala-backed Intel TDX path, **where it ran** through hardware measurements and attestation evidence,
- or, through the **Edgeless Contrast** path, **which confidential workload** produced it — the Coordinator-issued mesh certificate, its measurements and its policy hash, bound to the same signing key.

Sensitive values are committed as salted hashes and discarded; receipts never carry plaintext.

> **CooL records what happened. It does not judge whether it was correct, fair or safe.**

---

## CooL × Phala: how it works

<div align="center">

```text
             CooL
      CRYPTOGRAPHIC EVIDENCE
               │
               ▼
        PHALA / DSTACK
      CONFIDENTIAL RUNTIME
               │
               ▼
          INTEL TDX
      HARDWARE MEASUREMENT
               │
               ▼
       HARDWARE QUOTE
               │
               ▼
    INDEPENDENT VERIFIER
```

</div>

CooL's hardware-backed execution and attestation path is integrated with **Phala / dstack** and **Intel TDX**.

| Layer | Responsibility |
|---|---|
| **CooL** | Evidence records, commitments, signatures, transparency, witnesses and verification |
| **Phala / dstack** | Confidential runtime, workload identity, measurements, key sealing and attestation |
| **Intel TDX** | Hardware-backed confidential execution and measurement |
| **Verifier** | Independent evaluation of the evidence |

**Phala resources**

- [Phala](https://phala.com/)
- [dstack](https://phala.com/dstack)
- [Confidential VM](https://phala.com/confidential-vm)
- [Phala Cloud](https://cloud.phala.com/)

---

# The CooL Evidence Matrix

<div align="center">

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                           C O O L   M A T R I X                            │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  SOFTWARE                 CRYPTOGRAPHY             TRANSPARENCY            │
│  ────────                 ───────────             ────────────            │
│  name                     ML-DSA-65               RFC 6962                 │
│  version                  Ed25519                 Merkle tree              │
│  digest                   SHA-256                 signed tree head         │
│  model                    canonical CBOR          inclusion proof          │
│                                                                            │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  EXECUTION               WITNESS                  CONFIDENTIALITY         │
│  ─────────               ───────                  ───────────────         │
│  event                   separate process         Intel TDX                │
│  input commitment        independent key          Phala / dstack          │
│  output commitment       fork detection           measurement              │
│  timestamp               rollback detection       quote                    │
│                                                                            │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│                       INDEPENDENT VERIFICATION                             │
│                                                                            │
│       BINDING → SIGNATURE → INCLUSION → WITNESS → ATTESTATION             │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

</div>

The matrix separates the properties being established so that a verifier can see **which evidence supports which claim**.

---

# Capabilities

| Capability | What it does | Notes |
|---|---|---|
| **SDK** | `CooL` and `CoolTee` | TypeScript, ESM, Node >= 20 |
| **Receipts** | `cool.receipt.v2` with signed `cool.evidence.v1` | Canonical CBOR, salted commitments |
| **Cryptographic verification** | Binding, signature, inclusion, witnesses, attestation, enclave, workload, anchor | Structured verdict per domain |
| **Append-only log** | RFC 6962 Merkle tree | File-backed and in-memory logs |
| **Consistency** | `verifyLogConsistency` | Detects forks and altered heads |
| **Witness** | Independent log observer | Refuses forks and rollbacks |
| **Intel TDX** | Hardware-backed execution | Phala / dstack integration |
| **Confidential containers** | Workload-bound evidence on Kubernetes | Edgeless Contrast, Intel TDX or AMD SEV-SNP |
| **Attestation** | Quote verification | Configured verifier |
| **Runtime status** | Evidence-derived status | `REAL`, `UNVERIFIED`, `SIMULATED`, `UNAVAILABLE`, or failure |
| **CLI** | `status`, `seal`, `verify`, `records`, `wire`, `ui` | `COOL_REQUIRE_HARDWARE=1` |
| **Production enforcement** | Fail closed | Rejects non-real hardware states |

---

# Verification architecture

```text
                              RECEIPT
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
              ▼                  ▼                  ▼
           BINDING            SIGNATURE          INCLUSION
              │                  │                  │
              │              ML-DSA-65             │
              │              + Ed25519          RFC 6962
              │                  │                  │
              └──────────────────┼──────────────────┘
                                 │
                                 ▼
                              WITNESS
                                 │
                                 ▼
                           ATTESTATION
                                 │
                          Phala / dstack
                                 │
                            Intel TDX
                                 │
                                 ▼
                    STRUCTURED VERDICT
```

CooL deliberately does not collapse every security property into a single unexplained boolean.

Example:

```text
binding      PASS
signature    PASS
inclusion    PASS
consistency  PASS
witness      PASS
attestation  PASS
```

---

# Quick start

```bash
npm install cool-nwc
```

Requires **Node.js >= 20**.

```ts
import { CooL, verifyEvidence } from "cool-nwc";

const cool = new CooL({
  applicationId: "my-app",
});

const { evidence } = await cool.record({
  type: "model.execution",
  metadata: {
    model: "my-model",
    version: "1.0.0",
  },
  payloads: {
    input: "the request",
    output: "the response",
  },
});

const verdict = await verifyEvidence(evidence);

console.log(verdict.ok);
```

---

# Receipt anatomy

```text
cool.receipt.v2
│
├── cool.evidence.v1
│   ├── application identity
│   ├── software identity
│   ├── execution metadata
│   ├── model identity
│   ├── input commitment
│   ├── output commitment
│   ├── timestamp
│   └── binding hash
│
├── signature
│   ├── ML-DSA-65
│   └── Ed25519
│
├── transparency
│   ├── Merkle root
│   ├── signed tree head
│   └── inclusion proof
│
├── witness
│   └── independent witness evidence
│
└── attestation
    ├── TEE measurement
    ├── quote
    ├── report_data binding
    └── verifier result
```

Sensitive values are represented through salted commitments.

---

# Cryptographic model

### 01 · Canonicalization

```text
event
  │
  ▼
canonical CBOR
  │
  ▼
deterministic bytes
```

### 02 · Binding

```text
software identity ──┐
model identity ─────┤
input commitment ───┤
output commitment ──┤──► evidence ──► binding hash
timestamp ──────────┤
metadata ───────────┘
```

### 03 · Hybrid signature

```text
                 binding hash
                      │
             ┌────────┴────────┐
             ▼                 ▼
        ML-DSA-65          Ed25519
             │                 │
             └────────┬────────┘
                      ▼
               signed evidence
```

### 04 · Transparency

```text
receipt
   │
   ▼
Merkle leaf
   │
   ▼
RFC 6962 tree
   │
   ▼
signed tree head
   │
   ▼
inclusion proof
```

---

# Confidential execution

```text
┌────────────────────────────────────┐
│              CooL SDK              │
│                                    │
│ evidence · signing · transparency  │
└──────────────────┬─────────────────┘
                   │
                   ▼
┌────────────────────────────────────┐
│            PHALA / DSTACK          │
│                                    │
│ workload identity                  │
│ measurement                        │
│ key sealing                        │
│ quote retrieval                    │
└──────────────────┬─────────────────┘
                   │
                   ▼
┌────────────────────────────────────┐
│             INTEL TDX              │
│                                    │
│ confidential VM                    │
│ hardware-backed isolation          │
└──────────────────┬─────────────────┘
                   │
                   ▼
              hardware quote
                   │
                   ▼
┌────────────────────────────────────┐
│         INDEPENDENT VERIFIER       │
│                                    │
│ quote · measurement · identity     │
│ policy · evidence                  │
└────────────────────────────────────┘
```

---

# Hardware validation

The current validation path uses **real Phala-backed Intel TDX execution**.

The production path is intended to fail closed rather than silently downgrade to simulation.

```text
COOL WORKLOAD
      │
      ▼
PHALA / DSTACK
      │
      ▼
INTEL TDX
      │
      ▼
MEASUREMENT
      │
      ▼
HARDWARE QUOTE
      │
      ▼
CONFIGURED VERIFIER
      │
      ▼
MEASUREMENT POLICY
      │
      ▼
REAL
```

Production enforcement:

```bash
COOL_REQUIRE_HARDWARE=1
```

---

# CooL × Edgeless Contrast

A second confidential-execution path, alongside Phala dstack.

[Contrast](https://docs.edgeless.systems/contrast) runs Kubernetes pods as confidential containers on Intel TDX or AMD SEV-SNP. Its **Coordinator**, itself a confidential VM, admits a pod only if the pod's attestation report matches a signed manifest.

The shape is genuinely different from dstack's, and that difference is the integration. Contrast hands the workload a **credential, not a quote**: after verifying the report, the Coordinator issues a mesh certificate that **carries the claims it verified** as X.509 extensions, bound to a key only that pod holds.

```text
1.3.9901.2.2.14   MRTD
1.3.9901.2.2.18   RTMR0
1.3.9901.2.2.21   RTMR3
1.3.9901.2.2.15   MRCONFIGID  →  HOSTDATA  =  policy hash
1.3.9901.3.1      WorkloadSecretID
```

So CooL binds on both sides, and needs both.

```text
SEALING
      the CooL signing key is HKDF-derived from
      /contrast/secrets/workload-secret-seed, which the
      Coordinator releases only to a pod that passed
      attestation. No key in the image, in a vault, or in CI.

CERTIFYING
      the pod's mesh key signs a commitment to that CooL
      public key. The certificate travels in the receipt;
      the identity it states travels INSIDE the signed core.
```

```text
AI CHANGE
      │
      ▼
COOL RECEIPT  +  HYBRID SIGNATURE
      │
      ▼
KEY BINDING  signed by the pod's mesh key
      │
      ▼
MESH CERTIFICATE  measurements · policy hash
      │
      ▼
COORDINATOR ROOT CA  pinned via `contrast verify`
      │
      ▼
CONFIDENTIAL EXECUTION
```

A receipt from workload A **cannot** be presented as workload B's. The binding signature verifies only under A's certificate, and the identity is inside the signature, so making the two agree breaks the signature instead.

Adoption is a runtime swap, not a rewrite:

```ts
import { CooL } from "cool-nwc";
import { ContrastWorkload } from "cool-nwc/contrast";

const runtime = await ContrastWorkload.open({ requireConfidential: true });
const cool = new CooL({ applicationId: "refund-agent", runtime });

await cool.change({
  kind: "prompt",
  ref: "billing/refund-agent#system",
  before: "Refund when the policy allows.",
  after: "Refund when the policy allows. Escalate above $500.",
  actor: { id: "user:priya@bank.example", method: "session" },
});
```

In a pod spec it is three lines:

```yaml
runtimeClassName: contrast-cc
metadata.annotations:
  contrast.edgeless.systems/workload-secret-id: default/ai-service
env:
  - name: COOL_CONTRAST_ROOT
    value: /contrast
```

Verification, by an auditor with no cluster access:

```bash
cool verify receipts.json   --coordinator-root verify/coordinator-root-ca.pem   --manifest manifest.json   --require-hardware
```

## What the Contrast path does not claim

CooL does **not** re-verify the TDX/SNP quote against Intel DCAP on this path. It checks that the credential chains to a Coordinator root **the reader pinned**, and the `workload` verdict domain says exactly that.

```text
no pinned Coordinator root   →  workload = absent   (reported, never passed)
Contrast insecure platform   →  workload = simulated
pinned root, real claims     →  workload = pass
```

A compromised Coordinator can certify an arbitrary workload. That is Contrast's own trust assumption; CooL inherits it and narrows it by requiring the reader to attest the Coordinator themselves.

**No hardware run has been performed on this path.** The test fixtures carry a software-built TDX quote, and the Kubernetes manifests have not been applied to a cluster. `docs/contrast.md` §7 states exactly what was and was not tested.

```bash
npm run demo:contrast
```

End to end in about ninety seconds, with no cluster: the workload's Contrast identity, four AI changes sealed inside it, an independent verdict, then four forgeries that must fail.

## Documents and demo video

| | |
|---|---|
| **Demo video** (43s, 1080p) | [`assets/video/cool-contrast-demo.mp4`](assets/video/cool-contrast-demo.mp4) — a replay of a real `npm run demo:contrast`, not a reconstruction |
| **Technical documentation** | [PDF](docs/reports/CooL-x-Contrast-Technical-Documentation.pdf) · [Word](docs/reports/CooL-x-Contrast-Technical-Documentation.docx) — architecture, the exact binding, receipt format, verifier, trust model, threat table, full test matrix, source citations |
| **Intersections** | [PDF](docs/reports/CooL-x-Contrast-Intersections.pdf) · [Word](docs/reports/CooL-x-Contrast-Intersections.docx) — where the two systems meet, what each side gains, honest boundaries, proposed next steps |
| **In-repo reference** | [`docs/contrast.md`](docs/contrast.md) |

Both documents are generated from one content source so the PDF and Word copies cannot drift; the video is encoded from captured output of an actual run. See [`tools/docs-build/`](tools/docs-build) to rebuild either.


---

# Deployment

## Development

```bash
git clone https://github.com/Northwind-Cipher/cool-sdk.git
cd cool-sdk

npm install

npm run typecheck
npm run build
npm test
```

## Phala Cloud / Intel TDX

```bash
phala deploy \
  --compose docker-compose.yaml \
  --instance-type tdx.small
```

Mount:

```text
/var/run/dstack.sock
```

Configure:

```bash
QUOTE_VERIFIER_URL=<verifier>
COOL_EXPECTED_MEASUREMENT=<approved-measurement>
COOL_REQUIRE_HARDWARE=1
```

---

# CLI

```bash
cool status
cool seal
cool verify
cool records
cool wire
cool ui
```

---

# Validation evidence

`artifacts/` contains the recorded validation evidence generated through the documented Phala Cloud Intel TDX path.

It includes:

```text
receipts
quotes
verification outputs
tamper tests
workload-change tests
witness execution
evidence manifests
```

Start with:

```text
artifacts/closure-verification-matrix.md
```

These artifacts are historical records of specific validation runs, not a certification or third-party audit.

---

# Verification limitations

- Binding, signature and inclusion can be verified offline.
- Hardware quote verification uses the configured verifier unless local collateral is supplied.
- CooL records TCB status as `Unknown`; it does not independently evaluate TCB quality or quote freshness.
- Measurement pins are only as trustworthy as the process approving them.
- A witness demonstrates separation of key custody and process, not organizational independence.
- The documented validation uses Intel TDX CPU instances. No GPU or confidential-GPU attestation is claimed.
- On the Edgeless Contrast path, CooL verifies a Coordinator-issued credential against a root the reader pins. It does **not** independently verify the underlying TDX/SNP quote against Intel DCAP or AMD KDS, so a compromised Coordinator could certify an arbitrary workload. No hardware run has been performed on this path; see `docs/contrast.md` §7.
- No third-party certification or security audit is claimed.

---

# Standards & primitives

| Standard / primitive | Role |
|---|---|
| **FIPS 204 / ML-DSA-65** | Post-quantum digital signatures |
| **Ed25519** | Classical digital signatures |
| **FIPS 203 / ML-KEM-1024** | Post-quantum key encapsulation where used |
| **X25519** | Classical key agreement |
| **ChaCha20-Poly1305** | AEAD channel encryption |
| **SHA-256** | Cryptographic commitments and hashing |
| **CBOR** | Canonical evidence serialization |
| **RFC 6962** | Merkle transparency log |
| **RFC 3161** | Timestamping integration |
| **Intel TDX** | Confidential CPU execution and attestation |
| **Phala / dstack** | Confidential runtime and attestation |

---

# Threat model

CooL is designed for environments where the verifier should not have to blindly trust:

- the application operator,
- the application process,
- the log storage layer,
- or a cloud operator's assertion about what ran.

```text
APPLICATION
    │
    ├── cryptographic binding
    │
    ├── hybrid signature
    │
    ├── append-only transparency log
    │
    ├── independent witness
    │
    └── Phala / dstack TEE
             │
             ▼
        Intel TDX quote
             │
             ▼
      independent verifier
```

The objective is to make important claims **independently checkable**.

---

# Repository structure

```text
cool-sdk/
│
├── src/
│   ├── sdk/
│   ├── crypto/
│   ├── evidence/
│   ├── log/
│   ├── witness/
│   ├── attestation/
│   └── verification/
│
├── examples/
├── artifacts/
├── docs/
│   ├── architecture/
│   ├── evidence/
│   ├── attestation/
│   └── threat-model/
│
├── SECURITY.md
├── CONTRIBUTING.md
├── NOTICE.txt
├── LICENSE
└── README.md
```

---

# Security

For vulnerability reporting:

```text
SECURITY.md
```

Please do not disclose exploitable vulnerabilities through public GitHub issues.

---

# Contributing

```bash
npm install
npm run typecheck
npm run build
npm test
```

See `CONTRIBUTING.md`.

---

# License

CooL is licensed under the **Business Source License 1.1 (BUSL-1.1)**.

BUSL-1.1 is a source-available license and is **not an open-source license**.

### Production threshold

```text
$1,000,000 USD ARR
```

Production use is permitted if you and your affiliates, taken together, have annual recurring revenue below this threshold.

At or above that threshold, production use requires a separate commercial license from **Northwind Cipher Pvt. Ltd.**

### Change date

```text
January 1, 2030
```

On that date, or the fourth anniversary of the first public distribution of a given version, whichever comes first, that version becomes available under the **Apache License 2.0**.

Versions released before this license change, including `cool-nwc@3.0.0`, were published under Apache-2.0 and remain available under that license.

See:

```text
LICENSE
NOTICE.txt
docs/THIRD_PARTY_LICENSES.md
```

for complete licensing information.

---

<div align="center">

<a href="https://phala.com/">
<img src="https://raw.githubusercontent.com/Phala-Network/phala-docs/main/images/phala-dark.png" alt="Phala" width="360">
</a>

### POWERED BY PHALA

**Confidential execution · Hardware-backed attestation · Verifiable runtime**

<br>

**CooL × Phala**

<br>

[Phala](https://phala.com/) · [dstack](https://phala.com/dstack) · [Phala Cloud](https://cloud.phala.com/)

<br><br>

© 2026 Northwind Cipher Pvt. Ltd.

</div>
