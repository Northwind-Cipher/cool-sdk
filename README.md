<div align="center">

<table width="100%" cellpadding="0" cellspacing="0" border="1" bordercolor="#3d444d">
<tr>
<td width="58%" align="center" valign="middle" bgcolor="#151b23">

<pre>
  ######    #####    #####    ##
 ##        ##   ##  ##   ##   ##
##        ##     ####     ##  ##
##        ##     ####     ##  ##
 ##        ##   ##  ##   ##   ##
  ######    #####    #####    #######
</pre>

</td>
<td width="8%" align="center" valign="middle" bgcolor="#0d1117">

<strong style="color:#cdfa50; font-size:20px;">×</strong>

</td>
<td width="34%" align="center" valign="middle" bgcolor="#151b23">

<a href="https://phala.com/">
<img src="https://raw.githubusercontent.com/Phala-Network/phala-docs/main/images/phala-dark.png" alt="Phala" width="300">
</a>

<br>

<strong style="color:#f0f6fc;">Phala</strong>

</td>
</tr>
</table>

# CooL × Phala

### The Black Box for AI · Confidential Execution

**Every AI change can be automatically captured, cryptographically recorded, and independently verified.**

<br>

<table cellpadding="10" cellspacing="0" border="0">
<tr>
<td bgcolor="#cdfa50"><strong style="color:#0d1117;">POWERED BY PHALA</strong></td>
</tr>
</table>

<sub>CONFIDENTIAL EXECUTION · HARDWARE-BACKED ATTESTATION · VERIFIABLE RUNTIME</sub>

<br><br>

[![CI](https://github.com/Northwind-Cipher/cool-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/Northwind-Cipher/cool-sdk)
[![License](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A5%2020-brightgreen.svg)](https://nodejs.org)
[![TEE](https://img.shields.io/badge/TEE-Intel%20TDX-111111?style=flat-square&labelColor=cdfa50)](https://phala.com/confidential-vm)
[![Powered by Phala](https://img.shields.io/badge/POWERED%20BY-PHALA-111111?style=flat-square&labelColor=cdfa50)](https://phala.com/)

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
- and, through the Phala-backed Intel TDX path, **where it ran** through hardware measurements and attestation evidence.

Sensitive values are committed as salted hashes and discarded; receipts never carry plaintext.

> **CooL records what happened. It does not judge whether it was correct, fair or safe.**

---

# CooL × Phala

<div align="center">

```text
CooL  ×  Phala

CRYPTOGRAPHIC OBSERVABILITY  ×  CONFIDENTIAL COMPUTING
```

<a href="https://phala.com/">
<img src="https://raw.githubusercontent.com/Phala-Network/phala-docs/main/images/phala-dark.png" alt="Phala" width="260">
</a>

### **POWERED BY PHALA**

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
| **Cryptographic verification** | Binding, signature, inclusion, witnesses, attestation | Structured verdict per domain |
| **Append-only log** | RFC 6962 Merkle tree | File-backed and in-memory logs |
| **Consistency** | `verifyLogConsistency` | Detects forks and altered heads |
| **Witness** | Independent log observer | Refuses forks and rollbacks |
| **Intel TDX** | Hardware-backed execution | Phala / dstack integration |
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
