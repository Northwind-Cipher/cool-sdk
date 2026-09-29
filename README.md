<div align="center">

<table>
<tr>
<td align="center" bgcolor="#0D1117">

<br>

<font color="#CDFA50" size="6"><b>C O O L</b></font>

<br><br>

<font color="#FFFFFF" size="7"><b>THE BLACK BOX FOR AI.</b></font>

<br>

<font color="#A7B0BA" size="4">
Cryptographic observability for AI execution.
</font>

<br><br>

<table>
<tr>
<td bgcolor="#CDFA50" width="74" height="74" align="center" valign="middle">
<font color="#0D1117" size="6"><b>▰<br>▐<br>▰</b></font>
</td>
<td bgcolor="#0D1117" width="18"></td>
<td bgcolor="#0D1117">
<font color="#FFFFFF" size="6"><b>PHALA</b></font>
<br>
<font color="#8B949E" size="2">CONFIDENTIAL COMPUTING</font>
</td>
</tr>
</table>

<br>

<font color="#CDFA50"><b>POWERED BY PHALA</b></font>
<br>
<font color="#8B949E">TEE ATTESTATION · HARDWARE-BACKED EXECUTION · VERIFIABLE RUNTIME</font>

<br><br>

</td>
</tr>
</table>

<br>

[![CI](https://github.com/Northwind-Cipher/cool-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/Northwind-Cipher/cool-sdk/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-BUSL--1.1-111111?style=flat-square&labelColor=cdfa50&color=111111)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A5%2020-111111?style=flat-square&labelColor=cdfa50&color=111111)](https://nodejs.org)
[![Intel TDX](https://img.shields.io/badge/TEE-Intel%20TDX-111111?style=flat-square&labelColor=cdfa50&color=111111)](https://phala.com/confidential-vm)
[![Phala](https://img.shields.io/badge/POWERED%20BY-PHALA-111111?style=flat-square&labelColor=cdfa50&color=111111)](https://phala.com/)

</div>

---

<div align="center">

### `evidence > claims`

**Every AI execution should leave behind evidence that another party can verify.**

</div>

---

## ◼ What is CooL?

CooL is a developer SDK and CLI for producing **independently verifiable evidence about what software did**.

An application records an event. CooL turns that event into a self-contained receipt that can be checked later without an account and without trusting the CooL process that created it.

```text
╔══════════════════════════════════════════════════════════════════════╗
║                         AI APPLICATION                              ║
║                                                                      ║
║     model ───── input ───── output ───── metadata ───── event      ║
╚══════════════════════════════════╤═══════════════════════════════════╝
                                   │
                                   ▼
                    ┌──────────────────────────┐
                    │          CooL            │
                    │                          │
                    │  CANONICALIZE            │
                    │       ↓                  │
                    │  COMMIT                  │
                    │       ↓                  │
                    │  SIGN                    │
                    │       ↓                  │
                    │  LOG                     │
                    │       ↓                  │
                    │  ATTEST                  │
                    └────────────┬─────────────┘
                                 │
                                 ▼
          ╔══════════════════════════════════════════════════╗
          ║                 CooL RECEIPT                     ║
          ║                                                  ║
          ║  binding hash        hybrid signature            ║
          ║  Merkle proof        witness evidence            ║
          ║  TEE measurement    attestation evidence        ║
          ╚══════════════════════╤═══════════════════════════╝
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │  INDEPENDENT VERIFIER    │
                    │                          │
                    │  "Does the evidence     │
                    │   actually check out?"   │
                    └──────────────────────────┘
```

CooL records **what happened**.

It does not decide whether what happened was correct, fair, safe, or desirable.

---

# ◼ CooL × Phala

<div align="center">

```text
┌───────────────────────────────────────────────────────────────────┐
│                           C O O L                                 │
│                                                                   │
│   CRYPTOGRAPHIC OBSERVABILITY                                    │
│                                                                   │
│   Evidence        Commitments        Signatures        Receipts   │
│       │                │                  │               │       │
└───────┼────────────────┼──────────────────┼───────────────┼───────┘
        │                │                  │               │
        └────────────────┴──────────────────┴───────────────┘
                               │
                               ▼
╔═══════════════════════════════════════════════════════════════════╗
║                           PHALA                                   ║
║                                                                   ║
║   CONFIDENTIAL EXECUTION                                          ║
║                                                                   ║
║   dstack            Workload Identity        Key Sealing          ║
║       │                    │                      │               ║
║       └────────────────────┴──────────────────────┘               ║
║                              │                                    ║
║                              ▼                                    ║
║                         INTEL TDX                                 ║
║                              │                                    ║
║                              ▼                                    ║
║                       HARDWARE QUOTE                              ║
╚══════════════════════════════╤════════════════════════════════════╝
                               │
                               ▼
                    ┌───────────────────────┐
                    │ INDEPENDENT VERIFIER  │
                    └───────────────────────┘
```

### `CooL` provides the evidence layer.
### `Phala` provides the confidential execution and attestation substrate.

</div>

CooL's hardware-backed execution path integrates with **Phala / dstack** and **Intel TDX** to bind cryptographic evidence to a measured confidential runtime.

Phala resources:

- [Phala](https://phala.com/)
- [dstack](https://phala.com/dstack)
- [Confidential VM](https://phala.com/confidential-vm)
- [Phala Cloud](https://cloud.phala.com/)

---

# ◼ The evidence stack

```text
                    ┌────────────────────────────┐
                    │       APPLICATION          │
                    │       AI / MODEL           │
                    └─────────────┬──────────────┘
                                  │
                                  ▼
                    ┌────────────────────────────┐
                    │       COOL EVIDENCE        │
                    │                            │
                    │  canonical CBOR            │
                    │  deterministic record       │
                    │  salted commitments        │
                    └─────────────┬──────────────┘
                                  │
                                  ▼
                    ┌────────────────────────────┐
                    │       CRYPTOGRAPHY         │
                    │                            │
                    │  ML-DSA-65 + Ed25519       │
                    │  SHA-256 binding            │
                    └─────────────┬──────────────┘
                                  │
                                  ▼
                    ┌────────────────────────────┐
                    │       TRANSPARENCY         │
                    │                            │
                    │  RFC 6962 Merkle tree      │
                    │  signed tree heads         │
                    │  inclusion proofs          │
                    └─────────────┬──────────────┘
                                  │
                         ┌────────┴────────┐
                         ▼                 ▼
              ┌─────────────────┐  ┌──────────────────┐
              │    WITNESS      │  │  PHALA / DSTACK  │
              │                 │  │                  │
              │ independent     │  │ confidential     │
              │ observation     │  │ execution        │
              └────────┬────────┘  └─────────┬────────┘
                       │                     │
                       └──────────┬──────────┘
                                  ▼
                    ┌────────────────────────────┐
                    │       VERIFICATION         │
                    │                            │
                    │ binding                    │
                    │ signature                  │
                    │ inclusion                  │
                    │ witness                    │
                    │ attestation                │
                    └────────────────────────────┘
```

---

# ◼ Capabilities

| Capability | What it does |
|---|---|
| **SDK** | `CooL` for simple use, `CoolTee` for advanced policy and hardware control |
| **Receipts** | `cool.receipt.v2` containing signed `cool.evidence.v1` |
| **Canonical evidence** | Deterministic CBOR serialization |
| **Sensitive-data protection** | Salted commitments instead of plaintext values |
| **Hybrid signatures** | ML-DSA-65 + Ed25519 |
| **Append-only log** | RFC 6962 Merkle tree with signed tree heads |
| **Inclusion proofs** | Proves a receipt belongs to the log |
| **Consistency verification** | Detects forks, rollbacks and altered histories |
| **Witnesses** | Independent process observes, verifies and signs log state |
| **Phala integration** | Phala / dstack confidential execution |
| **Intel TDX** | Hardware-backed execution measurement and quote binding |
| **Attestation** | Configured quote verification |
| **Runtime status** | Evidence-derived hardware state |
| **CLI** | `status`, `seal`, `verify`, `records`, `wire`, `ui` |
| **Fail closed** | `COOL_REQUIRE_HARDWARE=1` |

---

# ◼ Verification is not a boolean

CooL deliberately does **not** collapse every security property into:

```text
true
```

Instead:

```text
┌────────────────────────────────────────────────────┐
│                 VERIFICATION                       │
├───────────────────┬────────────────────────────────┤
│ Binding           │ PASS                           │
│ Signature         │ PASS                           │
│ Inclusion         │ PASS                           │
│ Consistency       │ PASS                           │
│ Witness           │ PASS                           │
│ Attestation       │ PASS                           │
└───────────────────┴────────────────────────────────┘
```

Each evidence domain can be evaluated independently.

That distinction matters when a verifier needs to know **which claim is supported by which evidence**.

---

# ◼ Quick start

```bash
npm install cool-nwc
```

**Node.js >= 20**

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

# ◼ What is actually inside a receipt?

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

Sensitive values are committed as salted hashes and discarded.

Receipts do not carry plaintext payloads.

---

# ◼ Cryptographic model

### `01` Canonicalization

```text
EVENT
  │
  ▼
CANONICAL CBOR
  │
  ▼
DETERMINISTIC BYTES
```

### `02` Binding

```text
software identity ──┐
model identity ─────┤
input commitment ───┤
output commitment ──┤──► EVIDENCE ──► BINDING HASH
timestamp ──────────┤
metadata ───────────┘
```

### `03` Hybrid signature

```text
                         BINDING HASH
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
                ML-DSA-65           Ed25519
                    │                   │
                    └─────────┬─────────┘
                              ▼
                       SIGNED EVIDENCE
```

### `04` Transparency

```text
RECEIPT
   │
   ▼
MERKLE LEAF
   │
   ▼
RFC 6962 TREE
   │
   ▼
SIGNED TREE HEAD
   │
   ▼
INCLUSION PROOF
```

---

# ◼ Confidential execution

The hardware path is backed by **Phala / dstack + Intel TDX**.

```text
┌─────────────────────────────────────┐
│              CooL SDK               │
│                                     │
│  evidence · signing · transparency  │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│             PHALA / DSTACK          │
│                                     │
│  workload identity                  │
│  measurements                       │
│  key sealing                        │
│  quote retrieval                    │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│              INTEL TDX              │
│                                     │
│  confidential VM                    │
│  hardware-backed isolation          │
└──────────────────┬──────────────────┘
                   │
                   ▼
             HARDWARE QUOTE
                   │
                   ▼
┌─────────────────────────────────────┐
│         INDEPENDENT VERIFIER        │
│                                     │
│ quote · measurement · identity      │
│ policy · evidence                   │
└─────────────────────────────────────┘
```

---

# ◼ Hardware status

The current validation path uses **real Phala-backed Intel TDX execution**.

Production can be configured to fail closed:

```bash
COOL_REQUIRE_HARDWARE=1
```

The expected chain is:

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
VERIFIER
     │
     ▼
REAL
```

A reachable endpoint is not treated as proof of hardware.

---

# ◼ Deployment

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

# ◼ CLI

```bash
cool status
cool seal
cool verify
cool records
cool wire
cool ui
```

---

# ◼ Validation evidence

The repository contains recorded validation material under:

```text
artifacts/
```

Start with:

```text
artifacts/closure-verification-matrix.md
```

The evidence set includes:

```text
receipts
quotes
verification outputs
tamper tests
workload-change tests
witness execution
evidence manifests
```

These artifacts are historical records of specific validation runs.

They are not a third-party certification or a blanket security guarantee for every deployment.

---

# ◼ Standards & primitives

| Standard / primitive | Role |
|---|---|
| **FIPS 204 / ML-DSA-65** | Post-quantum signatures |
| **Ed25519** | Classical signatures |
| **FIPS 203 / ML-KEM-1024** | Post-quantum key encapsulation where used |
| **X25519** | Classical key agreement |
| **ChaCha20-Poly1305** | AEAD channel encryption |
| **SHA-256** | Hashing and commitments |
| **CBOR** | Canonical serialization |
| **RFC 6962** | Merkle transparency log construction |
| **RFC 3161** | Timestamping integration |
| **Intel TDX** | Confidential CPU execution and attestation |
| **Phala / dstack** | Confidential runtime and attestation infrastructure |

---

# ◼ Threat model

CooL is designed for environments where the verifier should not have to blindly trust the application operator or storage layer.

```text
                         APPLICATION
                              │
                              ▼
                     CRYPTOGRAPHIC BINDING
                              │
                              ▼
                       HYBRID SIGNATURE
                              │
                              ▼
                       TRANSPARENCY LOG
                              │
                              ▼
                           WITNESS
                              │
                              ▼
                       PHALA / DSTACK
                              │
                              ▼
                         INTEL TDX
                              │
                              ▼
                     INDEPENDENT VERIFIER
```

The objective is not to make every component magically trustworthy.

The objective is to make important claims **independently checkable**.

---

# ◼ Security boundaries

CooL proves specific properties about execution evidence.

It does **not** by itself prove:

- model correctness
- output quality
- fairness
- legal compliance
- policy compliance
- safety
- desirability

A valid cryptographic receipt is evidence about **execution**, not a certificate that the result was good.

---

# ◼ Repository

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
├── SECURITY.md
├── CONTRIBUTING.md
├── NOTICE.txt
├── LICENSE
└── README.md
```

---

# ◼ Security

For vulnerability reporting:

```text
SECURITY.md
```

Please do not disclose exploitable vulnerabilities through public GitHub issues.

---

# ◼ Contributing

```bash
npm install
npm run typecheck
npm run build
npm test
```

See:

```text
CONTRIBUTING.md
```

---

# ◼ License

CooL is licensed under the **Business Source License 1.1 (BUSL-1.1)**.

BUSL-1.1 is a source-available license, not an open-source license.

### Production threshold

```text
$1,000,000 USD ARR
```

Production use is permitted when you and your affiliates, taken together, have annual recurring revenue below this threshold.

At or above the threshold, production use requires a separate commercial license from **Northwind Cipher Pvt. Ltd.**

### Change date

```text
January 1, 2030
```

On the change date, or the fourth anniversary of first public distribution of a given version, whichever comes first, that version becomes available under:

```text
Apache License 2.0
```

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

<table>
<tr>
<td bgcolor="#0D1117" align="center">

<font color="#CDFA50" size="6"><b>C O O L</b></font>

<br><br>

<font color="#FFFFFF" size="5"><b>THE BLACK BOX FOR AI.</b></font>

<br><br>

<font color="#CDFA50"><b>POWERED BY PHALA</b></font>

<br>

<font color="#8B949E">CONFIDENTIAL EXECUTION · HARDWARE-BACKED ATTESTATION · VERIFIABLE RUNTIME</font>

<br><br>

**© 2026 Northwind Cipher Pvt. Ltd.**

</td>
</tr>
</table>

</div>
