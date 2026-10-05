# contrast-fixture

Regenerates `tests/fixtures/contrast-fixtures.json` — the Contrast Coordinator
artefacts the CooL × Contrast conformance tests read.

The point of this tool is that **CooL does not write its own test fixtures for
Contrast's certificate format.** `main.go` calls Contrast's own packages, so the
certificates come out of the same code path a live Coordinator uses:

| what it calls | what that gives |
| --- | --- |
| `internal/seedengine.New` → `RootCAKey`, `GenerateMeshCAKey`, `DeriveWorkloadSecret` | the Coordinator's real key hierarchy and workload-secret derivation |
| `internal/ca.New` → `NewAttestedMeshCert` | the real cross-signed CA and the real mesh certificate template |
| `internal/attestation/tdx.Report.ClaimsToCertExtension` | the real TDX claim → X.509 extension encoding |
| `internal/oid.WorkloadSecretOID` | the real workload-secret extension |

A test that asserts "CooL recovered this MRTD" is therefore asserting agreement
between Contrast's Go encoder and CooL's TypeScript decoder, not agreement with
something CooL made up.

## What is synthetic

The TDX quote whose claims are copied into the extensions is built in-process.
A real Coordinator gets that quote from the workload's aTLS handshake and
verifies it against Intel DCAP before issuing anything. **No confidential
hardware is involved here, and the fixtures prove nothing about hardware** —
only that CooL binds to, parses and enforces the credential format correctly.

## Running it

Contrast's packages are `internal/`, so the tool only compiles inside a Contrast
checkout. It is kept here as source rather than vendored along with its
dependencies: Contrast is BUSL-1.1 under Edgeless Systems' terms, and nothing of
theirs is copied into or redistributed from this repository.

```sh
git clone --depth 1 https://github.com/edgelesssys/contrast.git
mkdir -p contrast/coolfixture
cp tools/contrast-fixture/main.go contrast/coolfixture/main.go
cd contrast && go run ./coolfixture -out ../cool-sdk/tests/fixtures/contrast-fixtures.json
```

Certificate serial numbers and validity windows come from `crypto/rand` and the
clock, so a regenerated fixture set is equivalent but not byte-identical. The
Coordinator seed and salt are fixed, so the CA keys, the policy hashes and the
workload secrets are stable across runs.

## What it generates

| workload | why it exists |
| --- | --- |
| `ai-service` | the happy path: TDX claims, a policy hash in the manifest, a workload secret |
| `restarted-ai-service` | same identity, fresh certificate — proves the sealed key survives pod churn |
| `sidecar-service` | a second genuine workload, for cross-workload substitution tests |
| `upgraded-ai-service` | same policy hash, different MRTD — a rebuilt image must fail a register pin |
| `insecure-service` | Contrast's non-CC platform: a certificate with **no** attestation claims |
| `no-secret-service` | no `WorkloadSecretID`, so no workload secret is released |
| `ai-service-rogue-coordinator` | the same identity certified by a Coordinator nobody attested |

Plus both Coordinators' root and mesh CAs, the `manifest.json` text, and the
policy hashes and measurements the tests compare against — all in one JSON file.

Certificates and keys are stored as **base64 DER, not PEM**. This repository
forbids committed `.pem` files and PEM private-key blocks
(`.github/workflows/security.yml`), and that rule is worth keeping literal.
`tests/support/contrast-pod.ts` writes a pod layout back out into a temporary
directory at run time, so the tests still exercise the real file paths and the
real PEM parsing. The keys are disposable and protect nothing.
