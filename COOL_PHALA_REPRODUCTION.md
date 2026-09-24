# Reproducing the CooL x Phala Real-TEE Validation

Two deployments are used. Keep them distinct:

| Role | Compose file | Image (registry tag / digest recorded in the run) |
|---|---|---|
| **Deployment A - primary validation image** | `phala-validation/docker-compose.deployment-a.yaml` | `runtime-a` / `sha256:a8a5f42c092771d65508e152a4cdffb5199ef1242622328a0fff083bd2f13633` (the earlier validation evidence used `final-a`, `sha256:3535a90e…`; the workload now also runs the CLI status check) |
| **Deployment B - workload-change test only** | `phala-validation/docker-compose.deployment-b.yaml` | `final-b` (`WORKLOAD_MARKER=v2`) / `sha256:1372fbe7ab61418519772146e59765a042c16a5d3f0080c1356e1cff4875ebca` |

Historical Run 1 evidence (commit de7230b, images `deployment-a` / `deployment-b`) is preserved under `artifacts/` and is
not what these compose files reference.

## 1. Prerequisites

- Node.js 22+, npm; Docker logged in to a registry you control; Phala CLI (`npm i -g phala`) authenticated (`phala login`); Phala Cloud credit (a run costs a few cents).
- Network access to `https://cloud-api.phala.com/api/v1/attestations/verify` (attestation verification is online).
- Accounts/credentials required: Phala Cloud, a container registry. No secrets are placed in any repository file or container.

## 2. Build and test

```sh
git clone https://github.com/Northwind-Cipher/cool-sdk.git && cd cool-sdk
npm install
npm run typecheck && npm run build && npm test     # expect 97 tests: 96 pass, 0 fail, 1 skipped (network-dependent)
```

## 3. Build and push the images

Image digests are not reproducible builds: rebuilding yields new digests and new RTMR3 values. Use your own registry and
record the digests you obtain.

```sh
docker build -t <you>/cool-phala-validation:final-a --build-arg WORKLOAD_MARKER=v1 -f phala-validation/Dockerfile .
docker build -t <you>/cool-phala-validation:final-b --build-arg WORKLOAD_MARKER=v2 -f phala-validation/Dockerfile .
docker push <you>/cool-phala-validation:final-a && docker push <you>/cool-phala-validation:final-b
```

In both compose files set `image:` to your tag and `COOL_IMAGE_DIGEST` to the pushed digest of that same image (the digest is only
known after the push, so this is a second edit).

## 4. Deploy A and collect evidence

```sh
phala deploy --name cool-phala-final --compose phala-validation/docker-compose.deployment-a.yaml --instance-type tdx.small --wait
phala cvms get --cvm-id <vm_uuid> --json        # read endpoints.app (the gateway host depends on the node)
curl <app-endpoint>/receipts > receipts-A.json
```

## 5. Deploy B to the same CVM and collect evidence

```sh
phala deploy --cvm-id <vm_uuid> --compose phala-validation/docker-compose.deployment-b.yaml --wait
curl <app-endpoint>/receipts > receipts-B.json
phala cvms delete --cvm-id <vm_uuid> --force    # then: phala cvms list  -> total 0
```

## 6. Verify outside the CVM

```sh
node phala-validation/final-verify.mjs receipts-A.json receipts-B.json out/
```

Writes `binding-`, `signature-`, `inclusion-`, `consistency-`, `witness-`, `attestation-`, `enclave-domain-final.json`,
`workload-change-final.json`, `tamper-final.json`, `tamper-final/`, `final-external-verification.json` and the raw Phala
API response. Exit code 0 means every check that must hold did hold.

Expected: all seven direct checks true; witness `operationally_independent: NOT DEMONSTRATED`; `B_against_A_pin` fails on `rtmr3`;
`B_against_B_pin` and historical A pass; binding_hash tamper fails binding, signature, inclusion; metadata_hash tamper fails binding and signature.

Optional local DCAP check using the collateral archived in the Phala response:

```sh
npm i --no-save @phala/dcap-qvl
node phala-validation/offline-dcap-verify.mjs receipts-A.json out/phala-attestation-api-response-A.json out/offline-dcap-verification-A.json
```

Expected: `result: PASS`, `tcb_status` reported by the library, and `negative_control.rejected: true`. This is offline at verify time only.

## 7. Witness operated by a third party (not demonstrated in this validation)

`final-verify.mjs` generates its own witness key, so it cannot show organizational independence. To do that, an independent operator runs
`cosign(sth, theirKey)` (`src/phala/witness.ts`) over the published STH (`log_id`, `tree_size`, `root_hash`, `timestamp`) and returns the statement;
the verifier obtains their public key out of band and passes it with `withTrustedKeys`.

## 8. Notes

- Measurement pins in the tests are taken from the receipts under test. Approval is procedural.
- The workload exposes only `/health`, `/receipt`, `/receipts`, `/verdict`, `/handshake`, `/environment`; Phala's default public gateway makes them internet-reachable while the CVM runs.
- The CVM used a dev OS image (`is_dev: true`). Not a production configuration.

## 9. Closure run (witness in its own CVM, consistency, tamper matrix)

1. Deploy the primary: `phala deploy --cvm-id <primary> --compose phala-validation/docker-compose.deployment-a.yaml --wait`; pull `/receipts` (8 receipts) and `/runtime`.
2. Edit `phala-validation/docker-compose.witness.yaml`: set `PRIMARY_URL` and `PRIMARY_MEASUREMENT` (the primary's five registers from the last receipt) and your image; `phala deploy --name <witness> --compose ... --instance-type tdx.small --wait`. Read `/identity`.
3. `GET <witness>/cosign?size=N` for N = 1..8 in order; `POST <witness>/cosign-presented` with forged heads (expect HTTP 409) and the genuine head (HTTP 200); save `/decisions`.
4. `phala deploy --cvm-id <primary> --compose phala-validation/docker-compose.deployment-b.yaml --wait`; pull B's `/receipts`; `GET <witness>/cosign?size=1` (expect a refusal).
5. Arrange the files as described in the header of `phala-validation/closure-verify.mjs` and run `npm i --no-save @phala/dcap-qvl && node phala-validation/closure-verify.mjs <dir>`. Exit 0 means every check held.

The old `final-verify.mjs` (self-generated witness key) is superseded and kept only to reproduce the earlier evidence.
