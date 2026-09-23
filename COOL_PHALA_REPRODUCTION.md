# Reproducing the CooL x Phala Real-TEE Validation

## 1. Prerequisites

- Node.js 22+, npm
- Docker, logged into a registry you can push to
- Phala CLI (`npm install -g phala`), authenticated (`phala login`)
- A Phala Cloud account with available credit

## 2. Exact commit

```
git clone https://github.com/Northwind-Cipher/cool-sdk.git
cd cool-sdk
git checkout 0eaf98533a55dcea7829218f7701da48a56b8b5c
```

Apply the `src/phala/dstack.ts` fix described in `artifacts/cool-phala-validation-report.md`
("Engineering issues found and fixed", item 3) if it has not yet been merged to `main`.

## 3. Build

```sh
npm install
npm run typecheck   # expect: clean
npm run build       # expect: 82 files compiled into dist/
npm test            # expect: 85 pass / 0 fail / 1 skipped (OTS calendar test, network-dependent)
```

## 4. Build and push the validation image

```sh
docker build -t <you>/cool-phala-validation:deployment-a -f phala-validation/Dockerfile .
docker push <you>/cool-phala-validation:deployment-a
```

Expected digest (this validation's actual build):
`sha256:cc4c8b917bfacd492e6afe6e6815777c4af5108d069284542466a7fbc7f64b75`

## 5. Deploy to Phala Cloud

Edit `phala-validation/docker-compose.yaml`'s `image:` to your pushed tag, then:

```sh
phala deploy --name cool-phala-validation --compose phala-validation/docker-compose.yaml \
  --instance-type tdx.small --wait
```

## 6. Pull evidence

```sh
curl https://<app_id>-8080.<gateway-domain>/receipt   > receipt.json
curl https://<app_id>-8080.<gateway-domain>/handshake > handshake.json
curl https://<app_id>-8080.<gateway-domain>/verdict   > verdict-internal.json
```

## 7. Verify externally

```sh
node phala-validation/external-verify.mjs receipt.json out-verdict.json
```

Expected: `ok: true`, all seven domains shown individually, `attestation: pass` against
`intel-dcap`, `enclave: pass` with a non-zero MRTD.

## 8. Tamper test

```sh
node -e '
const fs = require("fs");
const r = JSON.parse(fs.readFileSync("receipt.json","utf8"));
const h = r.binding_hash;
r.binding_hash = h.slice(0,-1) + (h.slice(-1)==="0"?"1":"0");
fs.writeFileSync("tampered.json", JSON.stringify(r,null,2));
'
node phala-validation/external-verify.mjs tampered.json
```

Expected: exit code 1, `ok: false`, `binding`/`signature`/`inclusion` all `fail`.

## 9. Workload-change test

Rebuild with `--build-arg WORKLOAD_MARKER=v2`, push under a new tag, redeploy the same CVM, pull
the new receipt, and compare `record.runtime.enclave_measurement` between the two receipts — only
`rtmr3` should differ. Then run `verifyReceiptV2` with `expectedMeasurement` set to the old
receipt's measurement (expect `enclave: fail`) and then to the new one (expect `enclave: pass`).

## 10. Cleanup

```sh
phala cvms delete --cvm-id <vm_uuid> --force
```

## Security note

No secrets, credentials, or personal data are required by or embedded in any step above. The
container never receives a Phala API key, Docker credential, or any customer data — only synthetic
event metadata (`"input": "synthetic-input"`, etc).
