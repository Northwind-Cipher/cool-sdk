# CooL in a real AWS Nitro Enclave

This kit runs CooL's receipt sealer inside a Nitro Enclave. It then proves the run from the parent instance: it challenges the enclave with a fresh nonce, verifies the attestation against the **pinned AWS root** and the PCRs `nitro-cli` reported at build time, seals receipts, and verifies them. The result is written as a validation artifact.

**Status: ready to run; not yet run on AWS hardware.** CI builds the image and compiles the NSM helper on every pull request. The protocol is tested end to end over real sockets with a synthetic NSM (`tests/nitro-kit.test.ts`). CooL is labelled as having run in a real enclave only when an artifact with `"synthetic": false, "passed": true` is committed to `artifacts/nitro-validation/`.

## What runs where

```
parent EC2 instance                                   Nitro Enclave (no network, no disk)
───────────────────                                   ──────────────────────────────────
host/collect.mjs ── TCP 127.0.0.1:5005 ── socat ── vsock(CID 16):5005 ── socat ── server.mjs
   │  1. hello {fresh 32-byte nonce}                                               │ NitroReceiptSealer
   │  2. ← register {key_id, public keys, attestation}   ← cool-nsm-helper ← /dev/nsm
   │  3. verify: AWS root, PCR0/1/2, nonce, user_data binds the key  (nothing trusted before this)
   │  4. register {epoch} → ack;  receipt {event} → sealed envelope   (×5)
   └─ 5. verify each envelope; write artifacts/nitro-validation/nitro-validation-<time>.json
```

| File | Role |
|---|---|
| `nsm-helper/` | Rust; calls `/dev/nsm` through `aws-nitro-enclaves-nsm-api` 0.5.2. This is the helper `CommandNsmSource` needs |
| `enclave/server.mjs`, `enclave/start.sh` | enclave entrypoint: `serveEnclave()` from `cool-nwc/nitro`, with socat vsock → loopback in front |
| `Dockerfile` | the enclave image: the Rust helper plus Node 22 plus *this commit's* packed `cool-nwc` |
| `host/collect.mjs` | the parent-side verifier; `collectFromEnclave()` from `cool-nwc/nitro` |
| `scripts/build.sh` | `npm pack` → `docker build` → `nitro-cli build-enclave` → `build/pcrs.json`, `build/eif.sha256` |
| `scripts/validate.sh` | `nitro-cli run-enclave` (never debug mode) → socat bridge → collect → terminate |

## Run it

These steps need an AWS account. They cost a few cents per hour of instance time.

1. **Launch** a Nitro-capable instance with enclaves enabled. For example, `m6i.xlarge` (4 vCPU) on Amazon Linux 2023:
   ```bash
   aws ec2 run-instances --image-id resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
     --instance-type m6i.xlarge --enclave-options 'Enabled=true' --key-name <your-key> \
     --security-group-ids <sg-allowing-ssh> --subnet-id <subnet>
   ```
2. **Install** the tooling on the instance:
   ```bash
   sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker git socat nodejs npm python3
   sudo usermod -aG ne,docker ec2-user && newgrp ne
   # give the enclave 2 vCPU / 2 GiB
   sudo sed -i 's/^cpu_count:.*/cpu_count: 2/; s/^memory_mib:.*/memory_mib: 2048/' /etc/nitro_enclaves/allocator.yaml
   sudo systemctl enable --now nitro-enclaves-allocator.service docker
   ```
3. **Build and validate**:
   ```bash
   git clone https://github.com/Northwind-Cipher/cool-sdk && cd cool-sdk
   examples/nitro-enclave/scripts/build.sh
   examples/nitro-enclave/scripts/validate.sh     # exit 0 = PASSED against the real AWS root
   ```
4. **Record it.** Commit `artifacts/nitro-validation/nitro-validation-*.json` together with `build/pcrs.json`. The artifact contains:
   - the raw attestation document
   - the nonce
   - every check result
   - every sealed envelope
   - the instance type, nitro-cli version, EIF SHA-256 and commit

   Anyone can re-verify it offline:
   ```bash
   node -e "const a=require('./artifacts/nitro-validation/<file>.json'); console.log(a.passed, a.synthetic)"
   ```
   To re-check the attestation itself, run `verifyNitroAttestation` on the `attestation_b64` field with `certificateTime: "attestation-timestamp"`. That setting matters because Nitro leaf certificates live for hours.
5. **Terminate** the instance.

## What a pass proves, and what it doesn't

- **Proves:** an enclave whose image measured PCR0/1/2 as built ran under the AWS Nitro root. It answered *this* verifier's nonce. It generated a key that never left the enclave and bound that key in `user_data`. Every receipt it sealed verifies under that key, with the attestation attached.
- **Does not prove:**
  - that the image is free of bugs
  - that the host cannot deny service
  - revocation status (AWS publishes no CRL for this PKI)
  - anything about runs other than this one

Rebuilding from the same commit with the same base-image digests should reproduce the PCRs. Pin the images by digest before you rely on that.
