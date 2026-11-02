#!/usr/bin/env bash
# CooL — run the enclave (production mode, NOT debug), collect a validation
# artifact, and stop the enclave. From the repo root, after build.sh:
#   examples/nitro-enclave/scripts/validate.sh
set -euo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$KIT/../.." && pwd)"
OUT="$KIT/build"
CID="${COOL_ENCLAVE_CID:-16}"
PORT="${COOL_ENCLAVE_PORT:-5005}"

# Never --debug-mode: debug enclaves report all-zero PCRs and the verifier rejects them.
nitro-cli run-enclave --eif-path "$OUT/cool.eif" --cpu-count "${COOL_CPUS:-2}" --memory "${COOL_MEMORY_MIB:-2048}" --enclave-cid "$CID" | tee "$OUT/run-enclave.json"
ENCLAVE_ID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["EnclaveID"])' "$OUT/run-enclave.json")"
trap 'nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID" >/dev/null 2>&1 || true; kill "${SOCAT_PID:-0}" 2>/dev/null || true' EXIT

socat TCP-LISTEN:"$PORT",bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:"$CID":5005 &
SOCAT_PID=$!
for _ in $(seq 1 30); do (echo > /dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && break; sleep 1; done
sleep 3 # let node start inside the enclave

export COOL_INSTANCE_TYPE="$(curl -s -m 2 -H "X-aws-ec2-metadata-token: $(curl -s -m 2 -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')" http://169.254.169.254/latest/meta-data/instance-type || echo unknown)"
export COOL_REGION="${AWS_REGION:-unknown}"
export COOL_NITRO_CLI_VERSION="$(nitro-cli --version 2>/dev/null || echo unknown)"
export COOL_EIF_SHA256="$(cat "$OUT/eif.sha256")"
export COOL_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
export COOL_ENCLAVE_PORT="$PORT"

cd "$ROOT"
node "$KIT/host/collect.mjs" "$OUT/pcrs.json" "$ROOT/artifacts/nitro-validation" "${COOL_RECEIPTS:-5}"
