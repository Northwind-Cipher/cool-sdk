#!/usr/bin/env bash
# CooL — build the enclave image and the EIF, and record its measurements.
# Run on the parent EC2 instance (needs docker and nitro-cli), from the repo root:
#   examples/nitro-enclave/scripts/build.sh
set -euo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$KIT/../.." && pwd)"
OUT="$KIT/build"
mkdir -p "$OUT"

echo "› packing cool-nwc from $(git -C "$ROOT" rev-parse --short HEAD)"
( cd "$ROOT" && npm ci --no-audit --no-fund && npm run build && npm pack --pack-destination "$OUT" >/dev/null )
cp "$(ls -t "$OUT"/cool-nwc-*.tgz | head -1)" "$KIT/cool-nwc.tgz"

echo "› docker build"
docker build -t cool-enclave:latest "$KIT"

echo "› nitro-cli build-enclave"
nitro-cli build-enclave --docker-uri cool-enclave:latest --output-file "$OUT/cool.eif" | tee "$OUT/build-enclave.json"

# PCR0 (image), PCR1 (kernel+boot), PCR2 (application) — the values the verifier pins.
python3 - "$OUT/build-enclave.json" "$OUT/pcrs.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))["Measurements"]
json.dump({"version": "1", "PCR0": m["PCR0"], "PCR1": m["PCR1"], "PCR2": m["PCR2"], "PCR8": m.get("PCR8", "not_applicable")}, open(sys.argv[2], "w"), indent=2)
print("› measurements written to", sys.argv[2])
PY
sha256sum "$OUT/cool.eif" | cut -d' ' -f1 > "$OUT/eif.sha256"
rm -f "$KIT/cool-nwc.tgz"
echo "done: $OUT/cool.eif ($(cat "$OUT/eif.sha256"))"
