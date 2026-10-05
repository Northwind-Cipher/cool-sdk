#!/usr/bin/env bash
#
# Deploy the CooL × Contrast example onto a Contrast-enabled Kubernetes cluster.
#
# This script does not hide anything: it is the five `contrast` commands from
# Edgeless's own workload-deployment guide, in order, with the one CooL-specific
# step (publishing the manifest to the pod) in the middle. Read it before you
# run it.
#
# Requires: kubectl pointed at a cluster with the Contrast node-installer and
# runtime class already applied, and the `contrast` CLI on PATH. Neither is
# something this script should install for you on a cluster you care about.
#
#   ./deploy.sh <platform>
#
# where <platform> is one of the platforms your Contrast release supports, e.g.
# metal-qemu-tdx, metal-qemu-snp, aks-clh-snp. Run `contrast generate --help`
# for the list your release actually has.
set -euo pipefail

PLATFORM="${1:-}"
NAMESPACE="${NAMESPACE:-default}"
COORDINATOR="${COORDINATOR:-}"

if [[ -z "$PLATFORM" ]]; then
  echo "usage: ./deploy.sh <platform>   (e.g. metal-qemu-tdx)" >&2
  exit 2
fi

for tool in kubectl contrast; do
  command -v "$tool" >/dev/null || { echo "error: $tool is not on PATH" >&2; exit 1; }
done

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

# ── 1 · the Coordinator ───────────────────────────────────────────────────
#
# The Coordinator is itself a confidential VM. Everything downstream rests on
# it, which is why it is deployed from Edgeless's own release artefact rather
# than from anything in this repository.
step "1/6  deploying the Contrast Coordinator"
if ! kubectl -n "$NAMESPACE" get deployment coordinator >/dev/null 2>&1; then
  RELEASE="$(contrast --version 2>/dev/null | head -1 | awk '{print $NF}')"
  echo "    fetching coordinator.yml for Contrast ${RELEASE:-latest}"
  curl -fsSLO "https://github.com/edgelesssys/contrast/releases/${RELEASE:+download/$RELEASE/}${RELEASE:-latest/download/}coordinator.yml"
  kubectl -n "$NAMESPACE" apply -f coordinator.yml
else
  echo "    already present"
fi
kubectl -n "$NAMESPACE" rollout status deployment/coordinator --timeout=5m

if [[ -z "$COORDINATOR" ]]; then
  COORDINATOR="$(kubectl -n "$NAMESPACE" get svc coordinator \
    -o jsonpath='{.status.loadBalancer.ingress[0].ip}{.status.loadBalancer.ingress[0].hostname}')"
  [[ -n "$COORDINATOR" ]] || { echo "error: set COORDINATOR=<host> — the coordinator service has no external address" >&2; exit 1; }
fi
echo "    coordinator at $COORDINATOR"

# ── 2 · generate ──────────────────────────────────────────────────────────
#
# This is where Contrast rewrites the Deployment: it injects the initializer and
# the service-mesh sidecar, mounts the shared /contrast volume, pins the
# platform runtime class, and writes manifest.json with the reference values and
# the policy hash of every pod.
step "2/6  contrast generate (platform: $PLATFORM)"
contrast generate --reference-values "$PLATFORM" k8s/ai-service.yaml

echo
echo "    policy hashes now in manifest.json:"
node -e '
  const m = JSON.parse(require("fs").readFileSync("manifest.json", "utf8"));
  for (const [hash, p] of Object.entries(m.Policies ?? {})) {
    console.log(`      ${hash}  ${(p.SANs ?? []).join(", ")}  secret=${p.WorkloadSecretID ?? "(none)"}`);
  }
' || true

# ── 3 · the manifest, into the pod ────────────────────────────────────────
#
# The one CooL-specific step. CooL seals the manifest's DIGEST into every
# receipt, so each record states which manifest governed it. The pod needs the
# bytes to compute that digest.
step "3/6  publishing manifest.json to the workload"
kubectl -n "$NAMESPACE" create configmap contrast-manifest \
  --from-file=manifest.json=manifest.json \
  --dry-run=client -o yaml | kubectl -n "$NAMESPACE" apply -f -

# ── 4 · set ───────────────────────────────────────────────────────────────
step "4/6  contrast set — telling the Coordinator which pods are allowed"
contrast set -c "$COORDINATOR:1313" k8s/ai-service.yaml

# ── 5 · apply ─────────────────────────────────────────────────────────────
step "5/6  applying the workload"
kubectl -n "$NAMESPACE" apply -f k8s/ai-service.yaml
kubectl -n "$NAMESPACE" rollout status deployment/ai-service --timeout=10m

# ── 6 · verify ────────────────────────────────────────────────────────────
#
# Remote attestation of the Coordinator CVM against the manifest's reference
# values. This is what makes verify/coordinator-root-ca.pem worth pinning, and
# therefore what makes every CooL receipt from this deployment checkable.
step "6/6  contrast verify — attesting the Coordinator"
contrast verify -c "$COORDINATOR:1313"

cat <<EOF

Deployed. The two files an auditor needs are now on disk:

  verify/coordinator-root-ca.pem   the attested Coordinator root
  manifest.json                    the deployment you approved

Exercise it:

  kubectl -n $NAMESPACE port-forward deployment/ai-service 8080:8080 &
  curl -s localhost:8080/identity | jq .contrast
  curl -s -XPOST localhost:8080/change -d '{"kind":"prompt","ref":"billing/refund-agent#system","after":"Escalate above \$200."}'
  curl -s localhost:8080/receipts > receipts.json

Then verify independently — no cluster access required:

  node verify.mjs receipts.json \\
    --coordinator-root verify/coordinator-root-ca.pem \\
    --manifest manifest.json \\
    --require-hardware

EOF
