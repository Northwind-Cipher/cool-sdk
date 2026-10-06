# The AI workload image for a CooL × Contrast deployment.
#
# Two things matter here and nothing else does.
#
# 1. The image must be REPRODUCIBLE. Contrast measures it into the TD, the
#    measurement lands in the pod's mesh certificate, and CooL seals that
#    measurement into every receipt. A non-reproducible build makes
#    "unmodified code" unverifiable, so pin the base image by digest and commit
#    a lockfile. The digest below is a placeholder — replace it with the one you
#    actually audited.
#
# 2. The image must NOT carry a signing key. It does not need one: CooL derives
#    its key from the Contrast workload secret at start-up, which is released
#    only to a pod that passed attestation. There is no secret to bake in, leak
#    or rotate, which is the main reason this integration is worth building.
FROM node:22-alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS base

WORKDIR /app

# Dependencies first, from the lockfile only, so the layer is deterministic.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY ai-service.mjs ./

# The pod does not need to write anything. CooL holds its log in memory here;
# for a log that survives restarts, mount a volume and use FileLog from
# `cool-nwc/node` — see docs/contrast.md.
USER node

ENV NODE_ENV=production \
    PORT=8080 \
    COOL_CONTRAST_ROOT=/contrast

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:8080/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "ai-service.mjs"]
