# CooL — the enclave image for `nitro-cli build-enclave`.
#
# Build context: examples/nitro-enclave/, with the packed SDK copied in as
# cool-nwc.tgz by scripts/build.sh (so the enclave runs exactly this commit).
#
# Reproducibility: base images are pinned by digest-free tags here for
# readability; for a release, pin them by digest and record the resulting
# PCR0/1/2 — those measurements, not this file, are what the verifier trusts.

FROM rust:1.95-slim-bookworm AS nsm
WORKDIR /src
COPY nsm-helper/ ./
RUN cargo build --release --locked \
 && cp target/release/cool-nsm-helper /cool-nsm-helper

FROM node:22-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends socat \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY cool-nwc.tgz ./
RUN npm init -y >/dev/null \
 && npm install --omit=dev --no-audit --no-fund ./cool-nwc.tgz \
 && rm cool-nwc.tgz
COPY --from=nsm /cool-nsm-helper /app/cool-nsm-helper
COPY enclave/server.mjs enclave/start.sh ./
RUN chmod +x /app/start.sh /app/cool-nsm-helper
ENV NODE_ENV=production
CMD ["/app/start.sh"]
