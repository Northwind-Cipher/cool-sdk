# CooL x Phala Cloud real-TDX validation image.
#
#   docker build -t cool-phala-validation -f phala-validation/Dockerfile .
#
# Built from the repo root so it can pull in the local cool-nwc build (pinned
# at the exact commit under validation, not the npm registry).
FROM node:22-slim AS build
WORKDIR /sdk
COPY package.json package-lock.json* tsconfig*.json ./
COPY src ./src
COPY scripts ./scripts
RUN npm ci && npm run build

FROM node:22-slim
WORKDIR /app
COPY --from=build /sdk /sdk
COPY phala-validation/package.json phala-validation/server.mjs ./
RUN npm pkg set dependencies.cool-nwc=file:/sdk && npm install --no-audit --no-fund
ENV NODE_ENV=production
ENV COOL_DSTACK_ENDPOINT=/var/run/dstack.sock
ENV PORT=8080
ARG WORKLOAD_MARKER=v1
ENV WORKLOAD_MARKER=${WORKLOAD_MARKER}
EXPOSE 8080
CMD ["node", "server.mjs"]
