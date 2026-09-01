# The dstack example, containerised the way it would run inside a Phala CVM.
#
#   docker build -t cool-dstack-example -f examples/dstack/Dockerfile .
#   docker run --rm -v /var/run/dstack.sock:/var/run/dstack.sock cool-dstack-example
#
# Built from the repo root so it can pull in the local cool-nwc build.
FROM node:22-slim AS build
WORKDIR /sdk
COPY package.json package-lock.json* tsconfig*.json ./
COPY src ./src
COPY scripts ./scripts
RUN npm ci && npm run build

FROM node:22-slim
WORKDIR /app
COPY --from=build /sdk /sdk
COPY examples/dstack/package.json examples/dstack/index.mjs ./
# Point the example's "file:../.." dependency at the built SDK.
RUN npm pkg set dependencies.cool-nwc=file:/sdk && npm install --no-audit --no-fund
ENV NODE_ENV=production
# Inside a real CVM the guest-agent socket is mounted here.
ENV COOL_DSTACK_ENDPOINT=/var/run/dstack.sock
CMD ["node", "index.mjs"]
