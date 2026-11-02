#!/bin/sh
# CooL — enclave entrypoint. vsock:5005 → 127.0.0.1:5005 (the enclave has no other network).
set -eu
socat VSOCK-LISTEN:5005,fork,reuseaddr TCP:127.0.0.1:5005 &
exec node /app/server.mjs
