// CooL
// Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0
//
// Runs INSIDE the enclave. The sealer's key is generated here and never leaves;
// its attestation comes from /dev/nsm through the Rust helper. start.sh puts
// socat in front so the host reaches this over vsock port 5005.
import { serveEnclave, CommandNsmSource } from "cool-nwc/nitro";

const server = await serveEnclave({
  nsm: new CommandNsmSource("/app/cool-nsm-helper"),
  host: "127.0.0.1",
  port: 5005,
  log: (m) => console.log(`[cool-enclave] ${m}`),
});
process.on("SIGTERM", () => server.close().then(() => process.exit(0)));
