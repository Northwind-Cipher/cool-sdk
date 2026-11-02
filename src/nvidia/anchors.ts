/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Pinned NVIDIA Remote Attestation Service (NRAS) signing intermediates.
 *
 * Taken 2026-11-02 from the x5c chains in NRAS's published JWKS
 * (https://nras.attestation.nvidia.com/.well-known/jwks.json, over TLS). Every
 * one of the 208 signing keys published that day chained to one of these two
 * intermediates; both are issued by "NVIDIA Attestation Service CA 001".
 *
 * Why intermediates and not the root: NVIDIA does not publish the CA 001 root
 * at a documented location we could find, and NRAS's JWKS omits it. Pinning
 * the intermediates is therefore the strongest anchor available offline. When
 * NVIDIA rotates to a new intermediate, tokens fail `untrusted_root` until the
 * new intermediate is added here (or passed as `anchors`) — a deliberate,
 * visible failure, never a silent pass.
 *
 * Public certificates; no key material.
 */
import { createHash } from "node:crypto";

export interface NrasAnchor { readonly name: string; readonly sha256: string; readonly der: Uint8Array }

const b64 = (s: string) => Uint8Array.from(Buffer.from(s, "base64"));

export const NRAS_ANCHORS: readonly NrasAnchor[] = [
  { name: "NVIDIA Attestation Service GPU Intermediate 004", sha256: "2df8907cf4d6c277b855d407ec178a649930a8e73f7294e8fce66e6ee27c5175", der: b64("MIIDjjCCAxWgAwIBAgIUX+djej7sXIvcZ8Ym8KJF8WsI3UMwCgYIKoZIzj0EAwMwVjELMAkGA1UEBhMCVVMxGzAZBgNVBAoMEk5WSURJQSBDb3Jwb3JhdGlvbjEqMCgGA1UEAwwhTlZJRElBIEF0dGVzdGF0aW9uIFNlcnZpY2UgQ0EgMDAxMB4XDTI1MTIwODAwMDAwMFoXDTI5MTIwODAwMDAwMFowZDE4MDYGA1UEAwwvTlZJRElBIEF0dGVzdGF0aW9uIFNlcnZpY2UgR1BVIEludGVybWVkaWF0ZSAwMDQxGzAZBgNVBAoMEk5WSURJQSBDb3Jwb3JhdGlvbjELMAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCmOUQzlKU+iKzdXwJZBpjIwkO2ZhrbeevIScmqL6QdkZMdj9FKxFResOdPoJA0IxMDwYFMy87MIJYV/hRAo9ut6q0OZiZwPFSfxqN+ZcDyFMkYEnHvMgFaSuYxMiNWm9WcOcOih8FdX0s8qmkHq+NM48l8R7VNhX0HB2IZ2mxp4nH/dxpFcbpRavaECEvLqbUSvSNAmg+xNCCVsihKPF/rksGZK1wky6E8HcydYxydK2MP95dc5Ovqq80COxCPgsjgUN/JT9Gr9iNXaof9W2ZKqasCjADRfITS7N9SQsp7Jv6UudT5tFbFKp7gCKwpjjUgQEUo3JkWTHiBuRrBZWFAgMBAAGjgecwgeQwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwSAYDVR0fBEEwPzA9oDugOYY3aHR0cDovL2NybC5uZGlzLm52aWRpYS5jb20vY3JsLW5yYXMvbnYtbnJhcy1sMS1yb290LmNybDA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLm5kaXMubnZpZGlhLmNvbTAdBgNVHQ4EFgQU+qgA049NpzpcZ2zfUTukavKMrt0wHwYDVR0jBBgwFoAUvgpv7XnCSKqKNwsm9oU3MWxyBL8wCgYIKoZIzj0EAwMDZwAwZAIwEaF8qbwlAoAWNm7WNnqdECSs9uQxqQkl1eQLKJIVEC+XsHTL2SGBrbUGlLX89zf/AjAL0Xav/uW7dMhqSqqE86RiojGbZR5jRNtWAJIw/YH9yBAJ5ktCAqSSfrJ4qjzf48U=") },
  { name: "NVIDIA Attestation Service GPU Intermediate 005", sha256: "38e3daf3cdbd5243bb15dd7993edcdd83a7238cb6745b980f8f3bf0a31a0d343", der: b64("MIIC4jCCAmegAwIBAgIUUA5gzr8tQT0EoBlM29wXhOqPYzIwCgYIKoZIzj0EAwMwVjELMAkGA1UEBhMCVVMxGzAZBgNVBAoMEk5WSURJQSBDb3Jwb3JhdGlvbjEqMCgGA1UEAwwhTlZJRElBIEF0dGVzdGF0aW9uIFNlcnZpY2UgQ0EgMDAxMB4XDTI2MTAwODAwMDAwMFoXDTMwMTAwODAwMDAwMFowZDE4MDYGA1UEAwwvTlZJRElBIEF0dGVzdGF0aW9uIFNlcnZpY2UgR1BVIEludGVybWVkaWF0ZSAwMDUxGzAZBgNVBAoMEk5WSURJQSBDb3Jwb3JhdGlvbjELMAkGA1UEBhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATQp9Q+gScoaTQJ/NNrEi7gGYQkkQoCas87/f0mbC0pzHhbBY1TsYbcRV+CJgA4j1vguKu+PfZMAhmmk+q0QqDFZjgOdLXD4QyfHA9a8J94Ya9lxdbiDVCrBhreV+5m3rejgecwgeQwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwSAYDVR0fBEEwPzA9oDugOYY3aHR0cDovL2NybC5uZGlzLm52aWRpYS5jb20vY3JsLW5yYXMvbnYtbnJhcy1sMS1yb290LmNybDA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLm5kaXMubnZpZGlhLmNvbTAdBgNVHQ4EFgQUgoIlnImhSWPJeddVjBGaSfESoVowHwYDVR0jBBgwFoAUvgpv7XnCSKqKNwsm9oU3MWxyBL8wCgYIKoZIzj0EAwMDaQAwZgIxAPnYkYQNCuVVW4lie+m5+upg8HYyvFYzYq7c5P6Ias2FVmbSIyX29DHHyLRV4iVntAIxAP0CwaKo6eRNz7dQuJwpYsIaVq7xtl8xWreBl9u7KFkj6kB5RXK5IjfUN4zQOStG8A==") },
];

for (const a of NRAS_ANCHORS) {
  if (createHash("sha256").update(a.der).digest("hex") !== a.sha256) throw new Error(`pinned ${a.name} does not match its fingerprint`);
}
