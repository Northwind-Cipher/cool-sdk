# Security policy

## Supported versions

| Version | Supported |
|---|---|
| `3.x` | yes |
| `< 3.0` | no |

## Reporting a vulnerability

Please **do not** open a public issue for a security report.

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**), or email the maintainers at the address
listed on the organisation profile. Include:

- affected version(s) and platform,
- a description of the issue and its impact,
- a minimal reproduction if you have one.

We aim to acknowledge within 3 working days and to ship a fix or a mitigation
plan within 30 days for a confirmed issue. We will credit reporters who want it
once a fix is released.

## What is in scope

- Forging or silently editing a receipt that still verifies `ok`.
- Making a `simulated` receipt verify as hardware-backed.
- Bypassing `requireAttestation` / `requireHardware`.
- Canonicalization ambiguities (two logical values, one signature).
- Signature / algorithm confusion in the verifier.
- Secret material (keys, salts, plaintext payloads) reaching logs, receipts, or
  the npm tarball.
- Arbitrary code execution during `npm install` or first use.

## What is out of scope

- Compromised application logic that produces valid evidence of the wrong thing.
- TEE hardware vulnerabilities and vendor attestation-service compromise.
- Denial of service against a self-hosted transparency or verifier endpoint.
- Incorrect trust roots configured by the operator.

## Security architecture

See [`docs/security-model.md`](docs/security-model.md) and
[`docs/threat-model.md`](docs/threat-model.md).

Design invariants the test suite enforces on every commit:

- the receipt never contains plaintext metadata or payloads;
- a single edited byte breaks both `binding` and `signature`;
- a valid quote cannot be stapled onto a record it did not attest;
- the verifier never throws on malformed input — it returns a failed verdict;
- `simulated` is never reported as `pass`.
