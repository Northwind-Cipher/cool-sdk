# Governance

CooL's open core (this repository, Apache-2.0) is maintained by Northwind Cipher Pvt. Ltd. This page describes how decisions are made, so that users and contributors can rely on the open core independently of the commercial platform.

## Commitments

1. **Verification stays open.** Every verifier for CooL evidence, including evidence produced by the commercial platform, is published here under Apache-2.0. A feature that is needed to verify evidence is never moved behind a commercial licence.
2. **The format is public.** Schemas and test vectors in `spec/` are the reference. The code follows the spec, not the reverse.
3. **No telemetry** in the open core (`docs/telemetry-and-egress.md`).
4. **Licences don't change retroactively.** A version released under Apache-2.0 stays Apache-2.0.

## Roles

| Role | Who | Can |
|---|---|---|
| Maintainer | Northwind Cipher engineers listed in `CODEOWNERS` (or the repository's admins) | merge, release, triage security reports |
| Contributor | anyone | open issues and pull requests (`CONTRIBUTING.md`) |

**Security-sensitive changes need review from a second maintainer.** These are changes under `src/platform/envelope.ts`, `src/platform/trust.ts`, `src/authz/`, `src/nitro/`, any verifier, and `spec/`.

## The RFC process (format and protocol changes)

The following need an RFC: a change to a schema in `spec/schemas/`, to a domain-separation context, to an algorithm in the registry, or to the outcome vocabulary.

1. Open an issue titled `RFC: <topic>` with the motivation, the proposed change, the compatibility impact, the security considerations and the test vectors.
2. Comment for at least **14 days**. Security fixes can shorten this, and the reason is stated.
3. A maintainer records the decision (accepted / rejected / deferred) on the issue.
4. Accepted RFCs land with the schema, test vectors, tests and a `CHANGELOG.md` entry in the same pull request.

## Security reports

See `SECURITY.md`. Please report privately; do not open public issues for vulnerabilities.
