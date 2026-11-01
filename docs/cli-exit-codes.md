# CLI exit codes

These are a stable contract for `cool bundle verify`. CI pipelines can gate on them.

| Code | Meaning | Examples |
|---|---|---|
| `0` | pass | bundle `pass` |
| `1` | fail | bundle `fail` (tampered, missing evidence, untrusted signer) |
| `2` | unknown | bundle `unknown`, for example verified only against the exporter's own trust snapshot |
| `64` | usage error | missing argument |
| `65` | input is not valid | not JSON; invalid policy; not a `cool.bundle.v1` |
| `66` | input could not be read | file missing or unreadable |

Codes 64–66 follow BSD `sysexits.h`.

Every command also accepts `--json` and prints the full machine-readable record. The shapes are in [`spec/schemas/`](../spec/schemas/):

- `cool.verification-report.v1`
- `cool.bundle.v1`
- `cool.trust-snapshot.v1`
- `cool.envelope.v1`

## CI example

```yaml
- name: Verify the release evidence
  run: npx cool bundle verify release-bundle.json --trust trust.json
```

The older commands (`cool verify`, `cool seal`, …) keep their existing behaviour: 0 for success, 1 for failure.
