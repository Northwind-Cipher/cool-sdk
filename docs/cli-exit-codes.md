# CLI exit codes

These are a stable contract for the platform commands `cool bundle verify`, `cool decide` and `cool gate-demo`. CI pipelines can gate on them.

| Code | Meaning | Examples |
|---|---|---|
| `0` | pass / allowed | bundle `pass`; decision `allow` or `audit_only`; demo behaved as expected |
| `1` | fail / refused | bundle `fail`; decision `deny` or `quarantine`; demo deviated |
| `2` | unknown, or a human must decide | bundle `unknown` (for example verified only against its own trust snapshot); decision `require_approval` or `defer` |
| `64` | usage error | missing argument |
| `65` | input is not valid | not JSON; invalid policy; not a `cool.bundle.v1` |
| `66` | input could not be read | file missing or unreadable |

Codes 64–66 follow BSD `sysexits.h`.

Every command also accepts `--json` and prints the full machine-readable record. The shapes are in [`spec/schemas/`](../spec/schemas/):

- `cool.verification-report.v1`
- `cool.bundle.v1`
- `cool.policy.v1`
- `cool.trust-snapshot.v1`
- `cool.envelope.v1`

## CI example

```yaml
- name: Verify the release evidence
  run: npx cool bundle verify release-bundle.json --trust trust.json
- name: Gate on policy
  run: npx cool decide release-policy.json facts.json   # exit 1 blocks the job, exit 2 needs a human
```

The older commands (`cool verify`, `cool seal`, …) keep their existing behaviour: 0 for success, 1 for failure.
