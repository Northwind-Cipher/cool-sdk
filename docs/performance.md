# Performance

`npm run bench` (`scripts/bench.ts`) measures the hot paths in one process, with no network. The numbers depend on the machine. They are a **baseline for spotting regressions, not a published performance claim**. No CI regression gate exists yet; that is planned.

## One reference run

These numbers come from Node 24 on a Windows x64 laptop, 30 iterations each, recorded at release time:

| Operation | Median | p95 |
|---|---:|---:|
| envelope create + hybrid ML-DSA-65+Ed25519 sign | 6.7 ms | 14.3 ms |
| envelope verify (all checks) | 3.3 ms | 4.9 ms |
| authorization request (salted commitments) | 0.04 ms | 0.08 ms |
| decide (evaluate the policy + sign) | 5.4 ms | 11.6 ms |
| verify decision in enforcement mode, **with replay**, principal state and delegation chain | 6.1 ms | 6.5 ms |
| gateway invoke, end to end (request → decide → every check → nonce → execute → signed confirmation) | 17.4 ms | 25.8 ms |

## Where the time goes

- **ML-DSA-65 signing dominates.** It is pure JavaScript (`@noble/post-quantum`). A native or KMS signer changes these numbers, but not the protocol.
- **Verification is cheaper than signing**, and it is the step auditors repeat.
- **The commitments are negligible.**

## Run it yourself

```bash
npm run bench            # 50 iterations per operation
npm run bench -- 500     # more iterations for steadier medians
```
