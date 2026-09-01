# Examples

Each folder is a self-contained project. From inside one:

```sh
npm install      # links the local build of cool-nwc
npm start
```

| Example | What it shows |
|---|---|
| [`basic/`](basic) | Record one piece of evidence, verify it. The 30-second integration. |
| [`verification/`](verification) | Write evidence to a file, verify it elsewhere, watch a tampered copy fail. |
| [`express/`](express) | Evidence for each HTTP request that reaches a model, off the response path. |
| [`agent/`](agent) | An AI agent that leaves a verifiable trail of tool calls and decisions. |
| [`dstack/`](dstack) | Bind evidence to a hardware-attested Phala dstack enclave. |

The examples depend on `"cool-nwc": "file:../.."`, so they run against the build
in this repo. In your own project the dependency is just `cool-nwc`.
