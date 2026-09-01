/**
 * The manual, as data.
 *
 * `cool help` used to be a list of one-line summaries, which is enough to remind
 * someone who already knows and useless to everyone else. This is the other
 * thing: a synopsis, a description that says *why*, worked examples, and the
 * concepts a reader needs before the commands make sense.
 *
 * Keeping it as data rather than printed strings means the same text serves the
 * terminal, `--json`, and anything that wants to render documentation elsewhere
 * — and it means a command with no examples is visibly missing them.
 */

export interface Example {
  readonly run: string;
  readonly does: string;
}

export interface CommandDoc {
  readonly name: string;
  readonly args: string;
  readonly summary: string;
  /** Prose. Two or three sentences on what it is FOR, not what it does. */
  readonly description: string;
  readonly examples: readonly Example[];
  readonly flags?: readonly { flag: string; does: string }[];
  readonly seeAlso?: readonly string[];
}

export interface TopicDoc {
  readonly name: string;
  readonly title: string;
  /** Paragraphs. Rendered wrapped, one blank line between. */
  readonly body: readonly string[];
  readonly seeAlso?: readonly string[];
}

/* ── commands ─────────────────────────────────────────────────────────── */

export const COMMANDS: readonly CommandDoc[] = [
  {
    name: "walkthrough",
    args: "",
    summary: "learn the whole model by doing it, in about three minutes",
    description:
      "A paced, interactive tour. It seals a real record, verifies it, breaks it, " +
      "shows the policy engine refusing something, opens one committed field without " +
      "revealing the rest, and ends with an audit pack. Everything it does is real and " +
      "stays in this directory afterwards.",
    examples: [{ run: "cool walkthrough", does: "start it; press Enter between steps" }],
    seeAlso: ["concepts", "seal", "verify"],
  },
  {
    name: "status",
    args: "",
    summary: "the enclave, the key, the channel, the log",
    description:
      "What this environment can currently prove. Shows the silicon and mode, the " +
      "measurement registers the signing key was derived from, every step of the RA-TLS " +
      "handshake, and how many records are in the log.",
    examples: [
      { run: "cool status", does: "the full picture" },
      { run: "cool status --json", does: "machine-readable, for a health check" },
    ],
    seeAlso: ["attestation", "attest", "doctor"],
  },
  {
    name: "seal",
    args: "<kind> <ref> [text]",
    summary: "capture and seal a change record",
    description:
      "Records a change to an AI system — a prompt edit, a model bump, a widened agent " +
      "permission. The plaintext is committed as a salted hash and discarded; the record " +
      "is signed with the enclave-derived key and appended to the transparency log. If a " +
      "policy is configured, its decision is evaluated here and sealed with the change.",
    examples: [
      {
        run: 'cool seal prompt billing/agent#system "Approve refunds up to $500."',
        does: "seal a production prompt change",
      },
      {
        run: 'cool seal model credit/underwriting#scorer "deepseek-v4-pro" --approvers a@x,b@x',
        does: "supply approvers so the policy can approve rather than escalate",
      },
      { run: "COOL_ENV=prod cool seal params kyc#model '{\"temperature\":0.2}'", does: "seal into production" },
    ],
    flags: [
      { flag: "--approvers a@x,b@x", does: "who signed off; the policy weighs these" },
      { flag: "--risk 0.9", does: "a risk signal from your own model, 0–1" },
      { flag: "--label tier:high", does: "repeatable; policies can match on labels" },
    ],
    seeAlso: ["policy", "verify", "records"],
  },
  {
    name: "verify",
    args: "[file|last|all]",
    summary: "run the offline verifier",
    description:
      "Checks a receipt the way a stranger would: recompute the commitment, verify both " +
      "signatures, walk the Merkle path to the signed tree head, and confirm the enclave " +
      "quote attests the very key that signed. Exits non-zero on any failure, which is " +
      "what a pipeline gates on. Needs no enclave and no network.",
    examples: [
      { run: "cool verify last", does: "the most recent record in this project" },
      { run: "cool verify all", does: "every record; exit 1 if any fails" },
      { run: "cool verify ./receipt.json --require-hardware", does: "refuse anything not backed by real silicon" },
    ],
    flags: [
      { flag: "--require-hardware", does: "a simulated attestation is no longer acceptable" },
      { flag: "--json", does: "the verdict as JSON" },
    ],
    seeAlso: ["receipts", "attestation", "pack"],
  },
  {
    name: "records",
    args: "[--kind …] [--ref …] [--env …]",
    summary: "search the evidence in this project",
    description:
      "Filter and list sealed records. The questions this answers are the ones that come " +
      "up in practice: what changed in production last week, what did this actor touch, " +
      "what went out without a human.",
    examples: [
      { run: "cool records", does: "everything, newest first" },
      { run: "cool records --kind prompt --env prod", does: "production prompt changes" },
      { run: "cool records --actor ci: --decision rejected", does: "what CI tried that policy refused" },
    ],
    flags: [
      { flag: "--kind <k>", does: "prompt, model, params, policy, dataset, agent-permission, tool" },
      { flag: "--ref <text>", does: "substring of the change ref or model id" },
      { flag: "--env <name>", does: "environment, e.g. prod" },
      { flag: "--actor <text>", does: "substring of the actor id" },
      { flag: "--decision <d>", does: "approved, auto-approved, rejected" },
      { flag: "--limit <n>", does: "cap the output" },
    ],
    seeAlso: ["stats", "verify"],
  },
  {
    name: "policy",
    args: "[test <kind> <ref>]",
    summary: "show the governance rules, or test one against them",
    description:
      "Policy is evaluated inside the enclave and its verdict is sealed with the change, " +
      "so an approval cannot be edited afterwards. This prints the active rule set with " +
      "the reasoning behind each rule, and can dry-run a hypothetical change through it.",
    examples: [
      { run: "cool policy", does: "the active rules and what they exist for" },
      {
        run: "cool policy test agent-permission support/copilot#tools --env prod",
        does: "what would happen if this were sealed now",
      },
    ],
    flags: [
      { flag: "--approvers a@x,b@x", does: "test with sign-off" },
      { flag: "--risk 0.9", does: "test with a risk signal" },
    ],
    seeAlso: ["governance", "seal"],
  },
  {
    name: "disclose",
    args: "<record> <field> <value>",
    summary: "open one committed field, proving it matches",
    description:
      "A receipt commits to prompts and diffs as salted hashes, so it can be published. " +
      "When somebody needs to see the actual text, this produces a disclosure: the " +
      "plaintext plus its salt, which anyone can check against the sealed commitment. " +
      "One field opens; everything else stays closed.",
    examples: [
      {
        run: 'cool disclose last change.after "Approve refunds up to $500."',
        does: "prove what the prompt said",
      },
      { run: "cool disclose <id> input --out disclosure.json", does: "write it to a file to send on" },
      { run: "cool disclose --check disclosure.json", does: "verify one you were given" },
    ],
    flags: [
      { flag: "--out <file>", does: "write the disclosure instead of printing it" },
      { flag: "--check <file>", does: "verify a disclosure against its receipt" },
    ],
    seeAlso: ["disclosure", "receipts"],
  },
  {
    name: "witness",
    args: "[cosign|list]",
    summary: "independent co-signatures on the log",
    description:
      "A log signed only by its operator proves they have not contradicted themselves. A " +
      "witness — anyone else — co-signs the tree heads they saw, which is what makes the " +
      "witnesses domain something other than 'absent'. This can generate a witness key, " +
      "co-sign the current head, and attach statements to receipts.",
    examples: [
      { run: "cool witness cosign --key auditor", does: "co-sign the current tree head" },
      { run: "cool witness list", does: "who has co-signed what is on disk" },
    ],
    seeAlso: ["witnesses", "verify"],
  },
  {
    name: "anchor",
    args: "[submit|upgrade|verify|export|status]",
    summary: "commit the tree head to Bitcoin",
    description:
      "Every other proof in a receipt is a signature, and a signature can be made at any " +
      "time by whoever holds the key — including later, about a past they would prefer. A " +
      "Bitcoin block header cannot be backdated. `submit` hands the current head to four " +
      "independent public calendars; an hour or so later `upgrade` collects the block they " +
      "aggregated it into; `verify` recomputes the commitment and checks it against the " +
      "block's merkle root. Until that last step succeeds the domain reads `pending`, never " +
      "`pass`.",
    examples: [
      { run: "cool anchor submit", does: "timestamp the current head — free, no key needed" },
      { run: "cool anchor upgrade", does: "collect the Bitcoin block once aggregated" },
      { run: "cool anchor verify", does: "check the commitment against the block header" },
      { run: "cool anchor export head.ots", does: "write a proof anyone can check with `ots`" },
    ],
    seeAlso: ["anchoring", "log", "verify"],
  },
  {
    name: "pack",
    args: "[build|verify <file>]",
    summary: "build or check an audit pack",
    description:
      "One self-contained file with every receipt, the keys to check them, the pinned " +
      "measurement and the clause mapping. `pack verify` re-derives everything rather " +
      "than trusting the pack's own summary — it is meant to be checked by someone who " +
      "does not trust you.",
    examples: [
      { run: "cool pack build --out audit.json", does: "produce the pack" },
      { run: "cool pack verify audit.json", does: "check every record in it" },
    ],
    seeAlso: ["compliance", "verify"],
  },
  {
    name: "compliance",
    args: "",
    summary: "obligations, and what evidence covers them",
    description:
      "Maps EU AI Act, DPDP, ISO 42001, SOC 2 and RBI clauses onto the receipt fields " +
      "that satisfy them, and counts the records behind each. Coverage is computed, never " +
      "asserted: an obligation with no evidence reports zero and says what would fix it.",
    examples: [
      { run: "cool compliance", does: "the coverage table" },
      { run: "cool compliance --gaps", does: "only what is uncovered" },
    ],
    seeAlso: ["pack", "governance"],
  },
  {
    name: "ui",
    args: "[folder]",
    summary: "watch a real project in a browser console",
    description:
      "Opens a folder, seeds a baseline from git so the first change is a real diff, and " +
      "seals every save into the project's own on-disk log. The console it serves is the " +
      "same one the website demonstrates, with the two things a demo cannot have: your " +
      "files and your hardware. Records land in .cool/receipts and the tree in .cool/log, " +
      "so history survives a restart. Bound to loopback — it can seal records and read " +
      "your source, so it is not meant to be reachable from anywhere else.",
    examples: [
      { run: "cool ui", does: "watch the current folder" },
      { run: "cool ui ./agents --env prod", does: "watch a subfolder, record it as production" },
      { run: "cool ui --host 0.0.0.0 --no-open", does: "inside a CVM, behind the gateway" },
    ],
    flags: [
      { flag: "--port <n>", does: "listen somewhere other than 4319" },
      { flag: "--host <addr>", does: "bind address; defaults to 127.0.0.1" },
      { flag: "--env <name>", does: "environment recorded on each change (default: COOL_ENV or dev)" },
      { flag: "--no-open", does: "do not launch a browser" },
    ],
    seeAlso: ["wire", "attest", "attestation"],
  },
  {
    name: "attest",
    args: "",
    summary: "the quote and the measurement registers",
    description:
      "Prints the attestation this environment can produce: quote format, root of trust, " +
      "TCB status, the 64 bytes bound into report_data, and all five measurement " +
      "registers. On a laptop this is the simulator, and it says so.",
    examples: [{ run: "cool attest", does: "the full quote body" }],
    seeAlso: ["attestation", "status"],
  },
  {
    name: "log",
    args: "",
    summary: "the transparency log's state",
    description:
      "Tree size, current root, the last signed tree head, and where the log lives on " +
      "disk. One tree per project, appended to across runs — which is what makes " +
      "ordering and completeness provable rather than a claim.",
    examples: [
      { run: "cool log", does: "size, root, checkpoint" },
      { run: "cool log --consistency 12", does: "prove the tree only grew since size 12" },
    ],
    seeAlso: ["log-concept", "verify"],
  },
  {
    name: "stats",
    args: "",
    summary: "volume, verdicts, capture cost",
    description:
      "What a platform team asks for: how many records, how many verify, how much the " +
      "capture path costs on the caller's thread, and how many events were dropped. The " +
      "cost figures are measured on this machine, not quoted from a datasheet.",
    examples: [{ run: "cool stats", does: "the analytics panel" }],
    seeAlso: ["records", "capture"],
  },
  {
    name: "update",
    args: "[version]",
    summary: "upgrade in place",
    description:
      "Checks the registry and installs the newer release over the top. One command " +
      "instead of uninstall-then-reinstall, which on Windows leaves the `cool` shim " +
      "behind and produces a confusing EEXIST on the next attempt. It shells out to " +
      "`npm install -g` rather than replacing itself, so nothing happens that you " +
      "could not have typed.",
    examples: [
      { run: "cool update", does: "upgrade to the latest release" },
      { run: "cool update --check", does: "exit 1 if an update exists; for CI" },
      { run: "cool update 2.4.0", does: "install an exact version" },
    ],
    seeAlso: ["doctor"],
  },
  {
    name: "doctor",
    args: "",
    summary: "what this environment can and cannot prove",
    description:
      "Checks Node, WebCrypto, whether a dstack endpoint and a quote verifier are " +
      "configured, that the channel opens, and that a seal-and-verify round trip is " +
      "clean. Exits non-zero when something is missing, including the honest case of a " +
      "laptop with no confidential VM.",
    examples: [{ run: "cool doctor", does: "run every check" }],
    seeAlso: ["status", "attestation"],
  },
  {
    name: "help",
    args: "[command|topic]",
    summary: "this manual",
    description:
      "With no argument, the command list and the concept index. With a command, its full " +
      "documentation and examples. With a topic, the explanation behind it.",
    examples: [
      { run: "cool help verify", does: "everything about one command" },
      { run: "cool help attestation", does: "the concept, not the command" },
      { run: "cool help concepts", does: "the topic index" },
    ],
  },
];

/* ── concepts ─────────────────────────────────────────────────────────── */

export const TOPICS: readonly TopicDoc[] = [
  {
    name: "concepts",
    title: "What this tool is about",
    body: [
      "CooL records what a system did and what was changed about it, in a way that " +
        "someone who does not trust you can check. Two record types: an evidence record " +
        "(an event type plus committed metadata and payloads) and a change (a prompt, a " +
        "model version, a permission).",
      "Nothing sensitive is stored. Metadata, inputs, outputs and diffs are committed as " +
        "salted hashes; the plaintext is hashed and discarded. A receipt can therefore be " +
        "handed to a regulator without handing over a customer's data.",
      "Each record is signed with a key that is derived inside a confidential VM from the " +
        "measurement of the code running there. Ship different code and the key changes. " +
        "That is what makes 'the vendor cannot forge your evidence' a mechanism rather " +
        "than a promise.",
      "Records are appended to a transparency log, so removing one later is detectable. " +
        "And the verifier is offline: it needs the bytes and nothing else.",
    ],
    seeAlso: ["receipts", "attestation", "log-concept", "verifier"],
  },
  {
    name: "receipts",
    title: "What a receipt contains",
    body: [
      "A receipt is one JSON document with five parts: the signed record, its binding " +
        "hash, an inclusion proof, the attestation, and the public keys needed to check " +
        "all of it. Self-contained on purpose — an auditor should not need an account.",
      "The record's core includes the commitments, the model or change details, the time, " +
        "and the runtime block: which silicon, which mode, which measurement, and the " +
        "digest of the enclave quote. Hashing the core produces the binding hash; both " +
        "signatures cover the core AND that hash.",
      "Because the quote's digest is inside the signed core, a valid quote from a " +
        "different enclave cannot be stapled onto a record afterwards — the enclave domain " +
        "catches it. Try it: `cool walkthrough` does exactly that.",
    ],
    seeAlso: ["verifier", "disclosure"],
  },
  {
    name: "attestation",
    title: "Attestation, and what it is not",
    body: [
      "A confidential VM can produce a quote: a statement signed by the CPU saying 'this " +
        "measurement is running, and here are 64 bytes it asked me to include'. CooL " +
        "spends those 64 bytes on a commitment to the public half of its signing key.",
      "That single decision is what ties the two halves together. A verifier recomputes " +
        "the commitment from the receipt's own key directory: if it matches, the code that " +
        "was attested is the code that holds the signing key.",
      "What a quote does not prove: that the output was correct, fair or safe. And on a " +
        "machine with no TEE, the quote is produced by the built-in simulator under a " +
        "CooL-held root — structurally complete, cryptographically real, and worth nothing " +
        "as evidence of confidentiality. The verifier reports that as `simulated`, never " +
        "as `pass`. `--require-hardware` refuses it outright.",
    ],
    seeAlso: ["status", "attest", "verifier"],
  },
  {
    name: "log-concept",
    title: "The transparency log",
    body: [
      "Every record's binding digest is appended to an RFC 6962 Merkle tree. A receipt " +
        "carries the audit path from its leaf to the root, plus a signed tree head — so " +
        "'this record was in the log at size N' is checkable arithmetic.",
      "One tree per project, kept in `.cool/log/` and appended to across runs. That " +
        "matters more than it sounds: a hundred separate trees of size one prove nothing " +
        "about ordering or completeness, which is most of what a log is for.",
      "`cool log --consistency <older size>` produces the proof that the tree only ever " +
        "grew. Hand that, plus an older tree head somebody kept, and they can check that " +
        "nothing was removed in between.",
    ],
    seeAlso: ["witnesses", "log"],
  },
  {
    name: "witnesses",
    title: "Why witnesses exist",
    body: [
      "A log signed only by its operator proves the operator has not contradicted " +
        "themselves. It cannot prove they never showed a different tree to somebody else, " +
        "because the same key can sign two different trees.",
      "A witness is anyone independent who signs the tree heads they saw. Once a witness " +
        "has co-signed size 40, producing a different size-40 tree requires forging their " +
        "signature too.",
      "CooL's own self-signature is shown on every tree head and NEVER counted as " +
        "independent — the verifier has enforced that since v1. `cool witness cosign` is " +
        "how the count becomes non-zero honestly.",
    ],
    seeAlso: ["witness", "log-concept"],
  },
  {
    name: "governance",
    title: "Policy, and where it runs",
    body: [
      "An approval that can be edited afterwards is not an approval. So policy is " +
        "evaluated inside the enclave at the moment of sealing, and the decision — plus " +
        "the rule that produced it and a hash of the whole rule set — is covered by the " +
        "same signature as the change.",
      "Rules are plain data: match on kind, environment, ref, actor method, approver " +
        "count, labels or a risk signal, and decide auto-approved, approved, escalate or " +
        "rejected. The strictest matching rule wins, so a permissive rule added later " +
        "cannot quietly override a restrictive one.",
      "The default set fails safe: nothing in production without two approvers, widening " +
        "an agent's permissions never automatic, and anything unmatched escalates rather " +
        "than sliding through. `cool policy` prints it with the reasoning attached.",
    ],
    seeAlso: ["policy", "compliance"],
  },
  {
    name: "disclosure",
    title: "Showing one field without showing the record",
    body: [
      "Commitments are salted, and the salt is stored in the receipt. That is what makes " +
        "selective disclosure possible: reveal the plaintext and its salt for one field, " +
        "and anyone can recompute the commitment and compare.",
      "One field opens. The rest of the record stays closed, and no other record is " +
        "affected — salts are per field and per record. Once disclosed, though, that field " +
        "is disclosed permanently.",
      "This proves the value was committed, not that it was used. The rest of the record " +
        "is what says it was used.",
    ],
    seeAlso: ["disclose", "receipts"],
  },
  {
    name: "capture",
    title: "What CooL costs your application",
    body: [
      "The SDK's capture call is an array push behind an async queue: measured p99 well " +
        "under a millisecond on the caller's thread. It never awaits, never throws into " +
        "your code, and never grows without bound — past its limit it drops the oldest " +
        "events and counts them.",
      "If the evidence plane is unreachable, your request still succeeds. The loss shows " +
        "up in `cool stats` and in your metrics, never in your latency. Fail-open toward " +
        "the application, fail-closed toward the network: nothing is transmitted to an " +
        "endpoint that has not attested.",
    ],
    seeAlso: ["stats", "status"],
  },
  {
    name: "verifier",
    title: "The seven domains",
    body: [
      "binding — the record's contents match its commitment. Pure arithmetic.",
      "signature — ML-DSA-65 and Ed25519 both verify over core‖binding. Both, always: one " +
        "post-quantum, one classical.",
      "inclusion — the leaf is in the log under a validly signed tree head.",
      "witnesses — independent co-signatures. A self-signature is displayed and never " +
        "counted.",
      "attestation — the quote chains to a hardware root. `pass` only with a real verifier " +
        "and a real root; `simulated` for the simulator; `absent` when a hardware quote is " +
        "present but unverifiable here.",
      "enclave — the quote, the measurement and the signing key are one chain. This is the " +
        "domain that makes a quote mean something about THIS record.",
      "anchor — the tree head is committed into a Bitcoin block. `pass` only once the " +
        "commitment has been recomputed and matched against a real block header; `pending` " +
        "between submission and aggregation, and whenever no header source was consulted.",
    ],
    seeAlso: ["verify", "attestation", "anchoring"],
  },
  {
    name: "anchoring",
    title: "Why anchor to Bitcoin",
    body: [
      "Six of the seven domains are signatures, and a signature says 'someone holding this " +
        "key asserts X'. It does not say when. Whoever holds the key can produce one at any " +
        "time, including about a past they would prefer — which is exactly the attack a " +
        "transparency log is supposed to rule out.",
      "A block header cannot be backdated. Commit the tree head into one and the head " +
        "provably existed before that block was mined, no matter who later obtains the key. " +
        "That is the one property cryptography alone cannot give you.",
      "CooL uses OpenTimestamps: the head's root hash goes to four independently operated " +
        "public calendars, which aggregate submissions into a single Bitcoin transaction " +
        "about once an hour. The cost is nothing and the proof is a standard `.ots` file, so " +
        "`cool anchor export` gives an auditor something they can check with the reference " +
        "tool and a Bitcoin node, without running any CooL code.",
      "One submission covers every record in the log up to that size, because the head " +
        "commits to all of them. Anchoring per-record would be thousands of transactions " +
        "proving nothing extra.",
    ],
    seeAlso: ["anchor", "log", "verifier"],
  },
  {
    name: "production",
    title: "Going to production",
    body: [
      "Three things change. Point `DSTACK_ENDPOINT` at the guest agent inside your " +
        "confidential VM, so quotes come from silicon instead of the simulator. Set " +
        "`QUOTE_VERIFIER_URL` so those quotes are chained to Intel or AMD rather than " +
        "merely reported. And pin the measurement of the image you reviewed.",
      "With a pin, a quote proves 'the code we approved'. Without one it proves 'some " +
        "TEE', which is a much weaker sentence. The pin lives in version control next to " +
        "the code it pins, so updating it requires a human who looked at the diff.",
      "Then turn on `--require-hardware` in whatever checks your pipeline runs, and " +
        "`allowSimulated: false` in the SDK. From that point a simulated receipt is not " +
        "acceptable evidence anywhere in your estate.",
    ],
    seeAlso: ["attestation", "doctor"],
  },
];

export const command = (name: string): CommandDoc | undefined =>
  COMMANDS.find((c) => c.name === name);

export const topic = (name: string): TopicDoc | undefined => TOPICS.find((t) => t.name === name);
