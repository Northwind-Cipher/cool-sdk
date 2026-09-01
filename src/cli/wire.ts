/**
 * `cool wire` — is this actually running on hardware, and can it prove it?
 *
 * The five steps between "simulated" and "pass" are easy to describe and easy to
 * get subtly wrong, and the failure modes look alike from the outside. So this
 * walks them in order, stops at the first one that is not satisfied, and says
 * precisely what to do about it — including the three cases where a *real* quote
 * still must not pass:
 *
 *   • the measurement does not match the image you pinned;
 *   • the platform's TCB is out of date;
 *   • report_data does not bind the key that signs the receipts.
 *
 * Each of those is the verifier working correctly. A tool that turned them green
 * would be worse than useless.
 */
import { verifyReceiptV2 } from "../phala/index";
import { isSocketPath } from "../phala/unix";
import type { Workspace } from "./workspace";
import { verify } from "./workspace";
import { c, g, out, panel, rule } from "./tty";
import { paragraph } from "./help";

interface Step {
  readonly n: number;
  readonly title: string;
  readonly ok: boolean;
  readonly detail: string;
  /** What to run next when this step is the one blocking. */
  readonly fix?: readonly string[];
}

const mark = (ok: boolean) => (ok ? c.green(g.pass) : c.yellow(g.warn));

export async function wire(workspace: Workspace): Promise<number> {
  const steps: Step[] = [];
  const endpoint = process.env["DSTACK_ENDPOINT"] ?? process.env["DSTACK_SIMULATOR_ENDPOINT"];
  const verifierUrl = process.env["QUOTE_VERIFIER_URL"];
  const info = workspace.info;
  const quote = workspace.cool.handshake.quote;

  panel("wiring CooL to real hardware", [
    "Five steps. Everything below is checked, not assumed — and a real quote that",
    "fails a pin or a TCB check is still reported as a failure, because that is",
    "what it means.",
  ]);
  out();

  /* 1 · hardware */
  const onHardware = info.mode === "hardware";
  steps.push({
    n: 1,
    title: "real TDX hardware",
    ok: onHardware,
    detail: onHardware
      ? `${info.vendor} · app ${info.appId}`
      : "running CooL's in-process simulator — no confidential VM in sight",
    fix: [
      "Deploy the evidence plane to a Phala CVM (this repo ships the compose file):",
      "  cd deploy && phala deploy -c docker-compose.yml -n cool-evidence",
      "…or run Phala's own dstack simulator locally to exercise the real protocol:",
      "  dstack-simulator            # then: export DSTACK_SIMULATOR_ENDPOINT=/tmp/dstack.sock",
    ],
  });

  /* 2 · the guest agent, and a quote bound to our key */
  const boundToKey = quote?.body.report_data === workspace.cool.plane.attestation.key_binding;
  steps.push({
    n: 2,
    title: "guest agent reachable, quote bound to the signing key",
    ok: Boolean(endpoint) && boundToKey,
    detail: endpoint
      ? `${endpoint}${isSocketPath(endpoint) ? " (unix socket)" : ""} · report_data ${
          boundToKey ? "commits to " + workspace.cool.plane.keys.record.keyId : "DOES NOT match the signing key"
        }`
      : "DSTACK_ENDPOINT unset — nothing to ask for a quote",
    fix: [
      "Inside the CVM the agent listens on a socket:",
      "  export DSTACK_ENDPOINT=/var/run/dstack.sock",
      "CooL puts a commitment to its signing key in report_data automatically —",
      "that binding is what makes the quote about YOUR key rather than about the box.",
    ],
  });

  /* 3 · the quote reaching the record */
  const quoteInRecord = quote !== null && quote.root !== "cool-sim-root";
  steps.push({
    n: 3,
    title: "seal path pulls a vendor quote",
    ok: quoteInRecord,
    detail: quote
      ? `format ${quote.format} · root ${quote.root}${
          quote.root === "cool-sim-root" ? c.yellow("  ← CooL's simulator, not a vendor") : ""
        }`
      : "no quote at all",
    fix: [
      "This follows automatically from step 2 — once the agent answers, the seal",
      "path fetches a real quote instead of generating a simulated one.",
    ],
  });

  /* 4 · a vendor root to check it against */
  steps.push({
    n: 4,
    title: "quote verifier configured (Intel DCAP / Trust Authority)",
    ok: Boolean(verifierUrl),
    detail: verifierUrl ?? "QUOTE_VERIFIER_URL unset — a quote would be reported, never verified",
    fix: [
      "Point it at a service that chains the quote to Intel's root:",
      "  export QUOTE_VERIFIER_URL=https://api.phala.network/attest/verify",
      "  export QUOTE_VERIFIER_KEY=<token, if the service needs one>",
      "This is the step that turns `attestation` from simulated into pass, because",
      "it is the first point at which anything checks a VENDOR root.",
    ],
  });

  /* 5 · the end-to-end proof */
  rule("proof");
  const probe = await workspace.cool.change({
    kind: "policy",
    ref: "cool#wire",
    environment: process.env["COOL_ENV"] ?? "dev",
    after: `wire check at ${new Date().toISOString()}`,
    actor: { id: "cool:wire", method: "cli" },
  });
  const verdict = await verify(probe, workspace, { pin: true });
  const strict = await verifyReceiptV2(probe, {
    ...(workspace.verifier ? { quoteVerifier: workspace.verifier } : {}),
    expectedMeasurement: info.measurement,
    requireHardware: true,
  });

  steps.push({
    n: 5,
    title: "a freshly sealed record passes under --require-hardware",
    ok: strict.ok,
    detail: strict.ok
      ? "attestation and enclave both PASS against a vendor root"
      : `attestation ${verdict.checks.attestation.status} · enclave ${verdict.checks.enclave.status}`,
    fix: ["Steps 1–4 first. This one is the consequence, not a separate action."],
  });

  for (const step of steps) {
    out(`  ${mark(step.ok)} ${c.bold(`${step.n}.`)} ${step.title}`);
    out(`       ${c.faint(step.detail)}`);
  }
  out();

  const blocking = steps.find((step) => !step.ok);
  if (!blocking) {
    panel(
      "wired",
      [
        `${c.green("Every domain that can pass, passes.")}`,
        "",
        `${c.grey("attestation")}  ${verdict.checks.attestation.detail}`,
        `${c.grey("enclave")}      ${verdict.checks.enclave.detail}`,
      ],
      c.green,
    );
    out();
    out(`  ${c.faint("Two domains are separate features, each one command away:")}`);
    out(
      `    ${c.brand("witnesses")} ${c.faint("— an independent party co-signs the head:")} ${c.dim(
        "cool witness cosign --key auditor",
      )}`,
    );
    out(
      `    ${c.brand("anchor")}    ${c.faint("— commit the head to Bitcoin:")} ${c.dim(
        "cool anchor submit",
      )} ${c.faint("then")} ${c.dim("cool anchor upgrade")} ${c.faint("an hour later")}`,
    );
    out();
    return 0;
  }

  out(`  ${c.bold(c.yellow(`Blocked at step ${blocking.n}: ${blocking.title}`))}`);
  out();
  for (const line of blocking.fix ?? []) {
    out(line.startsWith("  ") ? `  ${c.dim(line.trim())}` : `  ${c.faint(line)}`);
  }
  out();

  rule("the three ways a REAL quote still fails");
  paragraph(
    `${c.bold("Measurement pin")} — if the deployed image's MRTD/RTMR differs from the value you ` +
      "pinned, the enclave domain fails. That is correct: it means the running code is not the " +
      "code you approved.",
  );
  out();
  paragraph(
    `${c.bold("TCB status")} — if Intel reports the platform's firmware or microcode as out of ` +
      "date, the quote verifies but the platform is stale, and the verifier says so rather than " +
      "passing. Patch the host.",
  );
  out();
  paragraph(
    `${c.bold("report_data binding")} — a quote that does not commit to the signing key proves ` +
      "a TEE existed, not that it held your key. CooL fills report_data with that commitment " +
      "automatically, and the enclave domain recomputes it from the receipt's own key directory.",
  );
  out();
  return 1;
}
