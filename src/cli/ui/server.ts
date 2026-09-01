/**
 * The local console: a real evidence plane, behind a JSON API, over a real
 * project folder.
 *
 * The whole design constraint is that this ships inside an SDK. That rules out
 * a framework, a bundler at install time, and a runtime dependency tree — the
 * package's dependencies are four cryptography libraries and a CBOR codec, and
 * adding a web stack to get a dashboard would be a poor trade for anyone who
 * only wanted to sign things. So: `node:http`, a single static HTML file, and
 * server-sent events for the live updates.
 *
 * Three properties this has that the website's demo cannot:
 *
 *   - the records describe **your** files, with **your** git provenance;
 *   - the log is on disk in `.cool/log`, so it survives a restart and grows
 *     across sessions instead of starting a fresh tree of size one;
 *   - when `DSTACK_ENDPOINT` points at a guest agent, the attestation is real,
 *     and the console reports `pass` because a vendor root actually checked it.
 *
 * Verification is done **server-side, by the real verifier**, and the verdict is
 * shipped to the page. The page does not implement any cryptography — it could
 * not be trusted to, and duplicating the verifier in browser JavaScript is how
 * you end up with two verifiers that disagree.
 *
 * Bound to loopback. This serves the contents of a source tree and can seal
 * records; it has no authentication because it is not supposed to be reachable,
 * and binding it to 0.0.0.0 by default would make that assumption false.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildAuditPack, coverage, verifyReceiptV2 } from "../../phala/index";
import type { ReceiptV2, VerdictV2 } from "../../phala/index";
import { loadReceipts, saveReceipt, type Workspace } from "../workspace";
import { actorFrom, gitContext, labelsFrom, type GitContext } from "./git";
import type { FileChange } from "./watch";

/* ── shapes the page consumes ─────────────────────────────────────────── */

interface Row {
  id: string;
  kind: string;
  ref: string;
  path: string | null;
  actor: string;
  environment: string;
  at: string;
  decision: string;
  policyRule: string | null;
  fresh: boolean;
  verdict: {
    ok: boolean;
    checks: { domain: string; status: string; detail: string }[];
  } | null;
  /** Kept in the server's memory only, for the diff pane. Never in the receipt. */
  before: string | null;
  after: string | null;
}

export interface UiOptions {
  readonly workspace: Workspace;
  readonly root: string;
  readonly projectName: string;
  readonly port: number;
  readonly host: string;
  readonly environment: string;
  readonly onLog?: (line: string) => void;
}

/* ── helpers ──────────────────────────────────────────────────────────── */

const here = dirname(fileURLToPath(import.meta.url));

function json(res: ServerResponse, code: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(code, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function flatten(verdict: VerdictV2 | null): Row["verdict"] {
  if (!verdict) return null;
  return {
    ok: verdict.ok,
    checks: Object.entries(verdict.checks).map(([domain, check]) => ({
      domain,
      status: check.status,
      detail: check.detail,
    })),
  };
}

/** Read the request body, with a cap — this is a local tool, not a target. */
async function body(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > 2 * 1024 * 1024) throw new Error("request too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/* ── the console ──────────────────────────────────────────────────────── */

export class Console {
  private readonly rows = new Map<string, Row>();
  private readonly receipts = new Map<string, ReceiptV2>();
  private readonly clients = new Set<ServerResponse>();
  private server: Server | null = null;
  private git: GitContext;
  private notes: string[] = [];

  constructor(private readonly options: UiOptions) {
    this.git = gitContext(options.root);

  }

  /** Note something the operator should see in the UI rather than only in stdout. */
  note(message: string): void {
    this.notes.push(message);
    this.broadcast("note", { message });
  }

  /**
   * Adopt what is already on disk.
   *
   * The log and the receipts outlive the process, so opening the console on a
   * project that has been used before must show its history rather than an
   * empty page pretending this is the first change.
   */
  async loadExisting(): Promise<number> {
    const stored = loadReceipts(this.options.root);
    for (const { receipt } of stored) {
      const verdict = await this.verify(receipt);
      this.rows.set(receipt.record.record_id, this.rowOf(receipt, verdict, false, null, null));
      this.receipts.set(receipt.record.record_id, receipt);
    }
    return stored.length;
  }

  private verify(receipt: ReceiptV2): Promise<VerdictV2> {
    return verifyReceiptV2(receipt, {
      ...(this.options.workspace.verifier
        ? { quoteVerifier: this.options.workspace.verifier }
        : {}),
    });
  }

  private rowOf(
    receipt: ReceiptV2,
    verdict: VerdictV2 | null,
    fresh: boolean,
    before: string | null,
    path: string | null,
  ): Row {
    const isChange = receipt.record.schema === "cool.change.v2";
    const change = isChange ? receipt.record.change : null;
    const event = receipt.record.schema === "cool.evidence.v1" ? receipt.record.event : null;
    return {
      id: receipt.record.record_id,
      kind: change ? change.kind : (event ? event.type : "evidence"),
      ref: change ? change.ref : (event ? event.application_id : "—"),
      path,
      actor: change ? change.actor.id : "—",
      environment: change ? change.environment : this.options.environment,
      at: receipt.record.time.issued_at,
      decision: change?.approval?.decision ?? "—",
      policyRule: change?.approval?.policy_id ?? null,
      fresh,
      verdict: flatten(verdict),
      before,
      after: null,
    };
  }

  /**
   * Seal a real change from the watcher.
   *
   * No approval block is passed: the plane's policy set decides inside the
   * enclave and its verdict is sealed by the same signature as the change. That
   * is the property that makes the decision worth anything, and it is why this
   * function does not get to choose the outcome.
   */
  async sealChange(change: FileChange): Promise<Row | null> {
    const { workspace, root, projectName, environment } = this.options;
    // Re-read git per change: the branch or the HEAD can move while the console
    // is open, and a record should carry the state at the time it was sealed.
    this.git = gitContext(root);

    try {
      const receipt = await workspace.cool.change({
        kind: change.kind,
        ref: change.ref,
        environment,
        after: change.after,
        ...(change.before === null ? {} : { before: change.before }),
        actor: actorFrom(this.git),
        labels: labelsFrom(this.git, projectName),
      });

      saveReceipt(root, receipt);
      const verdict = await this.verify(receipt);
      const row = this.rowOf(receipt, verdict, true, change.before, change.path);
      row.after = change.after;

      this.rows.set(row.id, row);
      this.receipts.set(row.id, receipt);

      this.broadcast("record", { row, treeSize: receipt.sth?.tree_size ?? null });
      this.options.onLog?.(
        `sealed ${change.kind} ${change.path} → ${row.decision}${
          row.policyRule ? ` (${row.policyRule})` : ""
        }`,
      );
      return row;
    } catch (error) {
      // A refused channel or an unwritable directory must not take the console
      // down. It is surfaced, in the UI, as the thing that it is.
      this.note(`could not seal ${change.path}: ${(error as Error).message}`);
      return null;
    }
  }

  /* ── SSE ── */

  private broadcast(event: string, data: unknown): void {
    const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const client of this.clients) {
      try {
        client.write(payload);
      } catch {
        this.clients.delete(client);
      }
    }
  }

  /* ── state ── */

  private state() {
    const { workspace, root, projectName, environment } = this.options;
    const info = workspace.info;
    const rows = [...this.rows.values()].sort((a, b) => b.at.localeCompare(a.at));
    const receipts = [...this.receipts.values()];

    return {
      project: {
        name: projectName,
        root,
        environment,
        git: this.git,
      },
      runtime: {
        vendor: info.vendor,
        mode: info.mode,
        tcbStatus: info.tcbStatus,
        appId: info.appId,
        instanceId: info.instanceId,
        imageDigest: info.imageDigest,
        measurement: info.measurement,
        /** True only when a guest agent is answering AND a root can check it. */
        hardware: info.mode === "hardware",
        verifierConfigured: workspace.verifier !== null,
        endpoint:
          process.env["DSTACK_ENDPOINT"] ?? process.env["DSTACK_SIMULATOR_ENDPOINT"] ?? null,
        handshake: workspace.cool.handshake.steps.map((step) => ({
          label: step.label,
          ok: step.ok,
          detail: step.detail,
        })),
      },
      log: {
        treeSize: workspace.cool.plane.logSize,
        // Read off a tree head rather than the log object: `FileLog` keeps its
        // id private, and the STH is where the id actually has to be correct.
        logId: workspace.cool.plane.currentSTH().log_id,
        dir: join(root, ".cool", "log"),
      },
      obligations: coverage(receipts).map((row) => ({
        id: row.obligation.id,
        regime: row.obligation.regime,
        clause: row.obligation.clause,
        requirement: row.obligation.requirement,
        satisfiedBy: row.obligation.satisfiedBy,
        records: row.records,
        covered: row.covered,
      })),
      rows,
      notes: this.notes,
    };
  }

  /* ── routing ── */

  private async route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;

    if (path === "/" || path === "/index.html") {
      const html = readFileSync(join(here, "app.html"), "utf8");
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      });
      res.end(html);
      return;
    }

    if (path === "/api/state") {
      json(res, 200, this.state());
      return;
    }

    if (path === "/api/events") {
      res.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
        connection: "keep-alive",
      });
      res.write(": open\n\n");
      this.clients.add(res);
      // A comment every 25s keeps proxies and the browser from closing an idle
      // stream; it is not data and the page ignores it.
      const beat = setInterval(() => {
        try {
          res.write(": beat\n\n");
        } catch {
          /* the close handler will clean up */
        }
      }, 25_000);
      req.on("close", () => {
        clearInterval(beat);
        this.clients.delete(res);
      });
      return;
    }

    if (path.startsWith("/api/receipt/")) {
      const id = decodeURIComponent(path.slice("/api/receipt/".length));
      const receipt = this.receipts.get(id);
      if (!receipt) {
        json(res, 404, { error: "no such record" });
        return;
      }
      const payload = `${JSON.stringify(receipt, null, 2)}\n`;
      res.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "content-disposition": `attachment; filename="${id}.json"`,
      });
      res.end(payload);
      return;
    }

    if (path.startsWith("/api/verify/") && req.method === "POST") {
      const id = decodeURIComponent(path.slice("/api/verify/".length));
      const receipt = this.receipts.get(id);
      if (!receipt) {
        json(res, 404, { error: "no such record" });
        return;
      }
      const started = performance.now();
      const verdict = await this.verify(receipt);
      const row = this.rows.get(id);
      if (row) row.verdict = flatten(verdict);
      json(res, 200, {
        verdict: flatten(verdict),
        ms: Math.round((performance.now() - started) * 10) / 10,
      });
      return;
    }

    if (path.startsWith("/api/tamper/") && req.method === "POST") {
      const id = decodeURIComponent(path.slice("/api/tamper/".length));
      const receipt = this.receipts.get(id);
      if (!receipt) {
        json(res, 404, { error: "no such record" });
        return;
      }
      // Edit a copy. The stored receipt and the file on disk are untouched —
      // this demonstrates detection, it does not corrupt the user's evidence.
      const edited = JSON.parse(JSON.stringify(receipt)) as ReceiptV2;
      const record = edited.record as unknown as Record<string, unknown>;
      if (edited.record.schema === "cool.change.v2") {
        const change = record["change"] as Record<string, unknown>;
        change["environment"] = edited.record.change.environment === "prod" ? "staging" : "prod";
      } else {
        const response = record["response"] as Record<string, string>;
        response["output_hash"] = (response["output_hash"] ?? "").replace(/.$/, (ch) =>
          ch === "0" ? "1" : "0",
        );
      }
      json(res, 200, { verdict: flatten(await this.verify(edited)) });
      return;
    }

    if (path === "/api/verify-all" && req.method === "POST") {
      // Re-read from disk rather than verifying what is already in memory. The
      // question this answers is "is the evidence on this machine still good",
      // and only the bytes on disk can answer it — a cached object would still
      // verify after someone had edited the file underneath it.
      const stored = loadReceipts(this.options.root);
      const started = performance.now();
      const results = [];
      for (const { path: file, receipt } of stored) {
        const verdict = await this.verify(receipt);
        results.push({
          id: receipt.record.record_id,
          file: file.split(/[\\/]/).pop() ?? file,
          ok: verdict.ok,
          reasons: verdict.reasons,
          failed: Object.entries(verdict.checks)
            .filter(([, check]) => check.status === "fail")
            .map(([domain]) => domain),
        });
      }
      json(res, 200, {
        total: results.length,
        valid: results.filter((r) => r.ok).length,
        invalid: results.filter((r) => !r.ok).length,
        ms: Math.round((performance.now() - started) * 10) / 10,
        results,
      });
      return;
    }

    if (path === "/api/pack") {
      const receipts = [...this.receipts.values()];
      const info = this.options.workspace.info;
      const pack = buildAuditPack(receipts, {
        subject: `${this.options.projectName} · ${this.options.environment}`,
        enclave: {
          vendor: info.vendor,
          mode: info.mode,
          app_id: info.appId,
          measurement: info.measurement,
        },
      });
      const payload = `${JSON.stringify(pack, null, 2)}\n`;
      res.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "content-disposition": 'attachment; filename="audit-pack.json"',
      });
      res.end(payload);
      return;
    }

    if (path === "/api/verify-file" && req.method === "POST") {
      try {
        const parsed = JSON.parse(await body(req)) as Record<string, unknown>;
        if (parsed["schema"] === "cool.audit-pack.v2") {
          const { verifyAuditPack } = await import("../../phala/index");
          const verdict = await verifyAuditPack(parsed as never);
          json(res, 200, {
            kind: "pack",
            ok: verdict.ok,
            total: verdict.total,
            failed: verdict.failed,
          });
          return;
        }
        const verdict = await this.verify(parsed as unknown as ReceiptV2);
        json(res, 200, { kind: "receipt", verdict: flatten(verdict) });
      } catch (error) {
        json(res, 200, { kind: "error", message: (error as Error).message });
      }
      return;
    }

    json(res, 404, { error: "not found" });
  }

  /**
   * Bind, walking forward if the port is taken.
   *
   * A previous run that did not shut down cleanly, another project's console,
   * or anything else on 4319 used to end the command with "already in use, try
   * --port" — which asks the operator to solve a problem the tool is perfectly
   * capable of solving. Nothing depends on the number: the URL is printed and
   * the browser is opened with it.
   *
   * It walks rather than picking port 0 so the address stays predictable and
   * bookmarkable across restarts, and it gives up after a short run rather than
   * scanning the machine — sixteen consecutive busy ports means something is
   * wrong that a seventeenth will not fix.
   */
  async listen(): Promise<{ url: string; port: number; movedFrom: number | null }> {
    const first = this.options.port;
    for (let port = first; port < first + 16; port++) {
      try {
        const url = await this.bind(port);

        return { url, port, movedFrom: port === first ? null : first };
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "EADDRINUSE" || code === "EACCES") continue;
        throw error;
      }
    }
    throw new Error(
      `ports ${first}–${first + 15} are all in use — pass --port to choose another`,
    );
  }

  private bind(port: number): Promise<string> {
    return new Promise((resolve, reject) => {
      const server = createServer((req, res) => {
        void this.route(req, res).catch((error: unknown) => {
          json(res, 500, { error: (error as Error).message });
        });
      });
      const onError = (error: Error) => {
        server.close();
        reject(error);
      };
      server.once("error", onError);
      server.listen(port, this.options.host, () => {
        server.removeListener("error", onError);
        this.server = server;
        resolve(`http://${this.options.host}:${port}`);
      });
    });
  }

  close(): void {
    for (const client of this.clients) {
      try {
        client.end();
      } catch {
        /* already gone */
      }
    }
    this.clients.clear();
    this.server?.close();
  }
}
