/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Shared replay stores.
 *
 * 1. A RESP2 server in-process (SET NX PX semantics, AUTH, SELECT, faults on
 *    demand) exercises the protocol client, races across independent clients
 *    ("machines"), and every failure mode → `unavailable`.
 * 2. Against a REAL Redis when COOL_TEST_REDIS_URL is set (CI runs a redis
 *    service container for this; locally the test is skipped and says so).
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type Socket } from "node:net";
import { RedisNonceStore, SharedNonceStore, postgresAtomicInsert, dynamoDbAtomicInsert, type AtomicInsert } from "../src/authz/index";

interface FakeRedis { server: Server; port: number; mode: "ok" | "hang" | "error" | "drop"; commands: string[][]; close(): Promise<void> }

async function fakeRedis(options: { password?: string } = {}): Promise<FakeRedis> {
  const data = new Map<string, { v: string; exp: number }>();
  const sockets = new Set<Socket>();
  const state: FakeRedis = { server: undefined as never, port: 0, mode: "ok", commands: [], close: async () => { for (const s of sockets) s.destroy(); await new Promise<void>((r) => state.server.close(() => r())); } };
  state.server = createServer((sock) => {
    sockets.add(sock);
    let authed = options.password === undefined;
    let buf = "";
    sock.on("data", (d) => {
      buf += d.toString("utf8");
      for (;;) {
        // parse one array of bulk strings
        const m = buf.match(/^\*(\d+)\r\n/);
        if (!m) return;
        let p = m[0].length; const args: string[] = []; let ok = true;
        for (let i = 0; i < Number(m[1]); i++) {
          const h = buf.slice(p).match(/^\$(\d+)\r\n/);
          if (!h) { ok = false; break; }
          const n = Number(h[1]); p += h[0].length;
          if (buf.length < p + n + 2) { ok = false; break; }
          args.push(buf.slice(p, p + n)); p += n + 2;
        }
        if (!ok) return;
        buf = buf.slice(p);
        state.commands.push(args);
        const [cmd, ...rest] = args;
        if (state.mode === "hang") continue;
        if (state.mode === "drop") { sock.destroy(); return; }
        if (state.mode === "error") { sock.write("-ERR injected failure\r\n"); continue; }
        if (cmd === "AUTH") { authed = rest[rest.length - 1] === options.password; sock.write(authed ? "+OK\r\n" : "-WRONGPASS invalid password\r\n"); continue; }
        if (!authed) { sock.write("-NOAUTH Authentication required.\r\n"); continue; }
        if (cmd === "SELECT") { sock.write("+OK\r\n"); continue; }
        if (cmd === "SET" && rest[2] === "NX" && rest[3] === "PX") {
          const [k, v, , , ttl] = rest as [string, string, string, string, string];
          const cur = data.get(k);
          if (cur && cur.exp > Date.now()) sock.write("$-1\r\n");
          else { data.set(k, { v, exp: Date.now() + Number(ttl) }); sock.write("+OK\r\n"); }
          continue;
        }
        sock.write(`-ERR unknown command ${cmd}\r\n`);
      }
    });
    sock.on("close", () => sockets.delete(sock));
  });
  await new Promise<void>((r) => state.server.listen(0, "127.0.0.1", () => r()));
  state.port = (state.server.address() as { port: number }).port;
  return state;
}

test("redis: first use consumed, second replayed; keys are hashed and namespaced; TTL is sent", async () => {
  const srv = await fakeRedis();
  const store = new RedisNonceStore({ port: srv.port, ttlMs: 600_000 });
  try {
    assert.equal(await store.consume("acme-payments", "n-1", "req-1"), "consumed");
    assert.equal(await store.consume("acme-payments", "n-1", "req-2"), "replayed");
    assert.equal(await store.consume("other-audience", "n-1", "req-3"), "consumed", "scopes are independent");
    const set = srv.commands.find((c) => c[0] === "SET")!;
    assert.match(set[1]!, /^cool:nonce:[0-9a-f]{64}$/, "nonce values never reach the store in clear");
    assert.deepEqual(set.slice(3), ["NX", "PX", "600000"]);
  } finally { store.close(); await srv.close(); }
});

test("redis: two independent clients (two machines) racing 25 submissions of one nonce → exactly one wins", async () => {
  const srv = await fakeRedis({ password: "s3cret" });
  const a = new RedisNonceStore({ port: srv.port, password: "s3cret", ttlMs: 60_000, db: 2 });
  const b = new RedisNonceStore({ port: srv.port, password: "s3cret", ttlMs: 60_000, db: 2 });
  try {
    const results = await Promise.all(Array.from({ length: 25 }, (_, i) => (i % 2 ? a : b).consume("gw", "shared-nonce", `req-${i}`)));
    assert.equal(results.filter((r) => r === "consumed").length, 1);
    assert.equal(results.filter((r) => r === "replayed").length, 24);
    assert.ok(srv.commands.some((c) => c[0] === "AUTH") && srv.commands.some((c) => c[0] === "SELECT" && c[1] === "2"));
  } finally { a.close(); b.close(); await srv.close(); }
});

test("redis: every failure is `unavailable` — never a silent permit", async () => {
  const srv = await fakeRedis({ password: "right" });
  const wrongAuth = new RedisNonceStore({ port: srv.port, password: "wrong", ttlMs: 1000, timeoutMs: 500 });
  assert.equal(await wrongAuth.consume("s", "n", "r"), "unavailable");
  wrongAuth.close();
  const store = new RedisNonceStore({ port: srv.port, password: "right", ttlMs: 1000, timeoutMs: 200 });
  for (const mode of ["error", "hang", "drop"] as const) {
    srv.mode = mode;
    assert.equal(await store.consume("s", `n-${mode}`, "r"), "unavailable", mode);
  }
  srv.mode = "ok";
  assert.equal(await store.consume("s", "n-after", "r"), "consumed", "reconnects after a failure");
  srv.mode = "hang";
  assert.equal(await store.consume("s", "n-hang-2", "r"), "unavailable");
  srv.mode = "ok";
  assert.equal(await store.consume("s", "n-after-hang", "r"), "consumed", "a timed-out reply is never paired with the next command");
  store.close();
  await srv.close();
  const nothing = new RedisNonceStore({ port: srv.port, ttlMs: 1000, timeoutMs: 300 });
  assert.equal(await nothing.consume("s", "n", "r"), "unavailable", "connection refused");
  nothing.close();
});

test("shared store: Postgres and DynamoDB backends map their atomic primitives correctly", async () => {
  const rows = new Map<string, string>();
  const pg = postgresAtomicInsert(async (text, params) => {
    if (text.startsWith("DELETE")) return { rowCount: 0 };
    const k = params[0] as string;
    if (rows.has(k)) return { rowCount: 0 };
    rows.set(k, params[1] as string);
    return { rowCount: 1 };
  });
  const s1 = new SharedNonceStore(pg, { ttlMs: 60_000 });
  assert.equal(await s1.consume("s", "n", "r1"), "consumed");
  assert.equal(await s1.consume("s", "n", "r2"), "replayed");
  assert.throws(() => postgresAtomicInsert(async () => ({ rowCount: 1 }), "x; DROP TABLE y"));

  const items = new Set<string>();
  const ddb = dynamoDbAtomicInsert({ async putItem(i) { const k = ((i["Item"] as Record<string, { S: string }>)["k"]!).S; if (items.has(k)) throw Object.assign(new Error("cond"), { name: "ConditionalCheckFailedException" }); items.add(k); return {}; } }, "cool_nonces");
  const s2 = new SharedNonceStore(ddb, { ttlMs: 60_000 });
  assert.equal(await s2.consume("s", "n", "r1"), "consumed");
  assert.equal(await s2.consume("s", "n", "r2"), "replayed");
  const broken: AtomicInsert = { insertIfAbsent: async () => { throw new Error("ProvisionedThroughputExceeded"); } };
  assert.equal(await new SharedNonceStore(broken, { ttlMs: 1 }).consume("s", "n", "r"), "unavailable");
});

const REAL = process.env["COOL_TEST_REDIS_URL"];
test("redis (REAL server): consumed once, replayed after, across two connections", { skip: REAL ? false : "set COOL_TEST_REDIS_URL=redis://host:port to run against a real Redis (CI does)" }, async () => {
  const u = new URL(REAL!);
  const opts = { host: u.hostname, port: Number(u.port || 6379), ttlMs: 30_000, ...(u.password ? { password: decodeURIComponent(u.password) } : {}) };
  const a = new RedisNonceStore(opts);
  const b = new RedisNonceStore(opts);
  const nonce = `real-${Date.now()}-${Math.random()}`;
  try {
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? a : b).consume("ci", nonce, `r${i}`)));
    assert.equal(results.filter((r) => r === "consumed").length, 1);
    assert.equal(results.filter((r) => r === "replayed").length, 19);
  } finally { a.close(); b.close(); }
});
