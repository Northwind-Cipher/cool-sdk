/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Replay stores shared across machines.
 *
 * Every backend reduces to one atomic primitive — insert-if-absent with a TTL —
 * and the same three answers as the local stores: `consumed` (this caller won),
 * `replayed` (someone already did), `unavailable` (no answer: the gateway must
 * refuse). A timeout is `unavailable`, never a guess.
 *
 *   RedisNonceStore      built in: RESP over TCP or TLS, `SET key v NX PX ttl`. No dependency.
 *   SharedNonceStore     any AtomicInsert backend, e.g.
 *     postgresAtomicInsert   INSERT … ON CONFLICT DO NOTHING (node-postgres `query` shape)
 *     dynamoDbAtomicInsert   PutItem with attribute_not_exists (AWS SDK v3 shape)
 *
 * The TTL must exceed the request's validity window; after it, an expired
 * request is refused by its own expiry, so forgetting the nonce is safe.
 *
 * These are the only networked components of cool-nwc/authz; they connect
 * only to the store you configure.
 */
import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { createHash } from "node:crypto";
import type { ConsumeResult, NonceStore } from "./replay";

const keyOf = (prefix: string, scope: string, nonce: string) => `${prefix}${createHash("sha256").update(`${scope}\0${nonce}`).digest("hex")}`;

/* ── generic backend ──────────────────────────────────────────────────── */

export interface AtomicInsert {
  /** true: inserted (first use). false: the key already existed. Throw on any failure. */
  insertIfAbsent(key: string, value: string, ttlMs: number): Promise<boolean>;
}

export class SharedNonceStore implements NonceStore {
  constructor(readonly backend: AtomicInsert, readonly options: { readonly ttlMs: number; readonly prefix?: string; readonly timeoutMs?: number }) {
    if (!(options.ttlMs > 0)) throw new Error("ttlMs must be positive");
  }

  async consume(scope: string, nonce: string, requestId: string): Promise<ConsumeResult> {
    const key = keyOf(this.options.prefix ?? "cool:nonce:", scope, nonce);
    let timer: NodeJS.Timeout | undefined;
    try {
      const won = await Promise.race([
        this.backend.insertIfAbsent(key, requestId, this.options.ttlMs),
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("timeout")), this.options.timeoutMs ?? 2_000); }),
      ]);
      return won ? "consumed" : "replayed";
    } catch {
      return "unavailable";
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}

/** node-postgres compatible. Table: `CREATE TABLE cool_nonces (k text PRIMARY KEY, request_id text NOT NULL, expires_at timestamptz NOT NULL)`. */
export function postgresAtomicInsert(query: (text: string, params: unknown[]) => Promise<{ rowCount: number | null }>, table = "cool_nonces"): AtomicInsert {
  if (!/^[a-z_][a-z0-9_]*$/i.test(table)) throw new Error("invalid table name");
  return {
    async insertIfAbsent(key, value, ttlMs) {
      // Expired rows are reclaimed in the same statement, so a key can be reused only after its TTL.
      await query(`DELETE FROM ${table} WHERE k = $1 AND expires_at < now()`, [key]);
      const r = await query(`INSERT INTO ${table} (k, request_id, expires_at) VALUES ($1, $2, now() + ($3 || ' milliseconds')::interval) ON CONFLICT (k) DO NOTHING`, [key, value, String(ttlMs)]);
      return r.rowCount === 1;
    },
  };
}

/** AWS SDK v3 compatible: `putItem: (i) => ddb.send(new PutItemCommand(i))`. Enable DynamoDB TTL on attribute `expires_at`. */
export function dynamoDbAtomicInsert(client: { putItem(input: Record<string, unknown>): Promise<unknown> }, table: string): AtomicInsert {
  return {
    async insertIfAbsent(key, value, ttlMs) {
      const nowS = Math.floor(Date.now() / 1000);
      try {
        await client.putItem({
          TableName: table,
          Item: { k: { S: key }, request_id: { S: value }, expires_at: { N: String(nowS + Math.ceil(ttlMs / 1000)) } },
          ConditionExpression: "attribute_not_exists(k) OR expires_at < :now",
          ExpressionAttributeValues: { ":now": { N: String(nowS) } },
        });
        return true;
      } catch (err) {
        if ((err as { name?: string }).name === "ConditionalCheckFailedException") return false;
        throw err;
      }
    },
  };
}

/* ── Redis (built in) ─────────────────────────────────────────────────── */

export interface RedisOptions {
  readonly host?: string;
  readonly port?: number;
  readonly tls?: boolean | { readonly servername?: string; readonly ca?: string | Buffer; readonly rejectUnauthorized?: boolean };
  readonly username?: string;
  readonly password?: string;
  readonly db?: number;
  readonly ttlMs: number;
  readonly prefix?: string;
  readonly timeoutMs?: number;
}

type Reply = string | number | null | Error | Reply[];

/** Parse one RESP2 reply from `buf` at `i`; returns undefined when incomplete. */
function parseReply(buf: Buffer, i: number): { value: Reply; next: number } | undefined {
  const eol = buf.indexOf("\r\n", i);
  if (eol < 0) return undefined;
  const type = String.fromCharCode(buf[i]!);
  const line = buf.toString("utf8", i + 1, eol);
  switch (type) {
    case "+": return { value: line, next: eol + 2 };
    case "-": return { value: new Error(line), next: eol + 2 };
    case ":": return { value: Number(line), next: eol + 2 };
    case "$": {
      const n = Number(line);
      if (n < 0) return { value: null, next: eol + 2 };
      if (buf.length < eol + 2 + n + 2) return undefined;
      return { value: buf.toString("utf8", eol + 2, eol + 2 + n), next: eol + 2 + n + 2 };
    }
    case "*": {
      const n = Number(line);
      if (n < 0) return { value: null, next: eol + 2 };
      const out: Reply[] = [];
      let p = eol + 2;
      for (let k = 0; k < n; k++) { const r = parseReply(buf, p); if (!r) return undefined; out.push(r.value); p = r.next; }
      return { value: out, next: p };
    }
    default: throw new Error(`unexpected RESP type ${JSON.stringify(type)}`);
  }
}

const encode = (args: readonly string[]) => Buffer.from(`*${args.length}\r\n${args.map((a) => `$${Buffer.byteLength(a)}\r\n${a}\r\n`).join("")}`);

/** A minimal pipelined RESP2 client: one connection, replies matched in order, reconnect on demand. */
export class RedisClient {
  #socket: Socket | undefined;
  #ready: Promise<void> | undefined;
  #buf = Buffer.alloc(0);
  readonly #pending: Array<{ resolve(v: Reply): void; reject(e: Error): void }> = [];

  constructor(readonly options: Omit<RedisOptions, "ttlMs" | "prefix">) {}

  #fail(err: Error): void {
    this.#socket?.destroy();
    this.#socket = undefined;
    this.#ready = undefined;
    this.#buf = Buffer.alloc(0);
    for (const p of this.#pending.splice(0)) p.reject(err);
  }

  #connect(): Promise<void> {
    if (this.#ready) return this.#ready;
    this.#ready = new Promise<void>((resolve, reject) => {
      const o = this.options;
      const host = o.host ?? "127.0.0.1";
      const port = o.port ?? 6379;
      const sock = o.tls
        ? tlsConnect({ host, port, servername: typeof o.tls === "object" ? o.tls.servername ?? host : host, ...(typeof o.tls === "object" && o.tls.ca ? { ca: o.tls.ca } : {}), rejectUnauthorized: typeof o.tls === "object" ? o.tls.rejectUnauthorized ?? true : true })
        : netConnect({ host, port });
      this.#socket = sock;
      sock.setNoDelay(true);
      // Handlers act only while this socket is the current one: a late event from a
      // torn-down connection must never fail its replacement.
      const mine = () => this.#socket === sock;
      const onError = (err: Error) => { reject(err); if (mine()) this.#fail(err); };
      sock.once("error", onError);
      sock.on("close", () => { if (mine()) this.#fail(new Error("redis connection closed")); });
      sock.on("data", (chunk: Buffer) => {
        this.#buf = Buffer.concat([this.#buf, chunk]);
        // Replies here are a few bytes; a server streaming more is broken or hostile.
        if (this.#buf.length > 1_048_576) { if (mine()) this.#fail(new Error("redis reply exceeds 1 MiB")); return; }
        try {
          for (;;) {
            const r = parseReply(this.#buf, 0);
            if (!r) break;
            this.#buf = this.#buf.subarray(r.next);
            const p = this.#pending.shift();
            if (!mine()) return;
            if (!p) { this.#fail(new Error("unsolicited redis reply")); return; }
            if (r.value instanceof Error) p.reject(r.value); else p.resolve(r.value);
          }
        } catch (err) { this.#fail(err as Error); }
      });
      sock.once(o.tls ? "secureConnect" : "connect", () => {
        sock.off("error", onError);
        sock.on("error", (err) => { if (mine()) this.#fail(err); });
        const setup: Promise<Reply>[] = [];
        if (o.password !== undefined) setup.push(this.#send(o.username ? ["AUTH", o.username, o.password] : ["AUTH", o.password]));
        if (o.db) setup.push(this.#send(["SELECT", String(o.db)]));
        Promise.all(setup).then(() => resolve(), (err) => { reject(err); if (mine()) this.#fail(err); });
      });
    });
    return this.#ready;
  }

  #send(args: readonly string[]): Promise<Reply> {
    return new Promise<Reply>((resolve, reject) => {
      this.#pending.push({ resolve, reject });
      this.#socket!.write(encode(args));
    });
  }

  /**
   * Send one command. On timeout the connection is torn down (failing every
   * pending reply), so a late reply can never be paired with a later command.
   */
  async command(args: readonly string[]): Promise<Reply> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => { const e = new Error("redis timeout"); this.#fail(e); reject(e); }, this.options.timeoutMs ?? 2_000);
    });
    try {
      return await Promise.race([this.#connect().then(() => this.#send(args)), timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  close(): void {
    this.#socket?.end();
    this.#socket = undefined;
    this.#ready = undefined;
  }
}

/** Nonce store on Redis (or Valkey / any RESP2 server supporting SET NX PX). */
export class RedisNonceStore implements NonceStore {
  readonly #client: RedisClient;
  readonly #shared: SharedNonceStore;

  constructor(readonly options: RedisOptions) {
    this.#client = new RedisClient(options);
    const client = this.#client;
    this.#shared = new SharedNonceStore({
      async insertIfAbsent(key, value, ttlMs) {
        const r = await client.command(["SET", key, value, "NX", "PX", String(Math.ceil(ttlMs))]);
        if (r === "OK") return true;
        if (r === null) return false;
        throw new Error(`unexpected SET reply ${JSON.stringify(r)}`);
      },
    }, { ttlMs: options.ttlMs, prefix: options.prefix ?? "cool:nonce:", timeoutMs: options.timeoutMs ?? 2_000 });
  }

  consume(scope: string, nonce: string, requestId: string): Promise<ConsumeResult> {
    return this.#shared.consume(scope, nonce, requestId);
  }

  close(): void { this.#client.close(); }
}
