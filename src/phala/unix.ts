/**
 * Talking to the dstack guest agent over its unix socket.
 *
 * This is the gap between "supports dstack" and "runs inside a CVM". The guest
 * agent listens on `/var/run/dstack.sock`, not on a TCP port — and `fetch`
 * cannot open a unix socket. Setting `DSTACK_ENDPOINT=/var/run/dstack.sock`
 * would previously fail at the first call, which is exactly the configuration
 * every real deployment uses.
 *
 * So this provides a `fetch`-shaped function backed by `node:http`, which has
 * supported `socketPath` since forever. It also handles Windows named pipes
 * (`\\.\pipe\dstack`), because that is how the dstack simulator exposes itself
 * on a developer's laptop.
 *
 * Node-only by construction, which is why it lives behind `cool-nwc/node` and
 * not in the browser bundle.
 */
import { request } from "node:http";

/** What `HttpDstackClient` needs from a transport — a subset of `fetch`. */
export type FetchLike = (
  input: string | URL,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown>; text: () => Promise<string> }>;

/** True when an endpoint is a unix socket or a Windows named pipe, not a URL. */
export function isSocketPath(endpoint: string): boolean {
  if (endpoint.startsWith("http://") || endpoint.startsWith("https://")) return false;
  return (
    endpoint.startsWith("/") ||
    endpoint.startsWith("\\\\.\\pipe\\") ||
    endpoint.startsWith("//./pipe/") ||
    endpoint.endsWith(".sock")
  );
}

/**
 * A `fetch` that goes over a socket.
 *
 * The URL's host is ignored — it only exists because HTTP requires one. The path
 * is what matters, and the socket is what carries it.
 */
export function unixFetch(socketPath: string): FetchLike {
  return (input, init = {}) =>
    new Promise((resolve, reject) => {
      const url = new URL(String(input), "http://dstack");
      const req = request(
        {
          socketPath,
          path: `${url.pathname}${url.search}`,
          method: init.method ?? "GET",
          headers: {
            host: "dstack",
            ...(init.headers ?? {}),
            ...(init.body ? { "content-length": Buffer.byteLength(init.body).toString() } : {}),
          },
          // The agent is local; a slow answer means it is wedged, not far away.
          timeout: 10_000,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => chunks.push(chunk));
          res.on("end", () => {
            const body = Buffer.concat(chunks).toString("utf8");
            const status = res.statusCode ?? 0;
            resolve({
              ok: status >= 200 && status < 300,
              status,
              text: async () => body,
              json: async () => JSON.parse(body) as unknown,
            });
          });
        },
      );

      req.on("timeout", () => {
        req.destroy(new Error(`dstack agent at ${socketPath} did not answer within 10s`));
      });
      req.on("error", (error: NodeJS.ErrnoException) => {
        // The two failures worth naming, because they mean completely different
        // things to whoever is reading the output at 2am.
        if (error.code === "ENOENT") {
          reject(
            new Error(
              `no dstack guest agent at ${socketPath} — are you inside a CVM? ` +
                "Outside one, unset DSTACK_ENDPOINT and CooL runs its labelled simulator.",
            ),
          );
          return;
        }
        if (error.code === "EACCES") {
          reject(
            new Error(
              `permission denied on ${socketPath} — the container needs the socket mounted ` +
                "and the process needs access to it (see deploy/docker-compose.yml).",
            ),
          );
          return;
        }
        reject(error);
      });

      if (init.body) req.write(init.body);
      req.end();
    });
}

/**
 * Pick a transport for an endpoint.
 *
 * Returns `null` for ordinary URLs so the caller keeps using the platform
 * `fetch` — there is no reason to route TCP through this.
 */
export function transportFor(endpoint: string): FetchLike | null {
  return isSocketPath(endpoint) ? unixFetch(endpoint) : null;
}
