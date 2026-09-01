/**
 * `cool-nwc/node` — the parts that need a filesystem.
 *
 * Kept out of the main entry point on purpose. The browser bundle is built from
 * `phala/index.ts`, and a single `node:fs` import anywhere in that graph would
 * either break the bundle or drag a shim into every page that loads it. Anything
 * that touches disk lives here instead, and the rest of the library stays
 * runtime-agnostic.
 */
export { FileLog } from "./phala/log-file";
export type { FileLogOptions } from "./phala/log-file";
export type { AppendResult, EvidenceLog } from "./phala/log";

export { isSocketPath, transportFor, unixFetch } from "./phala/unix";
export type { FetchLike } from "./phala/unix";
