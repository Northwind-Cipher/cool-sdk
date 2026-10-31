/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Framing for the enclave ↔ host link, and the host-side forwarder.
 *
 * Frame:   magic 0xC0 0x01 · version 1 · type 1 · length u32 BE · payload
 *
 * The host proxy is untrusted transport. It validates only framing (magic,
 * version, size) so it cannot be made to buffer unbounded data, then forwards
 * the frame bytes UNCHANGED. It never parses or rewrites payloads; receipts
 * are signed inside the enclave before they cross, so a proxy that alters one
 * produces a receipt the log rejects. It can still drop, delay, duplicate or
 * reorder — the log's epoch/sequence accounting is what makes that visible.
 *
 * Transport: Node has no AF_VSOCK, so in a real deployment these frames ride
 * a stream that the platform's vsock proxy bridges (for example `vsock-proxy`
 * or socat). Anything that is a Node Readable/Writable works here. This has
 * not been run over a real vsock.
 */
import type { Readable, Writable } from "node:stream";

export const FRAME_VERSION = 1;
export const MAX_FRAME_BYTES = 1024 * 1024;
const MAGIC0 = 0xc0;
const MAGIC1 = 0x01;
const HEADER = 8;

export const FrameType = { hello: 1, receipt: 2, ack: 3, register: 4, error: 5 } as const;
export type FrameTypeName = keyof typeof FrameType;

export interface Frame {
  readonly type: number;
  readonly payload: Uint8Array;
  /** The exact bytes on the wire, header included — what a proxy forwards. */
  readonly raw: Uint8Array;
}

export class FrameError extends Error {
  constructor(readonly reason: "bad_magic" | "unsupported_version" | "frame_too_large" | "unknown_type", detail: string) {
    super(detail);
  }
}

export function encodeFrame(type: number, payload: Uint8Array): Uint8Array {
  if (payload.length > MAX_FRAME_BYTES) throw new FrameError("frame_too_large", `${payload.length} > ${MAX_FRAME_BYTES}`);
  const out = new Uint8Array(HEADER + payload.length);
  out[0] = MAGIC0;
  out[1] = MAGIC1;
  out[2] = FRAME_VERSION;
  out[3] = type;
  new DataView(out.buffer).setUint32(4, payload.length, false);
  out.set(payload, HEADER);
  return out;
}

/** Incremental decoder: feed arbitrary chunks, get whole frames. */
export class FrameDecoder {
  #buffer = new Uint8Array(0);

  push(chunk: Uint8Array): Frame[] {
    const merged = new Uint8Array(this.#buffer.length + chunk.length);
    merged.set(this.#buffer, 0);
    merged.set(chunk, this.#buffer.length);
    this.#buffer = merged;
    const frames: Frame[] = [];
    while (this.#buffer.length >= HEADER) {
      const b = this.#buffer;
      if (b[0] !== MAGIC0 || b[1] !== MAGIC1) throw new FrameError("bad_magic", "stream is not CooL frames");
      if (b[2] !== FRAME_VERSION) throw new FrameError("unsupported_version", `frame version ${b[2]} (this side speaks ${FRAME_VERSION})`);
      if (!Object.values(FrameType).includes(b[3] as never)) throw new FrameError("unknown_type", `frame type ${b[3]}`);
      const length = new DataView(b.buffer, b.byteOffset).getUint32(4, false);
      if (length > MAX_FRAME_BYTES) throw new FrameError("frame_too_large", `declared ${length} bytes > ${MAX_FRAME_BYTES}`);
      if (b.length < HEADER + length) break;
      const raw = b.slice(0, HEADER + length);
      frames.push({ type: raw[3]!, payload: raw.subarray(HEADER), raw });
      this.#buffer = b.slice(HEADER + length);
    }
    return frames;
  }

  get pending(): number {
    return this.#buffer.length;
  }
}

/**
 * Host-side forwarder: frames from `source` to `sink`, byte for byte, with
 * backpressure. Resolves with counts when the source ends; rejects on a
 * framing error (and stops forwarding).
 */
export function forwardFrames(source: Readable, sink: Writable): Promise<{ readonly frames: number; readonly bytes: number }> {
  const decoder = new FrameDecoder();
  let frames = 0;
  let bytes = 0;
  return new Promise((resolve, reject) => {
    source.on("data", (chunk: Buffer) => {
      let out: Frame[];
      try {
        out = decoder.push(new Uint8Array(chunk));
      } catch (err) {
        source.destroy();
        reject(err);
        return;
      }
      for (const f of out) {
        frames++;
        bytes += f.raw.length;
        if (!sink.write(f.raw)) {
          source.pause();
          sink.once("drain", () => source.resume());
        }
      }
    });
    source.on("end", () => {
      if (decoder.pending > 0) reject(new Error(`stream ended mid-frame (${decoder.pending} bytes)`));
      else resolve({ frames, bytes });
    });
    source.on("error", reject);
  });
}
