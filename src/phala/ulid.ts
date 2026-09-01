/**
 * A dependency-free, monotonic ULID.
 *
 * The v1 core uses the `ulid` package. The v2 tier cannot: that package detects
 * its randomness source by looking for `window`, and falls back to
 * `require("crypto")` when it does not find one — which breaks the moment the
 * library is bundled for a browser and then run anywhere that is not a browser
 * (Deno, a Worker, Node, a test runner). An id generator failing at runtime
 * would take the whole capture path down, so this replaces it with thirty lines
 * that read from the same CSPRNG as every other random value in the SDK.
 *
 * Two properties matter here beyond "unique":
 *
 *   • lexicographic order == time order, because record ids are sorted, paged
 *     and compared in a ledger;
 *   • monotonicity inside a millisecond. Records are sealed in tight loops, and
 *     a plain random suffix would let two records from the same millisecond sort
 *     in an order that contradicts their sequence numbers.
 */

/** Crockford base32 — no I, L, O or U, so an id cannot be misread aloud. */
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const TIME_CHARS = 10;
const RANDOM_CHARS = 16;
const MAX_TIME = 281_474_976_710_655; // 2^48 - 1

function encodeTime(ms: number): string {
  if (!Number.isInteger(ms) || ms < 0 || ms > MAX_TIME) {
    throw new RangeError(`ulid: timestamp ${ms} out of range`);
  }
  let out = "";
  let value = ms;
  for (let i = 0; i < TIME_CHARS; i++) {
    out = ALPHABET[value % 32]! + out;
    value = Math.floor(value / 32);
  }
  return out;
}

/**
 * 80 bits of randomness, unbiased: 256 is an exact multiple of 32, so masking a
 * random byte to five bits keeps the distribution uniform without rejection.
 */
function randomChars(): string {
  const bytes = new Uint8Array(RANDOM_CHARS);
  globalThis.crypto.getRandomValues(bytes);
  let out = "";
  for (let i = 0; i < RANDOM_CHARS; i++) out += ALPHABET[bytes[i]! & 31];
  return out;
}

/** Increment a base32 string by one, carrying leftwards. */
function increment(chars: string): string {
  const out = chars.split("");
  for (let i = out.length - 1; i >= 0; i--) {
    const index = ALPHABET.indexOf(out[i]!);
    if (index < ALPHABET.length - 1) {
      out[i] = ALPHABET[index + 1]!;
      return out.join("");
    }
    out[i] = ALPHABET[0]!;
  }
  // 2^80 ids inside one millisecond. Reached only by a bug, and silently
  // wrapping would break the ordering guarantee this function exists for.
  throw new Error("ulid: randomness overflow within a single millisecond");
}

/** Build a monotonic ULID factory. Inject `now` for deterministic tests. */
export function createUlid(now: () => number = () => Date.now()): () => string {
  let lastTime = -1;
  let lastRandom = "";
  return () => {
    const time = now();
    if (time === lastTime) {
      lastRandom = increment(lastRandom);
    } else {
      lastTime = time;
      lastRandom = randomChars();
    }
    return encodeTime(time) + lastRandom;
  };
}

/** The default factory — one monotonic sequence per process. */
export const ulid = createUlid();
