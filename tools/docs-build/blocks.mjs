/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * The document model shared by the PDF and Word renderers.
 *
 * Both deliverables are generated from one content source, because a technical
 * document that disagrees with itself across formats is worse than no document.
 * Content lives in `content/*.mjs` as arrays of these blocks; `render-pdf.mjs`
 * and `render-docx.mjs` are the only two places that know about formatting.
 *
 * Inline markup inside `text` is deliberately minimal: `**bold**`, `*italic*`
 * and `` `code` ``. Anything richer would start to need a real parser, and
 * these are documents, not a markup language.
 */

const bare = (text) => text.replace(/`/g, "");

/** Split inline markup into typed runs. */
export function runs(text) {
  const out = [];
  // One pass, alternating between bold spans, code spans and plain text.
  const pattern = /(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g;
  let last = 0;
  for (let m = pattern.exec(text); m !== null; m = pattern.exec(text)) {
    if (m.index > last) out.push({ kind: "text", text: text.slice(last, m.index) });
    const token = m[0];
    // Emphasis cannot nest code, so a `` `span` `` inside bold renders as bold
    // rather than leaking its backticks into the page.
    if (token.startsWith("**")) out.push({ kind: "bold", text: bare(token.slice(2, -2)) });
    else if (token.startsWith("*")) out.push({ kind: "italic", text: bare(token.slice(1, -1)) });
    else out.push({ kind: "code", text: token.slice(1, -1) });
    last = m.index + token.length;
  }
  if (last < text.length) out.push({ kind: "text", text: text.slice(last) });
  return out.length > 0 ? out : [{ kind: "text", text: "" }];
}

/** Strip markup, for places that cannot carry runs (table cells in some paths). */
export function plain(text) {
  return text
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/\*([^*]+)\*/g, "$1")
    .replace(/`([^`]+)`/g, "$1");
}

/* ── block constructors, so content files read as prose ─────────────── */

export const cover = (o) => ({ t: "cover", ...o });
export const h1 = (text, o = {}) => ({ t: "h1", text, ...o });
export const h2 = (text) => ({ t: "h2", text });
export const h3 = (text) => ({ t: "h3", text });
export const p = (text) => ({ t: "p", text });
export const lead = (text) => ({ t: "lead", text });
export const bullets = (items) => ({ t: "bullets", items });
export const numbers = (items) => ({ t: "numbers", items });
export const code = (lines, caption) => ({ t: "code", lines, caption });
export const table = (head, rows, widths) => ({ t: "table", head, rows, widths });
export const callout = (title, text, tone = "note") => ({ t: "callout", title, text, tone });
export const pagebreak = () => ({ t: "pagebreak" });
export const rule = () => ({ t: "rule" });
