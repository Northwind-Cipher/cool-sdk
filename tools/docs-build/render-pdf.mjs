/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/** Render the shared document model to PDF. */
import { createWriteStream, existsSync } from "node:fs";
import PDFDocument from "pdfkit";
import { runs, plain } from "./blocks.mjs";

const PAGE = { width: 612, height: 792 };
const M = { left: 64, right: 64, top: 64, bottom: 72 };
const COL = PAGE.width - M.left - M.right;

const INK = "#11161c";
const BODY = "#23303c";
const MUTED = "#6b7785";
const ACCENT = "#0f766e";
const WARN = "#b45309";
const LINE = "#d9e0e6";
const CODE_BG = "#f4f7f8";
const HEAD_BG = "#eef3f4";
const ZEBRA = "#f8fafb";

const FONTS = "C:/Windows/Fonts";
const face = (file, fallback) => (existsSync(`${FONTS}/${file}`) ? `${FONTS}/${file}` : fallback);

/** Register Calibri/Consolas when present, else fall back to the built-ins. */
function fonts(doc) {
  doc.registerFont("body", face("calibri.ttf", "Helvetica"));
  doc.registerFont("bold", face("calibrib.ttf", "Helvetica-Bold"));
  doc.registerFont("italic", face("calibrii.ttf", "Helvetica-Oblique"));
  doc.registerFont("mono", face("consola.ttf", "Courier"));
  doc.registerFont("monob", face("consolab.ttf", "Courier-Bold"));
}

/** Inline run kind → registered font. */
const FACE = { bold: "bold", italic: "italic", code: "mono", text: "body" };

/** Width of a run sequence at the given size. */
function runsWidth(doc, parts, size) {
  let w = 0;
  for (const part of parts) {
    doc.font(FACE[part.kind] ?? "body");
    doc.fontSize(part.kind === "code" ? size - 0.8 : size);
    w += doc.widthOfString(part.text);
  }
  return w;
}

/**
 * Lay out inline runs as wrapped lines.
 *
 * pdfkit can wrap a string but not a sequence of differently-styled runs, so
 * word-level layout is done here. Code runs get a slightly smaller size because
 * Consolas at body size reads as oversized next to Calibri.
 */
function wrap(doc, parts, size, width) {
  const words = [];
  for (const part of parts) {
    const pieces = part.text.split(/(\s+)/).filter((s) => s.length > 0);
    for (const piece of pieces) words.push({ kind: part.kind, text: piece });
  }
  const lines = [];
  let line = [];
  let used = 0;
  for (const word of words) {
    const w = runsWidth(doc, [word], size);
    if (used + w > width && line.length > 0 && /\S/.test(word.text)) {
      lines.push(line);
      line = [];
      used = 0;
    }
    if (line.length === 0 && /^\s+$/.test(word.text)) continue;
    line.push(word);
    used += w;
  }
  if (line.length > 0) lines.push(line);
  return lines;
}

export function renderPdf(blocks, meta, outPath) {
  const doc = new PDFDocument({
    size: [PAGE.width, PAGE.height],
    margins: { top: M.top, bottom: M.bottom, left: M.left, right: M.right },
    info: {
      Title: meta.title,
      Author: "Northwind Cipher Pvt. Ltd.",
      Subject: meta.subtitle,
      Keywords: "CooL, Contrast, confidential computing, Intel TDX, AMD SEV-SNP, AI governance",
    },
    autoFirstPage: false,
  });
  fonts(doc);
  const stream = createWriteStream(outPath);
  doc.pipe(stream);

  let pageNo = 0;
  let onCover = false;

  const newPage = () => {
    doc.addPage();
    pageNo++;
    if (!onCover) chrome();
  };

  /**
   * Draw outside the text margins without triggering pagination.
   *
   * pdfkit adds a page whenever text is written past the bottom margin, so a
   * running footer silently produces a blank page after every real one. Zeroing
   * the margins for the duration of the draw is the documented way round it.
   */
  const outsideMargins = (draw) => {
    const saved = { ...doc.page.margins };
    doc.page.margins = { top: 0, bottom: 0, left: 0, right: 0 };
    draw();
    doc.page.margins = saved;
  };

  /** Running header and footer. */
  const chrome = () => {
    doc.save();
    doc.font("body").fontSize(7.5).fillColor(MUTED);
    outsideMargins(() => {
      doc.text(meta.shortTitle, M.left, 34, { width: COL * 0.7, lineBreak: false });
      doc.text(`${pageNo - 1}`, M.left, 34, { width: COL, align: "right", lineBreak: false });
      doc.moveTo(M.left, 48).lineTo(PAGE.width - M.right, 48).lineWidth(0.5).strokeColor(LINE).stroke();
      doc
        .font("body")
        .fontSize(7)
        .fillColor(MUTED)
        .text(meta.footer, M.left, PAGE.height - 44, { width: COL, align: "center", lineBreak: false });
    });
    doc.restore();
    doc.y = M.top + 8;
    doc.x = M.left;
  };

  /** Make sure `need` points fit; otherwise start a page. */
  const room = (need) => {
    if (doc.y + need > PAGE.height - M.bottom) newPage();
  };

  const writeRuns = (parts, { size = 10.5, leading = 15, color = BODY, indent = 0, gap = 0 } = {}) => {
    const width = COL - indent;
    const lines = wrap(doc, parts, size, width);
    for (const line of lines) {
      room(leading);
      let x = M.left + indent;
      const baseline = doc.y;
      for (const word of line) {
        const isCode = word.kind === "code";
        doc.font(FACE[word.kind] ?? "body");
        doc.fontSize(isCode ? size - 0.8 : size);
        doc.fillColor(isCode ? ACCENT : color);
        const w = doc.widthOfString(word.text);
        doc.text(word.text, x, baseline + (isCode ? 0.6 : 0), { lineBreak: false });
        x += w;
      }
      doc.y = baseline + leading;
    }
    doc.y += gap;
  };

  /* ── cover ────────────────────────────────────────────────────────── */
  const drawCover = (b) => {
    onCover = true;
    newPage();
    onCover = false;

    doc.rect(0, 0, PAGE.width, 150).fill(INK);
    doc.font("bold").fontSize(9).fillColor("#7fd3cb");
    doc.text(b.eyebrow.toUpperCase(), M.left, 52, { characterSpacing: 1.6 });
    doc.font("bold").fontSize(27).fillColor("#ffffff");
    doc.text(b.title, M.left, 72, { width: COL - 20, lineGap: 2 });

    doc.y = 185;
    doc.x = M.left;
    doc.font("body").fontSize(13.5).fillColor(BODY);
    doc.text(b.subtitle, M.left, doc.y, { width: COL - 30, lineGap: 3 });

    doc.y += 24;
    const rows = b.meta;
    const labelW = 112;
    for (const [k, v] of rows) {
      room(17);
      const y = doc.y;
      doc.font("bold").fontSize(8.6).fillColor(MUTED);
      doc.text(k.toUpperCase(), M.left, y + 1, { width: labelW, characterSpacing: 0.7, lineBreak: false });
      doc.font("body").fontSize(10).fillColor(BODY);
      doc.text(plain(v), M.left + labelW, y, { width: COL - labelW, lineBreak: false });
      doc.y = y + 17;
    }

    doc.y += 18;
    const bh = doc.heightOfString(b.status, { width: COL - 44 }) + 30;
    doc.roundedRect(M.left, doc.y, COL, bh, 4).fill("#fff8ec");
    doc.rect(M.left, doc.y, 3, bh).fill(WARN);
    doc.font("bold").fontSize(8.6).fillColor(WARN);
    doc.text("STATUS OF THESE CLAIMS", M.left + 16, doc.y + 11, { characterSpacing: 0.8 });
    doc.font("body").fontSize(9.6).fillColor("#6b4a16");
    doc.text(b.status, M.left + 16, doc.y + 3, { width: COL - 44, lineGap: 1.5 });

    outsideMargins(() => {
      doc.font("body").fontSize(8).fillColor(MUTED);
      const h = doc.heightOfString(b.foot, { width: COL, lineGap: 1.5 });
      doc.text(b.foot, M.left, PAGE.height - 56 - h, { width: COL, lineGap: 1.5 });
    });
  };

  /* ── tables ───────────────────────────────────────────────────────── */
  const drawTable = (b) => {
    const widths = (b.widths ?? b.head.map(() => 1)).slice();
    const total = widths.reduce((a, c) => a + c, 0);
    const cols = widths.map((w) => (w / total) * COL);
    const pad = 6;

    const cellLines = (text, w, size, bold) => {
      const parts = bold ? [{ kind: "bold", text: plain(text) }] : runs(text);
      return wrap(doc, parts, size, w - pad * 2);
    };

    const drawRow = (cells, { bold = false, bg = null, size = 9 } = {}) => {
      const lineH = 12.4;
      const laid = cells.map((c, i) => cellLines(String(c), cols[i], size, bold));
      const h = Math.max(...laid.map((l) => l.length)) * lineH + pad * 2 - 3;
      room(h + 2);
      const top = doc.y;
      if (bg) doc.rect(M.left, top, COL, h).fill(bg);
      let x = M.left;
      laid.forEach((lines, i) => {
        let y = top + pad - 1;
        for (const line of lines) {
          let cx = x + pad;
          for (const word of line) {
            const isCode = word.kind === "code";
            doc.font(bold ? "bold" : (FACE[word.kind] ?? "body"));
            doc.fontSize(isCode ? size - 0.7 : size);
            doc.fillColor(bold ? INK : isCode ? ACCENT : BODY);
            doc.text(word.text, cx, y, { lineBreak: false });
            cx += doc.widthOfString(word.text);
          }
          y += lineH;
        }
        x += cols[i];
      });
      doc.moveTo(M.left, top + h).lineTo(M.left + COL, top + h).lineWidth(0.5).strokeColor(LINE).stroke();
      doc.y = top + h;
    };

    room(46);
    doc.y += 3;
    if (b.head.some((h) => String(h).length > 0)) drawRow(b.head, { bold: true, bg: HEAD_BG, size: 8.8 });
    b.rows.forEach((r, i) => drawRow(r, { bg: i % 2 === 1 ? ZEBRA : null }));
    doc.y += 12;
  };

  /* ── code ─────────────────────────────────────────────────────────── */
  const drawCode = (b) => {
    const size = 8.2;
    const lineH = 11.2;
    const h = b.lines.length * lineH + 16;
    room(Math.min(h, 160) + 10);
    const top = doc.y + 2;
    doc.roundedRect(M.left, top, COL, h, 3).fill(CODE_BG);
    doc.font("mono").fontSize(size).fillColor("#1f3a3a");
    let y = top + 8;
    for (const line of b.lines) {
      if (y + lineH > PAGE.height - M.bottom) {
        doc.y = y;
        newPage();
        y = doc.y + 4;
        doc.roundedRect(M.left, y - 6, COL, PAGE.height - M.bottom - y + 2, 3).fill(CODE_BG);
        doc.font("mono").fontSize(size).fillColor("#1f3a3a");
      }
      doc.text(line.length > 0 ? line : " ", M.left + 10, y, { lineBreak: false, width: COL - 20 });
      y += lineH;
    }
    doc.y = y + 8;
    if (b.caption) {
      doc.font("italic").fontSize(8.2).fillColor(MUTED);
      room(13);
      doc.text(plain(b.caption), M.left, doc.y, { width: COL });
      doc.y += 4;
    }
    doc.y += 6;
  };

  /* ── dispatch ─────────────────────────────────────────────────────── */
  for (const b of blocks) {
    switch (b.t) {
      case "cover":
        drawCover(b);
        break;
      case "pagebreak":
        newPage();
        break;
      case "rule":
        room(14);
        doc.moveTo(M.left, doc.y + 4).lineTo(M.left + COL, doc.y + 4).lineWidth(0.5).strokeColor(LINE).stroke();
        doc.y += 14;
        break;
      case "h1": {
        // A new page per chapter reads well but leaves half-empty pages all
        // through a reference document. Break only when the remainder of the
        // page could not hold a heading and a few lines under it.
        const left = PAGE.height - M.bottom - doc.y;
        if (b.newPage !== false && left < (PAGE.height - M.top - M.bottom) * 0.42) newPage();
        else if (doc.y > M.top + 12) doc.y += 20;
        doc.y += 2;
        doc.moveTo(M.left, doc.y).lineTo(M.left + 34, doc.y).lineWidth(2.2).strokeColor(ACCENT).stroke();
        doc.y += 9;
        doc.font("bold").fontSize(17).fillColor(INK);
        doc.text(b.text, M.left, doc.y, { width: COL, lineGap: 1 });
        doc.y += 10;
        break;
      }
      case "h2":
        room(40);
        doc.y += 9;
        doc.font("bold").fontSize(12.4).fillColor(INK);
        doc.text(b.text, M.left, doc.y, { width: COL });
        doc.y += 6;
        break;
      case "h3":
        room(32);
        doc.y += 7;
        doc.font("bold").fontSize(10.3).fillColor(ACCENT);
        doc.text(b.text, M.left, doc.y, { width: COL });
        doc.y += 4;
        break;
      case "lead":
        writeRuns(runs(b.text), { size: 12, leading: 17, color: INK, gap: 8 });
        break;
      case "p":
        writeRuns(runs(b.text), { gap: 7 });
        break;
      case "bullets":
        for (const item of b.items) {
          room(16);
          const y = doc.y;
          doc.font("body").fontSize(10.5).fillColor(ACCENT);
          doc.text("\u2022", M.left + 4, y, { lineBreak: false });
          doc.y = y;
          writeRuns(runs(item), { indent: 18, gap: 2.5 });
        }
        doc.y += 5;
        break;
      case "numbers":
        b.items.forEach((item, i) => {
          room(16);
          const y = doc.y;
          doc.font("bold").fontSize(9.6).fillColor(ACCENT);
          doc.text(`${i + 1}.`, M.left + 2, y + 0.8, { lineBreak: false });
          doc.y = y;
          writeRuns(runs(item), { indent: 20, gap: 2.5 });
        });
        doc.y += 5;
        break;
      case "code":
        drawCode(b);
        break;
      case "table":
        drawTable(b);
        break;
      case "callout": {
        const tone = b.tone === "warn" ? WARN : ACCENT;
        const bg = b.tone === "warn" ? "#fff8ec" : "#f0f8f7";
        const fg = b.tone === "warn" ? "#6b4a16" : "#13433f";
        doc.font("body").fontSize(9.8);
        const textH = doc.heightOfString(plain(b.text), { width: COL - 40, lineGap: 1.5 });
        const h = textH + 30;
        room(h + 8);
        const top = doc.y + 3;
        doc.roundedRect(M.left, top, COL, h, 3).fill(bg);
        doc.rect(M.left, top, 3, h).fill(tone);
        doc.font("bold").fontSize(8.4).fillColor(tone);
        doc.text(b.title.toUpperCase(), M.left + 15, top + 10, { characterSpacing: 0.8 });
        doc.font("body").fontSize(9.8).fillColor(fg);
        doc.text(plain(b.text), M.left + 15, doc.y + 2, { width: COL - 40, lineGap: 1.5 });
        doc.y = top + h + 10;
        break;
      }
      default:
        throw new Error(`unknown block '${b.t}'`);
    }
  }

  doc.end();
  return new Promise((resolve) => stream.on("finish", resolve));
}
