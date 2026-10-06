/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/** Render the shared document model to a Word .docx. */
import { writeFileSync } from "node:fs";
import {
  AlignmentType,
  BorderStyle,
  Document,
  Footer,
  Header,
  HeadingLevel,
  LevelFormat,
  PageBreak,
  PageNumber,
  Packer,
  Paragraph,
  ShadingType,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
} from "docx";
import { runs, plain } from "./blocks.mjs";

const INK = "11161C";
const BODY = "23303C";
const MUTED = "6B7785";
const ACCENT = "0F766E";
const WARN = "B45309";
const LINE = "D9E0E6";
const CODE_BG = "F4F7F8";
const HEAD_BG = "EEF3F4";
const ZEBRA = "F8FAFB";

/** US Letter in DXA; docx-js defaults to A4. */
const PAGE = { width: 12240, height: 15840 };
const MARGIN = 1080; // 0.75"
const CONTENT = PAGE.width - MARGIN * 2;

const BODY_FONT = "Calibri";
const MONO_FONT = "Consolas";

/** Inline runs → docx TextRuns. */
function textRuns(text, { size = 21, color = BODY, bold = false } = {}) {
  return runs(text).map((part) =>
    part.kind === "code"
      ? new TextRun({ text: part.text, font: MONO_FONT, size: size - 2, color: ACCENT })
      : new TextRun({
          text: part.text,
          font: BODY_FONT,
          size,
          color,
          bold: bold || part.kind === "bold",
          italics: part.kind === "italic",
        }),
  );
}

const noBorder = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
const cellBorders = {
  top: noBorder,
  left: noBorder,
  right: noBorder,
  bottom: { style: BorderStyle.SINGLE, size: 2, color: LINE },
};

function tableBlock(b) {
  const weights = b.widths ?? b.head.map(() => 1);
  const total = weights.reduce((a, c) => a + c, 0);
  const widths = weights.map((w) => Math.round((w / total) * CONTENT));
  // Rounding must not leave the columns short of the table width.
  widths[widths.length - 1] += CONTENT - widths.reduce((a, c) => a + c, 0);

  const row = (cells, { bold = false, bg = null, size = 18 } = {}) =>
    new TableRow({
      tableHeader: bold,
      children: cells.map(
        (cell, i) =>
          new TableCell({
            width: { size: widths[i], type: WidthType.DXA },
            borders: cellBorders,
            ...(bg ? { shading: { type: ShadingType.CLEAR, fill: bg, color: "auto" } } : {}),
            margins: { top: 90, bottom: 90, left: 110, right: 110 },
            children: [
              new Paragraph({
                spacing: { line: 240, after: 0 },
                children: textRuns(String(cell), {
                  size,
                  color: bold ? INK : BODY,
                  bold,
                }),
              }),
            ],
          }),
      ),
    });

  const rows = [];
  if (b.head.some((h) => String(h).length > 0)) {
    rows.push(row(b.head, { bold: true, bg: HEAD_BG, size: 17 }));
  }
  b.rows.forEach((r, i) => rows.push(row(r, { bg: i % 2 === 1 ? ZEBRA : null })));

  return new Table({
    columnWidths: widths,
    width: { size: CONTENT, type: WidthType.DXA },
    rows,
  });
}

function codeBlock(b) {
  const out = b.lines.map(
    (line, i) =>
      new Paragraph({
        spacing: { before: i === 0 ? 60 : 0, after: 0, line: 220 },
        shading: { type: ShadingType.CLEAR, fill: CODE_BG, color: "auto" },
        indent: { left: 170, right: 170 },
        children: [
          new TextRun({ text: line.length > 0 ? line : " ", font: MONO_FONT, size: 16, color: "1F3A3A" }),
        ],
      }),
  );
  if (b.caption) {
    out.push(
      new Paragraph({
        spacing: { before: 80, after: 160 },
        children: [new TextRun({ text: plain(b.caption), font: BODY_FONT, size: 17, italics: true, color: MUTED })],
      }),
    );
  } else {
    out.push(new Paragraph({ spacing: { after: 160 }, children: [] }));
  }
  return out;
}

function calloutBlock(b) {
  const tone = b.tone === "warn" ? WARN : ACCENT;
  const bg = b.tone === "warn" ? "FFF8EC" : "F0F8F7";
  const fg = b.tone === "warn" ? "6B4A16" : "13433F";
  return new Table({
    columnWidths: [CONTENT],
    width: { size: CONTENT, type: WidthType.DXA },
    rows: [
      new TableRow({
        children: [
          new TableCell({
            width: { size: CONTENT, type: WidthType.DXA },
            shading: { type: ShadingType.CLEAR, fill: bg, color: "auto" },
            borders: {
              top: noBorder,
              right: noBorder,
              bottom: noBorder,
              left: { style: BorderStyle.SINGLE, size: 18, color: tone },
            },
            margins: { top: 150, bottom: 150, left: 200, right: 200 },
            children: [
              new Paragraph({
                spacing: { after: 70 },
                children: [
                  new TextRun({
                    text: b.title.toUpperCase(),
                    font: BODY_FONT,
                    size: 16,
                    bold: true,
                    color: tone,
                  }),
                ],
              }),
              new Paragraph({
                spacing: { after: 0, line: 260 },
                children: textRuns(b.text, { size: 19, color: fg }),
              }),
            ],
          }),
        ],
      }),
    ],
  });
}

function coverBlocks(b) {
  const out = [
    new Paragraph({
      spacing: { after: 60 },
      children: [
        new TextRun({
          text: b.eyebrow.toUpperCase(),
          font: BODY_FONT,
          size: 18,
          bold: true,
          color: ACCENT,
          characterSpacing: 30,
        }),
      ],
    }),
    new Paragraph({
      spacing: { after: 220 },
      children: [new TextRun({ text: b.title, font: BODY_FONT, size: 50, bold: true, color: INK })],
    }),
    new Paragraph({
      spacing: { after: 300, line: 300 },
      children: [new TextRun({ text: b.subtitle, font: BODY_FONT, size: 26, color: BODY })],
    }),
  ];

  for (const [k, v] of b.meta) {
    out.push(
      new Paragraph({
        spacing: { after: 60 },
        children: [
          new TextRun({ text: `${k.toUpperCase()}   `, font: BODY_FONT, size: 17, bold: true, color: MUTED }),
          new TextRun({ text: plain(v), font: BODY_FONT, size: 20, color: BODY }),
        ],
      }),
    );
  }

  out.push(new Paragraph({ spacing: { after: 160 }, children: [] }));
  out.push(calloutBlock({ title: "Status of these claims", text: b.status, tone: "warn" }));
  out.push(
    new Paragraph({
      spacing: { before: 300, after: 0, line: 260 },
      children: [new TextRun({ text: b.foot, font: BODY_FONT, size: 16, color: MUTED })],
    }),
  );
  out.push(new Paragraph({ children: [new PageBreak()] }));
  return out;
}

export function renderDocx(blocks, meta, outPath) {
  const children = [];

  for (const b of blocks) {
    switch (b.t) {
      case "cover":
        children.push(...coverBlocks(b));
        break;
      case "pagebreak":
        children.push(new Paragraph({ children: [new PageBreak()] }));
        break;
      case "rule":
        children.push(
          new Paragraph({
            spacing: { before: 120, after: 160 },
            border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: LINE } },
            children: [],
          }),
        );
        break;
      case "h1":
        children.push(
          new Paragraph({
            heading: HeadingLevel.HEADING_1,
            pageBreakBefore: b.newPage !== false,
            spacing: { before: 120, after: 160 },
            border: { top: { style: BorderStyle.SINGLE, size: 12, color: ACCENT, space: 8 } },
            children: [new TextRun({ text: b.text, font: BODY_FONT, size: 34, bold: true, color: INK })],
          }),
        );
        break;
      case "h2":
        children.push(
          new Paragraph({
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 280, after: 110 },
            children: [new TextRun({ text: b.text, font: BODY_FONT, size: 25, bold: true, color: INK })],
          }),
        );
        break;
      case "h3":
        children.push(
          new Paragraph({
            heading: HeadingLevel.HEADING_3,
            spacing: { before: 200, after: 80 },
            children: [new TextRun({ text: b.text, font: BODY_FONT, size: 21, bold: true, color: ACCENT })],
          }),
        );
        break;
      case "lead":
        children.push(
          new Paragraph({
            spacing: { after: 180, line: 320 },
            children: textRuns(b.text, { size: 24, color: INK }),
          }),
        );
        break;
      case "p":
        children.push(
          new Paragraph({ spacing: { after: 150, line: 290 }, children: textRuns(b.text) }),
        );
        break;
      case "bullets":
        for (const item of b.items) {
          children.push(
            new Paragraph({
              numbering: { reference: "cool-bullets", level: 0 },
              spacing: { after: 70, line: 280 },
              children: textRuns(item),
            }),
          );
        }
        children.push(new Paragraph({ spacing: { after: 80 }, children: [] }));
        break;
      case "numbers":
        for (const item of b.items) {
          children.push(
            new Paragraph({
              numbering: { reference: "cool-numbers", level: 0 },
              spacing: { after: 70, line: 280 },
              children: textRuns(item),
            }),
          );
        }
        children.push(new Paragraph({ spacing: { after: 80 }, children: [] }));
        break;
      case "code":
        children.push(...codeBlock(b));
        break;
      case "table":
        children.push(tableBlock(b));
        children.push(new Paragraph({ spacing: { after: 200 }, children: [] }));
        break;
      case "callout":
        children.push(calloutBlock(b));
        children.push(new Paragraph({ spacing: { after: 200 }, children: [] }));
        break;
      default:
        throw new Error(`unknown block '${b.t}'`);
    }
  }

  const doc = new Document({
    title: meta.title,
    description: meta.subtitle,
    creator: "Northwind Cipher Pvt. Ltd.",
    numbering: {
      config: [
        {
          reference: "cool-bullets",
          levels: [
            {
              level: 0,
              format: LevelFormat.BULLET,
              text: "•",
              alignment: AlignmentType.LEFT,
              style: { paragraph: { indent: { left: 360, hanging: 200 } } },
            },
          ],
        },
        {
          reference: "cool-numbers",
          levels: [
            {
              level: 0,
              format: LevelFormat.DECIMAL,
              text: "%1.",
              alignment: AlignmentType.LEFT,
              style: { paragraph: { indent: { left: 400, hanging: 240 } } },
            },
          ],
        },
      ],
    },
    sections: [
      {
        properties: {
          page: {
            size: { width: PAGE.width, height: PAGE.height },
            margin: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN },
          },
          titlePage: true,
        },
        headers: {
          default: new Header({
            children: [
              new Paragraph({
                tabStops: [{ type: "right", position: CONTENT }],
                border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: LINE, space: 6 } },
                children: [
                  new TextRun({ text: meta.shortTitle, font: BODY_FONT, size: 15, color: MUTED }),
                  new TextRun({ text: "\t", font: BODY_FONT, size: 15 }),
                  new TextRun({ children: [PageNumber.CURRENT], font: BODY_FONT, size: 15, color: MUTED }),
                ],
              }),
            ],
          }),
          first: new Header({ children: [new Paragraph({ children: [] })] }),
        },
        footers: {
          default: new Footer({
            children: [
              new Paragraph({
                alignment: AlignmentType.CENTER,
                children: [new TextRun({ text: meta.footer, font: BODY_FONT, size: 14, color: MUTED })],
              }),
            ],
          }),
        },
        children,
      },
    ],
  });

  return Packer.toBuffer(doc).then((buffer) => {
    writeFileSync(outPath, buffer);
  });
}
