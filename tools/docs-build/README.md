# docs-build

Generates the CooL × Contrast documents: two deliverables in PDF **and** Word,
from one content source.

```sh
cd tools/docs-build
npm install
npm run docs     # → docs/cool-x-contrast/*.pdf and *.docx
```

The demo **video** is not built here — it is produced by the `/brag` workflow
through [Hyperframes](https://www.npmjs.com/package/hyperframes); its plan,
brief and composition live in `brag-output-2026-10-06-023130/` at the repository
root.

## Why a generator rather than hand-written files

Both documents are produced from **one content source**. A technical document
that disagrees with itself between its PDF and its Word copy is worse than no
document, and keeping two hand-edited files in step is a losing game.

```
content/technical.mjs      ─┐
content/intersections.mjs  ─┼─→ blocks.mjs ─┬─→ render-pdf.mjs  → .pdf
                            │               └─→ render-docx.mjs → .docx
```

`blocks.mjs` is the document model — headings, paragraphs, bullets, tables,
code, callouts. The two renderers are the only places that know about
formatting. Inline markup is deliberately minimal (`**bold**`, `*italic*`,
`` `code` ``); anything richer would need a real parser, and these are
documents, not a markup language.

| File | Role |
| --- | --- |
| `content/technical.mjs` | Technical documentation — architecture, binding, trust model, test matrix |
| `content/intersections.mjs` | Where the two systems meet and why it pays both ways |
| `blocks.mjs` | The shared document model and inline-markup parser |
| `render-pdf.mjs` | PDF via `pdfkit`, embedding Calibri and Consolas when present |
| `render-docx.mjs` | Word via `docx`, US Letter, running header and footer |
| `preview.mjs` | Renders PDF pages to PNG so the output can actually be looked at |

## Requirements

Node ≥ 20. The PDF renderer falls back to pdfkit's built-in Helvetica and
Courier if Calibri and Consolas are not installed, so it works off Windows —
the result is simply less pretty.
