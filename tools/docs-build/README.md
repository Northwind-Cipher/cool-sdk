# docs-build

Generates the CooL × Contrast deliverables: two documents in PDF **and** Word,
plus the demo video.

```sh
cd tools/docs-build
npm install

npm run docs     # → docs/reports/*.pdf and *.docx
npm run video    # → assets/video/cool-contrast-demo.mp4 (+ poster PNG)
```

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
| `video.mjs` | Canvas frames piped to `ffmpeg` |
| `preview.mjs` | Renders PDF pages to PNG so the output can actually be looked at |

## The video is a real run

`video.mjs` **executes** `examples/contrast/demo.mjs` and replays its captured
stdout. Nothing in the terminal transcript is written by hand — which is the
only thing that makes a demo video worth anything. Pass `--reuse` to skip the
re-run and encode from the previous capture.

Frames are rendered with `@napi-rs/canvas` and piped straight into `ffmpeg` as
JPEG, so no intermediate frames touch the disk. Output is 1920×1080, 24 fps.

## Requirements

Node ≥ 20 and `ffmpeg` on `PATH` (video only). The PDF renderer falls back to
pdfkit's built-in Helvetica and Courier if Calibri and Consolas are not
installed, so it works off Windows — the result is simply less pretty.
