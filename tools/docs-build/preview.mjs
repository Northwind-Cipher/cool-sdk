// Render PDF pages to PNG so the output can actually be looked at.
import { createCanvas } from "@napi-rs/canvas";
import { writeFileSync, mkdirSync, readFileSync } from "node:fs";
const { getDocument } = await import("pdfjs-dist/legacy/build/pdf.mjs");

const [file, outDir, pagesArg] = process.argv.slice(2);
mkdirSync(outDir, { recursive: true });
const data = new Uint8Array(readFileSync(file));
const pdf = await getDocument({ data, useSystemFonts: true }).promise;
console.log(`${file}: ${pdf.numPages} pages`);

const want = pagesArg ? pagesArg.split(",").map(Number) : Array.from({ length: pdf.numPages }, (_, i) => i + 1);
for (const n of want) {
  if (n > pdf.numPages) continue;
  const page = await pdf.getPage(n);
  const vp = page.getViewport({ scale: 1.45 });
  const canvas = createCanvas(Math.ceil(vp.width), Math.ceil(vp.height));
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#fff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  await page.render({ canvasContext: ctx, viewport: vp }).promise;
  const name = `${outDir}/p${String(n).padStart(2, "0")}.png`;
  writeFileSync(name, canvas.toBuffer("image/png"));
}
console.log(`wrote ${want.length} page image(s)`);
