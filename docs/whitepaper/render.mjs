// CooL — render the whitepaper HTML to PDF (and optional page PNGs for review).
//
//   npm i --no-save playwright-core@1.49.1 && npx playwright@1.49.1 install chromium
//   node docs/whitepaper/render.mjs [--png <dir>]
//
// Not a package dependency: only maintainers regenerating the PDF need it.
import { chromium } from "playwright-core";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { mkdirSync } from "node:fs";

const here = dirname(fileURLToPath(import.meta.url));
const html = join(here, "cool-whitepaper.html");
const pdf = join(here, "cool-whitepaper.pdf");
const pngDir = process.argv.includes("--png") ? process.argv[process.argv.indexOf("--png") + 1] : null;

const browser = await chromium.launch();
const page = await browser.newPage();
await page.goto(pathToFileURL(html).href, { waitUntil: "load" });
await page.pdf({
  path: pdf,
  format: "Letter",
  preferCSSPageSize: true,
  displayHeaderFooter: true,
  headerTemplate: "<span></span>",
  footerTemplate: '<div style="width:100%;text-align:center;font-family:\'Times New Roman\',serif;font-size:10pt;"><span class="pageNumber"></span></div>',
});
console.log(`wrote ${pdf}`);

if (pngDir) {
  // Page images for proofreading: print the PDF pages through Chromium's PDF viewer is not
  // scriptable, so render the HTML at print size instead.
  mkdirSync(pngDir, { recursive: true });
  await page.emulateMedia({ media: "print" });
  await page.setViewportSize({ width: 816, height: 1056 });
  await page.screenshot({ path: join(pngDir, "full.png"), fullPage: true });
  console.log(`wrote ${join(pngDir, "full.png")}`);
}
await browser.close();
