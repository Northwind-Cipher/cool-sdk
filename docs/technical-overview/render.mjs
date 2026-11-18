import { chromium } from "playwright-core";
import { pathToFileURL } from "node:url";
import { join } from "node:path";
// usage: node render.mjs <dir containing cool-technical-overview.html>  (needs playwright-core + chromium)
const dir = process.argv[2];
const browser = await chromium.launch();
const page = await browser.newPage();
await page.goto(pathToFileURL(join(dir, "cool-technical-overview.html")).href, { waitUntil: "load" });
await page.pdf({
  path: join(dir, "cool-technical-overview.pdf"), format: "A4", preferCSSPageSize: true, displayHeaderFooter: true,
  headerTemplate: "<span></span>",
  footerTemplate: '<div style="width:100%;font-family:Segoe UI,Arial,sans-serif;font-size:8pt;color:#5a6573;padding:0 18mm;display:flex;justify-content:space-between"><span>CooL technical overview · v1.0 · November 2026</span><span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>',
});
await browser.close();
console.log("ok");
