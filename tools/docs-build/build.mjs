/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/** Build the PDF and Word deliverables from one content source. */
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { renderPdf } from "./render-pdf.mjs";
import { renderDocx } from "./render-docx.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "..", "..", "docs", "reports");
mkdirSync(out, { recursive: true });

const DOCS = [
  ["technical", "CooL-x-Contrast-Technical-Documentation"],
  ["intersections", "CooL-x-Contrast-Intersections"],
];

for (const [module, base] of DOCS) {
  const { blocks, meta } = await import(`./content/${module}.mjs`);
  await renderPdf(blocks, meta, join(out, `${base}.pdf`));
  await renderDocx(blocks, meta, join(out, `${base}.docx`));
  console.log(`  ${base}.pdf + .docx`);
}

console.log(`\nwrote ${DOCS.length * 2} files to docs/reports/`);
