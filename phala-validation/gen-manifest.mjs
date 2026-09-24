// Regenerates artifacts/evidence-manifest.json: SHA-256 of every file under
// artifacts/ (except the manifest itself) plus the reproduction guide and the
// validation workload files. Run from the repository root.
import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";

function walk(dir, out) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else out.push(full);
  }
}

const files = [];
walk("artifacts", files);
walk("phala-validation", files);
files.push("COOL_PHALA_REPRODUCTION.md", "tests/real-tee-validation.test.ts", "tests/runtime-status.test.ts", "tests/witness-consistency.test.ts", "src/phala/consistency.ts", "src/phala/runtime.ts", "src/phala/witness.ts", "src/phala/verify.ts");

const manifest = files
  .filter((f) => !f.endsWith("evidence-manifest.json"))
  .sort()
  .map((f) => {
    const buf = fs.readFileSync(f);
    return {
      path: f.split(path.sep).join("/"),
      sha256: crypto.createHash("sha256").update(buf).digest("hex"),
      size_bytes: buf.length,
    };
  });

fs.writeFileSync(
  "artifacts/evidence-manifest.json",
  JSON.stringify(
    {
      generated_at_utc: new Date().toISOString(),
      note: "Unsigned integrity index; detects change, does not authenticate the author. Files outside the repository (e.g. the audit DOCX) are not listed.",
      file_count: manifest.length,
      files: manifest,
    },
    null,
    2,
  ),
);
console.log("manifest entries:", manifest.length);
