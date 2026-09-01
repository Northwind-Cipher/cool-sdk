/**
 * Compile the package — and make `npm pack` incapable of producing a broken one.
 *
 * Run automatically by `prepack`, so a hand-run `npm pack` / `npm publish`
 * cannot ship a tarball whose emitted imports are extensionless and therefore
 * unresolvable by Node's ESM loader.
 *
 * Three steps:
 *   1. tsc, from `src/` into `dist/`;
 *   2. rewrite relative specifiers to add `.js` / `/index.js`, because
 *      TypeScript emits them exactly as written and the source is authored for
 *      a bundler;
 *   3. copy the static assets tsc does not know about (`cli/ui/app.html`).
 */
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import {
  copyFileSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const src = join(root, "src");
const dist = join(root, "dist");
const require = createRequire(import.meta.url);

/* 1 · compile */
rmSync(dist, { recursive: true, force: true });
const tsc = require.resolve("typescript/bin/tsc");
execFileSync(process.execPath, [tsc, "-p", join(root, "tsconfig.build.json")], {
  stdio: "inherit",
});

/* 2 · make the emitted specifiers resolvable by Node's ESM loader */
function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(path));
    else out.push(path);
  }
  return out;
}

const SPECIFIER = /(from\s*|import\s*\(\s*|import\s+)(['"])(\.[^'"]*)\2/g;
let patched = 0;
let unresolved = 0;

for (const file of walk(dist)) {
  if (!file.endsWith(".js") && !file.endsWith(".d.ts")) continue;
  const source = readFileSync(file, "utf8");
  const next = source.replace(SPECIFIER, (match, head, quote, specifier) => {
    if (/\.(js|json|mjs)$/.test(specifier)) return match;
    const target = resolve(dirname(file), specifier);
    let resolved = null;
    try {
      statSync(`${target}.js`);
      resolved = `${specifier}.js`;
    } catch {
      try {
        statSync(join(target, "index.js"));
        resolved = `${specifier}/index.js`;
      } catch {
        unresolved++;
        console.error(`  ! unresolvable specifier '${specifier}' in ${relative(root, file)}`);
      }
    }
    return resolved ? `${head}${quote}${resolved}${quote}` : match;
  });
  if (next !== source) {
    writeFileSync(file, next);
    patched++;
  }
}

if (unresolved > 0) {
  console.error(`\n${unresolved} unresolvable specifier(s) — refusing to build.`);
  process.exit(1);
}

/* 3 · copy the static assets tsc does not emit */
const ASSETS = [["cli/ui/app.html", "cli/ui/app.html"]];
for (const [from, to] of ASSETS) {
  const from_ = join(src, from);
  const dest = join(dist, to);
  try {
    statSync(from_);
  } catch {
    console.error(`\nmissing asset ${from} — refusing to build.`);
    process.exit(1);
  }
  mkdirSync(dirname(dest), { recursive: true });
  copyFileSync(from_, dest);
}

console.log(
  `cool-nwc: compiled and patched ${patched} files into dist/, copied ${ASSETS.length} asset(s)`,
);
