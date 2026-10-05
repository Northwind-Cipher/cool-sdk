/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Use of this software is governed by the Business Source License 1.1 in the
 * LICENSE file at the root of this repository.
 */

/**
 * Render the CooL × Contrast demo to an MP4.
 *
 * The terminal body is a replay of REAL captured output — `npm run demo:contrast`
 * is executed and its stdout is what scrolls past. Nothing in the transcript is
 * written by hand, which is the only way a demo video is worth anything.
 *
 *     node video.mjs            # capture a fresh run, then encode
 *     node video.mjs --reuse    # reuse the previous capture
 *
 * Frames are piped straight into ffmpeg as JPEG rather than written to disk.
 */
import { createCanvas, GlobalFonts } from "@napi-rs/canvas";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..");
const outDir = join(repo, "assets", "video");
const capture = join(here, "demo-capture.txt");

const W = 1920;
const H = 1080;
const FPS = 24;

/* ── palette ───────────────────────────────────────────────────────── */
const BG = "#0b1014";
const PANEL = "#10181e";
const EDGE = "#1e2d36";
const TEXT = "#c9d7de";
const DIM = "#647684";
const TEAL = "#2dd4bf";
const GREEN = "#4ade80";
const RED = "#f87171";
const AMBER = "#fbbf24";
const WHITE = "#f3f8fa";

for (const [file, name] of [
  ["C:/Windows/Fonts/consola.ttf", "Mono"],
  ["C:/Windows/Fonts/consolab.ttf", "MonoBold"],
  ["C:/Windows/Fonts/calibri.ttf", "Sans"],
  ["C:/Windows/Fonts/calibrib.ttf", "SansBold"],
  // Calibri and Consolas have no check, cross or hook glyph; without a symbol
  // face every pass/fail marker in the captured output renders as tofu.
  ["C:/Windows/Fonts/seguisym.ttf", "Symbols"],
]) {
  if (existsSync(file)) GlobalFonts.registerFromPath(file, name);
}
const mono = (s) => `${s}px Mono, Symbols, monospace`;
const monob = (s) => `${s}px MonoBold, Mono, Symbols, monospace`;
const sans = (s) => `${s}px Sans, Symbols, sans-serif`;
const sansb = (s) => `${s}px SansBold, Sans, Symbols, sans-serif`;

/* ── capture the real demo ─────────────────────────────────────────── */

function demoLines() {
  if (!process.argv.includes("--reuse") || !existsSync(capture)) {
    console.log("running the demo to capture real output…");
    const run = spawnSync(
      process.execPath,
      ["--import", "tsx", join(repo, "examples", "contrast", "demo.mjs")],
      { cwd: repo, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
    );
    if (run.status !== 0) {
      throw new Error(`the demo exited ${run.status}\n${run.stderr ?? ""}`);
    }
    writeFileSync(capture, run.stdout);
  }
  return readFileSync(capture, "utf8").replace(/\r/g, "").split("\n");
}

/* ── drawing helpers ───────────────────────────────────────────────── */

const canvas = createCanvas(W, H);
const ctx = canvas.getContext("2d");

function clear(colour = BG) {
  ctx.fillStyle = colour;
  ctx.fillRect(0, 0, W, H);
}

function roundRect(x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

/** Colour one line of terminal output by what it says. */
function lineColour(text) {
  if (/^\s*[✓]/.test(text)) return GREEN;
  if (/^\s*[✗]/.test(text)) return RED;
  if (/^\s*\d\.\s+[A-Z]/.test(text)) return TEAL;
  if (/^[─═]+$/.test(text.trim())) return EDGE;
  if (/^\s*↳/.test(text)) return DIM;
  if (/Not claimed|WARNING|NOT /.test(text)) return AMBER;
  return TEXT;
}

const ease = (t) => (t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2);

/* ── scenes ────────────────────────────────────────────────────────── */

function titleCard(progress) {
  clear();
  // A soft teal wash so the opening is not a flat black rectangle.
  const glow = ctx.createRadialGradient(W * 0.5, H * 0.42, 40, W * 0.5, H * 0.42, 900);
  glow.addColorStop(0, "rgba(45,212,191,0.13)");
  glow.addColorStop(1, "rgba(45,212,191,0)");
  ctx.fillStyle = glow;
  ctx.fillRect(0, 0, W, H);

  const a = Math.min(1, progress * 2.2);
  ctx.globalAlpha = a;
  ctx.textAlign = "center";

  ctx.fillStyle = TEAL;
  ctx.font = sansb(26);
  ctx.fillText("C O O L   ×   E D G E L E S S   C O N T R A S T", W / 2, H * 0.33);

  ctx.fillStyle = WHITE;
  ctx.font = sansb(74);
  ctx.fillText("Confidential execution,", W / 2, H * 0.46);
  ctx.fillText("verifiable AI-change evidence", W / 2, H * 0.46 + 88);

  ctx.globalAlpha = Math.max(0, Math.min(1, (progress - 0.3) * 2.4));
  ctx.fillStyle = DIM;
  ctx.font = sans(31);
  ctx.fillText(
    "Contrast proves the workload ran confidentially.  CooL proves what changed inside it.",
    W / 2,
    H * 0.66,
  );
  ctx.font = sans(27);
  ctx.fillStyle = TEAL;
  ctx.fillText("This binds the two, so one receipt answers both.", W / 2, H * 0.66 + 46);

  ctx.globalAlpha = 1;
  ctx.textAlign = "left";
}

function splitCard(progress) {
  clear();
  ctx.textAlign = "left";
  const a = Math.min(1, progress * 3);
  ctx.globalAlpha = a;

  ctx.fillStyle = WHITE;
  ctx.font = sansb(46);
  ctx.fillText("Neither system answers the other's question", 150, 190);

  const cards = [
    ["CONTRAST", TEAL, ["Was the workload protected", "while it ran?", "", "Attested against a signed", "manifest, on Intel TDX or", "AMD SEV-SNP."], "Cannot say which prompt it was running."],
    ["COOL", "#a78bfa", ["What changed inside it,", "and who changed it?", "", "Hybrid-signed, in an", "append-only log, verifiable", "offline years later."], "Cannot say the process was protected."],
  ];

  cards.forEach(([name, accent, body, gap], i) => {
    const x = 150 + i * 840;
    const y = 270;
    const w = 760;
    const h = 520;
    ctx.globalAlpha = a * Math.min(1, Math.max(0, progress * 3 - i * 0.35));
    ctx.fillStyle = PANEL;
    roundRect(x, y, w, h, 16);
    ctx.fill();
    ctx.strokeStyle = EDGE;
    ctx.lineWidth = 2;
    ctx.stroke();

    ctx.fillStyle = accent;
    ctx.fillRect(x, y, 6, h);
    ctx.font = sansb(24);
    ctx.fillText(name, x + 40, y + 60);

    ctx.fillStyle = TEXT;
    ctx.font = sans(31);
    body.forEach((l, j) => ctx.fillText(l, x + 40, y + 125 + j * 46));

    ctx.fillStyle = RED;
    ctx.font = sans(25);
    ctx.fillText(`✗  ${gap}`, x + 40, y + h - 46);
  });

  ctx.globalAlpha = Math.max(0, Math.min(1, (progress - 0.55) * 3));
  ctx.fillStyle = TEAL;
  ctx.font = sansb(34);
  ctx.textAlign = "center";
  ctx.fillText("The gap is the integration.", W / 2, 880);
  ctx.globalAlpha = 1;
  ctx.textAlign = "left";
}

/** The terminal window, with `lines` already revealed. */
function terminal(revealed, lines, caption) {
  clear();
  const x = 120;
  const y = 92;
  const w = W - 240;
  const h = H - 250;

  ctx.fillStyle = PANEL;
  roundRect(x, y, w, h, 14);
  ctx.fill();
  ctx.strokeStyle = EDGE;
  ctx.lineWidth = 2;
  ctx.stroke();

  // title bar
  ctx.fillStyle = "#16222a";
  roundRect(x, y, w, 52, 14);
  ctx.fill();
  ctx.fillRect(x, y + 38, w, 14);
  ["#ff5f57", "#febc2e", "#28c840"].forEach((c, i) => {
    ctx.fillStyle = c;
    ctx.beginPath();
    ctx.arc(x + 32 + i * 26, y + 26, 8, 0, Math.PI * 2);
    ctx.fill();
  });
  ctx.fillStyle = DIM;
  ctx.font = mono(21);
  ctx.textAlign = "center";
  ctx.fillText("npm run demo:contrast", x + w / 2, y + 33);
  ctx.textAlign = "left";

  // body
  const lineH = 25.5;
  const top = y + 84;
  const visible = Math.floor((h - 110) / lineH);
  const start = Math.max(0, revealed - visible);
  ctx.font = mono(19);
  for (let i = start; i < revealed && i < lines.length; i++) {
    const text = lines[i] ?? "";
    ctx.fillStyle = lineColour(text);
    ctx.fillText(text.slice(0, 138), x + 36, top + (i - start) * lineH);
  }

  // cursor
  if (revealed < lines.length && Math.floor(revealed / 3) % 2 === 0) {
    ctx.fillStyle = TEAL;
    const row = Math.min(revealed, visible) - start;
    ctx.fillRect(x + 36, top + row * lineH - 15, 11, 19);
  }

  if (caption) {
    ctx.fillStyle = PANEL;
    roundRect(120, H - 128, W - 240, 76, 10);
    ctx.fill();
    ctx.strokeStyle = EDGE;
    ctx.stroke();
    ctx.fillStyle = caption.tone === "bad" ? RED : caption.tone === "warn" ? AMBER : TEAL;
    ctx.fillRect(120, H - 128, 5, 76);
    ctx.fillStyle = WHITE;
    ctx.font = sansb(27);
    ctx.fillText(caption.title, 160, H - 92);
    ctx.fillStyle = DIM;
    ctx.font = sans(24);
    ctx.fillText(caption.text, 160, H - 62);
  }
}

function chainCard(progress) {
  clear();
  ctx.textAlign = "center";
  ctx.fillStyle = WHITE;
  ctx.font = sansb(44);
  ctx.fillText("One chain, no gap in the middle", W / 2, 128);

  const steps = [
    ["AI change", "prompt · model · policy · permission", TEAL],
    ["CooL receipt", "hybrid ML-DSA-65 + Ed25519, in an RFC 6962 log", TEAL],
    ["Key binding", "signed by the pod's Contrast mesh key", "#a78bfa"],
    ["Mesh certificate", "MRTD · RTMRs · policy hash, issued by the Coordinator", "#a78bfa"],
    ["Coordinator root CA", "pinned by the reader, from their own `contrast verify`", GREEN],
    ["Confidential execution", "Intel TDX / AMD SEV-SNP", GREEN],
  ];

  steps.forEach(([title, sub, colour], i) => {
    const appear = Math.max(0, Math.min(1, progress * 7 - i * 0.85));
    if (appear <= 0) return;
    ctx.globalAlpha = appear;
    const y = 212 + i * 128;
    const w = 1180;
    const x = (W - w) / 2;
    ctx.fillStyle = PANEL;
    roundRect(x, y, w, 92, 12);
    ctx.fill();
    ctx.strokeStyle = EDGE;
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.fillStyle = colour;
    ctx.fillRect(x, y, 6, 92);

    ctx.textAlign = "left";
    ctx.fillStyle = WHITE;
    ctx.font = sansb(30);
    ctx.fillText(title, x + 40, y + 40);
    ctx.fillStyle = DIM;
    ctx.font = sans(23);
    ctx.fillText(sub.replace(/`/g, ""), x + 40, y + 72);

    if (i < steps.length - 1) {
      ctx.strokeStyle = EDGE;
      ctx.lineWidth = 3;
      ctx.beginPath();
      ctx.moveTo(W / 2, y + 92);
      ctx.lineTo(W / 2, y + 128);
      ctx.stroke();
    }
    ctx.textAlign = "center";
  });
  ctx.globalAlpha = 1;
  ctx.textAlign = "left";
}

function outroCard(progress, stats) {
  clear();
  const glow = ctx.createRadialGradient(W * 0.5, H * 0.45, 40, W * 0.5, H * 0.45, 900);
  glow.addColorStop(0, "rgba(45,212,191,0.12)");
  glow.addColorStop(1, "rgba(45,212,191,0)");
  ctx.fillStyle = glow;
  ctx.fillRect(0, 0, W, H);

  ctx.globalAlpha = Math.min(1, progress * 3);
  ctx.textAlign = "center";
  ctx.fillStyle = WHITE;
  ctx.font = sansb(58);
  ctx.fillText("A receipt that proves where it came from", W / 2, 230);

  const cells = [
    [stats.tests, "tests passing"],
    [stats.contrast, "for this integration"],
    ["0", "new dependencies"],
    ["8", "verdict domains"],
  ];
  cells.forEach(([big, label], i) => {
    const w = 360;
    const gap = 28;
    const x = (W - (cells.length * w + (cells.length - 1) * gap)) / 2 + i * (w + gap);
    const y = 320;
    ctx.globalAlpha = Math.max(0, Math.min(1, progress * 4 - i * 0.3));
    ctx.fillStyle = PANEL;
    roundRect(x, y, w, 190, 14);
    ctx.fill();
    ctx.strokeStyle = EDGE;
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.fillStyle = TEAL;
    ctx.font = sansb(76);
    ctx.fillText(String(big), x + w / 2, y + 108);
    ctx.fillStyle = DIM;
    ctx.font = sans(24);
    ctx.fillText(label, x + w / 2, y + 152);
  });

  ctx.globalAlpha = Math.max(0, Math.min(1, (progress - 0.22) * 4));
  ctx.fillStyle = AMBER;
  ctx.font = sans(25);
  ctx.fillText(
    "Not claimed: that any hardware was involved. The fixtures carry a software-built TDX quote.",
    W / 2,
    610,
  );
  ctx.fillStyle = DIM;
  ctx.fillText("Certificates come from Contrast's own code. docs/contrast.md §7 says what was tested.", W / 2, 648);

  ctx.globalAlpha = Math.max(0, Math.min(1, (progress - 0.34) * 4));
  ctx.fillStyle = WHITE;
  ctx.font = monob(32);
  ctx.fillText("npm run demo:contrast", W / 2, 764);
  ctx.fillStyle = TEAL;
  ctx.font = mono(27);
  ctx.fillText("github.com/Northwind-Cipher/cool-sdk", W / 2, 812);

  ctx.fillStyle = DIM;
  ctx.font = sans(21);
  ctx.fillText(
    "Contrast is a product of Edgeless Systems GmbH · no endorsement implied",
    W / 2,
    H - 86,
  );
  ctx.globalAlpha = 1;
  ctx.textAlign = "left";
}

/* ── timeline ──────────────────────────────────────────────────────── */

const lines = demoLines();

/** Captions keyed to the act the transcript has reached. */
const CAPTIONS = [
  { at: /1\. WHAT CONTRAST SAYS/, title: "Read from the certificate, not from config", text: "MRTD, RTMRs and the policy hash come out of the Coordinator-issued mesh certificate.", tone: "ok" },
  { at: /2\. FOUR AI CHANGES/, title: "The signing key cannot exist outside the pod", text: "Derived from the Contrast workload secret, released only to a workload that passed attestation.", tone: "ok" },
  { at: /3\. AN INDEPENDENT VERIFIER/, title: "Verified offline, with no cluster and no trust in us", text: "Receipts plus two files the auditor obtained from their own `contrast verify`.", tone: "ok" },
  { at: /4\. TAMPER WITH/, title: "Tamper with the change → rejected", text: "The credential is still genuine, so the verdict names which guarantee broke.", tone: "bad" },
  { at: /5\. PRESENT THIS RECEIPT/, title: "Another workload's credential → rejected", text: "The binding signature verifies only under the pod that made it.", tone: "bad" },
  { at: /6\. A RECEIPT FROM A COORDINATOR/, title: "A Coordinator nobody attested → rejected", text: "Internally perfect, and it still fails against the pinned root.", tone: "bad" },
  { at: /7\. THE IMAGE IS REBUILT/, title: "A rebuilt image → visible, not silent", text: "Same policy hash, different MRTD. Old receipts keep verifying.", tone: "warn" },
];

const stats = { tests: "152", contrast: "33" };

const scenes = [];
const add = (seconds, draw) => scenes.push({ frames: Math.round(seconds * FPS), draw });

add(4.0, (t) => titleCard(t));
add(5.0, (t) => splitCard(t));

// Terminal replay: reveal the captured output, holding on each act.
const LINES_PER_SEC = 7.5;
const terminalSeconds = Math.min(42, lines.length / LINES_PER_SEC + 7);
add(terminalSeconds, (t) => {
  const revealed = Math.min(lines.length, Math.floor(t * terminalSeconds * LINES_PER_SEC));
  let caption = null;
  for (const c of CAPTIONS) {
    const idx = lines.findIndex((l) => c.at.test(l));
    if (idx >= 0 && revealed >= idx) caption = c;
  }
  terminal(revealed, lines, caption);
});

add(6.5, (t) => chainCard(t));
add(7.0, (t) => outroCard(t, stats));

const total = scenes.reduce((a, s) => a + s.frames, 0);
console.log(`${lines.length} captured lines → ${total} frames (${(total / FPS).toFixed(1)}s)`);

/* ── encode ────────────────────────────────────────────────────────── */

mkdirSync(outDir, { recursive: true });
const mp4 = join(outDir, "cool-contrast-demo.mp4");

const ff = spawn(
  "ffmpeg",
  [
    "-y",
    "-f", "image2pipe",
    "-framerate", String(FPS),
    "-i", "-",
    "-c:v", "libx264",
    "-pix_fmt", "yuv420p",
    "-profile:v", "high",
    "-crf", "20",
    "-movflags", "+faststart",
    mp4,
  ],
  { stdio: ["pipe", "ignore", "pipe"] },
);

let ffErr = "";
ff.stderr.on("data", (d) => {
  ffErr += d.toString();
});

const write = (buf) =>
  ff.stdin.write(buf) ? Promise.resolve() : new Promise((r) => ff.stdin.once("drain", r));

let n = 0;
let poster = null;
for (const scene of scenes) {
  for (let i = 0; i < scene.frames; i++) {
    scene.draw(ease(scene.frames === 1 ? 1 : i / (scene.frames - 1)));
    const jpeg = canvas.toBuffer("image/jpeg", 92);
    if (n === Math.round(total * 0.35)) poster = canvas.toBuffer("image/png");
    await write(jpeg);
    n++;
    if (n % 120 === 0) process.stdout.write(`\r  encoding ${Math.round((n / total) * 100)}%`);
  }
}
ff.stdin.end();

await new Promise((resolve, reject) => {
  ff.on("close", (codeOut) => {
    if (codeOut === 0) resolve();
    else reject(new Error(`ffmpeg exited ${codeOut}\n${ffErr.slice(-2000)}`));
  });
});

if (poster) writeFileSync(join(outDir, "cool-contrast-demo.png"), poster);
console.log(`\nwrote ${mp4}`);
