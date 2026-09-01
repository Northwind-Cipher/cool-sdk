/**
 * Terminal drawing, with no dependencies.
 *
 * A CLI that ships `chalk`, `ora`, `boxen` and `cli-table` pulls twenty-odd
 * transitive packages into a security product's dependency tree in order to draw
 * boxes. This is the same output in one file: colour, panels, spinners, bars and
 * sparklines, degrading cleanly when the terminal cannot do them.
 *
 * Three environments are handled explicitly rather than assumed:
 *   • no TTY (a pipe, CI, `> file`) → no colour, no spinner, no cursor tricks;
 *   • `NO_COLOR` or `TERM=dumb` → the same;
 *   • legacy Windows consoles → ASCII glyphs instead of box-drawing and braille.
 */

/** ESC, built from its code point so the source holds no invisible characters. */
const ESC = String.fromCharCode(27);
const stdout = process.stdout;

export const isTTY = Boolean(stdout.isTTY);

export const useColor =
  isTTY && !process.env["NO_COLOR"] && process.env["TERM"] !== "dumb" && !process.env["CI"];

/**
 * Whether the terminal can be trusted with box-drawing and braille. Windows
 * Terminal, VS Code's terminal and every modern *nix terminal can; the legacy
 * conhost that `cmd.exe` still opens by default cannot.
 */
export const useUnicode =
  process.platform !== "win32" ||
  Boolean(process.env["WT_SESSION"] ?? process.env["TERM_PROGRAM"] ?? process.env["ConEmuANSI"]);

const wrap = (open: string, text: string): string =>
  useColor ? `${ESC}[${open}m${text}${ESC}[0m` : text;

const fg =
  (code: number) =>
  (text: string): string =>
    wrap(`38;5;${code}`, text);

export const c = {
  bold: (t: string) => wrap("1", t),
  dim: (t: string) => wrap("2", t),
  inverse: (t: string) => wrap("7", t),
  brand: fg(75),
  blue: fg(39),
  green: fg(78),
  red: fg(203),
  yellow: fg(179),
  cyan: fg(80),
  purple: fg(141),
  grey: fg(245),
  faint: fg(240),
};

/** Glyphs, with an ASCII fallback for terminals that would render tofu. */
export const g = useUnicode
  ? {
      tl: "╭",
      tr: "╮",
      bl: "╰",
      br: "╯",
      h: "─",
      v: "│",
      pass: "✓",
      fail: "✕",
      warn: "▲",
      partial: "◐",
      dot: "·",
      arrow: "›",
      bullet: "•",
      block: "█",
      light: "░",
      spark: ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"],
      spinner: ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
    }
  : {
      tl: "+",
      tr: "+",
      bl: "+",
      br: "+",
      h: "-",
      v: "|",
      pass: "v",
      fail: "x",
      warn: "!",
      partial: "~",
      dot: ".",
      arrow: ">",
      bullet: "*",
      block: "#",
      light: ".",
      spark: ["_", ".", ".", "-", "-", "=", "=", "#"],
      spinner: ["-", "\\", "|", "/"],
    };

const ANSI = new RegExp(`${ESC}\\[[0-9;]*m`, "g");

/** Printable width, ignoring escape sequences. */
export function width(text: string): number {
  return text.replace(ANSI, "").length;
}

export function pad(text: string, to: number): string {
  const gap = to - width(text);
  return gap > 0 ? text + " ".repeat(gap) : text;
}

export function padStart(text: string, to: number): string {
  const gap = to - width(text);
  return gap > 0 ? " ".repeat(gap) + text : text;
}

export function truncate(text: string, to: number): string {
  if (width(text) <= to) return text;
  return `${text.replace(ANSI, "").slice(0, Math.max(0, to - 1))}…`;
}

/** Usable columns, clamped so a maximised 4K terminal does not produce a mural. */
export function columns(): number {
  return Math.max(48, Math.min(stdout.columns ?? 80, 96));
}

export const out = (line = ""): void => {
  stdout.write(`${line}\n`);
};

export function rule(label?: string): void {
  const w = columns();
  if (!label) {
    out(c.faint(g.h.repeat(w)));
    return;
  }
  const text = ` ${label} `;
  out(c.faint(g.h.repeat(2)) + c.dim(text) + c.faint(g.h.repeat(Math.max(0, w - 2 - text.length))));
}

/** A titled panel — the one piece of chrome the whole CLI is built from. */
export function panel(
  title: string,
  lines: string[],
  tone: (t: string) => string = c.brand,
): void {
  const w = columns();
  const inner = w - 4;
  const heading = ` ${title} `;
  out(
    tone(g.tl + g.h) +
      c.bold(tone(heading)) +
      tone(g.h.repeat(Math.max(0, w - 3 - heading.length)) + g.tr),
  );
  for (const line of lines) {
    out(`${tone(g.v)} ${pad(truncate(line, inner), inner)} ${tone(g.v)}`);
  }
  out(tone(g.bl + g.h.repeat(w - 2) + g.br));
}

/** A two-column key/value list, aligned on the widest key. */
export function fields(rows: [string, string][], indent = "  "): void {
  const keyWidth = rows.reduce((max, [key]) => Math.max(max, key.length), 0);
  for (const [key, value] of rows) {
    out(`${indent}${c.grey(pad(key, keyWidth))}  ${value}`);
  }
}

/** A horizontal bar, for the analytics panel. */
export function bar(value: number, max: number, cells = 24): string {
  if (max <= 0) return c.faint(g.light.repeat(cells));
  const filled = Math.max(value > 0 ? 1 : 0, Math.round((value / max) * cells));
  return c.blue(g.block.repeat(filled)) + c.faint(g.light.repeat(Math.max(0, cells - filled)));
}

/** A sparkline over a series. */
export function sparkline(values: number[]): string {
  if (values.length === 0) return c.faint("no data");
  const max = Math.max(...values, 1);
  return c.blue(
    values
      .map(
        (value) =>
          g.spark[
            Math.min(g.spark.length - 1, Math.round((value / max) * (g.spark.length - 1)))
          ] ?? " ",
      )
      .join(""),
  );
}

/** Status glyph + colour + word — never colour alone. */
export function status(kind: string): string {
  switch (kind) {
    case "pass":
      return c.green(`${g.pass} pass`);
    case "fail":
      return c.red(`${g.fail} fail`);
    case "simulated":
      return c.cyan(`${g.partial} simulated`);
    case "pending":
      return c.yellow(`${g.partial} pending`);
    case "warn":
      return c.yellow(`${g.warn} warn`);
    default:
      return c.faint(`${g.dot} ${kind}`);
  }
}

/**
 * A spinner that knows when not to be one.
 *
 * On a pipe it prints each step as a plain line, so `cool seal | tee log` and CI
 * output stay readable instead of filling with cursor escapes.
 */
export class Progress {
  private timer: NodeJS.Timeout | null = null;
  private frame = 0;
  private text = "";
  private started = Date.now();

  start(text: string): this {
    this.text = text;
    this.started = Date.now();
    if (!isTTY) {
      out(`  ${g.dot} ${text}`);
      return this;
    }
    this.render();
    this.timer = setInterval(() => this.render(), 80);
    if (typeof this.timer.unref === "function") this.timer.unref();
    return this;
  }

  update(text: string): this {
    this.text = text;
    if (!isTTY) out(`  ${g.dot} ${text}`);
    return this;
  }

  private render(): void {
    const frame = g.spinner[this.frame % g.spinner.length] ?? "";
    this.frame++;
    stdout.write(`\r${ESC}[2K  ${c.brand(frame)} ${this.text}`);
  }

  private stop(glyph: string, text: string): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    const line = `  ${glyph} ${text} ${c.faint(`${Date.now() - this.started}ms`)}`;
    if (isTTY) stdout.write(`\r${ESC}[2K${line}\n`);
    else out(line);
  }

  succeed(text = this.text): void {
    this.stop(c.green(g.pass), text);
  }

  fail(text = this.text): void {
    this.stop(c.red(g.fail), text);
  }
}

/** Clear the screen, when there is a screen to clear. */
export function clear(): void {
  if (isTTY) stdout.write(`${ESC}[2J${ESC}[H`);
}
