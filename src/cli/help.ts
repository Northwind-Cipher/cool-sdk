/**
 * Rendering the manual.
 *
 * Three shapes: an index that shows what exists, a command page with worked
 * examples, and a concept page that explains the thing the commands are about.
 * The prose is wrapped to the terminal rather than hard-wrapped in the source,
 * so it reads properly in an 80-column window and in a 200-column one.
 */
import { COMMANDS, TOPICS, command, topic } from "./docs";
import { c, columns, g, out, panel } from "./tty";

/** Wrap a paragraph to the terminal width. */
export function paragraph(text: string, indent = "  "): void {
  const width = Math.max(40, columns() - indent.length - 2);
  let line = "";
  for (const word of text.split(/\s+/)) {
    if (line.length + word.length + 1 > width) {
      out(indent + line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) out(indent + line);
}

/** The default `cool help`: what exists, and where to read more. */
export function helpIndex(): void {
  const label = (name: string, args: string) => `${name}${args ? ` ${args}` : ""}`;
  const gutter = COMMANDS.reduce((max, cmd) => Math.max(max, label(cmd.name, cmd.args).length), 0) + 3;

  panel(
    "commands",
    COMMANDS.map(
      (cmd) =>
        c.brand(cmd.name) +
        c.faint(cmd.args ? ` ${cmd.args}` : "") +
        " ".repeat(Math.max(1, gutter - label(cmd.name, cmd.args).length)) +
        c.grey(cmd.summary),
    ),
  );
  out();

  const topicGutter = TOPICS.reduce((max, t) => Math.max(max, t.name.length), 0) + 3;
  panel(
    "concepts",
    TOPICS.map(
      (t) => c.cyan(t.name) + " ".repeat(Math.max(1, topicGutter - t.name.length)) + c.grey(t.title),
    ),
    c.cyan,
  );
  out();
  out(
    `  ${c.faint("Read one:")} ${c.brand("cool help verify")}   ${c.faint("or a concept:")} ${c.cyan(
      "cool help attestation",
    )}`,
  );
  out(
    `  ${c.faint("New here?")} ${c.brand("cool walkthrough")} ${c.faint(
      "teaches the whole model in about three minutes.",
    )}`,
  );
  out();
}

/** One command, in full. */
export function helpCommand(name: string): boolean {
  const doc = command(name);
  if (!doc) return false;

  out();
  out(`  ${c.bold(c.brand(`cool ${doc.name}`))}${doc.args ? c.faint(` ${doc.args}`) : ""}`);
  out(`  ${c.grey(doc.summary)}`);
  out();
  paragraph(doc.description);
  out();

  if (doc.flags && doc.flags.length > 0) {
    out(`  ${c.bold("Options")}`);
    const width = doc.flags.reduce((max, f) => Math.max(max, f.flag.length), 0) + 3;
    for (const flag of doc.flags) {
      out(`    ${c.cyan(flag.flag)}${" ".repeat(Math.max(1, width - flag.flag.length))}${c.grey(flag.does)}`);
    }
    out();
  }

  out(`  ${c.bold("Examples")}`);
  for (const example of doc.examples) {
    out(`    ${c.faint("$")} ${example.run}`);
    out(`      ${c.grey(example.does)}`);
  }
  out();

  if (doc.seeAlso && doc.seeAlso.length > 0) {
    out(`  ${c.faint("See also:")} ${doc.seeAlso.map((s) => c.brand(s)).join(c.faint(" · "))}`);
    out();
  }
  return true;
}

/** One concept, in full. */
export function helpTopic(name: string): boolean {
  const doc = topic(name);
  if (!doc) return false;

  out();
  out(`  ${c.bold(c.cyan(doc.title))}`);
  out(`  ${c.faint(`cool help ${doc.name}`)}`);
  out();
  for (const para of doc.body) {
    paragraph(para);
    out();
  }
  if (doc.seeAlso && doc.seeAlso.length > 0) {
    out(`  ${c.faint("See also:")} ${doc.seeAlso.map((s) => c.cyan(s)).join(c.faint(" · "))}`);
    out();
  }
  return true;
}

/**
 * `cool help [thing]`.
 *
 * Commands and concepts share one namespace on purpose: somebody typing
 * `cool help attestation` does not care which of the two it is, and being told
 * "no such command" when a perfectly good explanation exists is a small,
 * avoidable insult.
 */
export function help(args: string[]): number {
  const subject = args[0];
  if (!subject) {
    helpIndex();
    return 0;
  }
  if (helpCommand(subject) || helpTopic(subject)) return 0;

  const near = [...COMMANDS.map((cmd) => cmd.name), ...TOPICS.map((t) => t.name)].filter(
    (name) => name.startsWith(subject.slice(0, 3)) || subject.startsWith(name.slice(0, 3)),
  );
  out();
  out(`  ${c.red(g.fail)} nothing called ${c.bold(subject)}.`);
  if (near.length > 0) {
    out(`  ${c.faint("Did you mean:")} ${near.map((n) => c.brand(n)).join(c.faint(" · "))}`);
  }
  out(`  ${c.faint("Everything:")} ${c.brand("cool help")}`);
  out();
  return 1;
}
