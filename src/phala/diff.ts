/**
 * A minimal line diff.
 *
 * Change records commit to `diff_hash`, so something has to produce a canonical
 * diff text. This is a common-prefix/suffix diff rather than Myers: it is exact
 * for the edits CooL actually sees (a prompt paragraph rewritten, a temperature
 * changed, a tool added to an allow-list), it is deterministic, and it is thirty
 * lines instead of a dependency. The diff never leaves the customer's
 * environment — only its hash is committed — so its job is to be reproducible,
 * not to be beautiful.
 */

export interface DiffLine {
  readonly kind: "context" | "added" | "removed";
  readonly text: string;
}

/** Diff two texts by line. Deterministic for a given pair of inputs. */
export function lineDiff(before: string, after: string): DiffLine[] {
  const a = before.length === 0 ? [] : before.split("\n");
  const b = after.split("\n");

  let head = 0;
  while (head < a.length && head < b.length && a[head] === b[head]) head++;

  let tail = 0;
  while (
    tail < a.length - head &&
    tail < b.length - head &&
    a[a.length - 1 - tail] === b[b.length - 1 - tail]
  ) {
    tail++;
  }

  const out: DiffLine[] = [];
  for (let i = 0; i < head; i++) out.push({ kind: "context", text: a[i] ?? "" });
  for (let i = head; i < a.length - tail; i++) out.push({ kind: "removed", text: a[i] ?? "" });
  for (let i = head; i < b.length - tail; i++) out.push({ kind: "added", text: b[i] ?? "" });
  for (let i = b.length - tail; i < b.length; i++) out.push({ kind: "context", text: b[i] ?? "" });
  return out;
}

/** Render a diff in unified form — the exact string that gets committed. */
export function unifiedDiff(before: string, after: string): string {
  return lineDiff(before, after)
    .map((line) =>
      line.kind === "added" ? `+${line.text}` : line.kind === "removed" ? `-${line.text}` : ` ${line.text}`,
    )
    .join("\n");
}

/** Count of added/removed lines, for the console's change list. */
export function diffStat(before: string, after: string): { added: number; removed: number } {
  let added = 0;
  let removed = 0;
  for (const line of lineDiff(before, after)) {
    if (line.kind === "added") added++;
    else if (line.kind === "removed") removed++;
  }
  return { added, removed };
}
