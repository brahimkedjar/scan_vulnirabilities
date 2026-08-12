const CONTROL_AND_BIDI =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/gu;
const MAXIMUM_DIFF_CHARACTERS = 512 * 1024;
const MAXIMUM_DIFF_LINES = 10_000;

function safeLine(value: string): string {
  return value.replace(CONTROL_AND_BIDI, "�");
}

/** Bounded real line diff generated from actual before/after content. */
export function createUnifiedDiff(
  displayPath: string,
  before: string,
  after: string,
): string | undefined {
  if (before === after) return "";
  const beforeLines = before.split(/(?<=\n)/u);
  const afterLines = after.split(/(?<=\n)/u);
  if (
    beforeLines.length + afterLines.length > MAXIMUM_DIFF_LINES ||
    before.length + after.length > MAXIMUM_DIFF_CHARACTERS
  ) {
    return undefined;
  }
  let prefix = 0;
  while (
    prefix < beforeLines.length &&
    prefix < afterLines.length &&
    beforeLines[prefix] === afterLines[prefix]
  ) {
    prefix += 1;
  }
  let suffix = 0;
  while (
    suffix < beforeLines.length - prefix &&
    suffix < afterLines.length - prefix &&
    beforeLines[beforeLines.length - 1 - suffix] ===
      afterLines[afterLines.length - 1 - suffix]
  ) {
    suffix += 1;
  }
  const contextStart = Math.max(0, prefix - 3);
  const beforeEnd = beforeLines.length - suffix;
  const afterEnd = afterLines.length - suffix;
  const contextEndBefore = Math.min(beforeLines.length, beforeEnd + 3);
  const contextEndAfter = Math.min(afterLines.length, afterEnd + 3);
  const output = [
    `--- ${safeLine(displayPath)}`,
    `+++ ${safeLine(displayPath)}`,
    `@@ -${(contextStart + 1).toString()},${(contextEndBefore - contextStart).toString()} +${(contextStart + 1).toString()},${(contextEndAfter - contextStart).toString()} @@`,
  ];
  for (const line of beforeLines.slice(contextStart, prefix)) {
    output.push(` ${safeLine(line.replace(/\r?\n$/u, ""))}`);
  }
  for (const line of beforeLines.slice(prefix, beforeEnd)) {
    output.push(`-${safeLine(line.replace(/\r?\n$/u, ""))}`);
  }
  for (const line of afterLines.slice(prefix, afterEnd)) {
    output.push(`+${safeLine(line.replace(/\r?\n$/u, ""))}`);
  }
  for (const line of beforeLines.slice(beforeEnd, contextEndBefore)) {
    output.push(` ${safeLine(line.replace(/\r?\n$/u, ""))}`);
  }
  const joined = output.join("\n");
  return joined.length <= MAXIMUM_DIFF_CHARACTERS ? joined : undefined;
}
