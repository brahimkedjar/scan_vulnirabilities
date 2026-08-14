import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import test from "node:test";

async function collectFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...await collectFiles(path));
      continue;
    }
    if (/\.(?:ts|tsx|js|jsx|mts|cts|mjs|cjs)$/u.test(entry.name)) {
      files.push(path);
    }
  }
  return files;
}

void test("core modules do not import vscode", async () => {
  const root = join(process.cwd(), "src", "core");
  const offenders: string[] = [];
  const importPatterns = [
    /^\s*import\s+[^\n]*?from\s+["']vscode["']/mu,
    /^\s*import\s+["']vscode["']/mu,
    /^\s*export\s+\*\s+from\s+["']vscode["']/mu,
    /^\s*const\s+[^=]+?=\s*require\(\s*["']vscode["']\s*\)/mu,
    /^\s*import\(\s*["']vscode["']\s*\)/mu,
  ];

  for (const file of await collectFiles(root)) {
    const content = await readFile(file, "utf8");
    if (importPatterns.some((pattern) => pattern.test(content))) {
      offenders.push(relative(process.cwd(), file));
    }
  }

  assert.deepEqual(offenders, [], `core files must not import vscode: ${offenders.join(", ")}`);
});
