import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

void test("production CLI bundle is executable, self-contained, and has no spawn pathway", async () => {
  const bundle = await readFile(join(process.cwd(), "dist", "cli", "main.js"), "utf8");
  assert.equal(bundle.startsWith("#!/usr/bin/env node"), true);
  assert.equal(bundle.includes("sourceMappingURL="), false);
  assert.equal(bundle.includes('require("vscode")'), false);
  assert.equal(bundle.includes("node:child_process"), false);
  assert.equal(bundle.includes("child_process"), false);
  assert.equal(/\b(?:execSync|spawnSync|execFileSync)\b/u.test(bundle), false);
});
