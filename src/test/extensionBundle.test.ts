import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const EXTENSION_BUNDLE = path.resolve(__dirname, "..", "extension.js");

void test("the packaged extension bundle contains no unresolved jsonc-parser modules", () => {
  const bundle = readFileSync(EXTENSION_BUNDLE, "utf8");

  assert.doesNotMatch(bundle, /require\(["']\.\/impl\//u);
  assert.doesNotMatch(bundle, /jsonc-parser\/lib\/umd/u);
});
