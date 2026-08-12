import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  findDependencyOffset,
  findDependencyOffsets,
} from "../diagnostics/jsonDependencyLocator";

void test("locates an npm alias by its manifest key rather than advisory name", () => {
  const packageJson = `{
  "dependencies": {
    "alias-util": "npm:real-util@^3.0.0"
  }
}`;
  const offset = findDependencyOffset(packageJson, "alias-util");

  assert.ok(offset !== undefined);
  assert.equal(
    packageJson.slice(offset, offset + "alias-util".length),
    "alias-util",
  );
  assert.equal(findDependencyOffset(packageJson, "real-util"), undefined);
});

void test("bounds dependency lookup to a recognized dependency section", () => {
  const packageJson = `{
  "scripts": { "fake-package": "echo no" },
  "devDependencies": { "real-package": "1.0.0" }
}`;

  assert.equal(findDependencyOffset(packageJson, "fake-package"), undefined);
  assert.ok(findDependencyOffset(packageJson, "real-package") !== undefined);
});

void test("does not treat dependency-shaped text inside JSON strings as a declaration", () => {
  const packageJson = `{
  "description": "\\\"dependencies\\\": { \\\"spoofed-package\\\": \\\"9.9.9\\\" }",
  "metadata": {
    "example": "\\\"devDependencies\\\": { \\\"also-spoofed\\\": \\\"1.0.0\\\" }"
  },
  "dependencies": {
    "real-package": "1.0.0"
  }
}`;

  assert.equal(findDependencyOffset(packageJson, "spoofed-package"), undefined);
  assert.equal(findDependencyOffset(packageJson, "also-spoofed"), undefined);
  const offset = findDependencyOffset(packageJson, "real-package");
  assert.equal(offset, packageJson.lastIndexOf('"real-package"') + 1);
});

void test("ignores dependency-shaped comments and nested dependency objects", () => {
  const packageJson = `{
  // "dependencies": { "line-comment-package": "1.0.0" },
  "metadata": {
    "dependencies": { "nested-package": "1.0.0" }
  },
  "dependencies": {
    /* "block-comment-package": "1.0.0", */
    "real-package": "1.0.0"
  }
}`;

  assert.equal(
    findDependencyOffset(packageJson, "line-comment-package"),
    undefined,
  );
  assert.equal(
    findDependencyOffset(packageJson, "block-comment-package"),
    undefined,
  );
  assert.equal(findDependencyOffset(packageJson, "nested-package"), undefined);
  assert.ok(findDependencyOffset(packageJson, "real-package") !== undefined);
});

void test("does not reuse an ignored duplicate section or an escaped key range", () => {
  const duplicateSection = `{
  "dependencies": { "ignored-package": "1.0.0" },
  "dependencies": { "effective-package": "2.0.0" }
}`;
  const escapedKey = `{
  "dependencies": { "real\\u002dpackage": "1.0.0" }
}`;

  assert.equal(
    findDependencyOffset(duplicateSection, "ignored-package"),
    undefined,
  );
  assert.ok(
    findDependencyOffset(duplicateSection, "effective-package") !== undefined,
  );
  assert.equal(findDependencyOffset(escapedKey, "real-package"), undefined);
});

void test("returns no location for malformed, missing, or excessively large input", () => {
  assert.equal(
    findDependencyOffset('{ "dependencies": { "other": "1.0.0" } }', "missing"),
    undefined,
  );
  assert.equal(
    findDependencyOffset('{ "dependencies": { "target": } }', "target"),
    undefined,
  );
  assert.equal(
    findDependencyOffset(`{"description":"${"x".repeat(2 * 1024 * 1024)}"}`, "target"),
    undefined,
  );
});

void test("locates the maximum diagnostic key set in one bounded manifest pass", () => {
  const names = Array.from(
    { length: 2_000 },
    (_, index) => `package-${index.toString().padStart(4, "0")}`,
  );
  const dependencies = Object.fromEntries(
    names.map((name) => [name, "1.0.0"]),
  );
  const packageJson = JSON.stringify({
    name: "diagnostic-scale-fixture",
    dependencies,
  });

  const offsets = findDependencyOffsets(packageJson, names);

  assert.equal(offsets.size, names.length);
  for (const name of names) {
    const offset = offsets.get(name);
    assert.ok(offset !== undefined);
    assert.equal(packageJson.slice(offset, offset + name.length), name);
  }
});
