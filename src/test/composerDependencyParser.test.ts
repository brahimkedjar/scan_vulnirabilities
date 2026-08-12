import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { parseComposerDependencies } from "../package-managers/composer/ComposerDependencyParser";

const fixtureDirectory = join(
  process.cwd(),
  "src",
  "test",
  "fixtures",
  "composer",
  "graph",
);

function parseFixture(): ReturnType<typeof parseComposerDependencies> {
  return parseComposerDependencies({
    composerJson: readFileSync(
      join(fixtureDirectory, "composer.json"),
      "utf8",
    ),
    manifestPath: "/workspace/composer.json",
    composerLock: readFileSync(
      join(fixtureDirectory, "composer.lock"),
      "utf8",
    ),
    lockfilePath: "/workspace/composer.lock",
  });
}

void test("parses Composer production and development dependency graphs", () => {
  const result = parseFixture();
  const symfony = result.dependencies.find(
    (dependency) => dependency.name === "symfony/http-foundation",
  );
  const polyfill = result.dependencies.find(
    (dependency) => dependency.name === "symfony/polyfill-mbstring",
  );
  const phpunit = result.dependencies.find(
    (dependency) => dependency.name === "phpunit/phpunit",
  );
  const sebastian = result.dependencies.find(
    (dependency) => dependency.name === "sebastian/version",
  );
  assert.equal(symfony?.installedVersion, "v6.4.12");
  assert.equal(symfony?.dependencyType, "direct");
  assert.equal(polyfill?.dependencyType, "transitive");
  assert.equal(polyfill?.parent, "symfony/http-foundation@v6.4.12");
  assert.equal(phpunit?.environment, "development");
  assert.equal(sebastian?.environment, "development");
  assert.equal(
    result.dependencies.some((dependency) => dependency.name === "php"),
    false,
  );
});

void test("does not treat composer.json ranges as installed versions without a lock", () => {
  const result = parseComposerDependencies({
    composerJson: '{"require":{"symfony/console":"^7.0"}}',
    manifestPath: "/workspace/composer.json",
  });
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unresolved");
  assert.equal(result.issues.some((issue) => issue.code === "NO_LOCKFILE"), true);
});

void test("resolves Composer virtual replacements to the installed package identity", () => {
  const result = parseComposerDependencies({
    composerJson: '{"require":{"virtual/logger":"^1"}}',
    manifestPath: "/workspace/composer.json",
    composerLock: JSON.stringify({
      "content-hash": "x",
      packages: [
        {
          name: "vendor/logger",
          version: "1.2.0",
          replace: { "virtual/logger": "self.version" },
        },
      ],
      "packages-dev": [],
    }),
  });
  assert.equal(result.dependencies[0]?.name, "vendor/logger");
  assert.equal(result.dependencies[0]?.manifestName, "virtual/logger");
});

void test("marks Composer path repositories unsupported", () => {
  const result = parseComposerDependencies({
    composerJson: '{"require":{"vendor/local":"*"}}',
    manifestPath: "/workspace/composer.json",
    composerLock: JSON.stringify({
      "content-hash": "x",
      packages: [
        {
          name: "vendor/local",
          version: "dev-main",
          dist: { type: "path", url: "../local" },
        },
      ],
      "packages-dev": [],
    }),
  });
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
  assert.equal(result.dependencies[0]?.installedVersion, "");
});

void test("rejects non-exact versions forged into composer.lock", () => {
  const result = parseComposerDependencies({
    composerJson: '{"require":{"symfony/console":"^7"}}',
    manifestPath: "/workspace/composer.json",
    composerLock: JSON.stringify({
      packages: [{ name: "symfony/console", version: "^7" }],
      "packages-dev": [],
    }),
    lockfilePath: "/workspace/composer.lock",
  });
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unresolved");
  assert.equal(
    result.issues.some((issue) => issue.code === "INVALID_LOCKFILE"),
    true,
  );
});

void test("does not map custom Composer repositories to Packagist", () => {
  const result = parseComposerDependencies({
    composerJson: JSON.stringify({
      repositories: [
        {
          type: "package",
          package: {
            name: "private/acme",
            version: "1.2.3",
            dist: {
              type: "zip",
              url: "https://packages.example.invalid/acme.zip",
            },
          },
        },
      ],
      require: { "private/acme": "1.2.3" },
    }),
    manifestPath: "/workspace/composer.json",
    composerLock: JSON.stringify({
      packages: [
        {
          name: "private/acme",
          version: "1.2.3",
          dist: {
            type: "zip",
            url: "https://packages.example.invalid/acme.zip",
          },
        },
      ],
      "packages-dev": [],
    }),
    lockfilePath: "/workspace/composer.lock",
  });
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
  assert.equal(
    result.issues.some(
      (issue) => issue.code === "UNSUPPORTED_PACKAGE_SOURCE",
    ),
    true,
  );
});

void test("bounds malformed Composer locks and honors cancellation", () => {
  const malformed = parseComposerDependencies({
    composerJson: '{"require":{"symfony/console":"^7"}}',
    manifestPath: "/workspace/composer.json",
    composerLock: "{",
  });
  assert.equal(
    malformed.issues.some((issue) => issue.code === "INVALID_LOCKFILE"),
    true,
  );
  const bounded = parseComposerDependencies({
    composerJson: '{"require":{"a/a":"1","b/b":"1"}}',
    manifestPath: "/workspace/composer.json",
    composerLock: JSON.stringify({
      "content-hash": "x",
      packages: [
        { name: "a/a", version: "1.0.0" },
        { name: "b/b", version: "1.0.0" },
      ],
      "packages-dev": [],
    }),
    limits: { maxPackages: 1 },
  });
  assert.equal(bounded.truncated, true);
  const controller = new AbortController();
  controller.abort();
  const cancelled = parseComposerDependencies({
    composerJson: "{}",
    manifestPath: "/workspace/composer.json",
    signal: controller.signal,
  });
  assert.equal(cancelled.cancelled, true);
});
