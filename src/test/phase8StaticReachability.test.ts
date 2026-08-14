import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  analyzeStaticReachability,
  type ReachabilityTargetInput,
  type StaticSourceInput,
} from "../core/reachability/StaticReachability";

const NPM_TARGET: ReachabilityTargetInput = {
  targetId: "OSV-TEST-1",
  ecosystem: "npm",
  packageName: "vulnerable-package",
  affectedSymbols: ["dangerous"],
};

function source(
  fileId: string,
  content: string,
  overrides: Partial<StaticSourceInput> = {},
): StaticSourceInput {
  return {
    fileId,
    language: "typescript",
    content,
    ...overrides,
  };
}

void test("JavaScript/TypeScript analysis finds a bounded internal-module to affected-symbol path", () => {
  const result = analyzeStaticReachability({
    sources: [
      source("src/index.ts", 'import { run } from "./service"; run();', {
        entrypoint: true,
      }),
      source(
        "src/service.ts",
        'import { dangerous as invoke } from "vulnerable-package"; invoke();',
      ),
    ],
    targets: [NPM_TARGET],
  });
  const finding = result.findings[0];

  assert.equal(finding?.status, "REACHABLE");
  assert.equal(finding?.confidence, "HIGH");
  assert.equal(finding?.observedSymbol, "dangerous");
  assert.deepEqual(finding?.path, [
    "src/index.ts",
    "src/service.ts",
    "vulnerable-package",
    "dangerous",
  ]);
  assert.equal(finding?.exploitability, "NOT_ESTABLISHED");
  assert.equal(result.coverage.analysisComplete, true);
});

void test("Python analysis maps bounded internal imports to package symbols", () => {
  const result = analyzeStaticReachability({
    sources: [
      source("app/main.py", "import app.worker\napp.worker.run()", {
        language: "python",
        entrypoint: true,
      }),
      source(
        "app/worker.py",
        "from vulnerable_package import risky\ndef run():\n    risky()",
        { language: "python" },
      ),
    ],
    targets: [
      {
        targetId: "PYSEC-TEST-1",
        ecosystem: "PyPI",
        packageName: "vulnerable-package",
        affectedSymbols: ["risky"],
      },
    ],
  });

  assert.equal(result.findings[0]?.status, "REACHABLE");
  assert.deepEqual(result.findings[0]?.path, [
    "app/main.py",
    "app/worker.py",
    "vulnerable-package",
    "risky",
  ]);
});

void test("complete bounded coverage reports NOT_OBSERVED, never unreachable", () => {
  const result = analyzeStaticReachability({
    sources: [
      source("src/index.ts", 'import safe from "safe-package"; safe();', {
        entrypoint: true,
      }),
    ],
    targets: [NPM_TARGET],
  });
  const finding = result.findings[0];

  assert.equal(finding?.status, "NOT_OBSERVED");
  assert.match(finding?.limitations[0] ?? "", /does not mean unreachable/iu);
  assert.equal(finding?.exploitability, "NOT_ESTABLISHED");
  assert.doesNotMatch(JSON.stringify(finding), /exploitable.{0,8}true/iu);
});

void test("computed dynamic loading preserves UNKNOWN instead of a false negative", () => {
  const result = analyzeStaticReachability({
    sources: [
      source(
        "src/index.ts",
        'const requested = process.env.PACKAGE; void import(requested ?? "fallback");',
        { entrypoint: true },
      ),
    ],
    targets: [NPM_TARGET],
  });

  assert.equal(result.findings[0]?.status, "UNKNOWN");
  assert.equal(result.coverage.uncertainReachableFiles, 1);
  assert.equal(result.coverage.analysisComplete, false);
});

void test("literal dynamic or unresolved wildcard package use preserves UNKNOWN for affected symbols", () => {
  const dynamic = analyzeStaticReachability({
    sources: [
      source("src/index.ts", 'void import("vulnerable-package");', {
        entrypoint: true,
      }),
    ],
    targets: [NPM_TARGET],
  });
  const namespace = analyzeStaticReachability({
    sources: [
      source(
        "src/index.ts",
        'import * as vulnerable from "vulnerable-package"; consume(vulnerable);',
        { entrypoint: true },
      ),
    ],
    targets: [NPM_TARGET],
  });

  assert.equal(dynamic.findings[0]?.status, "UNKNOWN");
  assert.equal(namespace.findings[0]?.status, "UNKNOWN");
});

void test("comments, strings, and Python docstrings cannot fabricate reachability", () => {
  const javascript = analyzeStaticReachability({
    sources: [
      source(
        "src/index.ts",
        [
          '// require("vulnerable-package").dangerous();',
          'const example = "import { dangerous } from \'vulnerable-package\'";',
          "export const safe = true;",
        ].join("\n"),
        { entrypoint: true },
      ),
    ],
    targets: [NPM_TARGET],
  });
  const python = analyzeStaticReachability({
    sources: [
      source(
        "app.py",
        '\"\"\"\nfrom vulnerable_package import risky\n\"\"\"\nvalue = 1',
        { language: "python", entrypoint: true },
      ),
    ],
    targets: [
      {
        targetId: "PYSEC-TEST-2",
        ecosystem: "PyPI",
        packageName: "vulnerable-package",
        affectedSymbols: ["risky"],
      },
    ],
  });

  assert.equal(javascript.findings[0]?.status, "NOT_OBSERVED");
  assert.equal(python.findings[0]?.status, "NOT_OBSERVED");
});

void test("regular-expression text cannot fabricate imports and dynamic evaluation remains UNKNOWN", () => {
  const regexText = analyzeStaticReachability({
    sources: [
      source(
        "src/index.ts",
        'const pattern = /require\\("vulnerable-package"\\)\\.dangerous/;',
        { entrypoint: true },
      ),
    ],
    targets: [NPM_TARGET],
  });
  const evaluated = analyzeStaticReachability({
    sources: [
      source(
        "src/index.ts",
        'eval("require(\\\"vulnerable-package\\\").dangerous()")',
        { entrypoint: true },
      ),
    ],
    targets: [NPM_TARGET],
  });

  assert.equal(regexText.findings[0]?.status, "NOT_OBSERVED");
  assert.equal(evaluated.findings[0]?.status, "UNKNOWN");
});

void test("a lexical import in structurally unbalanced source remains UNKNOWN", () => {
  const result = analyzeStaticReachability({
    sources: [
      source(
        "src/index.ts",
        'if (enabled) { import { dangerous } from "vulnerable-package";',
        { entrypoint: true },
      ),
    ],
    targets: [NPM_TARGET],
  });

  assert.equal(result.findings[0]?.status, "UNKNOWN");
  assert.equal(result.coverage.analysisComplete, false);
});

void test("affected symbol evidence prevents package-only imports from proving API reachability", () => {
  const result = analyzeStaticReachability({
    sources: [
      source(
        "index.js",
        'const { harmless } = require("vulnerable-package"); harmless();',
        { language: "javascript", entrypoint: true },
      ),
    ],
    targets: [NPM_TARGET],
  });

  assert.equal(result.findings[0]?.status, "NOT_OBSERVED");
});

void test("invalid private paths and control-bearing target identities are rejected without disclosure", () => {
  const result = analyzeStaticReachability({
    sources: [
      source(
        "C:\\Users\\private\\secret.ts",
        'import { dangerous } from "vulnerable-package";',
        { entrypoint: true },
      ),
      source("../outside.ts", 'require("vulnerable-package")', {
        entrypoint: true,
      }),
    ],
    entrypoints: ["C:\\Users\\private\\secret.ts"],
    targets: [
      {
        ...NPM_TARGET,
        targetId: "bad\u202Eid",
        packageName: "bad\u0000package",
      },
    ],
  });
  const serialized = JSON.stringify(result);

  assert.equal(result.coverage.sourceFilesInvalid, 2);
  assert.equal(result.findings[0]?.status, "UNKNOWN");
  assert.doesNotMatch(serialized, /Users|private|secret|outside|\u202e/iu);
});

void test("source, byte, target, and import limits fail closed", () => {
  const result = analyzeStaticReachability(
    {
      sources: [
        source(
          "index.ts",
          'import "one"; import "two"; import "three";',
          { entrypoint: true },
        ),
        source("second.ts", "export const second = true;"),
      ],
      targets: [NPM_TARGET, { ...NPM_TARGET, targetId: "second" }],
    },
    {
      limits: {
        maximumFiles: 1,
        maximumTargets: 1,
        maximumImportsPerFile: 1,
      },
    },
  );

  assert.equal(result.coverage.truncated, true);
  assert.equal(result.coverage.sourceFilesOmitted, 1);
  assert.equal(result.coverage.targetsAnalyzed, 1);
  assert.equal(result.coverage.analysisComplete, false);
  assert.equal(result.findings[0]?.status, "UNKNOWN");
});

void test("reachability results are deterministic, immutable, and cancellable", () => {
  const input = {
    sources: [source("index.ts", "export const value = 1;", { entrypoint: true })],
    targets: [NPM_TARGET],
  } as const;
  const first = analyzeStaticReachability(input);
  const second = analyzeStaticReachability(input);
  assert.deepEqual(first, second);
  assert.ok(Object.isFrozen(first));
  assert.ok(Object.isFrozen(first.findings));
  assert.ok(Object.isFrozen(first.findings[0]?.limitations));

  const controller = new AbortController();
  controller.abort();
  const cancelled = analyzeStaticReachability(input, {
    signal: controller.signal,
  });
  assert.equal(cancelled.coverage.cancelled, true);
  assert.equal(cancelled.coverage.analysisComplete, false);
  assert.equal(cancelled.findings[0]?.status, "UNKNOWN");
});
