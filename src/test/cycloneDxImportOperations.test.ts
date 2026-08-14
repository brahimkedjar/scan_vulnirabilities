import assert from "node:assert/strict";
import test from "node:test";

import {
  CycloneDxImportError,
  CycloneDxOperationError,
  diffCycloneDxBoms,
  importCycloneDxJson,
  mergeCycloneDxBoms,
  verifyImportedCycloneDxBom,
} from "../core/sbom";

interface BomOptions {
  readonly name?: string;
  readonly version?: string;
  readonly vulnerability?: boolean;
  readonly severity?: "high" | "critical";
  readonly complete?: boolean;
  readonly absoluteOccurrence?: boolean;
  readonly secretProperty?: boolean;
}

function cycloneDocument(options: BomOptions = {}): Record<string, unknown> {
  const name = options.name ?? "alpha";
  const version = options.version ?? "1.0.0";
  const ref = `component-${name}-${version}`;
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    ...(options.secretProperty === true
      ? { password: "must-never-survive-normalization" }
      : {}),
    components: [
      {
        type: "library",
        "bom-ref": ref,
        name,
        version,
        purl: `pkg:npm/${name}@${version}?repository_url=https://user:secret@example.test`,
        ...(options.absoluteOccurrence === true
          ? {
              evidence: {
                occurrences: [
                  { location: "C:\\Users\\private\\secret-project\\package.json" },
                ],
              },
            }
          : {}),
      },
    ],
    dependencies: [{ ref, dependsOn: [] }],
    ...(options.vulnerability === false
      ? { vulnerabilities: [] }
      : {
          vulnerabilities: [
            {
              id: "CVE-2026-1234",
              source: { name: "OSV" },
              ratings: [
                {
                  source: { name: "OSV" },
                  severity: options.severity ?? "high",
                  score: options.severity === "critical" ? 9.8 : 8.1,
                },
              ],
              description: "untrusted prose token=must-never-survive",
              advisories: [
                { url: "https://user:secret@example.test/advisory" },
              ],
              affects: [{ ref }],
            },
          ],
        }),
    ...(options.complete === false
      ? {}
      : { compositions: [{ aggregate: "complete" }] }),
  };
}

void test("CycloneDX import retains bounded identity evidence and omits paths, prose, URLs, and secrets", () => {
  const raw = cycloneDocument({
    absoluteOccurrence: true,
    secretProperty: true,
  });
  const imported = importCycloneDxJson(JSON.stringify(raw));
  assert.equal(verifyImportedCycloneDxBom(imported), true);
  assert.equal(imported.source.specVersion, "1.6");
  assert.equal(imported.components.length, 1);
  assert.equal(imported.components[0]?.purl, "pkg:npm/alpha@1.0.0");
  assert.equal(imported.vulnerabilities.length, 1);
  assert.equal(imported.vulnerabilities[0]?.ratings[0]?.severity, "high");
  assert.equal(imported.coverage.inventory, "complete");
  assert.equal(imported.coverage.vulnerabilityAnalysis, "complete");
  assert.equal(imported.coverage.reasons.includes("PATH_EVIDENCE_OMITTED"), true);
  const normalized = JSON.stringify(imported);
  assert.doesNotMatch(
    normalized,
    /secret-project|private|must-never|repository_url|example\.test|description|advisories|password/u,
  );
  assert.equal(Object.isFrozen(imported), true);
  assert.equal(Object.isFrozen(imported.components[0]), true);

  const reordered = {
    ...raw,
    components: raw.components,
    version: 1,
    specVersion: "1.6",
    bomFormat: "CycloneDX",
  };
  assert.equal(
    importCycloneDxJson(JSON.stringify(reordered)).source.digest,
    imported.source.digest,
  );
});

void test("CycloneDX import exposes ambiguous references and incomplete coverage", () => {
  const document = cycloneDocument({ vulnerability: false });
  document.components = [
    {
      type: "library",
      "bom-ref": "duplicate",
      name: "alpha",
      version: "1.0.0",
      purl: "pkg:npm/alpha@1.0.0",
    },
    {
      type: "library",
      "bom-ref": "duplicate",
      name: "beta",
      version: "1.0.0",
      purl: "pkg:npm/beta@1.0.0",
    },
  ];
  document.dependencies = [{ ref: "duplicate", dependsOn: [] }];
  const imported = importCycloneDxJson(JSON.stringify(document));
  assert.equal(
    imported.conflicts.some(
      (conflict) => conflict.code === "DUPLICATE_COMPONENT_REFERENCE",
    ),
    true,
  );
  assert.equal(imported.coverage.dependencyGraph, "partial");
  assert.equal(imported.coverage.reasons.includes("REFERENCE_CONFLICT"), true);
});

void test("CycloneDX diff reports proven changes and keeps incomplete absence unknown", () => {
  const before = importCycloneDxJson(
    JSON.stringify(cycloneDocument({ version: "1.0.0", vulnerability: true })),
  );
  const after = importCycloneDxJson(
    JSON.stringify(cycloneDocument({ version: "2.0.0", vulnerability: false })),
  );
  const complete = diffCycloneDxBoms(before, after);
  assert.equal(complete.complete, true);
  assert.equal(complete.components.versionChanges.length, 1);
  assert.deepEqual(complete.components.versionChanges[0]?.beforeVersions, ["1.0.0"]);
  assert.deepEqual(complete.components.versionChanges[0]?.afterVersions, ["2.0.0"]);
  assert.equal(complete.vulnerabilities.resolved.length, 1);
  assert.equal(complete.vulnerabilities.unknownNoLongerObserved.length, 0);

  const incomplete = importCycloneDxJson(
    JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      version: 1,
    }),
  );
  const unknown = diffCycloneDxBoms(before, incomplete);
  assert.equal(unknown.complete, false);
  assert.equal(unknown.components.removed.length, 0);
  assert.equal(unknown.components.unknownRemovals.length, 1);
  assert.equal(unknown.vulnerabilities.resolved.length, 0);
  assert.equal(unknown.vulnerabilities.unknownNoLongerObserved.length, 1);

  const unknownBaselineAdditions = diffCycloneDxBoms(incomplete, before);
  assert.equal(unknownBaselineAdditions.components.added.length, 0);
  assert.equal(unknownBaselineAdditions.components.unknownAdditions.length, 1);
  assert.equal(unknownBaselineAdditions.vulnerabilities.added.length, 0);
  assert.equal(
    unknownBaselineAdditions.vulnerabilities.unknownPreviouslyUnobserved.length,
    1,
  );

  const changed = importCycloneDxJson(
    JSON.stringify(cycloneDocument({ severity: "critical" })),
  );
  assert.equal(diffCycloneDxBoms(before, changed).vulnerabilities.changed.length, 1);
});

void test("CycloneDX merge is input-order deterministic and surfaces evidence conflict", () => {
  const alpha = importCycloneDxJson(
    JSON.stringify(cycloneDocument({ name: "alpha", severity: "high" })),
  );
  const beta = importCycloneDxJson(
    JSON.stringify(cycloneDocument({ name: "beta", vulnerability: false })),
  );
  const first = mergeCycloneDxBoms([alpha, beta]);
  const second = mergeCycloneDxBoms([beta, alpha]);
  assert.deepEqual(first, second);
  assert.equal(first.components.length, 2);
  assert.equal(first.coverage.inventory, "complete");

  const critical = importCycloneDxJson(
    JSON.stringify(cycloneDocument({ name: "alpha", severity: "critical" })),
  );
  const conflicted = mergeCycloneDxBoms([alpha, critical]);
  assert.equal(
    conflicted.conflicts.some(
      (conflict) => conflict.code === "VULNERABILITY_EVIDENCE_CONFLICT",
    ),
    true,
  );
  assert.equal(conflicted.coverage.vulnerabilityAnalysis, "partial");
  assert.equal(verifyImportedCycloneDxBom(conflicted), true);
});

void test("CycloneDX import and operations enforce cancellation and resource limits", () => {
  assert.throws(
    () =>
      importCycloneDxJson(
        '{"bomFormat":"CycloneDX","specVersion":"1.6","__proto__":{}}',
      ),
    (error: unknown) =>
      error instanceof CycloneDxImportError && error.code === "INVALID_INPUT",
  );
  const twoComponents = cycloneDocument({ vulnerability: false });
  twoComponents.components = [
    {
      type: "library",
      name: "alpha",
      version: "1.0.0",
      purl: "pkg:npm/alpha@1.0.0",
    },
    {
      type: "library",
      name: "beta",
      version: "1.0.0",
      purl: "pkg:npm/beta@1.0.0",
    },
  ];
  assert.throws(
    () =>
      importCycloneDxJson(JSON.stringify(twoComponents), {
        limits: { maximumComponents: 1 },
      }),
    (error: unknown) =>
      error instanceof CycloneDxImportError && error.code === "LIMIT_EXCEEDED",
  );
  assert.throws(
    () =>
      importCycloneDxJson(JSON.stringify(cycloneDocument()), {
        jsonLimits: { maximumNodes: 2 },
      }),
    (error: unknown) =>
      error instanceof CycloneDxImportError && error.code === "LIMIT_EXCEEDED",
  );
  assert.throws(
    () =>
      importCycloneDxJson(
        JSON.stringify(
          cycloneDocument({ absoluteOccurrence: true }),
        ),
        { limits: { maximumPathLength: 8 } },
      ),
    CycloneDxImportError,
  );
  const controller = new AbortController();
  controller.abort();
  assert.throws(
    () =>
      importCycloneDxJson(JSON.stringify(cycloneDocument()), {
        signal: controller.signal,
      }),
    (error: unknown) =>
      error instanceof CycloneDxImportError && error.code === "CANCELLED",
  );
  const bom = importCycloneDxJson(JSON.stringify(cycloneDocument()));
  assert.throws(
    () => diffCycloneDxBoms(bom, bom, { signal: controller.signal }),
    (error: unknown) =>
      error instanceof CycloneDxOperationError && error.code === "CANCELLED",
  );
  assert.throws(
    () => mergeCycloneDxBoms([bom, bom], { maximumBoms: 1 }),
    (error: unknown) =>
      error instanceof CycloneDxOperationError && error.code === "LIMIT_EXCEEDED",
  );
});
