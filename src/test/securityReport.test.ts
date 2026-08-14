import assert from "node:assert/strict";
import { test } from "node:test";

import type { ScanResult } from "../models/ScanResult";
import {
  buildSecurityReport,
  exportSecurityReportCsv,
  exportSecurityReportHtml,
  exportSecurityReportJson,
  exportSecurityReportMarkdown,
} from "../core/reporting";

function result(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    workspacePath: "C:\\work\\repo",
    scannedAt: "2026-08-13T10:00:00.000Z",
    durationMs: 10,
    packageManagers: ["npm"],
    dependenciesScanned: 1,
    vulnerableDependencies: 1,
    vulnerabilities: [],
    unfilteredVulnerabilities: [
      {
        id: "CVE-2026-1234",
        aliases: ["GHSA-safe-alias"],
        packageName: "fixture-package",
        ecosystem: "npm",
        installedVersion: "1.0.0",
        severity: "HIGH",
        cvssScore: 8.1,
        summary: "not exported prose",
        fixedVersions: ["1.1.0"],
        remediationCandidates: ["1.1.0"],
        references: ["https://example.invalid/private"],
        source: "OSV",
      },
    ],
    dependencies: [
      {
        name: "fixture-package",
        ecosystem: "npm",
        installedVersion: "1.0.0",
        dependencyType: "direct",
        environment: "production",
        manifestPath: "C:\\work\\repo\\package.json",
        packageManager: "npm",
      },
    ],
    errors: [],
    providerResults: [
      {
        provider: "OSV",
        status: "available",
        dependenciesEligible: 1,
        dependenciesSubmitted: 1,
        successful: 1,
        failed: 0,
        cacheHits: 0,
        staleCacheFallbacks: 0,
        vulnerabilitiesFound: 1,
      },
    ],
    ecosystemCoverage: [
      {
        ecosystem: "npm",
        packageManagers: ["npm"],
        discovered: 1,
        resolved: 1,
        checked: 1,
        vulnerable: 1,
        unresolved: 0,
        unsupported: 0,
      },
    ],
    cancelled: false,
    ...overrides,
  };
}

void test("builds a deterministic complete report from unfiltered findings and explicit evidence", () => {
  const options = {
    generatedAt: "2026-08-13T10:01:00.000Z",
    toolVersion: "0.9.0",
    workspaceRoots: ["C:\\work\\repo"],
    licenses: [
      {
        ecosystem: "npm",
        packageName: "fixture-package",
        version: "1.0.0",
        expression: "MIT",
        status: "ALLOWED" as const,
        evidenceSource: "manifest-metadata",
      },
    ],
    provenance: [
      {
        ecosystem: "npm",
        packageName: "fixture-package",
        version: "1.0.0",
        status: "SAFE" as const,
        evidence: ["official registry", "sha512 integrity"],
        limitations: [],
      },
    ],
    reachability: [
      {
        ecosystem: "npm",
        packageName: "fixture-package",
        version: "1.0.0",
        status: "REACHABLE" as const,
        confidence: "HIGH" as const,
        path: ["src/index.ts", "fixture-package"],
        limitations: ["Package import reachability does not prove exploitability."],
      },
    ],
    anomalies: [],
    remediation: [
      {
        advisoryId: "CVE-2026-1234",
        ecosystem: "npm",
        packageName: "fixture-package",
        installedVersion: "1.0.0",
        strategy: "UPGRADE_DIRECT" as const,
        recommendedVersion: "1.1.0",
        reason: "Provider candidate is proven across grouped advisories.",
        risk: "LOW" as const,
      },
    ],
    knownExploitation: [
      {
        advisoryId: "CVE-2026-1234",
        ecosystem: "npm",
        packageName: "fixture-package",
        installedVersion: "1.0.0",
        status: "known-exploited" as const,
        source: "CISA KEV",
      },
    ],
  };
  const first = buildSecurityReport([result()], options);
  const second = buildSecurityReport([result()], options);
  assert.deepEqual(first, second);
  assert.equal(first.summary.coverage, "complete");
  assert.equal(first.summary.findings, 1);
  assert.equal(first.summary.reachable, 1);
  assert.equal(first.summary.kev, 1);
  assert.equal(first.summary.kevCoverage, "complete");
  assert.equal(first.vulnerabilities[0]?.location, "package.json");
  assert.deepEqual(first.vulnerabilities[0]?.fixedVersions, ["1.1.0"]);
  assert.equal(first.dependencies[0]?.location, "package.json");
  const encoded = exportSecurityReportJson(first);
  assert.equal(encoded, exportSecurityReportJson(second));
  assert.doesNotMatch(encoded, /C:\\\\work/u);
  assert.doesNotMatch(encoded, /example\.invalid/u);
  assert.doesNotMatch(encoded, /not exported prose/u);
});

void test("provider count mismatch and incomplete scans cannot render as complete", () => {
  const mismatch = result({
    unfilteredVulnerabilities: [],
    providerResults: [
      {
        provider: "OSV",
        status: "available",
        dependenciesEligible: 1,
        dependenciesSubmitted: 1,
        successful: 1,
        failed: 0,
        cacheHits: 0,
        staleCacheFallbacks: 0,
        vulnerabilitiesFound: 1,
      },
    ],
  });
  const report = buildSecurityReport([mismatch], {
    generatedAt: "2026-08-13T10:01:00Z",
    toolVersion: "0.9.0",
  });
  assert.equal(report.summary.findings, 0);
  assert.equal(report.summary.coverage, "incomplete");
  assert.match(report.limitations.join(" "), /zero findings is not a clean result/u);

  const providerFailure = buildSecurityReport(
    [
      result({
        errors: [{ code: "PROVIDER_ERROR", message: "unavailable" }],
        providerResults: [
          {
            provider: "OSV",
            status: "unavailable",
            dependenciesEligible: 1,
            dependenciesSubmitted: 1,
            successful: 0,
            failed: 1,
            cacheHits: 0,
            staleCacheFallbacks: 0,
            vulnerabilitiesFound: 0,
          },
        ],
      }),
    ],
    { generatedAt: "2026-08-13T10:01:00Z", toolVersion: "0.9.0" },
  );
  assert.equal(providerFailure.summary.coverage, "incomplete");
});

void test("qualifies identical paths from multiple workspace roots", () => {
  const left = result({
    workspacePath: "C:\\work\\a",
    dependencies: [
      {
        name: "fixture-package",
        ecosystem: "npm",
        installedVersion: "1.0.0",
        dependencyType: "direct",
        environment: "production",
        manifestPath: "C:\\work\\a\\package.json",
      },
    ],
  });
  const right = result({
    workspacePath: "C:\\work\\b",
    dependencies: [
      {
        name: "fixture-package",
        ecosystem: "npm",
        installedVersion: "1.0.0",
        dependencyType: "direct",
        environment: "production",
        manifestPath: "C:\\work\\b\\package.json",
      },
    ],
  });
  const report = buildSecurityReport([left, right], {
    generatedAt: "2026-08-13T10:01:00Z",
    toolVersion: "0.9.0",
    workspaceRoots: ["C:\\work\\b", "C:\\work\\a"],
  });
  assert.deepEqual(
    report.dependencies.map((entry) => entry.location),
    ["workspace-root-1/package.json", "workspace-root-2/package.json"],
  );
  assert.equal(report.vulnerabilities.length, 2);
});

void test("HTML and Markdown neutralize untrusted markup, controls, and bidi text", () => {
  const malicious = result({
    unfilteredVulnerabilities: [
      {
        id: '<img src=x onerror="alert(1)">\u202e',
        aliases: [],
        packageName: "fixture-package",
        ecosystem: "npm",
        installedVersion: "1.0.0",
        severity: "HIGH",
        summary: "irrelevant",
        references: [],
        source: "OSV",
      },
    ],
  });
  const report = buildSecurityReport([malicious], {
    generatedAt: "2026-08-13T10:01:00Z",
    toolVersion: "0.9.0",
    title: "<script>alert(1)</script>",
  });
  const html = exportSecurityReportHtml(report);
  assert.match(html, /Content-Security-Policy/u);
  assert.match(html, /default-src 'none'/u);
  assert.doesNotMatch(html, /<script>/u);
  assert.match(html, /&lt;script&gt;/u);
  assert.match(html, /&lt;img/u);
  assert.doesNotMatch(html, /\u202e/u);
  const markdown = exportSecurityReportMarkdown(report);
  assert.doesNotMatch(markdown, /\u202e/u);
  assert.match(markdown, /\\<script\\>/u);
});

void test("CSV neutralizes spreadsheet formulas", () => {
  const formula = result({
    dependencies: [
      {
        name: "=HYPERLINK(evil)",
        ecosystem: "npm",
        installedVersion: "1.0.0",
        dependencyType: "direct",
        environment: "production",
      },
    ],
    unfilteredVulnerabilities: [],
    providerResults: [],
  });
  const report = buildSecurityReport([formula], {
    generatedAt: "2026-08-13T10:01:00Z",
    toolVersion: "0.9.0",
  });
  const csv = exportSecurityReportCsv(report);
  assert.match(csv, /"'=HYPERLINK\(evil\)"/u);
});

void test("resource limits, timestamp validation, and cancellation fail closed", () => {
  assert.throws(
    () =>
      buildSecurityReport([result()], {
        generatedAt: "yesterday",
        toolVersion: "0.9.0",
      }),
    /generatedAt/u,
  );
  assert.throws(
    () =>
      buildSecurityReport([result()], {
        generatedAt: "2026-08-13T10:01:00Z",
        toolVersion: "0.9.0",
        maximumDependencies: 1,
        licenses: [
          {
            ecosystem: "npm",
            packageName: "a",
            version: "1",
            status: "UNKNOWN",
          },
          {
            ecosystem: "npm",
            packageName: "b",
            version: "1",
            status: "UNKNOWN",
          },
        ],
        maximumEvidenceRecords: 1,
      }),
    /evidence exceeds/u,
  );
  const report = buildSecurityReport([result()], {
    generatedAt: "2026-08-13T10:01:00Z",
    toolVersion: "0.9.0",
  });
  assert.throws(() => exportSecurityReportJson(report, 64), /output limit/u);

  const controller = new AbortController();
  controller.abort();
  assert.throws(
    () =>
      buildSecurityReport([result()], {
        generatedAt: "2026-08-13T10:01:00Z",
        toolVersion: "0.9.0",
        signal: controller.signal,
      }),
    /cancelled/u,
  );
});
