import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { Dependency } from "../models/Dependency";
import type { ProviderResult, ScanResult } from "../models/ScanResult";
import type { Severity, Vulnerability } from "../models/Vulnerability";
import type { RetainedVulnerabilityFinding } from "../services/ScanResultStore";
import {
  buildVulnerabilityTreeModel,
  sanitizeTreeText,
  type DependencyTreeNode,
  type InformationTreeNode,
  type SeverityTreeNode,
  type VulnerabilityTreeNode,
} from "../tree/treeModel";
import { isVulnerabilityIdentity } from "../webview/vulnerabilityDetailsRenderer";

function dependency(name: string, version = "1.0.0"): Dependency {
  return {
    name,
    ecosystem: "npm",
    installedVersion: version,
    dependencyType: "direct",
    environment: "production",
    packageJsonPath: "/workspace/package.json",
  };
}

function vulnerability(
  packageName: string,
  severity: Severity,
  id: string,
  version = "1.0.0",
): Vulnerability {
  return {
    id,
    aliases: [],
    packageName,
    ecosystem: "npm",
    installedVersion: version,
    severity,
    summary: `Summary for ${id}`,
    references: [`https://osv.dev/vulnerability/${id}`],
    source: "OSV",
  };
}

function providerResult(
  status: ProviderResult["status"],
  dependencies: number,
  vulnerabilitiesFound = 0,
): ProviderResult {
  const successful = status === "available" ? dependencies : 0;
  const failed = status === "available" ? 0 : dependencies;
  return {
    provider: "OSV",
    status,
    dependenciesEligible: dependencies,
    dependenciesSubmitted: dependencies,
    successful,
    failed,
    cacheHits: 0,
    staleCacheFallbacks: 0,
    vulnerabilitiesFound,
  };
}

function scanResult(options: {
  dependencies?: readonly Dependency[];
  vulnerabilities?: readonly Vulnerability[];
  providerStatus?: ProviderResult["status"];
  providerVulnerabilitiesFound?: number;
  vulnerableDependencies?: number;
} = {}): ScanResult {
  const dependencies = options.dependencies ?? [];
  const vulnerabilities = options.vulnerabilities ?? [];
  return {
    workspacePath: "/workspace",
    scannedAt: "2026-08-11T20:00:00.000Z",
    durationMs: 25,
    packageManagers: dependencies.length === 0 ? [] : ["npm"],
    dependenciesScanned: dependencies.length,
    vulnerableDependencies:
      options.vulnerableDependencies ??
      new Set(
        vulnerabilities.map((entry) =>
          JSON.stringify([
            entry.ecosystem,
            entry.packageName,
            entry.installedVersion,
          ]),
        ),
      ).size,
    vulnerabilities,
    dependencies,
    errors: [],
    providerResults: [
      providerResult(
        options.providerStatus ?? "available",
        dependencies.length,
        options.providerVulnerabilitiesFound,
      ),
    ],
    cancelled: false,
  };
}

function severityRoots(
  model: ReturnType<typeof buildVulnerabilityTreeModel>,
): SeverityTreeNode[] {
  return model.roots.filter(
    (root): root is SeverityTreeNode => root.kind === "severity",
  );
}

void test("tree model distinguishes no-workspace and not-scanned states", () => {
  const noWorkspace = buildVulnerabilityTreeModel([], { hasWorkspace: false });
  const notScanned = buildVulnerabilityTreeModel([], { hasWorkspace: true });

  assert.equal(noWorkspace.roots.length, 1);
  assert.equal(noWorkspace.roots[0]?.label, "No workspace is open.");
  assert.equal(notScanned.roots[0]?.label, "No dependency scan results yet.");
});

void test("tree model reports a supported-dependency empty state", () => {
  const model = buildVulnerabilityTreeModel([scanResult()]);

  assert.equal(model.roots.length, 1);
  assert.equal(
    model.roots[0]?.label,
    "No supported dependency files were found.",
  );
});

void test("groups every supported severity in deterministic order", () => {
  const dependencies = [
    dependency("zeta"),
    dependency("alpha"),
    dependency("medium"),
    dependency("low"),
    dependency("unknown"),
  ];
  const vulnerabilities = [
    vulnerability("zeta", "CRITICAL", "CVE-Z"),
    vulnerability("alpha", "HIGH", "CVE-A"),
    vulnerability("medium", "MEDIUM", "CVE-M"),
    vulnerability("low", "LOW", "CVE-L"),
    vulnerability("unknown", "UNKNOWN", "OSV-U"),
  ];
  const model = buildVulnerabilityTreeModel([
    scanResult({ dependencies, vulnerabilities }),
  ]);
  const groups = severityRoots(model);

  assert.deepEqual(
    groups.map((group) => group.severity),
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
  );
  assert.deepEqual(
    groups.map((group) => group.count),
    [1, 1, 1, 1, 1],
  );
});

void test("sorts vulnerable dependencies and retains multiple vulnerabilities", () => {
  const dependencies = [dependency("zeta"), dependency("alpha")];
  const alphaOne = vulnerability("alpha", "HIGH", "CVE-2026-2");
  const alphaTwo: Vulnerability = {
    ...vulnerability("alpha", "HIGH", "OSV-ALPHA"),
    aliases: ["GHSA-aaaa-bbbb-cccc", "CVE-2026-1"],
    fixedVersion: "1.0.1",
  };
  const model = buildVulnerabilityTreeModel([
    scanResult({
      dependencies,
      vulnerabilities: [
        vulnerability("zeta", "HIGH", "CVE-2026-3"),
        alphaOne,
        alphaTwo,
      ],
    }),
  ]);
  const high = severityRoots(model)[0];
  assert.ok(high !== undefined);
  const dependencyNodes = high.children.filter(
    (child): child is DependencyTreeNode => child.kind === "dependency",
  );

  assert.deepEqual(
    dependencyNodes.map((child) => child.label),
    ["alpha@1.0.0", "zeta@1.0.0"],
  );
  const alpha = dependencyNodes[0];
  assert.ok(alpha !== undefined);
  const vulnerabilityNodes = alpha.children.filter(
    (child): child is VulnerabilityTreeNode => child.kind === "vulnerability",
  );
  assert.equal(vulnerabilityNodes.length, 2);
  const aliasedVulnerability = vulnerabilityNodes.find(
    (child) => child.label === "GHSA-aaaa-bbbb-cccc",
  );
  assert.ok(aliasedVulnerability !== undefined);
  assert.equal(
    aliasedVulnerability.children.some((child) => child.label === "Fixed: 1.0.1"),
    true,
  );
  assert.doesNotThrow(() => JSON.stringify(aliasedVulnerability.identity));
  assert.deepEqual(aliasedVulnerability.identity, {
    workspacePath: "/workspace",
    source: "OSV",
    vulnerabilityId: "OSV-ALPHA",
    ecosystem: "npm",
    packageName: "alpha",
    installedVersion: "1.0.0",
  });
  assert.equal(isVulnerabilityIdentity(aliasedVulnerability.identity), true);
});

void test("dependency details select its first deterministic vulnerability", () => {
  const model = buildVulnerabilityTreeModel([
    scanResult({
      dependencies: [dependency("example")],
      vulnerabilities: [
        vulnerability("example", "HIGH", "CVE-2026-9999"),
        vulnerability("example", "HIGH", "CVE-2026-0001"),
      ],
    }),
  ]);
  const high = severityRoots(model)[0];
  assert.ok(high !== undefined);
  const vulnerableDependency = high.children.find(
    (child): child is DependencyTreeNode => child.kind === "dependency",
  );
  assert.ok(vulnerableDependency !== undefined);

  assert.deepEqual(vulnerableDependency.detailsIdentity, {
    workspacePath: "/workspace",
    source: "OSV",
    vulnerabilityId: "CVE-2026-0001",
    ecosystem: "npm",
    packageName: "example",
    installedVersion: "1.0.0",
  });
  assert.equal(
    isVulnerabilityIdentity(vulnerableDependency.detailsIdentity),
    true,
  );
  assert.doesNotThrow(() =>
    JSON.stringify(vulnerableDependency.detailsIdentity),
  );
});

void test("shows the complete no-known-vulnerabilities count", () => {
  const model = buildVulnerabilityTreeModel([
    scanResult({
      dependencies: [dependency("one"), dependency("two")],
    }),
  ]);
  const information = model.roots.filter(
    (root): root is InformationTreeNode => root.kind === "information",
  );

  assert.equal(model.coverageComplete, true);
  assert.equal(model.noKnownVulnerabilitiesCount, 2);
  assert.equal(information.at(-1)?.label, "No Known Vulnerabilities (2)");
  assert.deepEqual(severityRoots(model), []);
});

void test("tree surfaces findings hidden by severity filtering without inflating clean dependencies", () => {
  const model = buildVulnerabilityTreeModel([
    scanResult({
      dependencies: [dependency("hidden-risk"), dependency("known-clean")],
      vulnerabilities: [],
      providerVulnerabilitiesFound: 2,
      vulnerableDependencies: 1,
    }),
  ]);

  assert.equal(model.coverageComplete, true);
  assert.equal(model.vulnerabilityCount, 0);
  assert.equal(model.suppressedVulnerabilityCount, 2);
  assert.equal(model.noKnownVulnerabilitiesCount, 1);
  assert.equal(
    model.roots.some(
      (root) =>
        root.label === "Known Findings Hidden by Severity Filter (2)",
    ),
    true,
  );
  assert.equal(model.roots.at(-1)?.label, "No Known Vulnerabilities (1)");
});

void test("provider failure is never presented as a clean result", () => {
  const failed = scanResult({
    dependencies: [dependency("unchecked")],
    providerStatus: "unavailable",
  });
  const model = buildVulnerabilityTreeModel([failed]);

  assert.equal(model.coverageComplete, false);
  assert.equal(model.roots[0]?.label, "Vulnerability database unavailable.");
  assert.equal(model.roots.at(-1)?.label, "Coverage Unconfirmed (1)");
  assert.equal(
    model.roots.some((root) => root.label.includes("No Known Vulnerabilities")),
    false,
  );
});

void test("latest unavailable coverage warns above retained prior results", () => {
  const priorComplete = scanResult({ dependencies: [dependency("previously-safe")] });
  const model = buildVulnerabilityTreeModel([priorComplete], {
    latestAttemptCoverage: "unavailable",
  });

  assert.equal(model.coverageComplete, false);
  assert.equal(model.roots[0]?.label, "Vulnerability database unavailable.");
  assert.equal(model.roots.at(-1)?.label, "Coverage Unconfirmed (1)");
});

void test("cancelled attempt replaces the empty not-scanned tree state", () => {
  const model = buildVulnerabilityTreeModel([], {
    latestAttemptCoverage: "cancelled",
  });

  assert.equal(model.coverageComplete, false);
  assert.equal(model.roots[0]?.label, "Dependency scan cancelled.");
  assert.equal(
    model.roots.some((root) => root.label.includes("not scanned")),
    false,
  );
});

void test("cancelled attempt preserves prior findings below its warning", () => {
  const priorResult = scanResult({
    dependencies: [dependency("retained")],
    vulnerabilities: [
      vulnerability("retained", "HIGH", "CVE-2026-RETAINED"),
    ],
  });
  const model = buildVulnerabilityTreeModel([priorResult], {
    latestAttemptCoverage: "cancelled",
  });

  assert.equal(model.roots[0]?.label, "Dependency scan cancelled.");
  assert.equal(
    severityRoots(model).some((group) => group.severity === "HIGH"),
    true,
  );
  assert.equal(model.roots.at(-1)?.label, "Coverage Unconfirmed (0)");
});

void test("tree separates last-complete findings from current partial counts and deduplicates overlap", () => {
  const oldOnly = vulnerability("old-only", "HIGH", "OSV-OLD");
  const overlap = vulnerability("current", "HIGH", "OSV-CURRENT");
  const retained = (
    vulnerabilityValue: Vulnerability,
  ): RetainedVulnerabilityFinding => ({
    vulnerability: vulnerabilityValue,
    dependencies: [
      dependency(
        vulnerabilityValue.packageName,
        vulnerabilityValue.installedVersion,
      ),
    ],
    workspacePaths: ["/workspace"],
    lastConfirmedAt: "2026-08-11T19:00:00.000Z",
  });
  const model = buildVulnerabilityTreeModel(
    [
      scanResult({
        dependencies: [dependency("current")],
        vulnerabilities: [overlap],
        providerStatus: "partial",
      }),
    ],
    {
      latestAttemptCoverage: "partial",
      retainedFindings: [retained(oldOnly), retained(overlap)],
    },
  );

  assert.equal(model.dependenciesScanned, 1);
  assert.equal(model.vulnerabilityCount, 1);
  assert.equal(model.retainedFindingCount, 1);
  const retainedRoot = model.roots.find(
    (root) => root.kind === "retained-findings",
  );
  assert.ok(retainedRoot !== undefined);
  assert.equal(retainedRoot.label, "Last Complete Scan Findings (1)");
  assert.equal(
    retainedRoot.description,
    "Not reconfirmed by the current incomplete scan",
  );
  const retainedSeverity = retainedRoot.children.find(
    (child): child is SeverityTreeNode => child.kind === "severity",
  );
  assert.equal(retainedSeverity?.count, 1);
  assert.equal(
    retainedSeverity?.children.find((child) => child.kind === "dependency")
      ?.label,
    "old-only@1.0.0",
  );
});

void test("tree rendering bounds add explicit omission nodes", () => {
  const dependencies = [dependency("a"), dependency("b")];
  const vulnerabilities = [
    vulnerability("a", "HIGH", "CVE-A-1"),
    vulnerability("a", "HIGH", "CVE-A-2"),
    vulnerability("b", "HIGH", "CVE-B-1"),
  ];
  const model = buildVulnerabilityTreeModel(
    [scanResult({ dependencies, vulnerabilities })],
    {
      maximumDependenciesPerSeverity: 1,
      maximumVulnerabilitiesPerDependency: 1,
    },
  );
  const high = severityRoots(model)[0];
  assert.ok(high !== undefined);
  const dependencyNode = high.children.find(
    (child): child is DependencyTreeNode => child.kind === "dependency",
  );

  assert.equal(high.count, 3);
  assert.equal(
    high.children.some(
      (child) =>
        child.kind === "information" && child.label.includes("additional vulnerable"),
    ),
    true,
  );
  assert.equal(
    dependencyNode?.children.some(
      (child) =>
        child.kind === "information" && child.label.includes("additional vulnerabilities"),
    ),
    true,
  );
});

void test("tree text is single-line and bounded for untrusted provider data", () => {
  const sanitized = sanitizeTreeText(
    "bad\u0000name\u0085\u009b\u2028\u2029\n<script>alert(1)</script>",
    24,
  );

  assert.equal(
    /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u.test(sanitized),
    false,
  );
  assert.equal(sanitized.length <= 24, true);
});

void test("tree text strips bidirectional override and isolation controls", () => {
  const sanitized = sanitizeTreeText(
    "safe\u202amalicious\u202c-middle\u2066isolated\u2069-end",
  );

  assert.equal(sanitized, "safemalicious-middleisolated-end");
  assert.equal(/[\u202a-\u202e\u2066-\u2069]/u.test(sanitized), false);
});
