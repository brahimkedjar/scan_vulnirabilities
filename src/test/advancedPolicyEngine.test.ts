import assert from "node:assert/strict";
import { test } from "node:test";

import type { LicenseInventory } from "../core/license/LicenseIntelligence";
import {
  AdvancedPolicyEngine,
  advancedPolicyFindingKey,
  type AdvancedSecurityPolicy,
} from "../core/policy";
import type { ProvenanceAnalysisResult } from "../core/provenance/ProvenanceIntelligence";
import type { StaticReachabilityResult } from "../core/reachability/StaticReachability";
import type { ScanResult } from "../models/ScanResult";

function scan(
  severity: "LOW" | "HIGH" | "CRITICAL" = "CRITICAL",
  incomplete = false,
): ScanResult {
  return {
    workspacePath: "workspace",
    scannedAt: "2026-08-13T12:00:00.000Z",
    durationMs: 1,
    packageManagers: ["npm"],
    dependenciesScanned: 1,
    vulnerableDependencies: 1,
    vulnerabilities: [],
    unfilteredVulnerabilities: [
      {
        id: "CVE-2026-1000",
        aliases: [],
        packageName: "fixture-package",
        ecosystem: "npm",
        installedVersion: "1.0.0",
        severity,
        summary: "fixture",
        references: [],
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
        packageManager: "npm",
      },
    ],
    errors: incomplete
      ? [{ code: "PROVIDER_ERROR", message: "provider unavailable" }]
      : [],
    providerResults: [
      {
        provider: "OSV",
        status: incomplete ? "unavailable" : "available",
        dependenciesEligible: 1,
        dependenciesSubmitted: 1,
        successful: incomplete ? 0 : 1,
        failed: incomplete ? 1 : 0,
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
        checked: incomplete ? 0 : 1,
        vulnerable: 1,
        unresolved: 0,
        unsupported: 0,
      },
    ],
    cancelled: false,
  };
}

function policy(overrides: Partial<AdvancedSecurityPolicy> = {}): AdvancedSecurityPolicy {
  return { schemaVersion: 1, vulnerability: {}, ...overrides };
}

function licenseInventory(outcome: "ALLOWED" | "DENIED" | "REVIEW_REQUIRED" | "UNKNOWN"): LicenseInventory {
  return {
    entries: [
      {
        dependencyId: "fixture",
        name: "fixture-package",
        ecosystem: "npm",
        version: "1.0.0",
        dependencyType: "direct",
        detectionStatus: outcome === "UNKNOWN" ? "UNKNOWN" : "DECLARED",
        declaredLicenses: outcome === "UNKNOWN" ? [] : ["GPL-3.0"],
        normalizedExpressions: outcome === "UNKNOWN" ? [] : ["GPL-3.0-only"],
        identifiers: outcome === "UNKNOWN" ? [] : ["GPL-3.0-only"],
        dependencyPath: [],
        finding: {
          outcome,
          reason: "fixture policy outcome",
          authoritative: false,
        },
        limitations: [],
      },
    ],
    coverage: {
      totalRecords: 1,
      processedRecords: 1,
      knownLicenseRecords: outcome === "UNKNOWN" ? 0 : 1,
      unknownLicenseRecords: outcome === "UNKNOWN" ? 1 : 0,
      omittedRecords: 0,
      truncated: false,
      cancelled: false,
      analysisComplete: true,
      policyValid: true,
    },
  };
}

function provenance(status: "SAFE" | "KNOWN" | "SUSPICIOUS" | "UNKNOWN"): ProvenanceAnalysisResult {
  const anomaly = {
    signal: "INTEGRITY_MISMATCH" as const,
    evidence: "Declared digest did not match explicit verification evidence.",
    confidence: "HIGH" as const,
    limitations: ["No malware verdict."],
    securityVerdict: "NOT_ESTABLISHED" as const,
  };
  return {
    packages: [
      {
        dependencyId: "fixture",
        packageName: "fixture-package",
        ecosystem: "npm",
        version: "1.0.0",
        status,
        sourceKind: "registry",
        registryCanonical: true,
        integrityState: status === "SAFE" ? "VERIFIED" : "UNKNOWN",
        explicitFields: [],
        anomalies: status === "SUSPICIOUS" ? [anomaly] : [],
        limitations: [],
        malicious: "NOT_DETERMINED",
      },
    ],
    anomalies: status === "SUSPICIOUS" ? [anomaly] : [],
    coverage: {
      totalRecords: 1,
      processedRecords: 1,
      omittedRecords: 0,
      safeRecords: status === "SAFE" ? 1 : 0,
      knownRecords: status === "KNOWN" ? 1 : 0,
      suspiciousRecords: status === "SUSPICIOUS" ? 1 : 0,
      unknownRecords: status === "UNKNOWN" ? 1 : 0,
      truncated: false,
      cancelled: false,
      analysisComplete: true,
    },
  };
}

function reachability(
  status: "REACHABLE" | "NOT_OBSERVED" | "UNKNOWN",
  findingKey: string,
): StaticReachabilityResult {
  return {
    findings: [
      {
        targetId: findingKey,
        ecosystem: "npm",
        packageName: "fixture-package",
        affectedSymbols: [],
        status,
        confidence: status === "REACHABLE" ? "HIGH" : "LOW",
        path: status === "REACHABLE" ? ["src/index.ts", "fixture-package"] : [],
        evidence: "bounded fixture evidence",
        limitations: ["Exploitability is not established."],
        exploitability: "NOT_ESTABLISHED",
      },
    ],
    coverage: {
      sourceFilesTotal: 1,
      sourceFilesAnalyzed: 1,
      sourceFilesInvalid: 0,
      sourceFilesOmitted: 0,
      bytesAnalyzed: 10,
      targetsTotal: 1,
      targetsAnalyzed: 1,
      entrypointsResolved: 1,
      importEdgesObserved: 1,
      uncertainReachableFiles: 0,
      truncated: false,
      cancelled: false,
      analysisComplete: true,
    },
  };
}

void test("passes a complete scan when every configured advanced evidence rule passes", () => {
  const current = scan("LOW");
  const finding = current.unfilteredVulnerabilities?.[0];
  assert.ok(finding !== undefined);
  const result = new AdvancedPolicyEngine({ clock: () => Date.parse("2026-08-13T12:01:00Z") }).evaluate(
    [current],
    policy({
      requireCompleteCoverage: true,
      minimumCoveragePercent: 100,
      failOnKnownExploited: true,
      minimumReachableSeverity: "HIGH",
      failOnDeniedLicense: true,
      failOnSuspiciousProvenance: true,
      minimumProviderConfidence: "MEDIUM",
    }),
    {
      findingIntelligence: [
        {
          advisoryId: finding.id,
          ecosystem: finding.ecosystem,
          packageName: finding.packageName,
          installedVersion: finding.installedVersion,
          knownExploitation: "not-known-exploited",
        },
      ],
      licenses: licenseInventory("ALLOWED"),
      provenance: provenance("SAFE"),
      providerConfidence: "HIGH",
    },
  );
  assert.equal(result.status, "PASS");
  assert.equal(result.complete, true);
  assert.deepEqual(result.reasons, []);
  assert.equal(result.summary.coveragePercent, 100);
});

void test("fails closed for incomplete coverage and missing known-exploitation evidence", () => {
  const result = new AdvancedPolicyEngine().evaluate(
    [scan("HIGH", true)],
    policy({ requireCompleteCoverage: true, failOnKnownExploited: true }),
  );
  assert.equal(result.status, "FAIL");
  assert.equal(result.complete, false);
  assert.ok(result.reasons.some((reason) => reason.code === "SCAN_INCOMPLETE"));
  assert.ok(
    result.reasons.some(
      (reason) => reason.code === "KNOWN_EXPLOITATION_UNKNOWN",
    ),
  );
});

void test("fails a known-exploited finding deterministically", () => {
  const current = scan("HIGH");
  const finding = current.unfilteredVulnerabilities?.[0];
  assert.ok(finding !== undefined);
  const result = new AdvancedPolicyEngine().evaluate(
    [current],
    policy({ failOnKnownExploited: true }),
    {
      findingIntelligence: [
        {
          advisoryId: finding.id,
          ecosystem: finding.ecosystem,
          packageName: finding.packageName,
          installedVersion: finding.installedVersion,
          knownExploitation: "known-exploited",
        },
      ],
    },
  );
  assert.equal(result.status, "FAIL");
  assert.equal(result.complete, true);
  assert.equal(result.summary.knownExploited, 1);
});

void test("uses exact stable finding identity for static reachability gates", () => {
  const current = scan("CRITICAL");
  const finding = current.unfilteredVulnerabilities?.[0];
  assert.ok(finding !== undefined);
  const key = advancedPolicyFindingKey(finding);
  const result = new AdvancedPolicyEngine().evaluate(
    [current],
    policy({
      minimumReachableSeverity: "CRITICAL",
      unknownReachability: "fail",
    }),
    { reachability: reachability("REACHABLE", key) },
  );
  assert.equal(result.status, "FAIL");
  assert.equal(result.summary.reachableFindings, 1);
  assert.ok(
    result.reasons.some((reason) => reason.code === "REACHABLE_VULNERABILITY"),
  );

  const wrongOrigin = new AdvancedPolicyEngine().evaluate(
    [current],
    policy({ minimumReachableSeverity: "CRITICAL", unknownReachability: "warn" }),
    { reachability: reachability("REACHABLE", "another-finding") },
  );
  assert.equal(wrongOrigin.status, "WARN");
  assert.ok(
    wrongOrigin.reasons.some((reason) => reason.code === "REACHABILITY_UNKNOWN"),
  );
});

void test("evaluates license, provenance, and configured anomaly evidence without malware claims", () => {
  const result = new AdvancedPolicyEngine().evaluate(
    [scan("LOW")],
    policy({
      failOnDeniedLicense: true,
      failOnSuspiciousProvenance: true,
      failOnAnomalySignals: ["INTEGRITY_MISMATCH"],
    }),
    {
      licenses: licenseInventory("DENIED"),
      provenance: provenance("SUSPICIOUS"),
    },
  );
  assert.equal(result.status, "FAIL");
  assert.equal(result.summary.deniedLicenses, 1);
  assert.equal(result.summary.suspiciousProvenance, 1);
  assert.equal(result.summary.anomalySignals, 1);
  assert.ok(result.reasons.some((reason) => reason.code === "LICENSE_DENIED"));
  assert.ok(
    result.reasons.some((reason) => reason.code === "PROVENANCE_SUSPICIOUS"),
  );
  assert.ok(
    result.reasons.some((reason) => reason.code === "SUPPLY_CHAIN_ANOMALY"),
  );
  assert.ok(result.reasons.every((reason) => !/malicious/iu.test(reason.message)));
});

void test("fails configured dependency scope, provider confidence, and unsupported EPSS", () => {
  const result = new AdvancedPolicyEngine().evaluate(
    [scan("LOW")],
    policy({
      deniedDependencyTypes: ["direct"],
      deniedEnvironments: ["production"],
      deniedPackageManagers: ["npm"],
      deniedEcosystems: ["npm"],
      minimumProviderConfidence: "HIGH",
      requireEpssEvidence: true,
    }),
    { providerConfidence: "LOW" },
  );
  assert.equal(result.status, "FAIL");
  assert.deepEqual(
    new Set(result.reasons.map((reason) => reason.code)),
    new Set([
      "DEPENDENCY_TYPE_DENIED",
      "ENVIRONMENT_DENIED",
      "PACKAGE_MANAGER_DENIED",
      "ECOSYSTEM_DENIED",
      "PROVIDER_CONFIDENCE_INSUFFICIENT",
      "EPSS_NOT_CONFIGURED",
    ]),
  );
  assert.equal(result.complete, false);
});

void test("invalid policies, evidence limits, and cancellation fail closed", () => {
  const invalid = new AdvancedPolicyEngine().evaluate(
    [scan()],
    { schemaVersion: 1, unknownReachability: "ignore" },
  );
  assert.equal(invalid.status, "FAIL");
  assert.equal(invalid.policyValid, false);
  assert.ok(invalid.reasons.some((reason) => reason.code === "POLICY_INVALID"));

  const limited = new AdvancedPolicyEngine({ maximumEvidenceRecords: 1 }).evaluate(
    [scan()],
    policy({ failOnKnownExploited: true }),
    {
      findingIntelligence: [
        {
          advisoryId: "one",
          ecosystem: "npm",
          packageName: "one",
          installedVersion: "1",
          knownExploitation: "unknown",
        },
        {
          advisoryId: "two",
          ecosystem: "npm",
          packageName: "two",
          installedVersion: "1",
          knownExploitation: "unknown",
        },
      ],
    },
  );
  assert.ok(
    limited.reasons.some((reason) => reason.code === "EVIDENCE_LIMIT_EXCEEDED"),
  );
  assert.equal(limited.complete, false);

  const controller = new AbortController();
  controller.abort();
  const cancelled = new AdvancedPolicyEngine().evaluate(
    [scan()],
    policy(),
    { signal: controller.signal },
  );
  assert.equal(cancelled.cancelled, true);
  assert.equal(cancelled.status, "FAIL");
  assert.equal(cancelled.complete, false);
});

