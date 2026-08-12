import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { Dependency } from "../models/Dependency";
import type { ScanResult } from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";
import type {
  RemediationAnalysisResult,
  RemediationRecommendation,
} from "../remediation/RemediationModels";
import { buildDependencyStatusModel } from "../status/statusModel";
import { buildVulnerabilityTreeModel } from "../tree/treeModel";
import { renderDashboardDocument } from "../webview/dashboardRenderer";
import {
  renderVulnerabilityDetailsDocument,
  selectRemediationApplyView,
  type ResolvedVulnerabilityDetails,
} from "../webview/vulnerabilityDetailsRenderer";
import type {
  RemediationApplySnapshot,
  RemediationCapability,
  RemediationHistoryRecordView,
} from "../webview/webviewTypes";

const NONCE = "0123456789abcdef0123456789abcdef";
const DETAILS_SCRIPT = "vscode-webview://test/media/details.js";
const DASHBOARD_SCRIPT = "vscode-webview://test/media/dashboard.js";

const dependency: Dependency = {
  name: "lodash",
  ecosystem: "npm",
  requestedVersion: "^4.17.20",
  installedVersion: "4.17.20",
  resolutionStatus: "resolved",
  dependencyType: "direct",
  environment: "production",
  dependencyPath: ["sample", "lodash@4.17.20"],
  manifestPath: "C:\\work\\sample\\package.json",
  lockfilePath: "C:\\work\\sample\\package-lock.json",
  packageManager: "npm",
  projectPath: "C:\\work\\sample",
  workspacePath: "C:\\work\\sample",
};

const vulnerability: Vulnerability = {
  id: "GHSA-test",
  aliases: [],
  packageName: "lodash",
  ecosystem: "npm",
  installedVersion: "4.17.20",
  severity: "HIGH",
  summary: "A deterministic fixture vulnerability.",
  fixedVersions: ["4.17.21"],
  remediationCandidates: ["4.17.21"],
  fixedVersion: "4.17.21",
  references: ["https://osv.dev/vulnerability/GHSA-test"],
  source: "OSV",
};

const recommendation: RemediationRecommendation = {
  recommendationKey: "opaque-recommendation-key",
  vulnerabilityId: vulnerability.id,
  vulnerabilityIds: [vulnerability.id],
  dependency,
  currentVersion: dependency.installedVersion,
  recommendedVersion: "4.17.21",
  fixedVersions: ["4.17.21"],
  strategy: "upgrade-direct",
  confidence: "high",
  dependencyPath: dependency.dependencyPath ?? [],
  directDependency: true,
  breakingChangeRisk: "low",
  reason: "A provider-listed candidate is available.",
  evidence: [{ source: "osv", description: "Fixed in 4.17.21." }],
};

const analysis: RemediationAnalysisResult = {
  recommendations: [recommendation],
  remediable: [recommendation],
  noFix: [],
  manualReview: [],
  unresolved: [],
  summary: {
    totalVulnerabilities: 1,
    remediable: 1,
    noKnownFix: 0,
    manualReview: 0,
    unresolved: 0,
    remediationCoveragePercent: 100,
    analysisComplete: true,
  },
};

const scanResult: ScanResult = {
  workspacePath: "C:\\work\\sample",
  scannedAt: "2026-08-12T09:00:00.000Z",
  durationMs: 10,
  packageManagers: ["npm"],
  dependenciesScanned: 1,
  vulnerableDependencies: 1,
  vulnerabilities: [vulnerability],
  dependencies: [dependency],
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
  cancelled: false,
};

function details(
  snapshot: RemediationApplySnapshot,
): ResolvedVulnerabilityDetails {
  const remediationApply = selectRemediationApplyView(
    recommendation,
    snapshot,
  );
  assert.ok(remediationApply !== undefined);
  return {
    scanResult,
    vulnerability,
    dependencies: [dependency],
    retainedFromLastComplete: false,
    remediation: recommendation,
    remediationApply,
  };
}

function snapshot(
  capability: RemediationCapability,
  overrides: Partial<RemediationApplySnapshot> = {},
): RemediationApplySnapshot {
  return {
    capabilities: [
      {
        recommendationKey: recommendation.recommendationKey,
        capability,
        reason:
          capability === "safe"
            ? "A minimal npm manifest and lockfile edit is established."
            : "Package-manager resolution or manual review is required.",
      },
    ],
    history: [],
    ...overrides,
  };
}

function historyRecord(
  overrides: Partial<RemediationHistoryRecordView> = {},
): RemediationHistoryRecordView {
  return {
    id: "history-1",
    recommendationKey: recommendation.recommendationKey,
    packageName: "lodash",
    currentVersion: "4.17.20",
    recommendedVersion: "4.17.21",
    status: "partial",
    vulnerabilitiesResolved: 2,
    vulnerabilitiesRemaining: 1,
    rolledBack: false,
    message: "Two targeted vulnerabilities were resolved; one remains.",
    timestamp: "2026-08-12T09:20:00.000Z",
    before: {
      dependencies: 120,
      vulnerabilities: 5,
      critical: 1,
      high: 3,
      medium: 1,
      low: 0,
    },
    after: {
      dependencies: 120,
      vulnerabilities: 3,
      critical: 0,
      high: 2,
      medium: 1,
      low: 0,
    },
    ...overrides,
  };
}

void test("details exposes review states but never Apply Fix before a valid preview", () => {
  const safe = renderVulnerabilityDetailsDocument(
    details(snapshot("safe")),
    NONCE,
    DETAILS_SCRIPT,
  );
  assert.match(safe, /data-remediation-action="preview">Review Fix/u);
  assert.doesNotMatch(safe, /data-remediation-action="apply"/u);

  const previewOnly = renderVulnerabilityDetailsDocument(
    details(snapshot("preview-only")),
    NONCE,
    DETAILS_SCRIPT,
  );
  assert.match(previewOnly, /Review Remediation/u);
  assert.doesNotMatch(previewOnly, /Apply Fix/u);

  const unsupported = renderVulnerabilityDetailsDocument(
    details(snapshot("unsupported")),
    NONCE,
    DETAILS_SCRIPT,
  );
  assert.match(unsupported, /Manual Review/u);
  assert.doesNotMatch(unsupported, /data-remediation-action="preview"/u);
});

void test("details renders an actual bounded unified diff and enables explicit apply only for a valid safe preview", () => {
  const preview = {
    id: "opaque-preview-token",
    recommendationKey: recommendation.recommendationKey,
    capability: "safe" as const,
    packageName: "lodash",
    currentVersion: "4.17.20",
    recommendedVersion: "4.17.21",
    confidence: "high" as const,
    vulnerabilitiesAddressed: 3,
    totalVulnerabilities: 3,
    files: [
      {
        displayPath: "package.json",
        description: "Minimal range-preserving remediation.",
        beforeHash: "a".repeat(64),
        afterHash: "b".repeat(64),
        unifiedDiff:
          "--- package.json\n+++ package.json\n@@ -1 +1 @@\n- \"lodash\": \"^4.17.20\"\n+ \"lodash\": \"^4.17.21\"",
      },
    ],
    warnings: [],
    valid: true,
    createdAt: "2026-08-12T09:10:00.000Z",
  };
  const html = renderVulnerabilityDetailsDocument(
    details(
      snapshot("safe", {
        preview,
        lifecycles: [
          {
            remediationId: preview.id,
            recommendationKey: recommendation.recommendationKey,
            state: "approved",
            createdAt: preview.createdAt,
            updatedAt: preview.createdAt,
            transitions: [
              {
                sequence: 1,
                to: "preview",
                reason: "proposal-created",
                timestamp: preview.createdAt,
              },
              {
                sequence: 2,
                from: "preview",
                to: "awaitingApproval",
                reason: "approval-requested",
                timestamp: preview.createdAt,
              },
              {
                sequence: 3,
                from: "awaitingApproval",
                to: "approved",
                reason: "user-approved",
                timestamp: preview.createdAt,
              },
            ],
          },
        ],
      }),
    ),
    NONCE,
    DETAILS_SCRIPT,
  );
  assert.match(html, /Dependency Fix Preview/u);
  assert.match(html, /--- package\.json/u);
  assert.match(html, /\+\+\+ package\.json/u);
  assert.match(html, /\^4\.17\.20/u);
  assert.match(html, /\^4\.17\.21/u);
  assert.match(html, /Before SHA-256/u);
  assert.match(html, /data-remediation-action="cancel"/u);
  assert.match(html, /data-remediation-action="apply">Apply Fix/u);
  assert.match(html, /data-remediation-action="viewDiff"/u);

  const invalid = renderVulnerabilityDetailsDocument(
    details(snapshot("safe", { preview: { ...preview, valid: false } })),
    NONCE,
    DETAILS_SCRIPT,
  );
  assert.match(invalid, /preview is no longer valid/u);
  assert.doesNotMatch(invalid, /data-remediation-action="apply"/u);

  const awaiting = renderVulnerabilityDetailsDocument(
    details(
      snapshot("safe", {
        preview,
        lifecycles: [
          {
            remediationId: preview.id,
            recommendationKey: recommendation.recommendationKey,
            state: "awaitingApproval",
            createdAt: preview.createdAt,
            updatedAt: preview.createdAt,
            transitions: [
              {
                sequence: 1,
                to: "preview",
                reason: "proposal-created",
                timestamp: preview.createdAt,
              },
              {
                sequence: 2,
                from: "preview",
                to: "awaitingApproval",
                reason: "approval-requested",
                timestamp: preview.createdAt,
              },
            ],
          },
        ],
      }),
    ),
    NONCE,
    DETAILS_SCRIPT,
  );
  assert.match(awaiting, /data-remediation-action="approve">Approve Fix/u);
  assert.doesNotMatch(awaiting, /data-remediation-action="apply"/u);
});

void test("preview diff, warnings, paths, and history neutralize HTML, ANSI, and bidi payloads", () => {
  const payload = '</code><script>alert(1)</script>\u001b[31m\u202E';
  const lastResult = historyRecord({
    packageName: payload,
    message: payload,
    status: "failed",
    rolledBack: true,
    rollbackVerified: false,
  });
  const html = renderVulnerabilityDetailsDocument(
    details(
      snapshot("safe", {
        preview: {
          id: "preview",
          recommendationKey: recommendation.recommendationKey,
          capability: "safe",
          packageName: payload,
          currentVersion: "4.17.20",
          recommendedVersion: "4.17.21",
          confidence: "high",
          vulnerabilitiesAddressed: 1,
          totalVulnerabilities: 1,
          files: [
            {
              displayPath: payload,
              description: payload,
              beforeHash: "a".repeat(64),
              unifiedDiff: `--- package.json\n+${payload}`,
            },
          ],
          warnings: [payload],
          valid: true,
          createdAt: "2026-08-12T09:10:00.000Z",
        },
        history: [lastResult],
        lastResult,
      }),
    ),
    NONCE,
    DETAILS_SCRIPT,
  );
  assert.doesNotMatch(html, /<script>alert/u);
  assert.doesNotMatch(html, /\u001b|\u202E/u);
  assert.match(html, /&lt;script&gt;alert/u);
  assert.match(html, /rollback could not be fully verified/u);
  assert.match(html, /default-src 'none'/u);
  assert.doesNotMatch(html, /onclick=|eval\(|new Function/u);
});

void test("capability selection fails closed for absent or conflicting structural records", () => {
  assert.equal(selectRemediationApplyView(recommendation, undefined), undefined);
  assert.equal(
    selectRemediationApplyView(
      recommendation,
      snapshot("safe", {
        capabilities: [
          {
            recommendationKey: recommendation.recommendationKey,
            capability: "safe",
            reason: "safe",
          },
          {
            recommendationKey: recommendation.recommendationKey,
            capability: "preview-only",
            reason: "conflict",
          },
        ],
      }),
    ),
    undefined,
  );
});

void test("dashboard shows review actions, session history, and actual partial before/after results", () => {
  const lastResult = historyRecord();
  const html = renderDashboardDocument(
    {
      workspaceOpen: true,
      scanResults: [scanResult],
      remediationAnalysis: analysis,
      remediationApply: snapshot("safe", {
        history: [lastResult],
        lastResult,
      }),
    },
    NONCE,
    DASHBOARD_SCRIPT,
  );
  assert.match(html, /Remediation actions/u);
  assert.match(html, /1 fix available/u);
  assert.match(html, /data-action="reviewFixes">Review Fixes/u);
  assert.match(html, /Session remediation history \(1\)/u);
  assert.match(html, /Partial remediation/u);
  assert.match(html, /Before/u);
  assert.match(html, /120 dependencies · 5 vulnerabilities/u);
  assert.match(html, /After/u);
  assert.match(html, /120 dependencies · 3 vulnerabilities/u);
  assert.doesNotMatch(html, /Everything fixed|fully fixed|automatically fixed/iu);
});

void test("tree and status consume capability and transaction state without performing remediation logic", () => {
  const safeSnapshot = snapshot("safe");
  const safeTree = buildVulnerabilityTreeModel([scanResult], {
    remediationAnalysis: analysis,
    remediationApply: safeSnapshot,
  });
  assert.match(JSON.stringify(safeTree.roots), /Remediation available/u);

  const previewTree = buildVulnerabilityTreeModel([scanResult], {
    remediationAnalysis: analysis,
    remediationApply: snapshot("preview-only"),
  });
  assert.match(JSON.stringify(previewTree.roots), /Review remediation/u);

  const manualTree = buildVulnerabilityTreeModel([scanResult], {
    remediationAnalysis: analysis,
    remediationApply: snapshot("unsupported"),
  });
  assert.match(JSON.stringify(manualTree.roots), /Manual review required/u);

  const validating = buildDependencyStatusModel([scanResult], false, {
    remediationAnalysis: analysis,
    remediationApply: snapshot("safe", {
      activeOperation: {
        stage: "validating",
        recommendationKey: recommendation.recommendationKey,
        previewId: "opaque-preview-token",
        message: "Validating generated metadata.",
        cancellable: true,
      },
    }),
  });
  assert.match(validating.text, /validating remediation/u);
  assert.match(validating.tooltip, /user-initiated remediation/u);

  const failed = historyRecord({
    status: "failed",
    rolledBack: true,
    rollbackVerified: true,
  });
  const rolledBack = buildDependencyStatusModel([scanResult], false, {
    remediationApply: snapshot("safe", {
      history: [failed],
      lastResult: failed,
    }),
  });
  assert.match(rolledBack.text, /remediation rolled back/u);
  assert.doesNotMatch(rolledBack.text, /fixed|secure/iu);
});
