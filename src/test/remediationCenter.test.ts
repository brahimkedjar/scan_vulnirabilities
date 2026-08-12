import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { Dependency } from "../models/Dependency";
import type { ScanResult } from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";
import type {
  RemediationAnalysisResult,
  RemediationRecommendation,
} from "../remediation/RemediationModels";
import {
  buildRemediationCenterRows,
  renderRemediationCenterDocument,
} from "../webview/remediationCenterRenderer";
import type {
  RemediationApplySnapshot,
  RemediationLifecycleState,
} from "../webview/webviewTypes";

const NONCE = "0123456789abcdef0123456789abcdef";
const SCRIPT = "vscode-webview://test/media/remediation-center.js";

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
  summary: "fixture",
  fixedVersion: "4.17.21",
  fixedVersions: ["4.17.21"],
  remediationCandidates: ["4.17.21"],
  references: [],
  source: "OSV",
};

const recommendation: RemediationRecommendation = {
  recommendationKey: "recommendation-key",
  vulnerabilityId: "GHSA-test",
  vulnerabilityIds: ["GHSA-test"],
  dependency,
  currentVersion: "4.17.20",
  recommendedVersion: "4.17.21",
  fixedVersions: ["4.17.21"],
  strategy: "upgrade-direct",
  confidence: "high",
  dependencyPath: dependency.dependencyPath ?? [],
  directDependency: true,
  breakingChangeRisk: "low",
  reason: "Provider evidence\u202e lists an exact target.",
  evidence: [{ source: "osv", description: "Fixed in 4.17.21.\u001b[31m" }],
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

const scan: ScanResult = {
  workspacePath: "C:\\work\\sample",
  scannedAt: "2026-08-12T12:00:00.000Z",
  durationMs: 1,
  packageManagers: ["npm"],
  dependenciesScanned: 1,
  vulnerableDependencies: 1,
  vulnerabilities: [vulnerability],
  dependencies: [dependency],
  errors: [],
  providerResults: [],
  cancelled: false,
};

function snapshot(
  capability: "safe" | "preview-only" | "unsupported",
  state: RemediationLifecycleState,
): RemediationApplySnapshot {
  return {
    capabilities: [
      {
        recommendationKey: recommendation.recommendationKey,
        capability,
        reason: "Capability is bounded by the host replacement primitive.",
      },
    ],
    preview: {
      id: "a".repeat(43),
      recommendationKey: recommendation.recommendationKey,
      capability,
      packageName: "lodash",
      currentVersion: "4.17.20",
      recommendedVersion: "4.17.21",
      confidence: "high",
      vulnerabilitiesAddressed: 1,
      totalVulnerabilities: 1,
      files: [
        {
          displayPath: "package.json",
          description: "Minimal JSONC edit.",
          beforeHash: "b".repeat(64),
          afterHash: "c".repeat(64),
          unifiedDiff: "--- package.json\n+++ package.json\n- old\n+ new\n",
          gitState: "clean",
        },
      ],
      warnings: ["No workspace write has occurred."],
      valid: true,
      createdAt: "2026-08-12T12:01:00.000Z",
    },
    lifecycles: [
      {
        remediationId: "a".repeat(43),
        recommendationKey: recommendation.recommendationKey,
        state,
        createdAt: "2026-08-12T12:01:00.000Z",
        updatedAt: "2026-08-12T12:01:01.000Z",
        transitions: [
          {
            sequence: 1,
            to: "preview",
            reason: "proposal-created",
            timestamp: "2026-08-12T12:01:00.000Z",
          },
          {
            sequence: 2,
            from: "preview",
            to: state,
            reason:
              state === "awaitingApproval"
                ? "approval-requested"
                : state === "manualActionRequired"
                  ? "manual-action-required"
                  : "manual-review-required",
            timestamp: "2026-08-12T12:01:01.000Z",
          },
        ],
      },
    ],
    history: [],
  };
}

void test("dedicated remediation center renders real preview evidence and production refusal", () => {
  const state = snapshot("preview-only", "manualActionRequired");
  const rows = buildRemediationCenterRows([scan], analysis, state);
  const html = renderRemediationCenterDocument(
    {
      workspaceOpen: true,
      rows,
      analysisComplete: true,
      productionApplyAvailable: false,
    },
    NONCE,
    SCRIPT,
  );
  assert.match(html, /Production Apply is unavailable in this build/u);
  assert.match(html, /lodash/u);
  assert.match(html, /GHSA-test/u);
  assert.match(html, /This change has NOT been applied/u);
  assert.match(html, /--- package\.json/u);
  assert.match(html, /Git: <strong>clean<\/strong> \(advisory only\)/u);
  assert.match(html, /manualActionRequired/u);
  assert.match(html, /data-remediation-center-action="copyPatch"/u);
  assert.match(html, /data-remediation-center-action="openFile"/u);
  assert.match(html, /data-remediation-center-action="viewDiff"/u);
  assert.match(html, /data-remediation-center-action="rescan"/u);
  assert.doesNotMatch(html, /data-remediation-center-action="approve"/u);
  assert.doesNotMatch(html, /data-remediation-center-action="apply"/u);
  assert.doesNotMatch(html, /\u202e|\u001b/u);
  assert.match(
    html,
    /default-src &#39;none&#39;|default-src 'none'/u,
  );
});

void test("approval and apply buttons follow the explicit lifecycle", () => {
  const awaiting = snapshot("safe", "awaitingApproval");
  const awaitingHtml = renderRemediationCenterDocument(
    {
      workspaceOpen: true,
      rows: buildRemediationCenterRows([scan], analysis, awaiting),
      analysisComplete: true,
      productionApplyAvailable: true,
    },
    NONCE,
    SCRIPT,
  );
  assert.match(awaitingHtml, /data-remediation-center-action="approve"/u);
  assert.doesNotMatch(awaitingHtml, /data-remediation-center-action="apply"/u);

  const approved = snapshot("safe", "approved");
  const approvedHtml = renderRemediationCenterDocument(
    {
      workspaceOpen: true,
      rows: buildRemediationCenterRows([scan], analysis, approved),
      analysisComplete: true,
      productionApplyAvailable: true,
    },
    NONCE,
    SCRIPT,
  );
  assert.doesNotMatch(approvedHtml, /data-remediation-center-action="approve"/u);
  assert.match(approvedHtml, /data-remediation-center-action="apply"/u);
});

void test("conflicting capability records fail closed", () => {
  const state = snapshot("safe", "awaitingApproval");
  const rows = buildRemediationCenterRows([scan], analysis, {
    ...state,
    capabilities: [
      ...state.capabilities,
      {
        recommendationKey: recommendation.recommendationKey,
        capability: "safe",
        reason: "duplicate",
      },
    ],
  });
  assert.equal(rows[0]?.capability.capability, "unsupported");
});
