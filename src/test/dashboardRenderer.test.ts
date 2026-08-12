import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { ScanResult } from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";
import type { RemediationAnalysisResult } from "../remediation/RemediationModels";
import type { RetainedVulnerabilityFinding } from "../services/ScanResultStore";
import {
  calculateDependencyRiskScore,
  DEPENDENCY_RISK_FORMULA,
  renderDashboardDocument,
  summarizeScanResults,
} from "../webview/dashboardRenderer";

const NONCE = "0123456789abcdef0123456789abcdef";
const SCRIPT_URI = "vscode-webview://test/media/dashboard.js";

function vulnerability(
  severity: Vulnerability["severity"],
  packageName = "example-package",
  installedVersion = "1.0.0",
): Vulnerability {
  return {
    id: `OSV-${severity}`,
    aliases: [],
    packageName,
    ecosystem: "npm",
    installedVersion,
    severity,
    summary: "A deterministic test vulnerability",
    references: ["https://osv.dev/vulnerability/OSV-TEST"],
    source: "OSV",
  };
}

function result(
  overrides: Partial<ScanResult> = {},
): ScanResult {
  return {
    workspacePath: "C:\\work\\sample-project",
    scannedAt: "2026-08-11T20:30:00.000Z",
    durationMs: 50,
    packageManagers: ["npm"],
    dependenciesScanned: 10,
    vulnerableDependencies: 0,
    vulnerabilities: [],
    dependencies: [],
    errors: [],
    providerResults: [
      {
        provider: "OSV",
        status: "available",
        dependenciesEligible: 10,
        dependenciesSubmitted: 10,
        successful: 10,
        failed: 0,
        cacheHits: 2,
        staleCacheFallbacks: 0,
        vulnerabilitiesFound: 0,
      },
    ],
    cancelled: false,
    ...overrides,
  };
}

function remediationAnalysis(
  overrides: Partial<RemediationAnalysisResult["summary"]> = {},
): RemediationAnalysisResult {
  return {
    recommendations: [],
    remediable: [],
    noFix: [],
    manualReview: [],
    unresolved: [],
    summary: {
      totalVulnerabilities: 5,
      remediable: 3,
      noKnownFix: 1,
      manualReview: 1,
      unresolved: 0,
      remediationCoveragePercent: 60,
      analysisComplete: true,
      ...overrides,
    },
  };
}

void test("summarizes severity, coverage, top dependencies, and deterministic risk", () => {
  const vulnerabilities = [
    vulnerability("CRITICAL", "alpha"),
    vulnerability("HIGH", "beta"),
    vulnerability("HIGH", "beta"),
    vulnerability("MEDIUM", "gamma"),
    vulnerability("LOW", "delta"),
    vulnerability("UNKNOWN", "epsilon"),
  ];
  const summary = summarizeScanResults([
    result({
      vulnerableDependencies: 5,
      vulnerabilities,
      providerResults: [
        {
          provider: "OSV",
          status: "available",
          dependenciesEligible: 10,
          dependenciesSubmitted: 8,
          successful: 10,
          failed: 0,
          cacheHits: 2,
          staleCacheFallbacks: 0,
          vulnerabilitiesFound: 6,
        },
      ],
    }),
  ]);

  assert.deepEqual(summary.severityCounts, {
    CRITICAL: 1,
    HIGH: 2,
    MEDIUM: 1,
    LOW: 1,
    UNKNOWN: 1,
  });
  assert.equal(summary.weightedRiskPoints, 45);
  assert.equal(summary.dependencyRiskScore, 23);
  assert.equal(summary.coverageComplete, true);
  assert.equal(summary.dependenciesWithNoKnownFindings, 5);
  assert.equal(summary.topVulnerableDependencies[0]?.packageName, "alpha");
  assert.equal(summary.topVulnerableDependencies[1]?.packageName, "beta");
  assert.equal(summary.topVulnerableDependencies[1]?.vulnerabilityCount, 2);
  assert.equal(
    calculateDependencyRiskScore(1, [
      vulnerability("CRITICAL"),
      vulnerability("CRITICAL"),
    ]),
    100,
  );
  assert.equal(calculateDependencyRiskScore(0, vulnerabilities), 0);
  assert.match(DEPENDENCY_RISK_FORMULA, /20×critical/u);
});

void test("severity-filtered findings cannot produce a false clean dashboard", () => {
  const filteredResult = result({
    vulnerableDependencies: 2,
    vulnerabilities: [],
    providerResults: [
      {
        provider: "OSV",
        status: "available",
        dependenciesEligible: 10,
        dependenciesSubmitted: 10,
        successful: 10,
        failed: 0,
        cacheHits: 0,
        staleCacheFallbacks: 0,
        vulnerabilitiesFound: 3,
      },
    ],
  });
  const summary = summarizeScanResults([filteredResult]);
  assert.equal(summary.totalVulnerabilities, 0);
  assert.equal(summary.hiddenFindings, 3);
  assert.equal(summary.vulnerableDependencies, 2);
  assert.equal(summary.dependencyRiskScore, 0);

  const html = renderDashboardDocument(
    { workspaceOpen: true, scanResults: [filteredResult] },
    NONCE,
    SCRIPT_URI,
  );
  assert.match(html, /No findings meet the configured severity threshold\./u);
  assert.match(
    html,
    /3 known findings hidden by configured severity threshold\./u,
  );
  assert.match(
    html,
    /Known findings hidden by configured severity threshold<\/dt><dd>3/u,
  );
  assert.match(html, /Displayed known findings<\/dt><dd>0/u);
  assert.match(html, /weighted displayed-finding points/u);
  assert.match(html, /score uses findings that meet the configured severity threshold/u);
  assert.doesNotMatch(html, /No known vulnerabilities were found\./u);
});

void test("risk and severity cards use displayed findings while hidden counts remain visible", () => {
  const displayed = vulnerability("HIGH", "displayed-package");
  const filteredResult = result({
    vulnerableDependencies: 2,
    vulnerabilities: [displayed],
    providerResults: [
      {
        provider: "OSV",
        status: "available",
        dependenciesEligible: 10,
        dependenciesSubmitted: 10,
        successful: 10,
        failed: 0,
        cacheHits: 0,
        staleCacheFallbacks: 0,
        vulnerabilitiesFound: 2,
      },
    ],
  });
  const summary = summarizeScanResults([filteredResult]);
  assert.equal(summary.severityCounts.HIGH, 1);
  assert.equal(summary.hiddenFindings, 1);
  assert.equal(summary.weightedRiskPoints, 10);
  assert.equal(summary.dependencyRiskScore, 5);

  const html = renderDashboardDocument(
    { workspaceOpen: true, scanResults: [filteredResult] },
    NONCE,
    SCRIPT_URI,
  );
  assert.match(
    html,
    /1 known finding hidden by configured severity threshold\./u,
  );
  assert.match(html, /Dependency Risk Score 5 out of 100/u);
  assert.match(html, /displayed-package@1\.0\.0/u);
});

void test("renders remediation coverage as calculated candidates, never fixed state", () => {
  const html = renderDashboardDocument(
    {
      workspaceOpen: true,
      scanResults: [
        result({
          vulnerableDependencies: 5,
          vulnerabilities: [
            vulnerability("HIGH", "one"),
            vulnerability("HIGH", "two"),
            vulnerability("MEDIUM", "three"),
            vulnerability("LOW", "four"),
            vulnerability("UNKNOWN", "five"),
          ],
        }),
      ],
      remediationAnalysis: remediationAnalysis(),
      remediationAnalysisLabel: "Latest complete scan",
      remediationAnalysisTimestamp: "2026-08-12T10:15:00.000Z",
    },
    NONCE,
    SCRIPT_URI,
  );
  assert.match(html, /<h2 id="remediation-summary-heading">Remediation<\/h2>/u);
  assert.match(html, /5 displayed vulnerabilities/u);
  assert.match(html, /Remediable<\/dt><dd>3/u);
  assert.match(html, /Manual review required<\/dt><dd>1/u);
  assert.match(html, /No known fixed version<\/dt><dd>1/u);
  assert.match(html, /Remediation Coverage/u);
  assert.match(html, /Analysis source: Latest complete scan · 2026-08-12 10:15 UTC/u);
  assert.match(html, /3 of 5 displayed vulnerability records have a calculated remediation candidate/u);
  assert.match(html, /This does not mean they are fixed/u);
  assert.doesNotMatch(html, /Guaranteed|Fully secure|100% fixed/u);
});

void test("remediation card excludes retained historical evidence and marks incomplete analysis", () => {
  const old = vulnerability("CRITICAL", "historical-package");
  const html = renderDashboardDocument(
    {
      workspaceOpen: true,
      scanResults: [
        result({
          dependenciesScanned: 1,
          vulnerableDependencies: 1,
          vulnerabilities: [vulnerability("HIGH", "current-package")],
        }),
      ],
      remediationAnalysis: remediationAnalysis({
        totalVulnerabilities: 1,
        remediable: 0,
        noKnownFix: 0,
        manualReview: 1,
        remediationCoveragePercent: 0,
        analysisComplete: false,
      }),
      latestAttemptCoverage: "partial",
      retainedFindings: [
        {
          vulnerability: old,
          dependencies: [],
          workspacePaths: ["C:\\work\\sample-project"],
          lastConfirmedAt: "2026-08-10T19:00:00.000Z",
        },
      ],
    },
    NONCE,
    SCRIPT_URI,
  );
  assert.match(html, /1 displayed vulnerability/u);
  assert.match(html, /Analysis is incomplete; manual review remains required/u);
  assert.match(html, /Last complete scan findings/u);
  const remediationSection = html.slice(
    html.indexOf("remediation-summary-heading"),
    html.indexOf("</section>", html.indexOf("remediation-summary-heading")),
  );
  assert.doesNotMatch(remediationSection, /historical-package/u);
});

void test("renders no-workspace, no-result, unsupported-file, and clean completed states", () => {
  const noWorkspace = renderDashboardDocument(
    { workspaceOpen: false, scanResults: [] },
    NONCE,
    SCRIPT_URI,
  );
  assert.match(noWorkspace, /No workspace is open\./u);

  const retainedNoWorkspace = renderDashboardDocument(
    {
      workspaceOpen: false,
      scanResults: [
        result({
          workspacePath: "C:\\private\\retained-project-name",
          vulnerableDependencies: 1,
          vulnerabilities: [
            vulnerability("CRITICAL", "retained-private-package"),
          ],
          providerResults: [
            {
              provider: "retained-private-provider",
              status: "available",
              dependenciesEligible: 10,
              dependenciesSubmitted: 10,
              successful: 10,
              failed: 0,
              cacheHits: 0,
              staleCacheFallbacks: 0,
              vulnerabilitiesFound: 1,
            },
          ],
        }),
      ],
      retainedFindings: [
        {
          vulnerability: vulnerability(
            "HIGH",
            "last-complete-private-package",
          ),
          dependencies: [],
          workspacePaths: ["C:\\private\\retained-project-name"],
          lastConfirmedAt: "2026-08-10T19:00:00.000Z",
        },
      ],
    },
    NONCE,
    SCRIPT_URI,
  );
  assert.match(retainedNoWorkspace, /No workspace is open\./u);
  assert.match(retainedNoWorkspace, />Scan Workspace<\/button>/u);
  assert.doesNotMatch(retainedNoWorkspace, /retained-project-name/u);
  assert.doesNotMatch(retainedNoWorkspace, /retained-private-package/u);
  assert.doesNotMatch(retainedNoWorkspace, /retained-private-provider/u);
  assert.doesNotMatch(retainedNoWorkspace, /last-complete-private-package/u);
  assert.doesNotMatch(retainedNoWorkspace, /Findings summary/u);
  assert.doesNotMatch(retainedNoWorkspace, /Provider coverage/u);
  assert.doesNotMatch(retainedNoWorkspace, /Dependencies scanned/u);
  assert.doesNotMatch(retainedNoWorkspace, /Last successful scan/u);

  const notScanned = renderDashboardDocument(
    { workspaceOpen: true, scanResults: [] },
    NONCE,
    SCRIPT_URI,
  );
  assert.match(notScanned, /No scan results yet\./u);

  const unsupported = renderDashboardDocument(
    {
      workspaceOpen: true,
      scanResults: [
        result({
          dependenciesScanned: 0,
          providerResults: [],
          errors: [
            {
              code: "NO_LOCKFILE",
              message: "No npm lockfile was found.",
            },
          ],
        }),
      ],
      latestAttemptCoverage: "partial",
    },
    NONCE,
    SCRIPT_URI,
  );
  assert.match(unsupported, /No supported dependency files were found\./u);

  const clean = renderDashboardDocument(
    { workspaceOpen: true, scanResults: [result()] },
    NONCE,
    SCRIPT_URI,
  );
  assert.match(clean, /No known vulnerabilities were found\./u);
  assert.doesNotMatch(clean, />Secure</u);
});

void test("a failed latest attempt is visible while prior usable results remain", () => {
  const prior = result({
    scannedAt: "2026-08-10T10:00:00.000Z",
    vulnerabilities: [vulnerability("HIGH", "prior-finding")],
    vulnerableDependencies: 1,
  });
  const failed = result({
    dependenciesScanned: 182,
    providerResults: [
      {
        provider: "OSV & <mirror>",
        status: "unavailable",
        dependenciesEligible: 182,
        dependenciesSubmitted: 182,
        successful: 0,
        failed: 182,
        cacheHits: 0,
        staleCacheFallbacks: 0,
        vulnerabilitiesFound: 0,
      },
    ],
    errors: [
      {
        code: "PROVIDER_ERROR",
        message: "Provider unavailable",
        provider: "OSV",
      },
    ],
  });
  const html = renderDashboardDocument(
    {
      workspaceOpen: true,
      scanResults: [prior],
      displayedCoverage: "complete",
      latestAttempt: [failed],
      latestAttemptCoverage: "unavailable",
      latestAttemptTimestamp: "2026-08-11T20:30:00.000Z",
      lastSuccessfulTimestamp: "2026-08-10T10:00:01.000Z",
    },
    NONCE,
    SCRIPT_URI,
  );

  assert.match(html, /Vulnerability database unavailable\./u);
  assert.match(html, /Previously stored results may remain visible/u);
  assert.match(html, /Dependencies discovered<\/dt><dd>182/u);
  assert.match(html, /Successfully checked<\/dt><dd>0/u);
  assert.match(html, /Failed<\/dt><dd>182/u);
  assert.match(html, /OSV &amp; &lt;mirror&gt;/u);
  assert.match(html, /2026-08-10 10:00 UTC/u);
  assert.match(html, /prior-finding@1\.0\.0/u);
});

void test("cancellation is visible before empty or retained successful results", () => {
  const firstCancelled = renderDashboardDocument(
    {
      workspaceOpen: true,
      scanResults: [],
      latestAttempt: [],
      latestAttemptCoverage: "cancelled",
    },
    NONCE,
    SCRIPT_URI,
  );
  assert.match(firstCancelled, /Latest dependency scan was cancelled\./u);
  assert.doesNotMatch(firstCancelled, /No scan results yet\./u);

  const retained = renderDashboardDocument(
    {
      workspaceOpen: true,
      scanResults: [result()],
      latestAttempt: [],
      displayedCoverage: "complete",
      latestAttemptCoverage: "cancelled",
      lastSuccessfulTimestamp: "2026-08-11T20:31:00.000Z",
    },
    NONCE,
    SCRIPT_URI,
  );
  assert.match(retained, /Latest dependency scan was cancelled\./u);
  assert.match(retained, /Previously stored results may remain visible/u);
  assert.match(retained, /Dependencies scanned<\/dt><dd>10/u);
  assert.doesNotMatch(retained, /No known vulnerabilities were found\./u);
});

void test("dashboard renders retained last-complete findings separately from current partial arithmetic", () => {
  const current = vulnerability("HIGH", "current-only");
  const old = vulnerability("CRITICAL", "<old-only>");
  const retained = (
    vulnerabilityValue: Vulnerability,
  ): RetainedVulnerabilityFinding => ({
    vulnerability: vulnerabilityValue,
    dependencies: [],
    workspacePaths: ["C:\\work\\sample-project"],
    lastConfirmedAt: "2026-08-10T19:00:00.000Z",
  });
  const partial = result({
    dependenciesScanned: 2,
    vulnerableDependencies: 1,
    vulnerabilities: [current],
    providerResults: [
      {
        provider: "OSV",
        status: "partial",
        dependenciesEligible: 2,
        dependenciesSubmitted: 2,
        successful: 1,
        failed: 1,
        cacheHits: 0,
        staleCacheFallbacks: 0,
        vulnerabilitiesFound: 1,
      },
    ],
  });
  const html = renderDashboardDocument(
    {
      workspaceOpen: true,
      scanResults: [partial],
      latestAttemptCoverage: "partial",
      retainedFindings: [retained(old), retained(current)],
    },
    NONCE,
    SCRIPT_URI,
  );

  assert.match(html, /Last complete scan findings — not reconfirmed \(1\)/u);
  assert.match(html, /&lt;old-only&gt;@1\.0\.0/u);
  assert.match(
    html,
    /not included in current coverage, provider, risk, or dependency counts/u,
  );
  assert.match(html, /Dependencies scanned<\/dt><dd>2/u);
  assert.match(html, /Displayed known findings<\/dt><dd>1/u);
  assert.match(html, /Dependency Risk Score 25 out of 100/u);
  assert.match(html, /<td>1 \/ 2<\/td>/u);
  const retainedSection = html.slice(
    html.indexOf("Last complete scan findings"),
    html.indexOf("</section>", html.indexOf("Last complete scan findings")),
  );
  assert.doesNotMatch(retainedSection, /current-only/u);
});

void test("available labels cannot hide failed or missing provider checks", () => {
  const incomplete = result({
    providerResults: [
      {
        provider: "OSV",
        status: "available",
        dependenciesEligible: 10,
        dependenciesSubmitted: 10,
        successful: 9,
        failed: 1,
        cacheHits: 0,
        staleCacheFallbacks: 0,
        vulnerabilitiesFound: 0,
      },
    ],
  });
  assert.equal(summarizeScanResults([incomplete]).coverageComplete, false);
  assert.equal(
    summarizeScanResults([
      result({
        providerResults: [
          {
            provider: "OSV",
            status: "available",
            dependenciesEligible: 10,
            dependenciesSubmitted: 9,
            successful: 9,
            failed: 0,
            cacheHits: 0,
            staleCacheFallbacks: 0,
            vulnerabilitiesFound: 0,
          },
        ],
      }),
    ]).coverageComplete,
    false,
  );

  const html = renderDashboardDocument(
    { workspaceOpen: true, scanResults: [incomplete] },
    NONCE,
    SCRIPT_URI,
  );
  assert.match(html, /Scan coverage is incomplete\./u);
  assert.match(html, /9 \/ 10/u);
  assert.match(html, /<td>1<\/td>/u);
  assert.doesNotMatch(html, /No known vulnerabilities were found\./u);
});

void test("summarizes and filters canonical ecosystems without conflating Gradle and Maven", () => {
  const pythonFinding: Vulnerability = {
    ...vulnerability("HIGH", "requests", "2.19.0"),
    ecosystem: "PyPI",
  };
  const gradleFinding: Vulnerability = {
    ...vulnerability("CRITICAL", "org.apache.commons:commons-text", "1.9"),
    ecosystem: "Maven",
  };
  const multiEcosystem = result({
    packageManagers: ["pip", "gradle"],
    dependenciesScanned: 2,
    vulnerableDependencies: 2,
    vulnerabilities: [pythonFinding, gradleFinding],
    dependencies: [
      {
        name: "requests",
        ecosystem: "PyPI",
        installedVersion: "2.19.0",
        dependencyType: "direct",
        environment: "production",
        packageManager: "pip",
      },
      {
        name: "org.apache.commons:commons-text",
        ecosystem: "Maven",
        installedVersion: "1.9",
        dependencyType: "direct",
        environment: "production",
        packageManager: "gradle",
      },
    ],
    projectCoverage: [
      {
        ecosystem: "PyPI",
        packageManagers: ["pip"],
        discovered: 2,
        resolved: 1,
        checked: 1,
        vulnerable: 1,
        unresolved: 1,
        unsupported: 0,
        workspacePath: "C:\\work",
        projectPath: "C:\\work\\python",
        manifestPaths: ["C:\\work\\python\\requirements.txt"],
      },
      {
        ecosystem: "Maven",
        packageManagers: ["gradle"],
        discovered: 1,
        resolved: 1,
        checked: 1,
        vulnerable: 1,
        unresolved: 0,
        unsupported: 0,
        workspacePath: "C:\\work",
        projectPath: "C:\\work\\jvm",
        manifestPaths: ["C:\\work\\jvm\\build.gradle"],
      },
    ],
    providerResults: [
      {
        provider: "OSV",
        status: "available",
        dependenciesEligible: 2,
        dependenciesSubmitted: 2,
        successful: 2,
        failed: 0,
        cacheHits: 0,
        staleCacheFallbacks: 0,
        vulnerabilitiesFound: 2,
      },
    ],
  });

  const summary = summarizeScanResults([multiEcosystem]);
  assert.deepEqual(
    summary.ecosystemCoverage.map((coverage) => coverage.label),
    ["Gradle", "Python"],
  );
  assert.equal(summary.coverageComplete, false);
  assert.equal(summary.ecosystemCoverage[1]?.percentage, 50);
  assert.equal(summary.topVulnerableDependencies[0]?.ecosystemLabel, "Gradle");

  const html = renderDashboardDocument(
    { workspaceOpen: true, scanResults: [multiEcosystem] },
    NONCE,
    SCRIPT_URI,
  );
  assert.match(html, /data-ecosystem-filter="Gradle"/u);
  assert.match(html, /data-ecosystem-filter="PyPI"/u);
  assert.match(html, />Gradle<\/td>/u);
  assert.match(html, />Python<span class="muted ecosystem-detail"> \(pip\)<\/span>/u);
  assert.doesNotMatch(html, />Maven<\/td>/u);
});

void test("attributes a deduplicated Maven subject to every matching Maven and Gradle project", () => {
  const finding: Vulnerability = {
    ...vulnerability("HIGH", "org.example:shared", "1.0.0"),
    ecosystem: "Maven",
  };
  const shared = result({
    packageManagers: ["maven", "gradle"],
    dependenciesScanned: 1,
    vulnerableDependencies: 1,
    vulnerabilities: [finding],
    dependencies: [
      {
        name: "org.example:shared",
        ecosystem: "Maven",
        installedVersion: "1.0.0",
        dependencyType: "direct",
        environment: "production",
        packageManager: "maven",
        projectPath: "C:\\work\\maven-app",
      },
      {
        name: "org.example:shared",
        ecosystem: "Maven",
        installedVersion: "1.0.0",
        dependencyType: "direct",
        environment: "production",
        packageManager: "gradle",
        projectPath: "C:\\work\\gradle-app",
      },
    ],
    projectCoverage: [
      {
        ecosystem: "Maven",
        packageManagers: ["maven"],
        discovered: 1,
        resolved: 1,
        checked: 1,
        vulnerable: 1,
        unresolved: 0,
        unsupported: 0,
        workspacePath: "C:\\work",
        projectPath: "C:\\work\\maven-app",
        manifestPaths: ["C:\\work\\maven-app\\pom.xml"],
      },
      {
        ecosystem: "Maven",
        packageManagers: ["gradle"],
        discovered: 1,
        resolved: 1,
        checked: 1,
        vulnerable: 1,
        unresolved: 0,
        unsupported: 0,
        workspacePath: "C:\\work",
        projectPath: "C:\\work\\gradle-app",
        manifestPaths: ["C:\\work\\gradle-app\\build.gradle"],
      },
    ],
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

  const summary = summarizeScanResults([shared]);
  assert.deepEqual(
    summary.ecosystemCoverage.map((coverage) => [
      coverage.label,
      coverage.displayedFindings,
    ]),
    [
      ["Gradle", 1],
      ["Maven", 1],
    ],
  );
  assert.deepEqual(
    summary.topVulnerableDependencies.map(
      (dependency) => dependency.ecosystemLabel,
    ),
    ["Gradle", "Maven"],
  );
});

void test("dashboard escapes malicious provider and package content under a strict CSP", () => {
  const maliciousName = '\"><img src=x onerror="alert(1)">';
  const html = renderDashboardDocument(
    {
      workspaceOpen: true,
      scanResults: [
        result({
          workspacePath: "C:\\work\\<script>alert(1)</script>",
          vulnerableDependencies: 1,
          vulnerabilities: [vulnerability("HIGH", maliciousName)],
        }),
      ],
    },
    NONCE,
    SCRIPT_URI,
  );

  assert.match(html, /default-src 'none'/u);
  assert.match(html, /script-src 'nonce-0123456789abcdef0123456789abcdef'/u);
  assert.doesNotMatch(html, /<img src=x/u);
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/u);
  assert.match(html, /&lt;img src=x/u);
  assert.doesNotMatch(html, /onclick=/u);
  assert.match(
    html,
    /<script nonce="0123456789abcdef0123456789abcdef" src="vscode-webview:\/\/test\/media\/dashboard\.js"><\/script>/u,
  );
  assert.doesNotMatch(html, /acquireVsCodeApi/u);
  assert.doesNotMatch(html, /fetch\(|XMLHttpRequest|WebSocket/u);
});
