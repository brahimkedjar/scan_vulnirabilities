import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { ScanResult } from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";
import { SecurityPolicyEngine } from "../policy/SecurityPolicyEngine";

function finding(
  overrides: Partial<Vulnerability> = {},
): Vulnerability {
  return {
    id: "GHSA-policy-fixture",
    aliases: ["CVE-2026-0002"],
    packageName: "fixture-package",
    ecosystem: "npm",
    installedVersion: "1.0.0",
    severity: "HIGH",
    cvssScore: 8,
    summary: "fixture",
    references: [],
    source: "OSV",
    ...overrides,
  };
}

function result(
  vulnerabilities: readonly Vulnerability[] = [],
  overrides: Partial<ScanResult> = {},
): ScanResult {
  return {
    workspacePath: "/workspace",
    scannedAt: "2026-08-12T00:00:00.000Z",
    durationMs: 1,
    packageManagers: ["npm"],
    dependenciesScanned: 1,
    vulnerableDependencies: vulnerabilities.length > 0 ? 1 : 0,
    vulnerabilities,
    dependencies: [
      {
        name: "fixture-package",
        ecosystem: "npm",
        installedVersion: "1.0.0",
        dependencyType: "direct",
        environment: "production",
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
        vulnerabilitiesFound: vulnerabilities.length,
      },
    ],
    cancelled: false,
    ...overrides,
  };
}

void test("empty bounded policy passes only complete current evidence", () => {
  const gate = new SecurityPolicyEngine({
    clock: () => Date.parse("2026-08-12T00:00:00.000Z"),
  }).evaluate([result()], {}, { coverage: "complete" });

  assert.equal(gate.status, "PASS");
  assert.equal(gate.complete, true);
  assert.deepEqual(gate.reasons, []);
  assert.equal(gate.summary.dependenciesEvaluated, 1);
});

void test("gate combines deterministic severity, CVSS, ecosystem, and package reasons", () => {
  const engine = new SecurityPolicyEngine({
    clock: () => Date.parse("2026-08-12T00:00:00.000Z"),
  });
  const policy = {
    maxHigh: 0,
    minimumSeverity: "HIGH" as const,
    minimumCvss: 7,
    allowedEcosystems: ["PyPI"],
    blockedPackages: [{ ecosystem: "npm", name: "fixture-package" }],
    allowedPackages: ["another-package"],
  };
  const first = engine.evaluate([result([finding()])], policy, {
    coverage: "complete",
  });
  const second = engine.evaluate([result([finding()])], policy, {
    coverage: "complete",
  });

  assert.deepEqual(first, second);
  assert.equal(first.status, "FAIL");
  assert.deepEqual(
    new Set(first.reasons.map((reason) => reason.code)),
    new Set([
      "HIGH_LIMIT_EXCEEDED",
      "SEVERITY_THRESHOLD_EXCEEDED",
      "CVSS_THRESHOLD_EXCEEDED",
      "ECOSYSTEM_NOT_ALLOWED",
      "PACKAGE_BLOCKED",
    ]),
  );
  assert.equal(
    first.reasons.some((reason) => reason.code === "PACKAGE_NOT_ALLOWED"),
    false,
    "blocked package must win over allowlist reporting",
  );
});

void test("partial or unavailable latest attempts fail closed", () => {
  const engine = new SecurityPolicyEngine();
  for (const coverage of ["partial", "unavailable", "cancelled"] as const) {
    const gate = engine.evaluate([result()], {}, { coverage });
    assert.equal(gate.status, "FAIL");
    assert.equal(gate.complete, false);
    assert.ok(
      gate.reasons.some(
        (reason) =>
          reason.code === "SCAN_INCOMPLETE" ||
          reason.code === "SCAN_NOT_AVAILABLE",
      ),
    );
  }
});

void test("provider totals exceeding stored findings fail rather than hiding policy evidence", () => {
  const scan = result([], {
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
        vulnerabilitiesFound: 2,
      },
    ],
  });
  const gate = new SecurityPolicyEngine().evaluate([scan], { maxCritical: 0 }, {
    coverage: "complete",
  });

  assert.equal(gate.status, "FAIL");
  assert.equal(gate.complete, false);
  assert.equal(gate.summary.hiddenFindings, 2);
  assert.ok(gate.reasons.some((reason) => reason.code === "HIDDEN_FINDINGS"));
});

void test("unfiltered findings are evaluated without a false hidden-finding failure", () => {
  const displayed = finding();
  const hiddenLow = finding({
    id: "GHSA-hidden-low",
    aliases: [],
    severity: "LOW",
    cvssScore: 2,
  });
  const scan = result([displayed], {
    unfilteredVulnerabilities: [displayed, hiddenLow],
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
        vulnerabilitiesFound: 2,
      },
    ],
  });
  const gate = new SecurityPolicyEngine().evaluate(
    [scan],
    { minimumSeverity: "MEDIUM" },
    { coverage: "complete" },
  );

  assert.equal(gate.status, "FAIL", "the displayed HIGH finding remains blocking");
  assert.equal(gate.summary.findingsEvaluated, 2);
  assert.equal(gate.summary.hiddenFindings, 0);
  assert.equal(
    gate.reasons.some((reason) => reason.code === "HIDDEN_FINDINGS"),
    false,
  );
  assert.equal(
    gate.reasons.some(
      (reason) =>
        reason.code === "SEVERITY_THRESHOLD_EXCEEDED" &&
        reason.advisoryId === "GHSA-hidden-low",
    ),
    false,
  );
});

void test("ignored advisory aliases require a valid future expiration", () => {
  const engine = new SecurityPolicyEngine({
    clock: () => Date.parse("2026-08-12T00:00:00.000Z"),
  });
  const active = engine.evaluate(
    [result([finding()])],
    {
      maxHigh: 0,
      ignoredAdvisories: [
        {
          id: "CVE-2026-0002",
          expiresAt: "2026-08-13T00:00:00Z",
          reason: "bounded temporary exception",
        },
      ],
    },
    { coverage: "complete" },
  );
  assert.equal(active.status, "PASS");
  assert.equal(active.summary.ignoredFindings, 1);

  const expired = engine.evaluate(
    [result([finding()])],
    {
      maxHigh: 0,
      ignoredAdvisories: [
        { id: "CVE-2026-0002", expiresAt: "2026-08-12T00:00:00Z" },
      ],
    },
    { coverage: "complete" },
  );
  assert.equal(expired.status, "FAIL");
  assert.equal(expired.summary.ignoredFindings, 0);
  assert.ok(
    expired.reasons.some(
      (reason) => reason.code === "ADVISORY_IGNORE_EXPIRED",
    ),
  );
  assert.ok(
    expired.reasons.some((reason) => reason.code === "HIGH_LIMIT_EXCEEDED"),
  );
});

void test("known-exploited absence policy requires explicit unambiguous evidence", () => {
  const engine = new SecurityPolicyEngine();
  const scan = result([finding()]);
  const unknown = engine.evaluate(
    [scan],
    { requireKnownExploitedAbsent: true },
    { coverage: "complete" },
  );
  assert.equal(unknown.status, "FAIL");
  assert.equal(unknown.complete, false);
  assert.ok(
    unknown.reasons.some(
      (reason) => reason.code === "KNOWN_EXPLOITATION_UNKNOWN",
    ),
  );

  const absent = engine.evaluate(
    [scan],
    { requireKnownExploitedAbsent: true },
    {
      coverage: "complete",
      findingIntelligence: [
        {
          advisoryId: "GHSA-policy-fixture",
          ecosystem: "npm",
          packageName: "fixture-package",
          installedVersion: "1.0.0",
          knownExploitation: "not-known-exploited",
        },
      ],
    },
  );
  assert.equal(absent.status, "PASS");
  assert.equal(absent.complete, true);
});

void test("malformed policies, resource limits, and cancellation fail safely", () => {
  const scan = result([finding()]);
  const engine = new SecurityPolicyEngine({ maximumFindings: 1 });

  const malformed = engine.evaluate([scan], {
    maxCritical: -1,
    unexpected: true,
  });
  assert.equal(malformed.status, "FAIL");
  assert.equal(malformed.policyValid, false);
  assert.ok(malformed.reasons.some((reason) => reason.code === "POLICY_INVALID"));

  const tooLarge = engine.evaluate(
    [result([finding(), finding({ id: "GHSA-second" })])],
    {},
    { coverage: "complete" },
  );
  assert.equal(tooLarge.status, "FAIL");
  assert.ok(
    tooLarge.reasons.some((reason) => reason.code === "INPUT_LIMIT_EXCEEDED"),
  );

  const controller = new AbortController();
  controller.abort();
  const cancelled = engine.evaluate([scan], {}, {
    coverage: "complete",
    signal: controller.signal,
  });
  assert.equal(cancelled.status, "FAIL");
  assert.equal(cancelled.cancelled, true);
  assert.equal(cancelled.complete, false);
  assert.ok(
    cancelled.reasons.some(
      (reason) => reason.code === "EVALUATION_CANCELLED",
    ),
  );

  const malformedScan = {
    ...scan,
    vulnerabilities: [{ id: "bad", aliases: null }],
  } as unknown as ScanResult;
  const invalidInput = engine.evaluate([malformedScan], {}, {
    coverage: "complete",
  });
  assert.equal(invalidInput.status, "FAIL");
  assert.equal(invalidInput.complete, false);
  assert.ok(
    invalidInput.reasons.some(
      (reason) => reason.code === "INPUT_LIMIT_EXCEEDED",
    ),
  );
});
