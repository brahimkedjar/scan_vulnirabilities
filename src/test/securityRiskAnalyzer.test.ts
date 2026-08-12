import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { Vulnerability } from "../models/Vulnerability";
import {
  SecurityRiskAnalysisCancelledError,
  SecurityRiskAnalyzer,
} from "../intelligence/SecurityRiskAnalyzer";

function vulnerability(
  overrides: Partial<Vulnerability> = {},
): Vulnerability {
  return {
    id: "GHSA-risk-fixture",
    aliases: ["CVE-2026-0001"],
    packageName: "fixture-package",
    ecosystem: "npm",
    installedVersion: "1.0.0",
    severity: "HIGH",
    cvssScore: 8,
    summary: "deterministic fixture",
    references: [],
    source: "OSV",
    ...overrides,
  };
}

void test("risk score is deterministic, bounded, immutable, and explainable", () => {
  const analyzer = new SecurityRiskAnalyzer();
  const enrichment = {
    knownExploitation: {
      status: "known-exploited" as const,
      source: "CISA KEV",
    },
    reachability: {
      status: "confirmed" as const,
      source: "static import graph",
    },
  };
  const first = analyzer.analyze(vulnerability(), enrichment);
  const second = analyzer.analyze(vulnerability(), enrichment);

  assert.deepEqual(first, second);
  assert.equal(first.score, 84);
  assert.equal(first.maximumScore, 84);
  assert.equal(first.band, "CRITICAL");
  assert.equal(first.completeness, "complete");
  assert.deepEqual(first.missingEvidence, []);
  assert.deepEqual(
    first.factors.map((factor) => factor.id),
    ["severity", "cvss", "known-exploitation", "reachability"],
  );
  assert.equal(
    first.factors.reduce((total, factor) => total + factor.contribution, 0),
    first.score,
  );
  assert.ok(Object.isFrozen(first));
  assert.ok(Object.isFrozen(first.factors));
  assert.ok(first.factors.every(Object.isFrozen));
});

void test("unknown evidence adds no invented points and remains an explicit range", () => {
  const score = new SecurityRiskAnalyzer().analyze(
    (() => {
      const unknown = vulnerability({ severity: "UNKNOWN" });
      delete unknown.cvssScore;
      return unknown;
    })(),
  );

  assert.equal(score.score, 0);
  assert.equal(score.maximumScore, 100);
  assert.equal(score.band, "UNKNOWN");
  assert.equal(score.maximumBand, "CRITICAL");
  assert.equal(score.completeness, "unknown");
  assert.deepEqual(score.missingEvidence, [
    "severity",
    "cvss",
    "known-exploitation",
    "reachability",
  ]);
  assert.ok(
    score.factors.every(
      (factor) =>
        factor.evidenceState !== "unknown" || factor.contribution === 0,
    ),
  );
});

void test("not-observed reachability is not described as unreachable", () => {
  const score = new SecurityRiskAnalyzer().analyze(vulnerability(), {
    knownExploitation: { status: "not-known-exploited" },
    reachability: { status: "not-observed" },
  });
  const reachability = score.factors.find(
    (factor) => factor.id === "reachability",
  );

  assert.equal(score.completeness, "complete");
  assert.equal(reachability?.value, "NOT_OBSERVED");
  assert.match(reachability?.reason ?? "", /not a claim/u);
});

void test("batch analysis exposes truncation and cancellation without a complete result", () => {
  const analyzer = new SecurityRiskAnalyzer();
  const truncated = analyzer.analyzeMany(
    [vulnerability(), vulnerability({ id: "GHSA-second" })],
    () => ({
      knownExploitation: { status: "not-known-exploited" },
      reachability: { status: "not-observed" },
    }),
    { maximumFindings: 1 },
  );
  assert.equal(truncated.processed, 1);
  assert.equal(truncated.truncated, true);
  assert.equal(truncated.analysisComplete, false);

  const controller = new AbortController();
  controller.abort();
  const cancelled = analyzer.analyzeMany([vulnerability()], undefined, {
    signal: controller.signal,
  });
  assert.equal(cancelled.cancelled, true);
  assert.equal(cancelled.processed, 0);
  assert.equal(cancelled.analysisComplete, false);
  assert.throws(
    () => analyzer.analyze(vulnerability(), {}, { signal: controller.signal }),
    SecurityRiskAnalysisCancelledError,
  );
});

void test("risk options reject adversarial resource-limit values", () => {
  const analyzer = new SecurityRiskAnalyzer();
  assert.throws(
    () => analyzer.analyzeMany([vulnerability()], undefined, { maximumFindings: 0 }),
    RangeError,
  );
  assert.throws(
    () =>
      analyzer.analyzeMany([vulnerability()], undefined, {
        maximumFindings: Number.MAX_SAFE_INTEGER,
      }),
    RangeError,
  );
});
