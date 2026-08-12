import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { Dependency } from "../models/Dependency";
import type {
  ProviderResult,
  ScanError,
  ScanResult,
} from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";
import {
  classifyScanCoverage,
  ScanResultStore,
} from "../services/ScanResultStore";

function dependency(name = "example"): Dependency {
  return {
    name,
    ecosystem: "npm",
    installedVersion: "1.0.0",
    dependencyType: "direct",
    environment: "production",
    dependencyPath: ["application", `${name}@1.0.0`],
    packageJsonPath: "/workspace/package.json",
  };
}

function vulnerability(name = "example"): Vulnerability {
  return {
    id: "OSV-TEST-1",
    aliases: ["CVE-2026-0001"],
    packageName: name,
    ecosystem: "npm",
    installedVersion: "1.0.0",
    severity: "HIGH",
    summary: "Test advisory",
    fixedVersions: ["1.0.1"],
    remediationCandidates: ["1.0.1"],
    references: ["https://osv.dev/vulnerability/OSV-TEST-1"],
    source: "OSV",
    severityDetails: [
      {
        type: "CVSS_V3",
        score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      },
    ],
  };
}

function providerResult(
  status: ProviderResult["status"] = "available",
): ProviderResult {
  const hasSuccessfulCoverage = status !== "unavailable";
  return {
    provider: "OSV",
    status,
    dependenciesEligible: 1,
    dependenciesSubmitted: 1,
    successful: hasSuccessfulCoverage ? 1 : 0,
    failed: status === "available" ? 0 : 1,
    cacheHits: 0,
    staleCacheFallbacks: 0,
    vulnerabilitiesFound: hasSuccessfulCoverage ? 1 : 0,
  };
}

interface ResultOptions {
  readonly name?: string;
  readonly providerStatus?: ProviderResult["status"];
  readonly errors?: readonly ScanError[];
  readonly cancelled?: boolean;
  readonly dependenciesScanned?: number;
  readonly includeProvider?: boolean;
}

interface FindingSpec {
  readonly name: string;
  readonly id: string;
}

function scanResult(options: ResultOptions = {}): ScanResult {
  const name = options.name ?? "example";
  const dependenciesScanned = options.dependenciesScanned ?? 1;
  const dependencyValue = dependency(name);
  const vulnerabilityValue = vulnerability(name);
  return {
    workspacePath: "/workspace",
    scannedAt: "2026-08-11T20:00:00.000Z",
    durationMs: 25,
    packageManagers: dependenciesScanned === 0 ? [] : ["npm"],
    dependenciesScanned,
    vulnerableDependencies: dependenciesScanned === 0 ? 0 : 1,
    vulnerabilities: dependenciesScanned === 0 ? [] : [vulnerabilityValue],
    dependencies: dependenciesScanned === 0 ? [] : [dependencyValue],
    errors: options.errors ?? [],
    providerResults:
      options.includeProvider === false
        ? []
        : dependenciesScanned === 0
          ? []
          : [providerResult(options.providerStatus)],
    cancelled: options.cancelled ?? false,
  };
}

function resultWithFindings(
  findings: readonly FindingSpec[],
  providerStatus: ProviderResult["status"] = "available",
  workspacePath = "/workspace",
): ScanResult {
  const base = scanResult({
    name: findings[0]?.name ?? "empty",
    providerStatus,
    dependenciesScanned: findings.length,
  });
  return {
    ...base,
    workspacePath,
    dependenciesScanned: findings.length,
    vulnerableDependencies: findings.length,
    dependencies: findings.map((finding) => ({
      ...dependency(finding.name),
      workspacePath,
    })),
    vulnerabilities: findings.map((finding) => ({
      ...vulnerability(finding.name),
      id: finding.id,
    })),
  };
}

void test("classifies complete, partial, unavailable, cancelled, and empty coverage explicitly", () => {
  assert.equal(classifyScanCoverage([]), "not-scanned");
  assert.equal(classifyScanCoverage([scanResult()]), "complete");
  assert.equal(
    classifyScanCoverage([
      scanResult({
        errors: [
          {
            code: "NO_LOCKFILE",
            message: "A manifest was not covered",
          },
        ],
      }),
    ]),
    "partial",
  );
  assert.equal(
    classifyScanCoverage([scanResult({ providerStatus: "unavailable" })]),
    "unavailable",
  );
  assert.equal(
    classifyScanCoverage([scanResult({ includeProvider: false })]),
    "unavailable",
  );
  assert.equal(
    classifyScanCoverage([scanResult({ cancelled: true })]),
    "cancelled",
  );
  assert.equal(
    classifyScanCoverage([
      scanResult({ name: "covered" }),
      scanResult({ name: "failed", providerStatus: "unavailable" }),
    ]),
    "partial",
  );
});

void test("does not treat cache write errors or an empty dependency set as incomplete coverage", () => {
  assert.equal(
    classifyScanCoverage([
      scanResult({
        errors: [
          {
            code: "CACHE_ERROR",
            message: "Successful results were not cached",
          },
        ],
      }),
    ]),
    "complete",
  );
  assert.equal(
    classifyScanCoverage([scanResult({ dependenciesScanned: 0 })]),
    "complete",
  );
});

void test("uses project coverage when an ecosystem aggregate is unavailable", () => {
  const result = scanResult();
  assert.equal(
    classifyScanCoverage([
      {
        ...result,
        projectCoverage: [
          {
            ecosystem: "npm",
            packageManagers: ["npm"],
            workspacePath: "/workspace",
            projectPath: "/workspace",
            manifestPaths: ["/workspace/package.json"],
            discovered: 2,
            resolved: 2,
            checked: 1,
            vulnerable: 1,
            unresolved: 0,
            unsupported: 0,
          },
        ],
      },
    ]),
    "partial",
  );
});

void test("retains a usable result when the latest provider attempt is wholly unavailable", () => {
  let now = Date.parse("2026-08-11T20:01:00.000Z");
  const store = new ScanResultStore({ clock: () => now });
  const successful = scanResult({ name: "successful" });
  store.replace([successful]);

  now = Date.parse("2026-08-11T20:02:00.000Z");
  const failed = scanResult({
    name: "failed",
    providerStatus: "unavailable",
  });
  store.replace([failed]);

  assert.equal(store.coverage, "unavailable");
  assert.equal(store.getAll()[0]?.dependencies[0]?.name, "successful");
  assert.equal(store.latestAttempt[0]?.dependencies[0]?.name, "failed");
  assert.equal(
    store.latestAttemptTimestamp,
    "2026-08-11T20:02:00.000Z",
  );
  assert.equal(
    store.lastSuccessfulResult[0]?.dependencies[0]?.name,
    "successful",
  );
  assert.equal(
    store.lastSuccessfulTimestamp,
    "2026-08-11T20:01:00.000Z",
  );
  const snapshot = store.getSnapshot();
  assert.equal(snapshot.displayedCoverage, "complete");
  assert.equal(snapshot.latestAttemptCoverage, "unavailable");
});

void test("publishes a first unavailable attempt and accepts a later partial result as usable", () => {
  let now = 0;
  const store = new ScanResultStore({ clock: () => now });
  store.replace([
    scanResult({ name: "failed", providerStatus: "unavailable" }),
  ]);
  assert.equal(store.getAll()[0]?.dependencies[0]?.name, "failed");
  assert.equal(store.lastSuccessfulResult.length, 0);

  now = 1_000;
  store.replace([
    scanResult({
      name: "partial",
      providerStatus: "partial",
    }),
  ]);
  assert.equal(store.getAll()[0]?.dependencies[0]?.name, "partial");
  assert.equal(store.getSnapshot().displayedCoverage, "partial");
  assert.equal(store.lastSuccessfulResult.length, 0);
});

void test("publishes later partial findings while retaining the last complete scan", () => {
  const store = new ScanResultStore({ clock: () => 1_700_000_000_000 });
  store.replace([scanResult({ name: "complete" })]);
  store.replace([
    scanResult({
      name: "partial-refresh",
      providerStatus: "partial",
    }),
  ]);

  assert.equal(store.getAll()[0]?.dependencies[0]?.name, "partial-refresh");
  assert.equal(store.getSnapshot().displayedCoverage, "partial");
  assert.equal(store.getSnapshot().latestAttemptCoverage, "partial");
  assert.equal(
    store.latestAttempt[0]?.dependencies[0]?.name,
    "partial-refresh",
  );
  assert.equal(
    store.lastSuccessfulResult[0]?.dependencies[0]?.name,
    "complete",
  );
});

void test("keeps partial coverage current and retains only non-reconfirmed complete findings", () => {
  let now = Date.parse("2026-08-11T20:01:00.000Z");
  const store = new ScanResultStore({ clock: () => now });
  store.replace([
    resultWithFindings([
      { name: "complete-only", id: "OSV-COMPLETE" },
      { name: "overlap", id: "OSV-OVERLAP" },
    ]),
  ]);

  now = Date.parse("2026-08-11T20:02:00.000Z");
  const partialAttempt = [
    resultWithFindings(
      [
        { name: "partial-only", id: "OSV-PARTIAL" },
        { name: "overlap", id: "OSV-OVERLAP" },
      ],
      "partial",
    ),
  ];
  const preview = store.previewRetainedFindings(partialAttempt);
  assert.deepEqual(
    preview.findings.map((finding) => finding.vulnerability.id),
    ["OSV-COMPLETE"],
  );
  store.replace(partialAttempt);

  const snapshot = store.getSnapshot();
  assert.equal(snapshot.displayedCoverage, "partial");
  assert.equal(snapshot.latestAttemptCoverage, "partial");
  assert.equal(snapshot.results[0]?.dependenciesScanned, 2);
  assert.deepEqual(
    snapshot.results[0]?.vulnerabilities.map((item) => item.id),
    ["OSV-PARTIAL", "OSV-OVERLAP"],
  );
  assert.equal(snapshot.retainedFindings.length, 1);
  assert.equal(
    snapshot.retainedFindings[0]?.vulnerability.id,
    "OSV-COMPLETE",
  );
  assert.deepEqual(
    snapshot.retainedFindings[0]?.dependencies.map((item) => item.name),
    ["complete-only"],
  );
  assert.deepEqual(snapshot.retainedFindings[0]?.workspacePaths, [
    "/workspace",
  ]);
  assert.equal(
    snapshot.retainedFindings[0]?.lastConfirmedAt,
    "2026-08-11T20:01:00.000Z",
  );
  assert.equal(snapshot.retainedFindingsTruncated, false);
  assert.deepEqual(
    snapshot.retainedFindings.map((finding) => finding.vulnerability.id),
    preview.findings.map((finding) => finding.vulnerability.id),
  );
});

void test("deduplicates retained findings across workspaces and complete refresh clears them", () => {
  const store = new ScanResultStore({ clock: () => 0 });
  store.replace([
    resultWithFindings(
      [{ name: "shared", id: "OSV-SHARED" }],
      "available",
      "/workspace/a",
    ),
    resultWithFindings(
      [{ name: "shared", id: "OSV-SHARED" }],
      "available",
      "/workspace/b",
    ),
  ]);
  store.replace([
    resultWithFindings(
      [{ name: "current", id: "OSV-CURRENT" }],
      "partial",
      "/workspace/a",
    ),
  ]);

  const partial = store.getSnapshot();
  assert.equal(partial.retainedFindings.length, 1);
  assert.deepEqual(partial.retainedFindings[0]?.workspacePaths, [
    "/workspace/a",
    "/workspace/b",
  ]);
  assert.equal(partial.retainedFindings[0]?.dependencies.length, 2);

  store.replace([
    resultWithFindings([{ name: "new-complete", id: "OSV-NEW" }]),
  ]);
  assert.deepEqual(store.getSnapshot().retainedFindings, []);
  assert.equal(store.getSnapshot().retainedFindingsTruncated, false);
});

void test("retained transitive evidence shares coordinate arrays and includes its direct manifest anchor", () => {
  const direct: Dependency = {
    ...dependency("introducer"),
    manifestPath: "/workspace/package.json",
    dependencyPath: ["application", "introducer@1.0.0"],
  };
  const transitive: Dependency = {
    ...dependency("transitive"),
    dependencyType: "transitive",
    manifestPath: "/workspace/package.json",
    dependencyPath: [
      "application",
      "introducer@1.0.0",
      "transitive@1.0.0",
    ],
  };
  const complete = scanResult({ name: "transitive" });
  const first = {
    ...vulnerability("transitive"),
    id: "OSV-TRANSITIVE-ONE",
  };
  const second = {
    ...vulnerability("transitive"),
    id: "OSV-TRANSITIVE-TWO",
  };
  const store = new ScanResultStore({ clock: () => 0 });
  store.replace([
    {
      ...complete,
      dependenciesScanned: 2,
      vulnerableDependencies: 1,
      dependencies: [direct, transitive],
      vulnerabilities: [first, second],
    },
  ]);
  store.replace([
    resultWithFindings(
      [{ name: "current", id: "OSV-CURRENT" }],
      "partial",
    ),
  ]);

  const retained = store.getSnapshot().retainedFindings;
  assert.equal(retained.length, 2);
  assert.equal(retained[0]?.dependencies, retained[1]?.dependencies);
  assert.deepEqual(
    retained[0]?.dependencies.map((item) => item.name),
    ["transitive", "introducer"],
  );
});

void test("bounds retained evidence and preserves it across unavailable and cancelled attempts", () => {
  const store = new ScanResultStore({
    clock: () => 0,
    maximumRetainedFindings: 1,
  });
  store.replace([
    resultWithFindings([
      { name: "first", id: "OSV-FIRST" },
      { name: "second", id: "OSV-SECOND" },
    ]),
  ]);
  store.replace([
    resultWithFindings(
      [{ name: "partial", id: "OSV-PARTIAL" }],
      "partial",
    ),
  ]);
  const retained = store.getSnapshot().retainedFindings;
  assert.equal(retained.length, 1);
  assert.equal(store.getSnapshot().retainedFindingsTruncated, true);

  store.replace([
    resultWithFindings(
      [{ name: "unavailable", id: "OSV-UNAVAILABLE" }],
      "unavailable",
    ),
  ]);
  assert.equal(store.getSnapshot().retainedFindings, retained);
  store.recordCancelledAttempt();
  assert.equal(store.getSnapshot().retainedFindings, retained);
});

void test("records cancellation without replacing the last complete result", () => {
  let now = Date.parse("2026-08-11T20:01:00.000Z");
  const store = new ScanResultStore({ clock: () => now });
  store.replace([scanResult({ name: "complete" })]);

  now = Date.parse("2026-08-11T20:02:00.000Z");
  store.setScanning(true);
  store.recordCancelledAttempt();

  const snapshot = store.getSnapshot();
  assert.equal(snapshot.scanning, false);
  assert.equal(snapshot.latestAttemptCoverage, "cancelled");
  assert.deepEqual(snapshot.latestAttempt, []);
  assert.equal(
    snapshot.latestAttemptTimestamp,
    "2026-08-11T20:02:00.000Z",
  );
  assert.equal(snapshot.results[0]?.dependencies[0]?.name, "complete");
  assert.equal(
    snapshot.lastSuccessfulResult[0]?.dependencies[0]?.name,
    "complete",
  );
});

void test("makes one immutable defensive copy including nested array fields", () => {
  const store = new ScanResultStore({ clock: () => 0 });
  const source = [scanResult()];
  store.replace(source);

  (source[0]?.packageManagers as string[]).push("tampered");
  (source[0]?.dependencies[0]?.dependencyPath as string[]).push("tampered");
  (source[0]?.vulnerabilities[0]?.aliases as string[]).push("CVE-TAMPERED");
  (source[0]?.vulnerabilities[0]?.fixedVersions as string[]).push("9.9.9");
  (source[0]?.vulnerabilities[0]?.remediationCandidates as string[]).push(
    "9.9.9",
  );
  assert.deepEqual(store.getAll()[0]?.packageManagers, ["npm"]);
  assert.equal(store.getAll()[0]?.dependencies[0]?.dependencyPath?.length, 2);
  assert.deepEqual(store.getAll()[0]?.vulnerabilities[0]?.aliases, [
    "CVE-2026-0001",
  ]);
  assert.deepEqual(store.getAll()[0]?.vulnerabilities[0]?.fixedVersions, [
    "1.0.1",
  ]);
  assert.deepEqual(
    store.getAll()[0]?.vulnerabilities[0]?.remediationCandidates,
    ["1.0.1"],
  );

  const returned = store.getAll() as ScanResult[];
  assert.throws(() => returned.splice(0), TypeError);
  assert.equal(store.getAll().length, 1);
  const nestedReturn = store.getAll()[0];
  assert.throws(
    () =>
      (nestedReturn?.vulnerabilities[0]?.references as string[]).push(
        "https://example.test/tampered",
      ),
    TypeError,
  );
  assert.equal(store.getAll()[0]?.vulnerabilities[0]?.references.length, 1);
  assert.equal(store.getAll(), store.getAll());
  assert.equal(store.getSnapshot().results, store.getAll());
  assert.equal(Object.isFrozen(store.getSnapshot()), true);
});

void test("normalizes legacy fixedVersion-only findings when storing snapshots", () => {
  const store = new ScanResultStore({ clock: () => 0 });
  const legacyVulnerability = vulnerability();
  delete legacyVulnerability.fixedVersions;
  delete legacyVulnerability.remediationCandidates;
  legacyVulnerability.fixedVersion = "1.0.2";

  store.replace([
    {
      ...scanResult(),
      vulnerabilities: [legacyVulnerability],
    },
  ]);

  const stored = store.getAll()[0]?.vulnerabilities[0];
  assert.deepEqual(stored?.fixedVersions, ["1.0.2"]);
  assert.deepEqual(stored?.remediationCandidates, ["1.0.2"]);
  assert.equal(Object.isFrozen(stored?.fixedVersions), true);
  assert.equal(Object.isFrozen(stored?.remediationCandidates), true);
});

void test("emits bounded, disposable change subscriptions without allowing listener failures to escape", () => {
  const store = new ScanResultStore({ clock: () => 0, maximumListeners: 2 });
  let successfulListenerCalls = 0;
  const failingSubscription = store.onDidChange(() => {
    throw new Error("subscriber failure");
  });
  const successfulSubscription = store.onDidChange((snapshot) => {
    successfulListenerCalls += 1;
    assert.equal(snapshot.scanning, successfulListenerCalls === 1);
  });
  assert.throws(() => store.onDidChange(() => undefined), RangeError);

  store.setScanning(true);
  store.setScanning(true);
  store.replace([scanResult()]);
  assert.equal(successfulListenerCalls, 2);

  successfulSubscription.dispose();
  successfulSubscription.dispose();
  failingSubscription.dispose();
  const replacement = store.onDidChange(() => {
    successfulListenerCalls += 1;
  });
  store.clear();
  assert.equal(successfulListenerCalls, 3);
  replacement.dispose();
});

void test("replace with an empty array preserves getAll compatibility and clear resets all state", () => {
  const store = new ScanResultStore({ clock: () => 0 });
  store.replace([scanResult()]);
  store.replace([]);
  assert.deepEqual(store.getAll(), []);
  assert.equal(store.coverage, "not-scanned");

  store.setScanning(true);
  store.clear();
  assert.deepEqual(store.getSnapshot(), {
    results: [],
    displayedCoverage: "not-scanned",
    scanning: false,
    latestAttempt: [],
    latestAttemptCoverage: "not-scanned",
    lastSuccessfulResult: [],
    retainedFindings: [],
    retainedFindingsTruncated: false,
  });
});

void test("dispose removes subscribers and rejects new subscriptions", () => {
  const store = new ScanResultStore();
  let calls = 0;
  store.onDidChange(() => {
    calls += 1;
  });
  store.dispose();
  store.setScanning(true);
  assert.equal(calls, 0);
  assert.throws(() => store.onDidChange(() => undefined), /disposed/u);
});
