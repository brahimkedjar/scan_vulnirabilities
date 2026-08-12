import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  SecurityPlatformCommands,
  type SecurityExportLocation,
  type SecurityExportKind,
  type SecurityPlatformCommandUi,
} from "../commands/SecurityPlatformCommands";
import { SecurityIntelligenceService } from "../intelligence/SecurityIntelligenceService";
import type { Dependency } from "../models/Dependency";
import type { ScanResult } from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";
import type { Logger } from "../services/Logger";
import type {
  ScanCoverage,
  ScanResultStoreSnapshot,
} from "../services/ScanResultStore";

const WORKSPACE = "C:\\repo";

function vulnerability(): Vulnerability {
  return {
    id: "OSV-2026-TEST",
    aliases: ["CVE-2026-12345"],
    packageName: "example",
    ecosystem: "npm",
    installedVersion: "1.0.0",
    severity: "CRITICAL",
    cvssScore: 9.8,
    summary: "Fixture advisory",
    fixedVersions: ["1.0.1"],
    remediationCandidates: ["1.0.1"],
    references: ["https://osv.dev/vulnerability/OSV-2026-TEST"],
    source: "OSV",
  };
}

function dependency(): Dependency {
  return {
    name: "example",
    ecosystem: "npm",
    installedVersion: "1.0.0",
    resolutionStatus: "resolved",
    dependencyType: "direct",
    environment: "production",
    dependencyPath: ["example"],
    manifestPath: `${WORKSPACE}\\package.json`,
    packageManager: "npm",
    projectPath: WORKSPACE,
    workspacePath: WORKSPACE,
    metadata: { sourceLine: 4 },
  };
}

function result(coverage: ScanCoverage = "complete"): ScanResult {
  const finding = vulnerability();
  return {
    workspacePath: WORKSPACE,
    scannedAt: "2026-08-12T20:00:00.000Z",
    durationMs: 10,
    packageManagers: ["npm"],
    dependenciesScanned: 1,
    vulnerableDependencies: 1,
    vulnerabilities: [finding],
    unfilteredVulnerabilities: [finding],
    dependencies: [dependency()],
    errors:
      coverage === "complete"
        ? []
        : [{ code: "PROVIDER_ERROR", message: "Provider unavailable" }],
    providerResults: [
      {
        provider: "OSV",
        status: coverage === "complete" ? "available" : "partial",
        dependenciesEligible: 1,
        dependenciesSubmitted: 1,
        successful: coverage === "complete" ? 1 : 0,
        failed: coverage === "complete" ? 0 : 1,
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
        checked: coverage === "complete" ? 1 : 0,
        vulnerable: 1,
        unresolved: 0,
        unsupported: 0,
      },
    ],
    cancelled: false,
  };
}

function snapshot(coverage: ScanCoverage = "complete"): ScanResultStoreSnapshot {
  const results = coverage === "not-scanned" ? [] : [result(coverage)];
  return {
    revision: 1,
    results,
    displayedCoverage: coverage,
    scanning: false,
    latestAttempt: results,
    latestAttemptCoverage: coverage,
    ...(results[0] === undefined
      ? {}
      : { latestAttemptTimestamp: results[0].scannedAt }),
    lastSuccessfulResult: coverage === "complete" ? results : [],
    ...(coverage === "complete" && results[0] !== undefined
      ? { lastSuccessfulTimestamp: results[0].scannedAt }
      : {}),
    retainedFindings: [],
    retainedFindingsTruncated: false,
  };
}

class MemoryLogger implements Logger {
  public readonly messages: string[] = [];
  public info(message: string): void {
    this.messages.push(`INFO ${message}`);
  }
  public warn(message: string): void {
    this.messages.push(`WARN ${message}`);
  }
  public error(message: string): void {
    this.messages.push(`ERROR ${message}`);
  }
  public show(): void {}
}

class MemoryUi implements SecurityPlatformCommandUi {
  public location: SecurityExportLocation | undefined = Object.freeze({
    id: "report",
  });
  public readonly writes: Uint8Array[] = [];
  public readonly messages: string[] = [];
  public kinds: SecurityExportKind[] = [];
  public async chooseSaveLocation(kind: SecurityExportKind): Promise<SecurityExportLocation | undefined> {
    this.kinds.push(kind);
    return this.location;
  }
  public async writeFile(_location: SecurityExportLocation, content: Uint8Array): Promise<void> {
    this.writes.push(content);
  }
  public async showInformation(message: string): Promise<void> {
    this.messages.push(`INFO ${message}`);
  }
  public async showWarning(message: string): Promise<void> {
    this.messages.push(`WARN ${message}`);
  }
  public async showError(message: string): Promise<void> {
    this.messages.push(`ERROR ${message}`);
  }
}

function commands(
  selected: ScanResultStoreSnapshot,
  ui: MemoryUi,
  logger = new MemoryLogger(),
): SecurityPlatformCommands {
  return new SecurityPlatformCommands({
    logger,
    getSnapshot: () => selected,
    getPolicy: () => ({ schemaVersion: 1, maxCritical: 0 }),
    getWorkspaceRoots: () => [WORKSPACE],
    ui,
    toolVersion: "0.8.0",
  });
}

void test("evaluates the latest complete unfiltered attempt and reports exact failure reasons", async () => {
  const ui = new MemoryUi();
  const logger = new MemoryLogger();
  const gate = await commands(snapshot(), ui, logger).evaluateSecurityGate();

  assert.equal(gate.status, "FAIL");
  assert.equal(gate.complete, true);
  assert.equal(gate.summary.findingsEvaluated, 1);
  assert.ok(
    gate.reasons.some((reason) => reason.code === "CRITICAL_LIMIT_EXCEEDED"),
  );
  assert.match(ui.messages[0] ?? "", /security gate: FAIL/u);
  assert.ok(logger.messages.some((message) => /CRITICAL_LIMIT_EXCEEDED/u.test(message)));
});

void test("latest partial coverage fails closed even when findings are present", async () => {
  const ui = new MemoryUi();
  const gate = await commands(snapshot("partial"), ui).evaluateSecurityGate();

  assert.equal(gate.status, "FAIL");
  assert.equal(gate.complete, false);
  assert.ok(gate.reasons.some((reason) => reason.code === "SCAN_INCOMPLETE"));
});

void test("an active scan cannot pass from a prior complete snapshot", async () => {
  const ui = new MemoryUi();
  const active = { ...snapshot(), scanning: true };
  const gate = await commands(active, ui).evaluateSecurityGate();

  assert.equal(gate.status, "FAIL");
  assert.equal(gate.complete, false);
  assert.ok(gate.reasons.some((reason) => reason.code === "SCAN_INCOMPLETE"));
});

void test("a scan revision change during enrichment fails closed", async () => {
  const ui = new MemoryUi();
  const logger = new MemoryLogger();
  const initial = snapshot();
  const changedResult: ScanResult = {
    ...result(),
    vulnerabilities: [],
    unfilteredVulnerabilities: [],
  };
  let selected: ScanResultStoreSnapshot = initial;
  const handler = new SecurityPlatformCommands({
    logger,
    getSnapshot: () => selected,
    getPolicy: () => ({ schemaVersion: 1, maxCritical: 1 }),
    getWorkspaceRoots: () => [WORKSPACE],
    ui,
    toolVersion: "0.8.0",
    loadIntelligence: async () => {
      selected = {
        ...snapshot(),
        revision: initial.revision + 1,
        latestAttempt: [changedResult],
        results: [changedResult],
      };
      return undefined;
    },
  });

  const gate = await handler.evaluateSecurityGate();

  assert.equal(gate.status, "FAIL");
  assert.equal(gate.complete, false);
  assert.ok(gate.reasons.some((reason) => reason.code === "SCAN_INCOMPLETE"));
  assert.ok(logger.messages.some((message) => /evidence changed/u.test(message)));
});

void test("explicit gate enrichment can prove a fresh KEV catalog absence without sending package data", async () => {
  const ui = new MemoryUi();
  const logger = new MemoryLogger();
  let catalogLoads = 0;
  const intelligence = new SecurityIntelligenceService(
    {
      load: async () => {
        catalogLoads += 1;
        return {
          source: "CISA KEV",
          status: "available",
          catalog: {
            schemaVersion: 1,
            source: "CISA KEV",
            catalogVersion: "fixture",
            releasedAt: "2026-08-12T19:00:00.000Z",
            fetchedAt: "2026-08-12T19:00:00.000Z",
            entries: [],
          },
        };
      },
    },
    { clock: () => Date.parse("2026-08-12T20:00:00.000Z") },
  );
  const handler = new SecurityPlatformCommands({
    logger,
    getSnapshot: () => snapshot(),
    getPolicy: () => ({
      schemaVersion: 1,
      requireKnownExploitedAbsent: true,
    }),
    getWorkspaceRoots: () => [WORKSPACE],
    ui,
    toolVersion: "0.8.0",
    loadIntelligence: async (findings, signal) =>
      intelligence.analyze(findings, {
        ...(signal === undefined ? {} : { signal }),
      }),
  });

  const gate = await handler.evaluateSecurityGate();

  assert.equal(catalogLoads, 1);
  assert.equal(gate.status, "PASS");
  assert.equal(gate.complete, true);
  assert.ok(logger.messages.some((message) => /CISA KEV enrichment status/u.test(message)));
  assert.ok(logger.messages.some((message) => /Why this is/u.test(message)));
});

void test("exports deterministic unfiltered CycloneDX and SARIF through the injected save boundary", async () => {
  const ui = new MemoryUi();
  const handler = commands(snapshot(), ui);

  assert.equal(await handler.exportCycloneDx(), true);
  assert.equal(await handler.exportSarif(), true);
  assert.deepEqual(ui.kinds, ["cyclonedx", "sarif"]);
  assert.equal(ui.writes.length, 2);
  const cyclone = JSON.parse(new TextDecoder().decode(ui.writes[0])) as {
    readonly bomFormat?: unknown;
    readonly vulnerabilities?: readonly unknown[];
  };
  const sarif = JSON.parse(new TextDecoder().decode(ui.writes[1])) as {
    readonly version?: unknown;
    readonly runs?: readonly { readonly results?: readonly unknown[] }[];
  };
  assert.equal(cyclone.bomFormat, "CycloneDX");
  assert.equal(cyclone.vulnerabilities?.length, 1);
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs?.[0]?.results?.length, 1);
});

void test("cancelled save and absent scans perform no write", async () => {
  const cancelledUi = new MemoryUi();
  cancelledUi.location = undefined;
  assert.equal(
    await commands(snapshot(), cancelledUi).exportCycloneDx(),
    false,
  );
  assert.equal(cancelledUi.writes.length, 0);

  const emptyUi = new MemoryUi();
  assert.equal(
    await commands(snapshot("not-scanned"), emptyUi).exportSarif(),
    false,
  );
  assert.equal(emptyUi.writes.length, 0);
  assert.match(emptyUi.messages[0] ?? "", /No completed latest scan/u);
});

void test("exports refuse active or superseded scan snapshots", async () => {
  const activeUi = new MemoryUi();
  assert.equal(
    await commands({ ...snapshot(), scanning: true }, activeUi).exportSarif(),
    false,
  );
  assert.equal(activeUi.writes.length, 0);

  const exportUi = new MemoryUi();
  const initial = snapshot();
  let selected = initial;
  exportUi.chooseSaveLocation = async (kind) => {
    exportUi.kinds.push(kind);
    selected = { ...initial, revision: initial.revision + 1 };
    return exportUi.location;
  };
  const handler = new SecurityPlatformCommands({
    logger: new MemoryLogger(),
    getSnapshot: () => selected,
    getPolicy: () => ({ schemaVersion: 1 }),
    getWorkspaceRoots: () => [WORKSPACE],
    ui: exportUi,
    toolVersion: "0.8.0",
  });

  assert.equal(await handler.exportCycloneDx(), false);
  assert.equal(exportUi.writes.length, 0);
  assert.ok(exportUi.messages.some((message) => /Scan results changed/u.test(message)));
});
