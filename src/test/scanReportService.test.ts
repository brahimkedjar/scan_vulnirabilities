import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { ScanResult } from "../models/ScanResult";
import type { Logger } from "../services/Logger";
import { ScanReportService } from "../services/ScanReportService";

class RecordingLogger implements Logger {
  public readonly messages: string[] = [];

  public info(message: string): void {
    this.messages.push(message);
  }

  public warn(message: string): void {
    this.messages.push(message);
  }

  public error(message: string): void {
    this.messages.push(message);
  }

  public show(): void {}
}

void test("report relationship lookup is isolated by ecosystem", () => {
  const logger = new RecordingLogger();
  const result: ScanResult = {
    workspacePath: "/workspace",
    scannedAt: "2026-08-12T00:00:00.000Z",
    durationMs: 1,
    packageManagers: ["npm", "pip"],
    dependenciesScanned: 2,
    vulnerableDependencies: 1,
    dependencies: [
      {
        name: "shared-name",
        ecosystem: "npm",
        installedVersion: "1.0.0",
        dependencyType: "direct",
        environment: "production",
        dependencyPath: ["wrong-npm-path"],
      },
      {
        name: "shared-name",
        ecosystem: "PyPI",
        installedVersion: "1.0.0",
        dependencyType: "direct",
        environment: "development",
        dependencyPath: ["correct-python-path"],
      },
    ],
    vulnerabilities: [
      {
        id: "PYSEC-TEST",
        aliases: [],
        packageName: "shared-name",
        ecosystem: "PyPI",
        installedVersion: "1.0.0",
        severity: "HIGH",
        summary: "fixture",
        references: [],
        source: "OSV",
      },
    ],
    errors: [],
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
        vulnerabilitiesFound: 1,
      },
    ],
    cancelled: false,
  };

  new ScanReportService(logger).log(result);
  const output = logger.messages.join("\n");
  assert.match(output, /Dependency path: correct-python-path/u);
  assert.match(output, /Environment: development/u);
  assert.doesNotMatch(output, /wrong-npm-path/u);
});
