import { stableSha256 } from "../sbom/ComponentIdentity";
import type { SecurityIntelligenceSnapshot } from "../intelligence/SecurityIntelligenceService";
import { scanResultKnownVulnerabilities } from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";
import {
  SecurityPolicyEngine,
  type SecurityGateResult,
  type SecurityPolicy,
} from "../policy";
import { exportSarifJson } from "../reporting";
import type { Logger } from "../services/Logger";
import type {
  ScanCoverage,
  ScanResultStoreSnapshot,
} from "../services/ScanResultStore";
import { exportCycloneDxJson } from "../sbom";

const MAXIMUM_LOGGED_GATE_REASONS = 200;
const MAXIMUM_LOGGED_RISK_FINDINGS = 20;
const MAXIMUM_EXPORT_BYTES = 64 * 1024 * 1024;

export type SecurityExportKind = "cyclonedx" | "sarif";
/** Opaque host-owned value returned only by the native save boundary. */
export type SecurityExportLocation = object;

export interface SecurityPlatformCommandUi {
  chooseSaveLocation(
    kind: SecurityExportKind,
    suggestedFileName: string,
  ): Promise<SecurityExportLocation | undefined>;
  writeFile(location: SecurityExportLocation, content: Uint8Array): Promise<void>;
  showInformation(message: string): Promise<void>;
  showWarning(message: string): Promise<void>;
  showError(message: string): Promise<void>;
}

export interface SecurityPlatformCommandOptions {
  readonly logger: Logger;
  readonly getSnapshot: () => ScanResultStoreSnapshot;
  readonly getPolicy: () => SecurityPolicy | unknown;
  readonly getWorkspaceRoots: () => readonly string[];
  readonly ui: SecurityPlatformCommandUi;
  readonly toolVersion: string;
  readonly loadIntelligence?: (
    vulnerabilities: readonly Vulnerability[],
    signal?: AbortSignal,
  ) => Promise<SecurityIntelligenceSnapshot | undefined>;
  readonly policyEngine?: SecurityPolicyEngine;
}

function findingKey(vulnerability: Vulnerability): string {
  return JSON.stringify([
    vulnerability.source,
    vulnerability.id,
    vulnerability.ecosystem,
    vulnerability.packageName,
    vulnerability.installedVersion,
  ]);
}

function riskFindingKey(
  finding: SecurityIntelligenceSnapshot["findings"][number],
): string {
  return JSON.stringify([
    finding.ecosystem,
    finding.packageName,
    finding.installedVersion,
    finding.advisoryId,
  ]);
}

function completeFindings(
  snapshot: ScanResultStoreSnapshot,
): readonly Vulnerability[] {
  const byIdentity = new Map<string, Vulnerability>();
  for (const result of snapshot.latestAttempt) {
    for (const vulnerability of scanResultKnownVulnerabilities(result)) {
      const key = findingKey(vulnerability);
      if (!byIdentity.has(key)) {
        byIdentity.set(key, vulnerability);
      }
    }
  }
  return Object.freeze([...byIdentity.values()]);
}

function latestTimestamp(snapshot: ScanResultStoreSnapshot): string {
  const values = snapshot.latestAttempt
    .map((result) => result.scannedAt)
    .filter((value) => Number.isFinite(Date.parse(value)))
    .sort((left, right) => Date.parse(right) - Date.parse(left));
  return values[0] ?? new Date(0).toISOString();
}

function deterministicSerial(snapshot: ScanResultStoreSnapshot): string {
  const identity = snapshot.latestAttempt.map((result) => ({
    scannedAt: result.scannedAt,
    workspacePath: result.workspacePath,
    dependencies: result.dependencies.map((dependency) => [
      dependency.ecosystem,
      dependency.name,
      dependency.installedVersion,
      dependency.projectPath ?? "",
    ]),
  }));
  const hash = stableSha256(JSON.stringify(identity)).slice(0, 32).split("");
  hash[12] = "4";
  hash[16] = "8";
  const value = hash.join("");
  return `urn:uuid:${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;
}

function coverageWarning(coverage: ScanCoverage): string {
  return `The exported report records latest-attempt coverage as ${coverage}; it must not be interpreted as a clean complete scan.`;
}

function boundedBytes(content: string): Uint8Array {
  const encoded = new TextEncoder().encode(content);
  if (encoded.byteLength > MAXIMUM_EXPORT_BYTES) {
    throw new RangeError("The generated report exceeds the export size limit");
  }
  return encoded;
}

function gateMessage(result: SecurityGateResult): string {
  const suffix = result.complete ? "" : " (evidence incomplete)";
  return `Dependency Auditor security gate: ${result.status}${suffix}. ${result.summary.findingsEvaluated.toString()} finding(s) and ${result.summary.dependenciesEvaluated.toString()} dependency coordinate(s) evaluated.`;
}

function snapshotAuthorityIsCurrent(
  initial: ScanResultStoreSnapshot,
  current: ScanResultStoreSnapshot,
): boolean {
  return (
    !initial.scanning &&
    !current.scanning &&
    initial.revision === current.revision &&
    initial.latestAttemptTimestamp === current.latestAttemptTimestamp &&
    initial.latestAttemptCoverage === current.latestAttemptCoverage
  );
}

export class SecurityPlatformCommands {
  private readonly policyEngine: SecurityPolicyEngine;

  public constructor(private readonly options: SecurityPlatformCommandOptions) {
    this.policyEngine = options.policyEngine ?? new SecurityPolicyEngine();
  }

  public async evaluateSecurityGate(
    signal?: AbortSignal,
  ): Promise<SecurityGateResult> {
    const snapshot = this.options.getSnapshot();
    const vulnerabilities = completeFindings(snapshot);
    let intelligence: SecurityIntelligenceSnapshot | undefined;
    if (
      !snapshot.scanning &&
      this.options.loadIntelligence !== undefined &&
      vulnerabilities.length > 0
    ) {
      try {
        intelligence = await this.options.loadIntelligence(
          vulnerabilities,
          signal,
        );
      } catch (error: unknown) {
        this.options.logger.error(
          "Security intelligence enrichment failed; required evidence remains unknown",
          error,
        );
      }
    }
    const currentSnapshot = this.options.getSnapshot();
    const authorityCurrent = snapshotAuthorityIsCurrent(
      snapshot,
      currentSnapshot,
    );
    if (!authorityCurrent) {
      intelligence = undefined;
      this.options.logger.warn(
        "Security gate evidence changed or a scan is active; evaluation is failing closed.",
      );
    }
    const gate = this.policyEngine.evaluate(
      snapshot.latestAttempt,
      this.options.getPolicy(),
      {
        coverage: authorityCurrent ? snapshot.latestAttemptCoverage : "partial",
        ...(intelligence === undefined
          ? {}
          : { findingIntelligence: intelligence.policyFindings }),
        ...(signal === undefined ? {} : { signal }),
      },
    );

    this.options.logger.info(gateMessage(gate));
    const loggedReasons = gate.reasons.slice(0, MAXIMUM_LOGGED_GATE_REASONS);
    for (const reason of loggedReasons) {
      const log = reason.disposition === "FAIL"
        ? this.options.logger.warn.bind(this.options.logger)
        : this.options.logger.info.bind(this.options.logger);
      log(`Security gate ${reason.disposition} [${reason.code}]: ${reason.message}`);
    }
    if (gate.reasons.length > loggedReasons.length) {
      this.options.logger.warn(
        `${(gate.reasons.length - loggedReasons.length).toString()} additional security gate reason(s) were omitted from the Output Channel view.`,
      );
    }
    if (intelligence !== undefined) {
      this.options.logger.info(
        `CISA KEV enrichment status: ${intelligence.source.status}; complete=${intelligence.complete.toString()}.`,
      );
      const risks = [...intelligence.findings]
        .sort(
          (left, right) =>
            right.risk.score - left.risk.score ||
            riskFindingKey(left).localeCompare(riskFindingKey(right), "en"),
        )
        .slice(0, MAXIMUM_LOGGED_RISK_FINDINGS);
      for (const finding of risks) {
        const factors = finding.risk.factors
          .map(
            (factor) =>
              `${factor.id}=${factor.value} (+${factor.contribution.toString()}/${factor.maximumContribution.toString()})`,
          )
          .join(", ");
        this.options.logger.info(
          `Why this is ${finding.risk.band} risk: ${finding.ecosystem}/${finding.packageName}@${finding.installedVersion} ${finding.advisoryId}; score ${finding.risk.score.toString()}-${finding.risk.maximumScore.toString()}; ${factors}.`,
        );
      }
    }
    this.options.logger.show(true);
    const message = gateMessage(gate);
    if (gate.status === "FAIL") {
      await this.options.ui.showError(message);
    } else if (gate.status === "WARN" || !gate.complete) {
      await this.options.ui.showWarning(message);
    } else {
      await this.options.ui.showInformation(message);
    }
    return gate;
  }

  public async exportCycloneDx(): Promise<boolean> {
    const snapshot = this.options.getSnapshot();
    if (snapshot.scanning) {
      await this.options.ui.showWarning(
        "Wait for the active dependency scan to finish before exporting.",
      );
      return false;
    }
    if (snapshot.latestAttempt.length === 0) {
      await this.options.ui.showWarning(
        "No completed latest scan is available to export.",
      );
      return false;
    }
    try {
      const content = exportCycloneDxJson(snapshot.latestAttempt, {
        timestamp: latestTimestamp(snapshot),
        serialNumber: deterministicSerial(snapshot),
        workspaceRoots: this.options.getWorkspaceRoots(),
        toolVersion: this.options.toolVersion,
      });
      const location = await this.options.ui.chooseSaveLocation(
        "cyclonedx",
        "dependency-auditor.cdx.json",
      );
      if (location === undefined) {
        return false;
      }
      if (!snapshotAuthorityIsCurrent(snapshot, this.options.getSnapshot())) {
        await this.options.ui.showWarning(
          "Scan results changed before export; create a new report from the latest attempt.",
        );
        return false;
      }
      await this.options.ui.writeFile(location, boundedBytes(content));
      const incomplete = snapshot.latestAttemptCoverage !== "complete";
      await (incomplete
        ? this.options.ui.showWarning(coverageWarning(snapshot.latestAttemptCoverage))
        : this.options.ui.showInformation(
            "CycloneDX JSON 1.6 report exported from the latest complete scan.",
          ));
      return true;
    } catch (error: unknown) {
      this.options.logger.error("CycloneDX export failed", error);
      await this.options.ui.showError(
        "Dependency Auditor could not export CycloneDX. See the Output Channel for the failure class.",
      );
      return false;
    }
  }

  public async exportSarif(): Promise<boolean> {
    const snapshot = this.options.getSnapshot();
    if (snapshot.scanning) {
      await this.options.ui.showWarning(
        "Wait for the active dependency scan to finish before exporting.",
      );
      return false;
    }
    if (snapshot.latestAttempt.length === 0) {
      await this.options.ui.showWarning(
        "No completed latest scan is available to export.",
      );
      return false;
    }
    try {
      const content = exportSarifJson(snapshot.latestAttempt, {
        workspaceRoots: this.options.getWorkspaceRoots(),
        toolVersion: this.options.toolVersion,
      });
      const location = await this.options.ui.chooseSaveLocation(
        "sarif",
        "dependency-auditor.sarif.json",
      );
      if (location === undefined) {
        return false;
      }
      if (!snapshotAuthorityIsCurrent(snapshot, this.options.getSnapshot())) {
        await this.options.ui.showWarning(
          "Scan results changed before export; create a new report from the latest attempt.",
        );
        return false;
      }
      await this.options.ui.writeFile(location, boundedBytes(content));
      const incomplete = snapshot.latestAttemptCoverage !== "complete";
      await (incomplete
        ? this.options.ui.showWarning(coverageWarning(snapshot.latestAttemptCoverage))
        : this.options.ui.showInformation(
            "SARIF 2.1.0 report exported from the latest complete scan.",
          ));
      return true;
    } catch (error: unknown) {
      this.options.logger.error("SARIF export failed", error);
      await this.options.ui.showError(
        "Dependency Auditor could not export SARIF. See the Output Channel for the failure class.",
      );
      return false;
    }
  }
}
