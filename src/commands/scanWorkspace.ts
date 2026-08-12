import * as vscode from "vscode";

import type { DiagnosticManager } from "../diagnostics/DiagnosticManager";
import {
  dependencyManifestPath,
  type Dependency,
} from "../models/Dependency";
import type {
  ProjectCoverage,
  ScanError,
  ScanResult,
} from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";
import type { WorkspaceDependencyScanner } from "../package-managers/WorkspaceDependencyScanner";
import { registerDependencyMetadataBudget } from "../package-managers/dependencyMetadataBudget";
import { registerDependencyRecordBudget } from "../package-managers/dependencyRecordBudget";
import type { DependencyAuditService } from "../services/DependencyAuditService";
import type { RemediationAnalysisSource } from "../remediation/RemediationAnalysisSource";
import {
  filterDependencies,
  filterVulnerabilitiesBySeverity,
  type DependencyAuditorConfiguration,
} from "../services/DependencyAuditorConfiguration";
import type { Logger } from "../services/Logger";
import { sanitizeDisplayValue } from "../services/Logger";
import { buildCoverage } from "../services/CoverageBuilder";
import type { ScanReportService } from "../services/ScanReportService";
import {
  classifyScanCoverage,
  type ScanResultStore,
} from "../services/ScanResultStore";

interface ScanWorkspaceServices {
  readonly logger: Logger;
  readonly workspaceScanner: WorkspaceDependencyScanner;
  readonly auditService: DependencyAuditService;
  readonly reportService: ScanReportService;
  readonly diagnosticManager: DiagnosticManager;
  readonly resultStore: ScanResultStore;
  readonly remediationSource: RemediationAnalysisSource;
  readonly getConfiguration: () => DependencyAuditorConfiguration;
}

interface PipelineOutcome {
  readonly cancelled: boolean;
  readonly result?: ScanResult;
}

export interface ScanExecutionOptions {
  /** Automatic scans remain observable through the status bar without opening UI. */
  readonly interactive?: boolean;
}

export interface RemediationValidationScanOptions {
  readonly signal: AbortSignal;
}

function isAborted(signal: AbortSignal): boolean {
  return signal.aborted;
}

function isCancellation(error: unknown, signal: AbortSignal): boolean {
  return (
    isAborted(signal) ||
    error instanceof vscode.CancellationError ||
    (error instanceof Error && error.name === "AbortError") ||
    (typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "CANCELLED")
  );
}

function workspaceLocation(folder: vscode.WorkspaceFolder): string {
  return folder.uri.scheme === "file"
    ? folder.uri.fsPath
    : `${folder.uri.scheme}:${folder.uri.path}`;
}

function aggregateWorkspaceLocation(
  folders: readonly vscode.WorkspaceFolder[],
): string {
  return folders.map(workspaceLocation).join("; ");
}

function deduplicateDependencies(
  dependencies: readonly Dependency[],
): readonly Dependency[] {
  return [
    ...new Map(
      dependencies.map((dependency) => [
        `${dependency.workspacePath ?? ""}\u0000${dependency.projectPath ?? ""}\u0000${dependencyManifestPath(dependency) ?? ""}\u0000${dependency.lockfilePath ?? ""}\u0000${dependency.ecosystem}\u0000${dependency.name}\u0000${dependency.installedVersion}\u0000${dependency.resolutionStatus ?? "resolved"}\u0000${dependency.dependencyPath?.join("\u0000") ?? ""}`,
        dependency,
      ]),
    ).values(),
  ];
}

function vulnerableDependencyCount(
  vulnerabilities: readonly Vulnerability[],
): number {
  return new Set(
    vulnerabilities.map(
      (vulnerability) =>
        `${vulnerability.ecosystem}\u0000${vulnerability.packageName}\u0000${vulnerability.installedVersion}`,
    ),
  ).size;
}

function suppressedVulnerabilityCount(result: ScanResult): number {
  const providerCount = result.providerResults.reduce(
    (total, provider) => total + provider.vulnerabilitiesFound,
    0,
  );
  return Math.max(0, providerCount - result.vulnerabilities.length);
}

function coverageIsIncomplete(result: ScanResult): boolean {
  return classifyScanCoverage([result]) !== "complete";
}

export class ScanWorkspaceCommand implements vscode.Disposable {
  private activeController: AbortController | undefined;
  private runSequence = 0;
  private remediationSuspended = false;

  public constructor(private readonly services: ScanWorkspaceServices) {}

  public async execute(options: ScanExecutionOptions = {}): Promise<void> {
    const interactive = options.interactive ?? true;
    if (this.remediationSuspended) {
      this.services.logger.warn(
        "Dependency scan refused while a remediation transaction owns the workspace",
      );
      if (interactive) {
        await vscode.window.showInformationMessage(
          "Wait for the active dependency remediation to finish before scanning.",
        );
      }
      return;
    }
    const folders = vscode.workspace.workspaceFolders;
    if (interactive) {
      this.services.logger.show(true);
    }

    if (folders === undefined || folders.length === 0) {
      this.services.logger.warn("No workspace folder is open");
      if (interactive) {
        await vscode.window.showWarningMessage(
          "Dependency Auditor: open a workspace folder before scanning.",
        );
      }
      return;
    }
    const configuration = this.services.getConfiguration();
    if (!configuration.enabled) {
      this.services.logger.warn("Dependency vulnerability scanning is disabled");
      if (interactive) {
        await vscode.window.showInformationMessage(
          "Dependency Auditor is disabled in Settings.",
        );
      }
      return;
    }

    this.activeController?.abort();
    const controller = new AbortController();
    this.activeController = controller;
    const runId = this.runSequence + 1;
    this.runSequence = runId;
    this.services.resultStore.setScanning(true);
    this.services.logger.info("Dependency vulnerability scan started");

    try {
      const outcome = await vscode.window.withProgress(
        {
          location: interactive
            ? vscode.ProgressLocation.Notification
            : vscode.ProgressLocation.Window,
          title: "Dependency Auditor: scanning dependencies...",
          cancellable: interactive,
        },
        async (progress, token): Promise<PipelineOutcome> => {
          const cancellationSubscription = token.onCancellationRequested(() => {
            controller.abort();
          });
          if (token.isCancellationRequested) {
            controller.abort();
          }
          try {
            const metadataBudget = registerDependencyMetadataBudget(
              controller.signal,
            );
            const recordBudget = registerDependencyRecordBudget(
              controller.signal,
            );
            let outcome: PipelineOutcome;
            try {
              outcome = await this.runPipeline(
                folders,
                progress,
                token,
                controller.signal,
                configuration,
              );
            } finally {
              recordBudget.dispose();
              metadataBudget.dispose();
            }
            if (
              outcome.cancelled ||
              outcome.result === undefined ||
              isAborted(controller.signal)
            ) {
              return outcome;
            }
            progress.report({ message: "Updating dependency diagnostics..." });
            const published = await this.publishResult(
              outcome.result,
              controller.signal,
            );
            return published ? outcome : { cancelled: true };
          } finally {
            cancellationSubscription.dispose();
          }
        },
      );

      if (runId !== this.runSequence) {
        return;
      }
      if (outcome.cancelled || isAborted(controller.signal)) {
        this.services.resultStore.recordCancelledAttempt();
        this.services.logger.warn("Dependency scan cancelled");
        if (interactive) {
          await vscode.window.showInformationMessage(
            "Dependency scan cancelled.",
          );
        }
        return;
      }

      const result = outcome.result;
      if (result === undefined) {
        throw new Error("Completed scan did not produce a result");
      }

      this.services.reportService.log(result);
      if (interactive) {
        await this.showSummary(result);
      }
    } catch (error: unknown) {
      if (runId !== this.runSequence) {
        return;
      }
      if (isCancellation(error, controller.signal)) {
        this.services.resultStore.recordCancelledAttempt();
        this.services.logger.warn("Dependency scan cancelled");
        if (interactive) {
          await vscode.window.showInformationMessage(
            "Dependency scan cancelled.",
          );
        }
        return;
      }
      this.services.logger.error("Unexpected dependency scan failure", error);
      if (interactive) {
        await vscode.window.showErrorMessage(
          "Dependency Auditor could not complete the scan. See the Output Channel for details.",
        );
      }
    } finally {
      // An older cancelled run must not hide the scanning state of its
      // replacement. Only the newest run owns the shared UI flag.
      if (runId === this.runSequence) {
        this.services.resultStore.setScanning(false);
      }
      if (this.activeController === controller) {
        this.activeController = undefined;
      }
    }
  }

  public dispose(): void {
    this.activeController?.abort();
    this.activeController = undefined;
    this.remediationSuspended = false;
  }

  /** Excludes public/background scans while a remediation owns validation. */
  public setRemediationSuspended(suspended: boolean): void {
    this.remediationSuspended = suspended;
  }

  public get remediationInProgress(): boolean {
    return this.remediationSuspended;
  }

  /** Cancels an in-flight run without disposing the reusable command. */
  public cancelActive(): void {
    if (this.activeController === undefined) {
      return;
    }
    this.activeController.abort();
    this.activeController = undefined;
    // Supersede the old run immediately so its catch/finally blocks cannot
    // publish a cancellation notification or clear a newer scan's UI state.
    this.runSequence += 1;
    this.services.resultStore.setScanning(false);
  }

  /**
   * Runs the existing discovery/provider pipeline without publishing results,
   * diagnostics, notifications, or status. The remediation transaction owns
   * publication only after it has validated and committed its writes.
   */
  public async scanForRemediationValidation(
    options: RemediationValidationScanOptions,
  ): Promise<ScanResult> {
    if (!this.remediationSuspended) {
      throw new Error("A remediation transaction does not own the validation scan");
    }
    if (this.activeController !== undefined || this.services.resultStore.scanning) {
      throw new Error("A dependency scan is already in progress");
    }
    if (options.signal.aborted) {
      throw new vscode.CancellationError();
    }
    const folders = vscode.workspace.workspaceFolders;
    if (folders === undefined || folders.length === 0) {
      throw new Error("No workspace folder is open");
    }
    const configured = this.services.getConfiguration();
    const validationConfiguration: DependencyAuditorConfiguration = {
      ...configured,
      enabled: true,
      minimumSeverity: "UNKNOWN",
    };
    const cancellationToken: vscode.CancellationToken = {
      get isCancellationRequested(): boolean {
        return options.signal.aborted;
      },
      onCancellationRequested: (listener) => {
        options.signal.addEventListener("abort", listener, { once: true });
        return new vscode.Disposable(() => {
          options.signal.removeEventListener("abort", listener);
        });
      },
    };
    const progress: vscode.Progress<{ increment?: number; message?: string }> = {
      report: () => undefined,
    };
    const metadataBudget = registerDependencyMetadataBudget(options.signal);
    const recordBudget = registerDependencyRecordBudget(options.signal);
    try {
      const outcome = await this.runPipeline(
        folders,
        progress,
        cancellationToken,
        options.signal,
        validationConfiguration,
      );
      if (outcome.cancelled || outcome.result === undefined) {
        throw new vscode.CancellationError();
      }
      return outcome.result;
    } finally {
      recordBudget.dispose();
      metadataBudget.dispose();
    }
  }

  /** Publishes a transaction-validated result without issuing another scan. */
  public async publishRemediationValidationResult(
    result: ScanResult,
    signal: AbortSignal,
  ): Promise<boolean> {
    const configuredSeverity = this.services.getConfiguration().minimumSeverity;
    const displayedResult: ScanResult = Object.freeze({
      ...result,
      vulnerabilities: Object.freeze(
        filterVulnerabilitiesBySeverity(
          result.vulnerabilities,
          configuredSeverity,
        ),
      ),
    });
    return this.publishResult(displayedResult, signal);
  }

  private async publishResult(
    result: ScanResult,
    signal: AbortSignal,
  ): Promise<boolean> {
    if (isAborted(signal)) {
      return false;
    }
    const coverage = classifyScanCoverage([result]);
    const shouldReplaceDiagnostics =
      coverage === "complete" ||
      coverage === "partial" ||
      this.services.resultStore.lastSuccessfulResult.length === 0;
    if (shouldReplaceDiagnostics) {
      const retained =
        coverage === "partial"
          ? this.services.resultStore.previewRetainedFindings([result])
          : { findings: [], truncated: false };
      const remediationAnalysis = this.services.remediationSource.analyze(
        [result],
        { signal },
      );
      const diagnosticsCommitted =
        await this.services.diagnosticManager.replace(
          [result],
          signal,
          retained.findings,
          remediationAnalysis,
        );
      if (!diagnosticsCommitted) {
        return false;
      }
      if (retained.truncated) {
        this.services.logger.warn(
          "Historical vulnerability diagnostics were truncated by the retained-finding safety limit",
        );
      }
    } else {
      this.services.logger.warn(
        "Retained diagnostics from the last complete scan because the latest vulnerability provider attempt is unavailable",
      );
    }

    // No await is permitted between the confirmed synchronous diagnostics
    // commit and store publication; the two surfaces remain coherent.
    this.services.resultStore.replace([result]);
    return true;
  }

  private async runPipeline(
    folders: readonly vscode.WorkspaceFolder[],
    progress: vscode.Progress<{ increment?: number; message?: string }>,
    cancellationToken: vscode.CancellationToken,
    signal: AbortSignal,
    configuration: DependencyAuditorConfiguration,
  ): Promise<PipelineOutcome> {
    const startedAt = Date.now();
    const scannedAt = new Date(startedAt).toISOString();
    const dependencies: Dependency[] = [];
    const errors: ScanError[] = [];
    const projectCoverage: ProjectCoverage[] = [];
    const detectedPackageManagers = new Set<string>();

    for (const folder of folders) {
      const safeName = sanitizeDisplayValue(folder.name);
      this.services.logger.info(
        `Scanning workspace: ${safeName} (${workspaceLocation(folder)})`,
      );
    }
    if (isAborted(signal)) {
      return { cancelled: true };
    }
    progress.report({ message: "Reading dependency metadata across workspaces" });
    try {
      const workspaceResult = await this.services.workspaceScanner.scanMany(
        folders.map((folder) => folder.uri),
        {
          includeDevDependencies: configuration.includeDevDependencies,
          includeTransitiveDependencies:
            configuration.includeTransitiveDependencies,
          enabledEcosystems: new Set(configuration.enabledEcosystems),
          cancellationToken,
        },
        signal,
      );
      if (workspaceResult.cancelled || isAborted(signal)) {
        return { cancelled: true };
      }
      for (const manager of workspaceResult.packageManagers) {
        detectedPackageManagers.add(manager);
      }
      dependencies.push(...workspaceResult.dependencies);
      errors.push(...workspaceResult.errors);
      projectCoverage.push(...workspaceResult.projectCoverage);
    } catch (error: unknown) {
      if (isCancellation(error, signal)) {
        return { cancelled: true };
      }
      this.services.logger.error(
        "Could not read dependency metadata across workspace folders",
        error,
      );
      errors.push({
        code: "WORKSPACE_ERROR",
        message: "Could not read dependency metadata across workspace folders",
        path: aggregateWorkspaceLocation(folders),
      });
    }

    const uniqueDependencies = filterDependencies(
      deduplicateDependencies(dependencies),
      configuration,
    );
    progress.report({
      message: `Preparing ${uniqueDependencies.length.toString()} resolved dependencies...`,
    });
    const audit = await this.services.auditService.audit(uniqueDependencies, {
      signal,
      onProgress: (auditProgress) => {
        if (!isAborted(signal)) {
          progress.report({
            message: `Checking ${auditProgress.completed.toString()} / ${auditProgress.total.toString()} dependencies...`,
          });
        }
      },
    });
    if (audit.cancelled || isAborted(signal)) {
      return { cancelled: true };
    }

    errors.push(...audit.errors);
    const coverage = buildCoverage(
      projectCoverage,
      uniqueDependencies,
      audit,
    );
    const vulnerabilities = filterVulnerabilitiesBySeverity(
      audit.vulnerabilities,
      configuration.minimumSeverity,
    );
    const result: ScanResult = {
      workspacePath: aggregateWorkspaceLocation(folders),
      scannedAt,
      durationMs: Math.max(0, Date.now() - startedAt),
      packageManagers: [...detectedPackageManagers].sort(),
      dependenciesScanned: audit.providerResult.dependenciesEligible,
      vulnerableDependencies: vulnerableDependencyCount(
        audit.vulnerabilities,
      ),
      vulnerabilities,
      dependencies: uniqueDependencies,
      errors,
      // Provider coverage/counts remain unfiltered. The severity setting is a
      // presentation policy and must never turn a known finding into a
      // provider-reported clean result.
      providerResults: [audit.providerResult],
      ecosystemCoverage: coverage.ecosystems,
      projectCoverage: coverage.projects,
      cancelled: false,
    };
    if (isAborted(signal)) {
      return { cancelled: true };
    }
    return { cancelled: false, result };
  }

  private async showSummary(result: ScanResult): Promise<void> {
    const vulnerabilityCount = result.vulnerabilities.length;
    const suppressedCount = suppressedVulnerabilityCount(result);
    const incomplete = coverageIsIncomplete(result);

    if (result.dependenciesScanned === 0) {
      await vscode.window.showWarningMessage(
        "Dependency Auditor found no resolved dependencies to audit. See the Output Channel for coverage details.",
      );
      return;
    }
    if (vulnerabilityCount > 0) {
      const filteredSuffix =
        suppressedCount === 0
          ? ""
          : ` ${suppressedCount.toString()} additional known finding(s) were hidden by the configured severity threshold.`;
      const suffix = incomplete ? " Coverage was incomplete." : "";
      await vscode.window.showWarningMessage(
        `Dependency Auditor found ${vulnerabilityCount.toString()} displayed known vulnerability record(s).${filteredSuffix}${suffix}`,
      );
      return;
    }
    if (suppressedCount > 0) {
      const suffix = incomplete ? " Coverage was also incomplete." : "";
      await vscode.window.showWarningMessage(
        `No findings met the configured severity threshold; ${suppressedCount.toString()} known finding(s) were hidden.${suffix}`,
      );
      return;
    }
    if (incomplete) {
      await vscode.window.showWarningMessage(
        "No known vulnerabilities were found, but scan coverage was incomplete. See the Output Channel for details.",
      );
      return;
    }
    await vscode.window.showInformationMessage(
      `No known vulnerabilities found in ${result.dependenciesScanned.toString()} audited dependencies.`,
    );
  }
}
