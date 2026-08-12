import * as vscode from "vscode";

import { ScanWorkspaceCommand } from "./commands/scanWorkspace";
import { DiagnosticManager } from "./diagnostics/DiagnosticManager";
import { isVulnerabilityArray } from "./models/validators";
import type { Vulnerability } from "./models/Vulnerability";
import { BunAdapter } from "./package-managers/bun/BunAdapter";
import { CargoAdapter } from "./package-managers/cargo/CargoAdapter";
import { ComposerAdapter } from "./package-managers/composer/ComposerAdapter";
import { GoModulesAdapter } from "./package-managers/go/GoModulesAdapter";
import { GradleAdapter } from "./package-managers/gradle/GradleAdapter";
import { MavenAdapter } from "./package-managers/maven/MavenAdapter";
import { NpmAdapter } from "./package-managers/npm/NpmAdapter";
import { NugetAdapter } from "./package-managers/nuget/NugetAdapter";
import { PipenvAdapter } from "./package-managers/pipenv/PipenvAdapter";
import { PnpmAdapter } from "./package-managers/pnpm/PnpmAdapter";
import { PoetryAdapter } from "./package-managers/poetry/PoetryAdapter";
import { PythonRequirementsAdapter } from "./package-managers/python/PythonRequirementsAdapter";
import { WorkspaceDependencyScanner } from "./package-managers/WorkspaceDependencyScanner";
import { YarnAdapter } from "./package-managers/yarn/YarnAdapter";
import { RemediationAnalyzer } from "./remediation/RemediationAnalyzer";
import type { RemediationAnalysisResult } from "./remediation/RemediationModels";
import {
  gitStateInspectorFromExtension,
  publicApplyError,
  RemediationApplyController,
  type GitExtensionLike,
} from "./remediation/apply";
import {
  readDependencyAuditorConfiguration,
  type DependencyAuditorConfiguration,
} from "./services/DependencyAuditorConfiguration";
import { DependencyAuditService } from "./services/DependencyAuditService";
import { OutputChannelLogger } from "./services/Logger";
import { NetworkService } from "./services/NetworkService";
import { ScanReportService } from "./services/ScanReportService";
import {
  ScanResultStore,
  type ScanResultStoreSnapshot,
} from "./services/ScanResultStore";
import { ScanTriggerController } from "./services/ScanTriggerController";
import { VulnerabilityCache } from "./services/VulnerabilityCache";
import { DependencyStatusBar } from "./status/DependencyStatusBar";
import {
  buildDependencyStatusModel,
  type DependencyStatusModel,
} from "./status/statusModel";
import { VulnerabilityTreeProvider } from "./tree/VulnerabilityTreeProvider";
import { OsvProvider } from "./vulnerability/providers/OsvProvider";
import { DashboardProvider } from "./webview/DashboardProvider";
import {
  REMEDIATION_CENTER_VIEW,
  RemediationCenterProvider,
} from "./webview/RemediationCenterProvider";
import { VulnerabilityDetailsProvider } from "./webview/VulnerabilityDetailsProvider";
import type { RemediationApplySnapshot } from "./webview/webviewTypes";

export const SCAN_WORKSPACE_COMMAND = "dependencyAuditor.scanWorkspace";
export const SHOW_DASHBOARD_COMMAND = "dependencyAuditor.showDashboard";
export const REFRESH_SCAN_COMMAND = "dependencyAuditor.refreshScan";
export const SHOW_VULNERABILITIES_COMMAND =
  "dependencyAuditor.showVulnerabilities";
export const REFRESH_DATABASE_COMMAND =
  "dependencyAuditor.refreshVulnerabilityDatabase";
export const SHOW_VULNERABILITY_DETAILS_COMMAND =
  "dependencyAuditor.showVulnerabilityDetails";
export const SHOW_REMEDIATION_COMMAND = "dependencyAuditor.showRemediation";
export const PREVIEW_FIX_COMMAND = "dependencyAuditor.previewFix";
export const APPLY_FIX_COMMAND = "dependencyAuditor.applyFix";
export const CANCEL_REMEDIATION_COMMAND =
  "dependencyAuditor.cancelRemediation";
export const SECURITY_TREE_VIEW = "dependencyAuditor.securityView";
export const OUTPUT_CHANNEL_NAME = "Dependency Vulnerability Auditor";

export interface DependencyAuditorTestApi {
  readonly getDashboardHtml: () => string | undefined;
  readonly getDetailsHtml: () => string | undefined;
  readonly getSnapshot: () => ScanResultStoreSnapshot;
  readonly getRemediationAnalysis: () => RemediationAnalysisResult;
  readonly getRemediationApplySnapshot: () => RemediationApplySnapshot;
  readonly getRemediationCenterHtml: () => string | undefined;
  readonly getStatusModel: () => DependencyStatusModel;
  readonly getTreeRootLabels: () => readonly string[];
}

export function activate(
  context: vscode.ExtensionContext,
): void | DependencyAuditorTestApi {
  const outputChannel = vscode.window.createOutputChannel(OUTPUT_CHANNEL_NAME);
  const logger = new OutputChannelLogger(outputChannel);
  const getConfiguration = (): DependencyAuditorConfiguration =>
    readDependencyAuditorConfiguration(
      vscode.workspace.getConfiguration("dependencyAuditor"),
    );
  const configuration = getConfiguration();

  const networkService = new NetworkService({
    allowedHosts: ["api.osv.dev"],
    timeoutMs: configuration.networkTimeout,
    maximumAttempts: 3,
  });
  const cache = new VulnerabilityCache<Vulnerability[]>(context.globalState, {
    ttlMs: Math.round(configuration.cacheDuration * 60 * 60 * 1_000),
    maximumEntries: 5_000,
    maximumEntryBytes: 2 * 1024 * 1024,
    maximumTotalBytes: 32 * 1024 * 1024,
    validateValue: isVulnerabilityArray,
  });
  const provider = new OsvProvider(networkService, logger, 5);
  const auditService = new DependencyAuditService(provider, cache, {
    maximumConcurrency: 5,
  });
  const workspaceScanner = new WorkspaceDependencyScanner(
    [
      new NpmAdapter(logger),
      new YarnAdapter(),
      new PnpmAdapter(),
      new BunAdapter(),
      new PythonRequirementsAdapter(),
      new PoetryAdapter(),
      new PipenvAdapter(),
      new MavenAdapter(),
      new GradleAdapter(),
      new CargoAdapter(),
      new GoModulesAdapter(),
      new NugetAdapter(),
      new ComposerAdapter(),
    ],
    logger,
    4,
  );
  const reportService = new ScanReportService(logger);
  const resultStore = new ScanResultStore();
  const remediationAnalyzer = new RemediationAnalyzer();
  const diagnosticManager = new DiagnosticManager(
    vscode.languages.createDiagnosticCollection("dependency-vulnerability-auditor"),
  );
  const scanWorkspaceCommand = new ScanWorkspaceCommand({
    logger,
    workspaceScanner,
    auditService,
    reportService,
    diagnosticManager,
    resultStore,
    remediationSource: remediationAnalyzer,
    getConfiguration,
  });
  const scanTriggerController = new ScanTriggerController({
    getConfiguration,
    scan: async (): Promise<void> => {
      await scanWorkspaceCommand.execute({ interactive: false });
    },
  });
  const remediationApplyController = new RemediationApplyController({
    resultStore,
    analysisSource: remediationAnalyzer,
    scanCommand: scanWorkspaceCommand,
    scanTriggerController,
    workspaceFolders: () => vscode.workspace.workspaceFolders ?? [],
    gitStateInspector: gitStateInspectorFromExtension(
      vscode.extensions.getExtension("vscode.git") as unknown as
        | GitExtensionLike
        | undefined,
    ),
  });

  const treeProvider = new VulnerabilityTreeProvider(
    resultStore,
    remediationAnalyzer,
    remediationApplyController,
  );
  const treeView = vscode.window.createTreeView(SECURITY_TREE_VIEW, {
    treeDataProvider: treeProvider,
    showCollapseAll: true,
  });
  const statusBar = new DependencyStatusBar(
    resultStore,
    remediationAnalyzer,
    remediationApplyController,
  );
  const detailsProvider = new VulnerabilityDetailsProvider(
    resultStore,
    context.extensionUri,
    remediationAnalyzer,
    remediationApplyController,
  );
  const executeRegisteredCommand = async (command: string): Promise<void> => {
    await vscode.commands.executeCommand(command);
  };
  const dashboardProvider = new DashboardProvider(
    resultStore,
    context.extensionUri,
    {
      scanWorkspace: async () => {
        await executeRegisteredCommand(SCAN_WORKSPACE_COMMAND);
      },
      refreshScan: async () => {
        await executeRegisteredCommand(REFRESH_SCAN_COMMAND);
      },
      showVulnerabilities: async () => {
        await executeRegisteredCommand(SHOW_VULNERABILITIES_COMMAND);
      },
      reviewFixes: async () => {
        await executeRegisteredCommand(SHOW_REMEDIATION_COMMAND);
      },
      showRemediationHistory: async () => {
        await executeRegisteredCommand(`${REMEDIATION_CENTER_VIEW}.focus`);
      },
    },
    remediationAnalyzer,
    remediationApplyController,
  );
  const remediationCenterProvider = new RemediationCenterProvider(
    resultStore,
    context.extensionUri,
    remediationAnalyzer,
    remediationApplyController,
    async () => {
      await executeRegisteredCommand(REFRESH_SCAN_COMMAND);
    },
  );
  const remediationCenterRegistration =
    vscode.window.registerWebviewViewProvider(
      REMEDIATION_CENTER_VIEW,
      remediationCenterProvider,
      { webviewOptions: { retainContextWhenHidden: false } },
    );

  const scanCommandRegistration = vscode.commands.registerCommand(
    SCAN_WORKSPACE_COMMAND,
    async (): Promise<void> => {
      await scanWorkspaceCommand.execute();
    },
  );
  const dashboardCommandRegistration = vscode.commands.registerCommand(
    SHOW_DASHBOARD_COMMAND,
    (): void => {
      dashboardProvider.show();
    },
  );
  const refreshScanCommandRegistration = vscode.commands.registerCommand(
    REFRESH_SCAN_COMMAND,
    async (): Promise<void> => {
      await scanWorkspaceCommand.execute();
    },
  );
  const showVulnerabilitiesCommandRegistration =
    vscode.commands.registerCommand(
      SHOW_VULNERABILITIES_COMMAND,
      async (): Promise<void> => {
        await vscode.commands.executeCommand(`${SECURITY_TREE_VIEW}.focus`);
      },
    );
  const refreshDatabaseCommandRegistration = vscode.commands.registerCommand(
    REFRESH_DATABASE_COMMAND,
    async (): Promise<void> => {
      if (scanWorkspaceCommand.remediationInProgress) {
        await vscode.window.showInformationMessage(
          "Wait for the active dependency remediation to finish before refreshing vulnerability data.",
        );
        return;
      }
      scanWorkspaceCommand.cancelActive();
      try {
        await cache.clear();
        logger.info("Vulnerability response cache cleared by user request");
      } catch (error: unknown) {
        logger.error("Could not clear the vulnerability response cache", error);
        await vscode.window.showErrorMessage(
          "Dependency Auditor could not refresh the vulnerability database cache. See the Output Channel for details.",
        );
        return;
      }
      await scanWorkspaceCommand.execute();
    },
  );
  const detailsCommandRegistration = vscode.commands.registerCommand(
    SHOW_VULNERABILITY_DETAILS_COMMAND,
    (identity: unknown): void => {
      detailsProvider.show(identity);
    },
  );
  const remediationCommandRegistration = vscode.commands.registerCommand(
    SHOW_REMEDIATION_COMMAND,
    async (): Promise<void> => {
      const snapshot = resultStore.getSnapshot();
      if (snapshot.lastSuccessfulResult.length === 0) {
        await vscode.window.showInformationMessage(
          "No scan results available. Run a dependency scan first.",
        );
        return;
      }
      dashboardProvider.showRemediation(
        snapshot.lastSuccessfulResult,
        snapshot.lastSuccessfulTimestamp,
      );
      await vscode.commands.executeCommand(`${REMEDIATION_CENTER_VIEW}.focus`);
    },
  );
  const previewFixCommandRegistration = vscode.commands.registerCommand(
    PREVIEW_FIX_COMMAND,
    async (recommendationKey: unknown): Promise<void> => {
      if (
        typeof recommendationKey !== "string" ||
        recommendationKey.length === 0 ||
        recommendationKey.length > 32_768
      ) {
        await vscode.window.showInformationMessage(
          "Open a vulnerability details view and select Review Fix to create a remediation preview.",
        );
        return;
      }
      try {
        await remediationApplyController.previewFix(recommendationKey);
      } catch (error: unknown) {
        await vscode.window.showWarningMessage(publicApplyError(error).message);
      }
    },
  );
  const applyFixCommandRegistration = vscode.commands.registerCommand(
    APPLY_FIX_COMMAND,
    async (previewId: unknown): Promise<void> => {
      const boundedPreviewId =
        typeof previewId === "string" &&
        /^[A-Za-z0-9_-]{43}$/u.test(previewId)
          ? previewId
          : "";
      try {
        await remediationApplyController.applyFix(boundedPreviewId);
      } catch (error: unknown) {
        await vscode.window.showWarningMessage(publicApplyError(error).message);
      }
    },
  );
  const cancelRemediationCommandRegistration = vscode.commands.registerCommand(
    CANCEL_REMEDIATION_COMMAND,
    async (previewId: unknown): Promise<void> => {
      if (previewId === undefined) {
        remediationApplyController.cancelRemediation();
        return;
      }
      if (
        typeof previewId === "string" &&
        /^[A-Za-z0-9_-]{43}$/u.test(previewId)
      ) {
        remediationApplyController.cancelRemediation(previewId);
      }
    },
  );
  const workspaceResetRegistration =
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
      scanWorkspaceCommand.cancelActive();
      diagnosticManager.clear();
      resultStore.clear();
      logger.info(
        "Workspace folders changed; cleared results and diagnostics from the previous workspace",
      );
    });

  context.subscriptions.push(
    outputChannel,
    resultStore,
    diagnosticManager,
    scanWorkspaceCommand,
    treeProvider,
    treeView,
    statusBar,
    dashboardProvider,
    detailsProvider,
    remediationCenterProvider,
    remediationCenterRegistration,
    scanTriggerController,
    remediationApplyController,
    scanCommandRegistration,
    dashboardCommandRegistration,
    refreshScanCommandRegistration,
    showVulnerabilitiesCommandRegistration,
    refreshDatabaseCommandRegistration,
    detailsCommandRegistration,
    remediationCommandRegistration,
    previewFixCommandRegistration,
    applyFixCommandRegistration,
    cancelRemediationCommandRegistration,
    workspaceResetRegistration,
  );
  logger.info("Extension activated");
  scanTriggerController.triggerStartupScan();

  // A read-only API is exposed only to an Extension Development/Test Host so
  // isolated smoke tests can verify otherwise non-enumerable VS Code UI state.
  if (context.extensionMode !== vscode.ExtensionMode.Production) {
    return Object.freeze({
      getDashboardHtml: (): string | undefined =>
        dashboardProvider.getRenderedHtml(),
      getDetailsHtml: (): string | undefined =>
        detailsProvider.getRenderedHtml(),
      getSnapshot: (): ScanResultStoreSnapshot => resultStore.getSnapshot(),
      getRemediationAnalysis: (): RemediationAnalysisResult =>
        remediationAnalyzer.analyze(resultStore.getSnapshot().results),
      getRemediationApplySnapshot: (): RemediationApplySnapshot =>
        remediationApplyController.getSnapshot(),
      getRemediationCenterHtml: (): string | undefined =>
        remediationCenterProvider.getRenderedHtml(),
      getStatusModel: (): DependencyStatusModel => {
        const snapshot = resultStore.getSnapshot();
        return Object.freeze(
          buildDependencyStatusModel(
            snapshot.results,
            snapshot.scanning,
            {
              latestAttemptCoverage: snapshot.latestAttemptCoverage,
              retainedFindings: snapshot.retainedFindings,
              retainedFindingsTruncated: snapshot.retainedFindingsTruncated,
              remediationAnalysis: remediationAnalyzer.analyze(
                snapshot.results,
              ),
            },
          ),
        );
      },
      getTreeRootLabels: (): readonly string[] =>
        Object.freeze(
          treeProvider.getChildren().map((item) => item.label),
        ),
    });
  }
}

export function deactivate(): void {
  // VS Code disposes all subscriptions registered by activate().
}
