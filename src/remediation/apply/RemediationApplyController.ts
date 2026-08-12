import { basename, relative, resolve, sep } from "node:path";
import { realpath } from "node:fs/promises";

import * as vscode from "vscode";

import type { ScanResult } from "../../models/ScanResult";
import { DEPENDENCY_FILE_GLOB } from "../../discovery/dependencyFiles";
import type { RemediationAnalysisSource } from "../RemediationAnalysisSource";
import type { RemediationRecommendation } from "../RemediationModels";
import type { ScanResultStore } from "../../services/ScanResultStore";
import type { ScanWorkspaceCommand } from "../../commands/scanWorkspace";
import type { ScanTriggerController } from "../../services/ScanTriggerController";
import type {
  DisposableLike,
  RemediationApplyController as RemediationApplyControllerView,
  RemediationApplySnapshot,
  RemediationCapabilityView,
  RemediationHistoryRecordView,
  RemediationPreviewView,
  RemediationScanCountsView,
} from "../../webview/webviewTypes";
import { ApplyError } from "./ApplyError";
import type { GitStateInspector } from "./GitStateInspector";
import type { ApplyResult, ScanCounts } from "./ApplyResult";
import { NodeRemediationFileSystem } from "./NodeRemediationFileSystem";
import { RemediationDiffProvider } from "./RemediationDiffProvider";
import {
  RemediationExecutor,
  type RecommendationVerifier,
  type RemediationApplyGuard,
  type RemediationScanVerifier,
} from "./RemediationExecutor";
import type { RemediationPlan } from "./RemediationPlan";
import { RemediationPlanner } from "./RemediationPlanner";
import { RemediationPreviewRegistry } from "./RemediationPreviewRegistry";
import {
  RemediationApprovalRegistry,
  remediationPlanHash,
} from "./RemediationApproval";
import {
  RemediationStateRegistry,
  type RemediationAuthoritySource,
  type RemediationState,
  type RemediationStateSnapshot,
  type RemediationTransitionContext,
} from "./RemediationStateMachine";

const APPROVE_LABEL = "Approve";
const APPLY_LABEL = "Apply";
const MAXIMUM_CAPABILITIES = 10_000;

export interface RemediationApplyControllerServices {
  readonly resultStore: ScanResultStore;
  readonly analysisSource: RemediationAnalysisSource;
  readonly scanCommand: ScanWorkspaceCommand;
  readonly scanTriggerController?: ScanTriggerController;
  /** Read-only projection of an already-active SCM provider. */
  readonly gitStateInspector?: GitStateInspector;
  readonly workspaceFolders: () => readonly vscode.WorkspaceFolder[];
  readonly showWarningMessage?: typeof vscode.window.showWarningMessage;
}

function scanGeneration(results: readonly ScanResult[]): string {
  return JSON.stringify(
    results.map((result) => [result.workspacePath, result.scannedAt]),
  );
}

function toCounts(counts: ScanCounts): RemediationScanCountsView {
  return Object.freeze({
    dependencies: counts.dependencies,
    vulnerabilities: counts.vulnerabilities,
    critical: counts.critical,
    high: counts.high,
    medium: counts.medium,
    low: counts.low,
  });
}

function capabilityReason(plan: RemediationPlan): string {
  return plan.warnings[0] ??
    (plan.capability === "safe"
      ? "A bounded, existing npm lock resolution can be reused without executing npm."
      : "Automatic modification is unavailable for this remediation.");
}

function historyView(
  result: ApplyResult,
  plan: RemediationPlan,
): RemediationHistoryRecordView {
  const comparison = result.verification?.comparison;
  return Object.freeze({
    id: result.transactionId ?? plan.id,
    recommendationKey: plan.recommendationKey,
    packageName: plan.expectedOutcome.packageName,
    currentVersion: plan.expectedOutcome.fromVersion,
    ...(plan.expectedOutcome.toVersion === undefined
      ? {}
      : { recommendedVersion: plan.expectedOutcome.toVersion }),
    status:
      result.status === "success"
        ? "successful"
        : result.status === "partial"
          ? "partial"
          : result.status === "cancelled"
            ? "cancelled"
            : "failed",
    vulnerabilitiesResolved: comparison?.resolved ?? 0,
    vulnerabilitiesRemaining: comparison?.remaining ?? 0,
    rolledBack: result.rollback?.attempted === true,
    ...(result.rollback === undefined
      ? {}
      : { rollbackVerified: result.rollback.verified }),
    message: result.message.slice(0, 512),
    timestamp: new Date().toISOString(),
    ...(comparison === undefined
      ? {}
      : {
          before: toCounts(comparison.before),
          after: toCounts(comparison.after),
        }),
  });
}

export class RemediationApplyController
  implements RemediationApplyControllerView, vscode.Disposable
{
  private readonly planner: RemediationPlanner;
  private readonly executor: RemediationExecutor;
  private readonly previews = new RemediationPreviewRegistry();
  private readonly approvals = new RemediationApprovalRegistry();
  private readonly remediationStates = new RemediationStateRegistry();
  private readonly diffProvider = new RemediationDiffProvider();
  private readonly listeners = new Set<
    (snapshot: RemediationApplySnapshot) => void
  >();
  private readonly storeSubscription: DisposableLike;
  private readonly invalidationSubscriptions: vscode.Disposable[] = [];
  private currentPreview: RemediationPreviewView | undefined;
  private activeController: AbortController | undefined;
  private activeOperation: RemediationApplySnapshot["activeOperation"];
  private readonly sessionHistory: RemediationHistoryRecordView[] = [];
  private lastResult: RemediationHistoryRecordView | undefined;
  private authorityGeneration = 0;
  private activePlan: RemediationPlan | undefined;
  private transactionAuthorityGeneration: number | undefined;
  private currentRemediationId: string | undefined;

  public constructor(private readonly services: RemediationApplyControllerServices) {
    const fileSystem = new NodeRemediationFileSystem();
    this.planner = new RemediationPlanner({
      fileUri: (path) => vscode.Uri.file(path),
      readFile: (uri) => fileSystem.readFile(uri),
      canGuaranteeAtomicReplace: (uri) =>
        fileSystem.canGuaranteeAtomicReplace(uri),
    });
    const guard: RemediationApplyGuard = {
      isWorkspaceTrusted: () => vscode.workspace.isTrusted,
      isScanInProgress: () => services.resultStore.scanning,
      isTargetInsideWorkspace: (uri) => this.isInsideTrustedWorkspace(uri),
      hasUnsavedChanges: (uri) =>
        vscode.workspace.textDocuments.some(
          (document) => document.isDirty && document.uri.toString() === uri.toString(),
        ),
      hasUnexpectedGitChanges: (uri) => {
        const assessment = services.gitStateInspector?.assess(uri);
        // SCM state is an additional refusal signal, never write authority.
        // If a future atomic adapter is introduced, an unavailable assessment
        // must fail closed until that adapter's policy explicitly proves a
        // stronger source-control invariant.
        return assessment !== undefined &&
          (!assessment.available || assessment.blocked);
      },
    };
    const recommendationVerifier: RecommendationVerifier = {
      verifyRecommendation: (plan) => this.recommendationIsCurrent(plan),
      verifyRegistryProvenance: (plan) => this.recommendationIsCurrent(plan),
    };
    const scanVerifier: RemediationScanVerifier = {
      getBeforeResults: () => services.resultStore.getSnapshot().results,
      rescan: async (_plan, signal) => {
        const controller = signal ?? new AbortController().signal;
        return [
          await services.scanCommand.scanForRemediationValidation({
            signal: controller,
          }),
        ];
      },
    };
    this.executor = new RemediationExecutor({
      fileSystem,
      guard,
      recommendationVerifier,
      scanVerifier,
    });
    this.storeSubscription = services.resultStore.onDidChange(() =>
      this.authorityChanged("scan-results"),
    );
    const dependencyWatcher = vscode.workspace.createFileSystemWatcher(
      DEPENDENCY_FILE_GLOB,
    );
    this.invalidationSubscriptions.push(
      dependencyWatcher,
      dependencyWatcher.onDidCreate((uri) => this.dependencyMetadataChanged(uri)),
      dependencyWatcher.onDidChange((uri) => this.dependencyMetadataChanged(uri)),
      dependencyWatcher.onDidDelete((uri) => this.dependencyMetadataChanged(uri)),
      vscode.workspace.onDidChangeWorkspaceFolders(() =>
        this.authorityChanged("workspace-folders"),
      ),
      vscode.workspace.onDidChangeConfiguration((event) => {
        if (event.affectsConfiguration("dependencyAuditor")) {
          this.authorityChanged("configuration");
        }
      }),
      vscode.workspace.onDidChangeTextDocument((event) => {
        if (
          this.currentPreview !== undefined &&
          this.previewTargets(event.document.uri)
        ) {
          this.authorityChanged("dependency-files");
        }
      }),
      vscode.workspace.onDidGrantWorkspaceTrust(() =>
        this.authorityChanged("workspace-trust"),
      ),
    );
    const gitSubscription = services.gitStateInspector?.onDidChange?.(() =>
      this.authorityChanged("git"),
    );
    if (gitSubscription !== undefined) {
      this.invalidationSubscriptions.push(gitSubscription as vscode.Disposable);
    }
    if (services.gitStateInspector?.dispose !== undefined) {
      this.invalidationSubscriptions.push({
        dispose: () => services.gitStateInspector?.dispose?.(),
      });
    }
  }

  public getSnapshot(): RemediationApplySnapshot {
    return Object.freeze({
      capabilities: this.capabilities(),
      ...(this.currentPreview === undefined
        ? {}
        : { preview: this.currentPreview }),
      ...(this.activeOperation === undefined
        ? {}
        : { activeOperation: this.activeOperation }),
      history: Object.freeze([...this.sessionHistory]),
      ...(this.lastResult === undefined ? {} : { lastResult: this.lastResult }),
      lifecycles: Object.freeze(
        this.remediationStates.getAll().map((snapshot) =>
          Object.freeze({
            remediationId: snapshot.remediationId,
            recommendationKey: snapshot.recommendationKey,
            state: snapshot.state,
            createdAt: snapshot.createdAt,
            updatedAt: snapshot.updatedAt,
            transitions: Object.freeze(
              snapshot.transitions.map((transition) =>
                Object.freeze({
                  sequence: transition.sequence,
                  ...(transition.from === undefined
                    ? {}
                    : { from: transition.from }),
                  to: transition.to,
                  reason: transition.reason,
                  timestamp: transition.timestamp,
                  ...(transition.errorCode === undefined
                    ? {}
                    : { errorCode: transition.errorCode }),
                }),
              ),
            ),
          }),
        ),
      ),
    });
  }

  public onDidChange(
    listener: (snapshot: RemediationApplySnapshot) => void,
  ): DisposableLike {
    this.listeners.add(listener);
    return { dispose: () => this.listeners.delete(listener) };
  }

  public async previewFix(recommendationKey: string): Promise<void> {
    if (this.activeController !== undefined) {
      throw new ApplyError("CONCURRENT_REMEDIATION");
    }
    const recommendation = this.currentRecommendation(recommendationKey);
    if (recommendation === undefined) throw new ApplyError("STALE_RECOMMENDATION");
    const authorityGeneration = this.authorityGeneration;
    this.rejectCurrentProposal("cancelled-before-apply");
    this.approvals.invalidateAll();
    this.previews.invalidateAll();
    this.diffProvider.clear();
    this.currentPreview = undefined;
    const controller = new AbortController();
    this.activeController = controller;
    this.activeOperation = Object.freeze({
      stage: "previewing",
      recommendationKey,
      message: "Generating a read-only remediation preview...",
      cancellable: true,
    });
    this.fire();
    try {
      const results = this.currentCompleteResults();
      const generation = scanGeneration(results);
      const plan = await this.planner.plan(recommendation, {
        signal: controller.signal,
        scanGeneration: generation,
      });
      if (
        this.authorityGeneration !== authorityGeneration ||
        scanGeneration(this.currentCompleteResults()) !== generation
      ) {
        throw new ApplyError("STALE_RECOMMENDATION");
      }
      const record = this.previews.issue(plan);
      const remediationId = record.token;
      this.remediationStates.create({
        remediationId,
        recommendationKey: plan.recommendationKey,
        planHash: remediationPlanHash(plan),
      });
      if (plan.capability === "safe") {
        this.remediationStates.transition(remediationId, "awaitingApproval", {
          reason: "approval-requested",
        });
      } else if (plan.capability === "unsupported") {
        this.remediationStates.transition(remediationId, "unsupported", {
          reason: "capability-unsupported",
        });
      } else {
        const hasDeterministicPatch = plan.files.some(
          (file) => file.unifiedDiff !== undefined && file.afterHash !== undefined,
        );
        this.remediationStates.transition(
          remediationId,
          hasDeterministicPatch
            ? "manualActionRequired"
            : "manualReviewRequired",
          {
            reason: hasDeterministicPatch
              ? "manual-action-required"
              : "manual-review-required",
          },
        );
      }
      this.currentRemediationId = remediationId;
      const preview = this.previewView(record.token, plan);
      this.currentPreview = preview;
      this.activeOperation = Object.freeze({
        stage: "preview-ready",
        recommendationKey,
        previewId: record.token,
        message:
          plan.capability === "safe"
            ? "Preview ready. Explicit approval is required before Apply."
            : capabilityReason(plan),
        cancellable: true,
      });
    } catch (error: unknown) {
      this.approvals.invalidateAll();
      this.previews.invalidateAll();
      this.diffProvider.clear();
      this.currentPreview = undefined;
      this.activeOperation = undefined;
      throw error;
    } finally {
      this.activeController = undefined;
      this.fire();
    }
  }

  /**
   * Records a distinct, exact-proposal approval. This does not write files;
   * Apply still requires a second confirmation and a freshly rebuilt plan.
   */
  public async approveFix(previewId: string): Promise<string | undefined> {
    if (this.activeController !== undefined) {
      throw new ApplyError("CONCURRENT_REMEDIATION");
    }
    const remediationId = this.currentRemediationId;
    const record = this.previews.peek(previewId);
    const lifecycle =
      remediationId === undefined
        ? undefined
        : this.remediationStates.get(remediationId);
    if (
      record === undefined ||
      this.currentPreview?.id !== previewId ||
      remediationId !== previewId ||
      lifecycle?.state !== "awaitingApproval" ||
      record.plan.capability !== "safe"
    ) {
      await vscode.window.showInformationMessage(
        "Create an applicable remediation preview before approving a fix.",
      );
      return undefined;
    }
    const authorityGeneration = this.authorityGeneration;
    const showWarning =
      this.services.showWarningMessage ?? vscode.window.showWarningMessage;
    const approval = await showWarning(
      this.approvalMessage(record.plan),
      { modal: true },
      APPROVE_LABEL,
    );
    if (
      approval !== APPROVE_LABEL ||
      this.authorityGeneration !== authorityGeneration
    ) {
      if (approval !== APPROVE_LABEL) {
        this.transitionIf(remediationId, ["awaitingApproval"], "rejected", {
          reason: "user-rejected",
        });
        this.discardPreview(previewId);
      } else {
        this.invalidateAuthority("external", remediationId);
      }
      this.approvals.invalidateAll();
      return undefined;
    }
    const approvalRecord = this.approvals.issue(
      record.plan,
      previewId,
      remediationId,
    );
    this.remediationStates.transition(remediationId, "approved", {
      reason: "user-approved",
      approvalHash: approvalRecord.approvalHash,
    });
    this.activeOperation = Object.freeze({
      stage: "preview-ready",
      recommendationKey: record.plan.recommendationKey,
      previewId,
      message: "Approved. Apply requires a final confirmation and revalidation.",
      cancellable: true,
    });
    this.fire();
    return approvalRecord.id;
  }

  public async applyFix(previewId: string): Promise<void> {
    if (this.activeController !== undefined) throw new ApplyError("CONCURRENT_REMEDIATION");
    const record = this.previews.peek(previewId);
    const remediationId = this.currentRemediationId;
    const lifecycle =
      remediationId === undefined
        ? undefined
        : this.remediationStates.get(remediationId);
    if (
      record === undefined ||
      this.currentPreview?.id !== previewId ||
      remediationId !== previewId ||
      lifecycle?.state !== "approved" ||
      record.plan.capability !== "safe"
    ) {
      await vscode.window.showInformationMessage(
        "Create and explicitly approve a remediation preview before applying a fix.",
      );
      return;
    }
    const authorityGeneration = this.authorityGeneration;
    let rebuiltPlan: RemediationPlan;
    try {
      const recommendation = this.currentRecommendation(record.plan.recommendationKey);
      if (recommendation === undefined) throw new ApplyError("STALE_RECOMMENDATION");
      const results = this.currentCompleteResults();
      const generation = scanGeneration(results);
      rebuiltPlan = await this.planner.plan(recommendation, {
        scanGeneration: generation,
      });
      const validation = this.approvals.validate(
        previewId,
        remediationId,
        rebuiltPlan,
      );
      if (
        !validation.valid ||
        authorityGeneration !== this.authorityGeneration ||
        generation !== scanGeneration(this.currentCompleteResults())
      ) {
        this.markApprovalStale(
          remediationId,
          validation.valid
            ? "authority-changed"
            : validation.reason === "expired"
              ? "approval-expired"
              : "approval-mismatch",
        );
        await vscode.window.showWarningMessage(
          "This remediation is no longer valid. The project changed after approval.",
        );
        return;
      }
    } catch (error: unknown) {
      this.markApprovalStale(remediationId, "approval-mismatch");
      if (error instanceof ApplyError && error.code === "CONCURRENT_REMEDIATION") {
        throw error;
      }
      await vscode.window.showWarningMessage(
        "This remediation is no longer valid. The project changed after approval.",
      );
      return;
    }
    const showWarning = this.services.showWarningMessage ?? vscode.window.showWarningMessage;
    const approval = await showWarning(
      this.finalApplyMessage(rebuiltPlan),
      { modal: true },
      APPLY_LABEL,
    );
    if (approval !== APPLY_LABEL) {
      this.transitionIf(remediationId, ["approved"], "rejected", {
        reason: "cancelled-before-apply",
      });
      this.approvals.invalidateAll();
      this.discardPreview(previewId);
      return;
    }
    if (authorityGeneration !== this.authorityGeneration) {
      this.markApprovalStale(remediationId, "authority-changed");
      await vscode.window.showWarningMessage(
        "This remediation is no longer valid. The project changed after approval.",
      );
      return;
    }
    const consumedApproval = this.approvals.consume(
      previewId,
      remediationId,
      rebuiltPlan,
    );
    if (!consumedApproval.valid) {
      this.markApprovalStale(
        remediationId,
        consumedApproval.reason === "expired"
          ? "approval-expired"
          : "approval-mismatch",
      );
      await vscode.window.showWarningMessage(
        "This remediation is no longer valid. The project changed after approval.",
      );
      return;
    }
    const consumed = this.previews.consume(previewId);
    if (consumed === undefined) throw new ApplyError("PREVIEW_REQUIRED");
    this.remediationStates.transition(remediationId, "validating", {
      reason: "validation-started",
      approvalHash: consumedApproval.record.approvalHash,
    });
    const controller = new AbortController();
    this.activeController = controller;
    this.activePlan = rebuiltPlan;
    this.transactionAuthorityGeneration = this.authorityGeneration;
    this.services.scanCommand.setRemediationSuspended(true);
    this.services.scanTriggerController?.setRemediationSuspended(true);
    this.activeOperation = Object.freeze({
      stage: "applying",
      recommendationKey: rebuiltPlan.recommendationKey,
      previewId,
      message: "Applying the approved transaction...",
      cancellable: true,
    });
    this.fire();
    try {
      this.remediationStates.transition(remediationId, "applying", {
        reason: "apply-started",
        approvalHash: consumedApproval.record.approvalHash,
      });
      const result = await this.executor.execute(rebuiltPlan, {
        approved: true,
        signal: controller.signal,
      });
      if (
        (result.status === "success" || result.status === "partial") &&
        result.verification?.results[0] !== undefined
      ) {
        await this.services.scanCommand.publishRemediationValidationResult(
          result.verification.results[0],
          new AbortController().signal,
        );
      }
      this.recordExecutionState(
        remediationId,
        consumedApproval.record.approvalHash,
        result,
      );
      const view = historyView(result, rebuiltPlan);
      this.lastResult = view;
      this.sessionHistory.unshift(view);
      this.sessionHistory.length = Math.min(this.sessionHistory.length, 100);
      if (result.rollback?.verified === false) {
        await vscode.window.showErrorMessage(result.message, { modal: true });
      } else if (result.status === "success") {
        await vscode.window.showInformationMessage(result.message);
      } else {
        await vscode.window.showWarningMessage(result.message);
      }
    } finally {
      this.currentPreview = undefined;
      this.diffProvider.revoke(previewId);
      this.services.scanCommand.setRemediationSuspended(false);
      this.services.scanTriggerController?.setRemediationSuspended(false);
      this.activeOperation = undefined;
      this.activeController = undefined;
      this.activePlan = undefined;
      this.transactionAuthorityGeneration = undefined;
      this.fire();
    }
  }

  public cancelRemediation(previewId?: string): void {
    if (previewId !== undefined) {
      this.rejectProposal(previewId, "cancelled-before-apply");
      this.approvals.invalidateAll();
      this.previews.revoke(previewId);
      this.diffProvider.revoke(previewId);
      if (this.currentPreview?.id === previewId) this.currentPreview = undefined;
      if (this.activeOperation?.previewId === previewId) {
        this.activeOperation = undefined;
      }
    } else if (this.activeController === undefined) {
      this.rejectCurrentProposal("cancelled-before-apply");
      this.approvals.invalidateAll();
      this.previews.invalidateAll();
      this.diffProvider.clear();
      this.currentPreview = undefined;
      if (this.activeOperation?.stage === "preview-ready") {
        this.activeOperation = undefined;
      }
    }
    this.activeController?.abort();
    this.fire();
  }

  public async showPreviewDiff(
    previewId: string,
    fileIndex: number,
  ): Promise<void> {
    const record = this.previews.peek(previewId);
    const file = record?.plan.files[fileIndex];
    if (
      record === undefined ||
      this.currentPreview?.id !== previewId ||
      file?.beforeContent === undefined ||
      file.afterContent === undefined
    ) {
      return;
    }
    const entry = this.diffProvider.register(
      previewId,
      fileIndex,
      file.beforeContent,
      file.afterContent,
    );
    if (entry === undefined) {
      await vscode.window.showWarningMessage(
        "This remediation diff exceeds the safe native-preview limit.",
      );
      return;
    }
    await this.diffProvider.show(
      previewId,
      `Dependency Remediation Preview — ${basename(file.uri.fsPath)}`,
    );
  }

  public async copyPatch(previewId: string, fileIndex: number): Promise<void> {
    const record = this.previews.peek(previewId);
    const file = record?.plan.files[fileIndex];
    const diff = file?.unifiedDiff;
    if (
      record === undefined ||
      this.currentPreview?.id !== previewId ||
      diff === undefined ||
      diff.length === 0
    ) {
      await vscode.window.showInformationMessage(
        "Create a remediation preview before copying a patch.",
      );
      return;
    }
    await vscode.env.clipboard.writeText(diff);
    await vscode.window.showInformationMessage(
      "Remediation patch copied. No workspace files were modified.",
    );
  }

  public async openAffectedFile(
    previewId: string,
    fileIndex: number,
  ): Promise<void> {
    const record = this.previews.peek(previewId);
    const file = record?.plan.files[fileIndex];
    if (
      record === undefined ||
      this.currentPreview?.id !== previewId ||
      file === undefined
    ) {
      await vscode.window.showInformationMessage(
        "Create a remediation preview before opening a target file.",
      );
      return;
    }
    if (!(await this.isInsideTrustedWorkspace(file.uri))) {
      await vscode.window.showWarningMessage(
        "The remediation target is no longer inside a trusted workspace.",
      );
      return;
    }
    const document = await vscode.workspace.openTextDocument(file.uri);
    await vscode.window.showTextDocument(document, { preview: false });
  }

  public invalidatePreviews(): void {
    this.approvals.invalidateAll();
    this.invalidateAuthority("external");
    this.previews.invalidateAll();
    this.diffProvider.clear();
    this.currentPreview = undefined;
    if (this.activeOperation?.stage === "preview-ready") {
      this.activeOperation = undefined;
    }
    this.fire();
  }

  public dispose(): void {
    this.activeController?.abort();
    this.storeSubscription.dispose();
    for (const subscription of this.invalidationSubscriptions.splice(0)) {
      subscription.dispose();
    }
    this.previews.dispose();
    this.approvals.dispose();
    this.remediationStates.clear();
    this.diffProvider.dispose();
    this.listeners.clear();
  }

  /** Immutable lifecycle for one remediation proposal, if still retained. */
  public getRemediationState(
    remediationId: string,
  ): RemediationStateSnapshot | undefined {
    return this.remediationStates.get(remediationId);
  }

  /** Bounded, newest-first session lifecycle history. */
  public getRemediationStateHistory(): readonly RemediationStateSnapshot[] {
    return this.remediationStates.getAll();
  }

  /**
   * Revokes all approval/preview authority after an external read-only signal.
   * A Git inspector may call this; the controller never performs Git writes.
   */
  public invalidateRemediationAuthority(
    source: RemediationAuthoritySource = "external",
  ): void {
    this.authorityChanged(source);
  }

  private currentCompleteResults(): readonly ScanResult[] {
    const snapshot = this.services.resultStore.getSnapshot();
    if (
      snapshot.scanning ||
      snapshot.latestAttemptCoverage !== "complete" ||
      snapshot.latestAttemptTimestamp !== snapshot.lastSuccessfulTimestamp ||
      snapshot.retainedFindings.length > 0
    ) {
      throw new ApplyError("STALE_RECOMMENDATION");
    }
    const findingsReported = snapshot.latestAttempt.reduce(
      (total, result) =>
        total +
        result.providerResults.reduce(
          (providerTotal, provider) =>
            providerTotal + provider.vulnerabilitiesFound,
          0,
        ),
      0,
    );
    const findingsStored = snapshot.latestAttempt.reduce(
      (total, result) => total + result.vulnerabilities.length,
      0,
    );
    if (findingsReported > findingsStored) {
      throw new ApplyError(
        "INCOMPLETE_COVERAGE",
        "Remediation preview requires a complete scan with minimum severity UNKNOWN so no known findings are suppressed.",
      );
    }
    return snapshot.latestAttempt;
  }

  private recommendations(): readonly RemediationRecommendation[] {
    return this.services.analysisSource.analyze(this.currentCompleteResults())
      .recommendations;
  }

  private currentRecommendation(key: string): RemediationRecommendation | undefined {
    if (typeof key !== "string" || key.length === 0 || key.length > 32_768) return undefined;
    const matches = this.recommendations().filter(
      (recommendation) => recommendation.recommendationKey === key,
    );
    return matches.length === 1 ? matches[0] : undefined;
  }

  private recommendationIsCurrent(plan: RemediationPlan): boolean {
    try {
      const results = this.currentCompleteResults();
      const recommendation = this.currentRecommendation(plan.recommendationKey);
      return (
        recommendation !== undefined &&
        recommendation.currentVersion === plan.expectedOutcome.fromVersion &&
        recommendation.recommendedVersion === plan.expectedOutcome.toVersion &&
        plan.scanGeneration === scanGeneration(results) &&
        (this.transactionAuthorityGeneration === undefined ||
          this.transactionAuthorityGeneration === this.authorityGeneration)
      );
    } catch {
      return false;
    }
  }

  private capabilities(): readonly RemediationCapabilityView[] {
    let recommendations: readonly RemediationRecommendation[];
    try {
      recommendations = this.recommendations();
    } catch {
      return Object.freeze([]);
    }
    return Object.freeze(
      recommendations.slice(0, MAXIMUM_CAPABILITIES).map((recommendation) => {
        let capability: RemediationCapabilityView["capability"] = "unsupported";
        let reason = "No exact automatic remediation is available.";
        if (recommendation.recommendedVersion !== undefined) {
          capability = "preview-only";
          reason =
            recommendation.dependency.ecosystem === "npm" &&
            recommendation.dependency.packageManager === "npm" &&
            recommendation.strategy === "upgrade-direct"
              ? "Generate a bounded preview to determine whether the local host can prove safe atomic npm application."
              : "Review only; safe lockfile resolution is not established for automatic apply.";
        }
        if (
          this.currentPreview?.recommendationKey ===
          recommendation.recommendationKey
        ) {
          capability = this.currentPreview.capability;
          reason =
            capability === "safe"
              ? "The generated preview proved a bounded existing npm lock resolution."
              : this.currentPreview.warnings[0] ?? reason;
        }
        return Object.freeze({
          recommendationKey: recommendation.recommendationKey,
          capability,
          reason,
        });
      }),
    );
  }

  private previewView(token: string, plan: RemediationPlan): RemediationPreviewView {
    return Object.freeze({
      id: token,
      recommendationKey: plan.recommendationKey,
      capability: plan.capability,
      packageName: plan.expectedOutcome.packageName,
      currentVersion: plan.expectedOutcome.fromVersion,
      ...(plan.expectedOutcome.toVersion === undefined
        ? {}
        : { recommendedVersion: plan.expectedOutcome.toVersion }),
      confidence: plan.recommendation.confidence,
      vulnerabilitiesAddressed: plan.expectedOutcome.expectedAddressed,
      totalVulnerabilities: plan.recommendation.vulnerabilityIds.length,
      files: Object.freeze(
        plan.files.map((file) =>
          Object.freeze({
            displayPath: basename(file.uri.fsPath),
            description: file.description,
            beforeHash: file.beforeHash,
            ...(file.afterHash === undefined ? {} : { afterHash: file.afterHash }),
            unifiedDiff: file.unifiedDiff ?? "",
            ...(this.services.gitStateInspector === undefined
              ? {}
              : {
                  gitState: this.services.gitStateInspector.assess(file.uri)
                    .state,
                }),
          }),
        ),
      ),
      warnings: Object.freeze([...plan.warnings]),
      valid: true,
      createdAt: new Date().toISOString(),
    });
  }

  private async isInsideTrustedWorkspace(uri: vscode.Uri): Promise<boolean> {
    if (uri.scheme !== "file" || !vscode.workspace.isTrusted) return false;
    const target = await realpath(resolve(uri.fsPath)).catch(() => undefined);
    if (target === undefined) return false;
    for (const folder of this.services.workspaceFolders()) {
      if (folder.uri.scheme !== "file") continue;
      const root = await realpath(resolve(folder.uri.fsPath)).catch(() => undefined);
      if (root === undefined) continue;
      const rel = relative(root, target);
      if (rel === "" || (!rel.startsWith(`..${sep}`) && rel !== "..")) return true;
    }
    return false;
  }

  private previewTargets(uri: vscode.Uri): boolean {
    const previewId = this.currentPreview?.id;
    const record = previewId === undefined ? undefined : this.previews.peek(previewId);
    return (
      record?.plan.files.some(
        (change) => change.uri.toString() === uri.toString(),
      ) === true
    );
  }

  private authorityChanged(source: RemediationAuthoritySource): void {
    this.authorityGeneration += 1;
    this.approvals.invalidateAll();
    this.invalidateAuthority(source);
    if (this.activeController === undefined) {
      this.invalidatePreviews();
    }
  }

  private dependencyMetadataChanged(uri: vscode.Uri): void {
    if (
      this.activePlan?.files.some(
        (change) => change.uri.toString() === uri.toString(),
      ) === true
    ) {
      // The executor performs stronger per-write identity/hash checks for its
      // own targets. Other dependency/config changes still revoke authority.
      return;
    }
    this.authorityChanged("dependency-files");
  }

  private approvalMessage(plan: RemediationPlan): string {
    const recommendation = plan.recommendation;
    const affectedFiles = plan.files
      .map((file) => basename(file.uri.fsPath))
      .join(", ");
    return [
      "Approve this exact dependency remediation proposal?",
      `${this.safeMessage(recommendation.dependency.name)}: ${this.safeMessage(recommendation.currentVersion)} -> ${this.safeMessage(recommendation.recommendedVersion ?? "unknown")}`,
      `Vulnerabilities: ${recommendation.vulnerabilityIds.map((id) => this.safeMessage(id)).join(", ")}`,
      `Confidence: ${recommendation.confidence.toUpperCase()}`,
      `Files: ${this.safeMessage(affectedFiles)}`,
      "Approval does not modify files. Apply requires a separate confirmation.",
    ].join("\n");
  }

  private finalApplyMessage(plan: RemediationPlan): string {
    const files = plan.files
      .map((file) => basename(file.uri.fsPath))
      .join(", ");
    return [
      `You are about to modify: ${this.safeMessage(files)}`,
      `${this.safeMessage(plan.expectedOutcome.packageName)}: ${this.safeMessage(plan.expectedOutcome.fromVersion)} -> ${this.safeMessage(plan.expectedOutcome.toVersion ?? "unknown")}`,
      "This exact action will be revalidated and rolled back if verification fails. Continue?",
    ].join("\n");
  }

  private safeMessage(value: string): string {
    return value
      .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/gu, "?")
      .slice(0, 512);
  }

  private transitionIf(
    remediationId: string,
    allowed: readonly RemediationState[],
    to: RemediationState,
    context: RemediationTransitionContext,
  ): void {
    const snapshot = this.remediationStates.get(remediationId);
    if (snapshot !== undefined && allowed.includes(snapshot.state)) {
      this.remediationStates.transition(remediationId, to, context);
    }
  }

  private rejectProposal(
    remediationId: string,
    reason: "cancelled-before-apply" | "user-rejected",
  ): void {
    this.transitionIf(
      remediationId,
      ["preview", "awaitingApproval", "approved"],
      "rejected",
      { reason },
    );
  }

  private rejectCurrentProposal(
    reason: "cancelled-before-apply" | "user-rejected",
  ): void {
    if (this.currentRemediationId !== undefined) {
      this.rejectProposal(this.currentRemediationId, reason);
    }
  }

  private invalidateAuthority(
    source: RemediationAuthoritySource,
    remediationId = this.currentRemediationId,
  ): void {
    if (remediationId !== undefined) {
      this.remediationStates.invalidate(remediationId, source);
    }
  }

  private markApprovalStale(
    remediationId: string,
    reason: "authority-changed" | "approval-expired" | "approval-mismatch",
  ): void {
    this.approvals.invalidateAll();
    this.transitionIf(
      remediationId,
      ["preview", "awaitingApproval", "approved", "validating"],
      "stale",
      { reason },
    );
    this.discardPreview(remediationId);
  }

  private discardPreview(previewId: string): void {
    this.previews.revoke(previewId);
    this.diffProvider.revoke(previewId);
    if (this.currentPreview?.id === previewId) {
      this.currentPreview = undefined;
    }
    if (this.activeOperation?.previewId === previewId) {
      this.activeOperation = undefined;
    }
    this.fire();
  }

  private recordExecutionState(
    remediationId: string,
    approvalHash: string,
    result: ApplyResult,
  ): void {
    const transaction =
      result.transactionId === undefined
        ? {}
        : { transactionId: result.transactionId };
    if (result.status === "success" || result.status === "partial") {
      this.remediationStates.transition(remediationId, "verifying", {
        reason: "verification-started",
        approvalHash,
        ...transaction,
      });
      const comparison = result.verification?.comparison;
      const finalState: RemediationState =
        result.status === "success" &&
        comparison !== undefined &&
        comparison.targetedAfter === 0 &&
        comparison.coverageComplete
          ? "verifiedFixed"
          : comparison?.coverageComplete === false
            ? "incompleteCoverage"
            : comparison !== undefined && comparison.targetedAfter > 0
              ? "stillVulnerable"
              : "providerUnavailable";
      const reason =
        finalState === "verifiedFixed"
          ? "verified-fixed"
          : finalState === "stillVulnerable"
            ? "still-vulnerable"
            : finalState === "incompleteCoverage"
              ? "incomplete-coverage"
              : "provider-unavailable";
      this.remediationStates.transition(remediationId, finalState, {
        reason,
        approvalHash,
        ...transaction,
      });
      return;
    }
    this.remediationStates.transition(remediationId, "failed", {
      reason:
        result.errorCode === "VALIDATION_FAILED" ||
        result.errorCode === "RESCAN_FAILED" ||
        result.errorCode === "INCOMPLETE_COVERAGE" ||
        result.errorCode === "TARGET_REMAINS"
          ? "verification-failed"
          : "operation-failed",
      approvalHash,
      ...transaction,
      errorCode: result.errorCode ?? "UNEXPECTED",
    });
    if (result.rollback?.verified === true && result.transactionId !== undefined) {
      this.remediationStates.transition(remediationId, "rolledBack", {
        reason: "rollback-verified",
        approvalHash,
        transactionId: result.transactionId,
      });
    }
  }

  private fire(): void {
    const snapshot = this.getSnapshot();
    for (const listener of [...this.listeners]) {
      try {
        listener(snapshot);
      } catch {
        // UI listeners are observational and cannot affect transaction state.
      }
    }
  }
}
