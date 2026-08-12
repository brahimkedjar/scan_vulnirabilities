import * as vscode from "vscode";

import type { ScanResult } from "../models/ScanResult";
import type { RemediationAnalysisSource } from "../remediation/RemediationAnalysisSource";
import {
  renderDashboardDocument,
  type DashboardRenderContext,
} from "./dashboardRenderer";
import { createWebviewNonce } from "./webviewSecurity";
import type {
  DisposableLike,
  RemediationApplyController,
  ScanResultSource,
  WebviewAction,
} from "./webviewTypes";

export const DASHBOARD_VIEW_TYPE = "dependencyAuditor.dashboard";

export interface DashboardActions {
  readonly scanWorkspace: WebviewAction;
  readonly refreshScan: WebviewAction;
  readonly showVulnerabilities: WebviewAction;
  readonly reviewFixes?: WebviewAction;
  readonly showRemediationHistory?: WebviewAction;
}

interface DashboardMessage {
  readonly type: "action";
  readonly action:
    | "scanWorkspace"
    | "refreshScan"
    | "showVulnerabilities"
    | "reviewFixes"
    | "showRemediationHistory";
}

function isDashboardMessage(value: unknown): value is DashboardMessage {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const candidate = value as Partial<DashboardMessage>;
  return (
    candidate.type === "action" &&
    (candidate.action === "scanWorkspace" ||
      candidate.action === "refreshScan" ||
      candidate.action === "showVulnerabilities" ||
      candidate.action === "reviewFixes" ||
      candidate.action === "showRemediationHistory")
  );
}

/** Read-only projection of ScanResultStore; opening this panel never scans. */
export class DashboardProvider implements vscode.Disposable {
  private panel: vscode.WebviewPanel | undefined;
  private remediationOverride:
    | {
        readonly results: readonly ScanResult[];
        readonly timestamp?: string;
      }
    | undefined;
  private readonly storeSubscription: DisposableLike | undefined;
  private readonly remediationSubscription: DisposableLike | undefined;
  private readonly workspaceSubscription: vscode.Disposable;
  private panelSubscriptions: vscode.Disposable[] = [];

  public constructor(
    private readonly resultStore: ScanResultSource,
    private readonly extensionUri: vscode.Uri,
    private readonly actions: DashboardActions,
    private readonly remediationSource?: RemediationAnalysisSource,
    private readonly remediationController?: RemediationApplyController,
  ) {
    this.storeSubscription = this.resultStore.onDidChange?.(() => {
      this.remediationOverride = undefined;
      this.render();
    });
    this.workspaceSubscription = vscode.workspace.onDidChangeWorkspaceFolders(
      () => {
        this.remediationOverride = undefined;
        this.render();
      },
    );
    this.remediationSubscription = this.remediationController?.onDidChange?.(
      () => this.render(),
    );
  }

  public show(column: vscode.ViewColumn = vscode.ViewColumn.One): void {
    this.remediationOverride = undefined;
    this.openPanel(column);
    this.render();
  }

  /** Opens a read-only analysis of the latest complete scan without rescanning. */
  public showRemediation(
    results: readonly ScanResult[],
    lastSuccessfulTimestamp?: string,
    column: vscode.ViewColumn = vscode.ViewColumn.One,
  ): void {
    this.remediationOverride = {
      results,
      ...(lastSuccessfulTimestamp === undefined
        ? {}
        : { timestamp: lastSuccessfulTimestamp }),
    };
    this.openPanel(column);
    this.render();
  }

  private openPanel(column: vscode.ViewColumn): void {
    if (this.panel !== undefined) {
      this.panel.reveal(column, true);
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      DASHBOARD_VIEW_TYPE,
      "Dependency Security",
      column,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [vscode.Uri.joinPath(this.extensionUri, "media")],
      },
    );
    this.panel = panel;
    this.panelSubscriptions = [
      panel.webview.onDidReceiveMessage((message: unknown) => {
        this.handleMessage(message);
      }),
    ];
    panel.onDidDispose(() => {
      this.disposePanelSubscriptions();
      if (this.panel === panel) {
        this.panel = undefined;
      }
    });
  }

  /** Re-renders only from the store. It does not invoke a scan or network API. */
  public refresh(): void {
    this.remediationOverride = undefined;
    this.render();
  }

  private render(): void {
    if (this.panel === undefined) {
      return;
    }
    const snapshot = this.resultStore.getSnapshot?.();
    const scanResults =
      this.remediationOverride?.results ??
      snapshot?.results ??
      this.resultStore.getAll();
    let remediationAnalysis:
      | ReturnType<RemediationAnalysisSource["analyze"]>
      | undefined;
    try {
      remediationAnalysis = this.remediationSource?.analyze(scanResults);
    } catch {
      // The dashboard remains usable with an explicit absent analysis card.
    }
    let remediationApply;
    try {
      remediationApply = this.remediationController?.getSnapshot();
    } catch {
      // Mutation actions remain hidden if controller state is unavailable.
    }
    const context: DashboardRenderContext = {
      workspaceOpen: (vscode.workspace.workspaceFolders?.length ?? 0) > 0,
      scanResults,
      ...(remediationAnalysis === undefined ? {} : { remediationAnalysis }),
      ...(remediationApply === undefined ? {} : { remediationApply }),
      ...(this.remediationOverride === undefined
        ? {}
        : {
            remediationAnalysisLabel: "Latest complete scan",
            ...(this.remediationOverride.timestamp === undefined
              ? {}
              : {
                  remediationAnalysisTimestamp:
                    this.remediationOverride.timestamp,
                }),
          }),
      ...(snapshot === undefined
        ? {}
        : {
            displayedCoverage:
              this.remediationOverride === undefined
                ? snapshot.displayedCoverage
                : "complete",
            latestAttempt:
              this.remediationOverride === undefined
                ? snapshot.latestAttempt
                : scanResults,
            latestAttemptCoverage:
              this.remediationOverride === undefined
                ? snapshot.latestAttemptCoverage
                : "complete",
            ...(snapshot.latestAttemptTimestamp === undefined
              ? {}
              : { latestAttemptTimestamp: snapshot.latestAttemptTimestamp }),
            ...((this.remediationOverride?.timestamp ??
              snapshot.lastSuccessfulTimestamp) === undefined
              ? {}
              : {
                  lastSuccessfulTimestamp:
                    this.remediationOverride?.timestamp ??
                    snapshot.lastSuccessfulTimestamp,
                }),
            retainedFindings:
              this.remediationOverride === undefined
                ? snapshot.retainedFindings
                : [],
            retainedFindingsTruncated:
              this.remediationOverride === undefined
                ? snapshot.retainedFindingsTruncated
                : false,
          }),
    };
    this.panel.webview.html = renderDashboardDocument(
      context,
      createWebviewNonce(),
      this.panel.webview
        .asWebviewUri(
          vscode.Uri.joinPath(this.extensionUri, "media", "dashboard.js"),
        )
        .toString(),
    );
  }

  /** Read-only inspection used by the isolated Extension Development Host. */
  public getRenderedHtml(): string | undefined {
    return this.panel?.webview.html;
  }

  public dispose(): void {
    this.storeSubscription?.dispose();
    this.remediationSubscription?.dispose();
    this.workspaceSubscription.dispose();
    const panel = this.panel;
    this.panel = undefined;
    panel?.dispose();
    this.disposePanelSubscriptions();
  }

  private handleMessage(message: unknown): void {
    if (!isDashboardMessage(message)) {
      return;
    }
    if (
      message.action === "scanWorkspace" ||
      message.action === "refreshScan"
    ) {
      this.remediationOverride = undefined;
      this.render();
    }
    const action = this.actions[message.action];
    if (action === undefined) {
      return;
    }
    void Promise.resolve()
      .then(() => action())
      .catch(() => {
        void vscode.window.showErrorMessage(
          "The dependency security action could not be completed.",
        );
      });
  }

  private disposePanelSubscriptions(): void {
    for (const subscription of this.panelSubscriptions) {
      subscription.dispose();
    }
    this.panelSubscriptions = [];
  }
}
