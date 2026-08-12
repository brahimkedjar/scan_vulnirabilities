import * as vscode from "vscode";

import type { RemediationAnalysisSource } from "../remediation/RemediationAnalysisSource";
import {
  buildRemediationCenterRows,
  renderRemediationCenterDocument,
  type RemediationCenterRow,
} from "./remediationCenterRenderer";
import { createWebviewNonce } from "./webviewSecurity";
import type {
  DisposableLike,
  RemediationApplyController,
  ScanResultSource,
  WebviewAction,
} from "./webviewTypes";

export const REMEDIATION_CENTER_VIEW = "dependencyAuditor.remediationView";

interface RemediationCenterMessage {
  readonly type: "remediationCenterAction";
  readonly action:
    | "preview"
    | "approve"
    | "apply"
    | "cancel"
    | "viewDiff"
    | "copyPatch"
    | "openFile"
    | "rescan";
  readonly rowId?: string;
  readonly fileIndex?: number;
}

function isMessage(value: unknown): value is RemediationCenterMessage {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const candidate = value as Partial<RemediationCenterMessage>;
  return (
    candidate.type === "remediationCenterAction" &&
    (candidate.action === "preview" ||
      candidate.action === "approve" ||
      candidate.action === "apply" ||
      candidate.action === "cancel" ||
      candidate.action === "viewDiff" ||
      candidate.action === "copyPatch" ||
      candidate.action === "openFile" ||
      candidate.action === "rescan") &&
    (candidate.rowId === undefined ||
      /^remediation-(?:0|[1-9][0-9]{0,2})$/u.test(candidate.rowId)) &&
    (candidate.fileIndex === undefined ||
      (Number.isSafeInteger(candidate.fileIndex) &&
        candidate.fileIndex >= 0 &&
        candidate.fileIndex < 10))
  );
}

/** Dedicated read-only remediation projection with host-resolved actions. */
export class RemediationCenterProvider
  implements vscode.WebviewViewProvider, vscode.Disposable
{
  private view: vscode.WebviewView | undefined;
  private rows = new Map<string, RemediationCenterRow>();
  private readonly subscriptions: DisposableLike[] = [];
  private viewSubscriptions: vscode.Disposable[] = [];

  public constructor(
    private readonly resultStore: ScanResultSource,
    private readonly extensionUri: vscode.Uri,
    private readonly remediationSource: RemediationAnalysisSource,
    private readonly controller: RemediationApplyController,
    private readonly rescan: WebviewAction,
  ) {
    const storeSubscription = resultStore.onDidChange?.(() => this.render());
    const remediationSubscription = controller.onDidChange?.(() => this.render());
    if (storeSubscription !== undefined) this.subscriptions.push(storeSubscription);
    if (remediationSubscription !== undefined) {
      this.subscriptions.push(remediationSubscription);
    }
  }

  public resolveWebviewView(webviewView: vscode.WebviewView): void {
    this.view = webviewView;
    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(this.extensionUri, "media")],
    };
    this.viewSubscriptions = [
      webviewView.webview.onDidReceiveMessage((message: unknown) => {
        this.handleMessage(message);
      }),
      webviewView.onDidDispose(() => {
        this.disposeViewSubscriptions();
        if (this.view === webviewView) this.view = undefined;
      }),
    ];
    this.render();
  }

  public getRenderedHtml(): string | undefined {
    return this.view?.webview.html;
  }

  public dispose(): void {
    for (const subscription of this.subscriptions.splice(0)) {
      subscription.dispose();
    }
    this.disposeViewSubscriptions();
    this.rows.clear();
    this.view = undefined;
  }

  private render(): void {
    if (this.view === undefined) return;
    const scanSnapshot = this.resultStore.getSnapshot?.();
    const results = scanSnapshot?.results ?? this.resultStore.getAll();
    const applySnapshot = this.controller.getSnapshot();
    let analysis;
    try {
      analysis = this.remediationSource.analyze(results);
    } catch {
      analysis = {
        recommendations: [],
        remediable: [],
        noFix: [],
        manualReview: [],
        unresolved: [],
        summary: {
          totalVulnerabilities: 0,
          remediable: 0,
          noKnownFix: 0,
          manualReview: 0,
          unresolved: 0,
          remediationCoveragePercent: 0,
          analysisComplete: false,
        },
      } as const;
    }
    const rows = buildRemediationCenterRows(results, analysis, applySnapshot);
    this.rows = new Map(rows.map((row) => [row.rowId, row]));
    this.view.webview.html = renderRemediationCenterDocument(
      {
        workspaceOpen: (vscode.workspace.workspaceFolders?.length ?? 0) > 0,
        rows,
        analysisComplete: analysis.summary.analysisComplete,
        ...(applySnapshot.activeOperation === undefined
          ? {}
          : { activeOperation: applySnapshot.activeOperation }),
        productionApplyAvailable: applySnapshot.capabilities.some(
          (capability) => capability.capability === "safe",
        ),
      },
      createWebviewNonce(),
      this.view.webview
        .asWebviewUri(
          vscode.Uri.joinPath(
            this.extensionUri,
            "media",
            "remediation-center.js",
          ),
        )
        .toString(),
    );
  }

  private handleMessage(value: unknown): void {
    if (!isMessage(value)) return;
    if (value.action === "rescan") {
      void Promise.resolve(this.rescan()).catch(() => {
        void vscode.window.showErrorMessage("The remediation rescan could not be started.");
      });
      return;
    }
    const row = value.rowId === undefined ? undefined : this.rows.get(value.rowId);
    if (row === undefined) return;
    const snapshot = this.controller.getSnapshot();
    const currentCapability = snapshot.capabilities.filter(
      (capability) =>
        capability.recommendationKey === row.recommendation.recommendationKey,
    );
    if (currentCapability.length !== 1) return;
    const preview =
      snapshot.preview?.recommendationKey ===
      row.recommendation.recommendationKey
        ? snapshot.preview
        : undefined;
    const lifecycle = (snapshot.lifecycles ?? []).find(
      (candidate) =>
        candidate.recommendationKey === row.recommendation.recommendationKey,
    );
    let action: (() => unknown | PromiseLike<unknown>) | undefined;
    switch (value.action) {
      case "preview":
        if (currentCapability[0]?.capability !== "unsupported") {
          action = () =>
            this.controller.previewFix(row.recommendation.recommendationKey);
        }
        break;
      case "approve":
        if (
          this.controller.approveFix !== undefined &&
          preview?.valid === true &&
          preview.capability === "safe" &&
          lifecycle?.state === "awaitingApproval"
        ) {
          action = () => this.controller.approveFix?.(preview.id);
        }
        break;
      case "apply":
        if (
          preview?.valid === true &&
          preview.capability === "safe" &&
          lifecycle?.state === "approved"
        ) {
          action = () => this.controller.applyFix(preview.id);
        }
        break;
      case "cancel":
        if (preview !== undefined && lifecycle !== undefined) {
          action = () => this.controller.cancelRemediation(preview.id);
        }
        break;
      case "viewDiff":
        if (
          preview !== undefined &&
          value.fileIndex !== undefined &&
          value.fileIndex < Math.min(preview.files.length, 10)
        ) {
          action = () =>
            this.controller.showPreviewDiff(preview.id, value.fileIndex ?? -1);
        }
        break;
      case "copyPatch":
        if (
          preview !== undefined &&
          value.fileIndex !== undefined &&
          value.fileIndex < Math.min(preview.files.length, 10)
        ) {
          action = () =>
            this.controller.copyPatch(preview.id, value.fileIndex ?? -1);
        }
        break;
      case "openFile":
        if (
          preview !== undefined &&
          value.fileIndex !== undefined &&
          value.fileIndex < Math.min(preview.files.length, 10)
        ) {
          action = () =>
            this.controller.openAffectedFile(preview.id, value.fileIndex ?? -1);
        }
        break;
    }
    if (action === undefined) return;
    void Promise.resolve()
      .then(() => action())
      .catch(() => {
        void vscode.window.showErrorMessage(
          "The remediation action could not be completed safely.",
        );
      });
  }

  private disposeViewSubscriptions(): void {
    for (const subscription of this.viewSubscriptions.splice(0)) {
      subscription.dispose();
    }
  }
}
