import * as vscode from "vscode";

import type { RemediationAnalysisSource } from "../remediation/RemediationAnalysisSource";
import type { ScanResultStore } from "../services/ScanResultStore";
import type {
  DisposableLike,
  RemediationApplyController,
} from "../webview/webviewTypes";
import { buildDependencyStatusModel } from "./statusModel";

export class DependencyStatusBar implements vscode.Disposable {
  private readonly statusBarItem: vscode.StatusBarItem;
  private readonly storeSubscription: vscode.Disposable;
  private readonly remediationSubscription: DisposableLike | undefined;
  private scanning = false;

  public constructor(
    private readonly resultStore: ScanResultStore,
    private readonly remediationSource?: RemediationAnalysisSource,
    private readonly remediationController?: RemediationApplyController,
  ) {
    this.statusBarItem = vscode.window.createStatusBarItem(
      "dependencyAuditor.status",
      vscode.StatusBarAlignment.Left,
      100,
    );
    this.statusBarItem.name = "Dependency Security";
    this.statusBarItem.command = "dependencyAuditor.showDashboard";
    this.storeSubscription = this.resultStore.onDidChange(() => this.refresh());
    this.remediationSubscription = this.remediationController?.onDidChange?.(
      () => this.refresh(),
    );
    this.refresh();
    this.statusBarItem.show();
  }

  public setScanning(scanning: boolean): void {
    if (this.scanning === scanning) {
      return;
    }
    this.scanning = scanning;
    this.refresh();
  }

  public refresh(): void {
    const snapshot = this.resultStore.getSnapshot();
    let remediationAnalysis:
      | ReturnType<RemediationAnalysisSource["analyze"]>
      | undefined;
    try {
      remediationAnalysis = this.remediationSource?.analyze(snapshot.results);
    } catch {
      // Status remains truthful about findings if local analysis cannot run.
    }
    let remediationApply;
    try {
      remediationApply = this.remediationController?.getSnapshot();
    } catch {
      // Status remains truthful when apply state is unavailable.
    }
    const model = buildDependencyStatusModel(
      snapshot.results,
      this.scanning || snapshot.scanning,
      {
        latestAttemptCoverage: snapshot.latestAttemptCoverage,
        retainedFindings: snapshot.retainedFindings,
        retainedFindingsTruncated: snapshot.retainedFindingsTruncated,
        ...(remediationAnalysis === undefined
          ? {}
          : { remediationAnalysis }),
        ...(remediationApply === undefined ? {} : { remediationApply }),
      },
    );
    this.statusBarItem.text = model.text;
    this.statusBarItem.tooltip = model.tooltip;
    this.statusBarItem.accessibilityInformation = {
      label: model.text.replace("$(shield) ", ""),
      role: "button",
    };
  }

  public dispose(): void {
    this.remediationSubscription?.dispose();
    this.storeSubscription.dispose();
    this.statusBarItem.dispose();
  }
}
