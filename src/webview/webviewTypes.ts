import type { ScanResult } from "../models/ScanResult";
import type {
  ScanCoverage,
  ScanResultStoreSnapshot,
} from "../services/ScanResultStore";

export interface DisposableLike {
  dispose(): unknown;
}

export type { ScanCoverage };
export type ScanResultSnapshotView = ScanResultStoreSnapshot;

/** The UI's intentionally small, read-only view of ScanResultStore. */
export interface ScanResultSource {
  getAll(): readonly ScanResult[];
  readonly getSnapshot?: () => ScanResultSnapshotView;
  readonly onDidChange?: (
    listener: (snapshot: ScanResultSnapshotView) => void,
  ) => DisposableLike;
}

export type WebviewAction = () => void | PromiseLike<void>;

export type RemediationCapability = "safe" | "preview-only" | "unsupported";

export interface RemediationCapabilityView {
  readonly recommendationKey: string;
  readonly capability: RemediationCapability;
  readonly reason: string;
}

/** Actual, already-generated preview data. The UI never synthesizes file edits. */
export interface RemediationPreviewFileView {
  readonly displayPath: string;
  readonly description: string;
  readonly beforeHash: string;
  readonly afterHash?: string;
  readonly unifiedDiff: string;
  /** Read-only SCM projection. It is an extra refusal signal, never write authority. */
  readonly gitState?:
    | "clean"
    | "modified"
    | "untracked"
    | "conflicted"
    | "partially-staged"
    | "unavailable";
}

export interface RemediationPreviewView {
  readonly id: string;
  readonly recommendationKey: string;
  readonly capability: RemediationCapability;
  readonly packageName: string;
  readonly currentVersion: string;
  readonly recommendedVersion?: string;
  readonly confidence: "high" | "medium" | "low";
  readonly vulnerabilitiesAddressed: number;
  readonly totalVulnerabilities: number;
  readonly files: readonly RemediationPreviewFileView[];
  readonly warnings: readonly string[];
  /** True only while the controller still considers this preview applicable. */
  readonly valid: boolean;
  readonly createdAt: string;
}

export type RemediationOperationStage =
  | "previewing"
  | "preview-ready"
  | "applying"
  | "validating"
  | "rescanning"
  | "rolling-back";

export interface RemediationOperationView {
  readonly stage: RemediationOperationStage;
  readonly recommendationKey?: string;
  readonly previewId?: string;
  readonly message?: string;
  readonly cancellable: boolean;
}

export interface RemediationScanCountsView {
  readonly dependencies: number;
  readonly vulnerabilities: number;
  readonly critical: number;
  readonly high: number;
  readonly medium: number;
  readonly low: number;
}

export type RemediationHistoryStatus =
  | "successful"
  | "partial"
  | "failed"
  | "cancelled";

/** Session-only summary. Full file contents and secrets must never be included. */
export interface RemediationHistoryRecordView {
  readonly id: string;
  readonly recommendationKey: string;
  readonly packageName: string;
  readonly currentVersion: string;
  readonly recommendedVersion?: string;
  readonly status: RemediationHistoryStatus;
  readonly vulnerabilitiesResolved: number;
  readonly vulnerabilitiesRemaining: number;
  readonly rolledBack: boolean;
  readonly rollbackVerified?: boolean;
  readonly message: string;
  readonly timestamp: string;
  readonly before?: RemediationScanCountsView;
  readonly after?: RemediationScanCountsView;
}

export interface RemediationApplySnapshot {
  readonly capabilities: readonly RemediationCapabilityView[];
  readonly preview?: RemediationPreviewView;
  readonly activeOperation?: RemediationOperationView;
  readonly history: readonly RemediationHistoryRecordView[];
  readonly lastResult?: RemediationHistoryRecordView;
  readonly lifecycles?: readonly RemediationLifecycleView[];
}

export type RemediationLifecycleState =
  | "preview"
  | "awaitingApproval"
  | "approved"
  | "validating"
  | "applying"
  | "verifying"
  | "applied"
  | "rejected"
  | "stale"
  | "failed"
  | "rolledBack"
  | "unsupported"
  | "manualReviewRequired"
  | "manualActionRequired"
  | "verifiedFixed"
  | "stillVulnerable"
  | "incompleteCoverage"
  | "providerUnavailable";

export interface RemediationLifecycleTransitionView {
  readonly sequence: number;
  readonly from?: RemediationLifecycleState;
  readonly to: RemediationLifecycleState;
  readonly reason: string;
  readonly timestamp: string;
  readonly errorCode?: string;
}

/** Content-free, bounded state history suitable for a webview. */
export interface RemediationLifecycleView {
  readonly remediationId: string;
  readonly recommendationKey: string;
  readonly state: RemediationLifecycleState;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly transitions: readonly RemediationLifecycleTransitionView[];
}

/**
 * Narrow controller consumed by UI providers. Implementations own all planning,
 * confirmation, mutation, validation, rescanning, and rollback safeguards.
 */
export interface RemediationApplyController {
  getSnapshot(): RemediationApplySnapshot;
  readonly onDidChange?: (
    listener: (snapshot: RemediationApplySnapshot) => void,
  ) => DisposableLike;
  previewFix(recommendationKey: string): void | PromiseLike<void>;
  readonly approveFix?: (previewId: string) =>
    | string
    | undefined
    | PromiseLike<string | undefined>;
  applyFix(previewId: string): void | PromiseLike<void>;
  cancelRemediation(previewId?: string): void | PromiseLike<void>;
  copyPatch(previewId: string, fileIndex: number): void | PromiseLike<void>;
  openAffectedFile(previewId: string, fileIndex: number): void | PromiseLike<void>;
  showPreviewDiff(
    previewId: string,
    fileIndex: number,
  ): void | PromiseLike<void>;
}
