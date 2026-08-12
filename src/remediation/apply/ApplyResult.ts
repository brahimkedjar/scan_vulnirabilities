import type { ScanResult } from "../../models/ScanResult";

import type { ApplyErrorCode } from "./ApplyError";

export type ApplyStatus =
  | "success"
  | "partial"
  | "failed"
  | "cancelled"
  | "refused";

export interface RollbackResult {
  readonly attempted: boolean;
  readonly restoredFiles: number;
  readonly verified: boolean;
  readonly criticalWarning?: string;
}

export interface ScanCounts {
  readonly dependencies: number;
  readonly vulnerabilities: number;
  readonly critical: number;
  readonly high: number;
  readonly medium: number;
  readonly low: number;
  readonly unknown: number;
}

export interface BeforeAfterComparison {
  readonly before: ScanCounts;
  readonly after: ScanCounts;
  readonly targetedBefore: number;
  readonly targetedAfter: number;
  readonly resolved: number;
  readonly remaining: number;
  readonly coverageComplete: boolean;
}

export interface RemediationVerification {
  readonly results: readonly ScanResult[];
  readonly comparison: BeforeAfterComparison;
  readonly explanation: string;
}

export interface ApplyResult {
  readonly planId: string;
  readonly transactionId?: string;
  readonly status: ApplyStatus;
  readonly changedFiles: number;
  readonly verification?: RemediationVerification;
  readonly rollback?: RollbackResult;
  readonly errorCode?: ApplyErrorCode;
  readonly message: string;
}

export interface RemediationHistoryRecord {
  readonly id: string;
  readonly planId: string;
  readonly recommendationKey: string;
  readonly packageName: string;
  readonly fromVersion: string;
  readonly toVersion?: string;
  readonly timestamp: string;
  readonly status: ApplyStatus;
  readonly resolved: number;
  readonly remaining: number;
  readonly rolledBack: boolean;
  readonly message: string;
}
