import { randomUUID } from "node:crypto";

import type { ApplyResult, RemediationHistoryRecord } from "./ApplyResult";
import type { RemediationPlan } from "./RemediationPlan";

export const MAX_REMEDIATION_HISTORY_RECORDS = 100;
const MAX_HISTORY_TEXT_LENGTH = 512;
const UNSAFE_DISPLAY_CHARACTERS =
  /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu;

export interface RemediationHistoryOptions {
  readonly clock?: () => Date;
  readonly createId?: () => string;
  readonly maximumRecords?: number;
}

function safeText(value: string): string {
  return value
    .replace(UNSAFE_DISPLAY_CHARACTERS, "")
    .slice(0, MAX_HISTORY_TEXT_LENGTH);
}

function boundedMaximum(value: number | undefined): number {
  const selected = value ?? MAX_REMEDIATION_HISTORY_RECORDS;
  if (
    !Number.isSafeInteger(selected) ||
    selected < 1 ||
    selected > MAX_REMEDIATION_HISTORY_RECORDS
  ) {
    throw new RangeError(
      `maximumRecords must be between 1 and ${MAX_REMEDIATION_HISTORY_RECORDS.toString()}`,
    );
  }
  return selected;
}

/** Session-only, content-free remediation audit history. */
export class RemediationHistory {
  private readonly records: RemediationHistoryRecord[] = [];
  private readonly clock: () => Date;
  private readonly createId: () => string;
  private readonly maximumRecords: number;

  public constructor(options: RemediationHistoryOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
    this.createId = options.createId ?? randomUUID;
    this.maximumRecords = boundedMaximum(options.maximumRecords);
  }

  public record(
    plan: RemediationPlan,
    result: ApplyResult,
  ): RemediationHistoryRecord {
    const verification = result.verification?.comparison;
    const record: RemediationHistoryRecord = Object.freeze({
      id: safeText(this.createId()),
      planId: safeText(plan.id),
      recommendationKey: safeText(plan.recommendationKey),
      packageName: safeText(plan.expectedOutcome.packageName),
      fromVersion: safeText(plan.expectedOutcome.fromVersion),
      ...(plan.expectedOutcome.toVersion === undefined
        ? {}
        : { toVersion: safeText(plan.expectedOutcome.toVersion) }),
      timestamp: this.clock().toISOString(),
      status: result.status,
      resolved: verification?.resolved ?? 0,
      remaining: verification?.remaining ?? 0,
      rolledBack: result.rollback?.attempted === true,
      message: safeText(result.message),
    });
    this.records.unshift(record);
    if (this.records.length > this.maximumRecords) {
      this.records.length = this.maximumRecords;
    }
    return record;
  }

  public getAll(): readonly RemediationHistoryRecord[] {
    return Object.freeze([...this.records]);
  }

  public clear(): void {
    this.records.length = 0;
  }
}
