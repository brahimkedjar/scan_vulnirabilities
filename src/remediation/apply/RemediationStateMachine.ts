export type RemediationState =
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

export type RemediationTransitionReason =
  | "preview-created"
  | "approval-requested"
  | "user-approved"
  | "validation-started"
  | "apply-started"
  | "verification-started"
  | "verification-succeeded"
  | "user-rejected"
  | "cancelled-before-apply"
  | "authority-changed"
  | "approval-expired"
  | "approval-mismatch"
  | "operation-failed"
  | "verification-failed"
  | "rollback-verified"
  | "capability-unsupported"
  | "manual-review-required"
  | "manual-action-required"
  | "verified-fixed"
  | "still-vulnerable"
  | "incomplete-coverage"
  | "provider-unavailable";

/** The read-only authority boundary which invalidated an approval or plan. */
export type RemediationAuthoritySource =
  | "dependency-files"
  | "dependency-source"
  | "git"
  | "scan-results"
  | "configuration"
  | "workspace-folders"
  | "workspace-trust"
  | "external";

export interface RemediationTransitionContext {
  readonly reason: RemediationTransitionReason;
  readonly approvalHash?: string;
  readonly transactionId?: string;
  readonly errorCode?: string;
  readonly authoritySource?: RemediationAuthoritySource;
}

export interface RemediationStateTransition {
  readonly sequence: number;
  readonly from?: RemediationState;
  readonly to: RemediationState;
  readonly reason: RemediationTransitionReason;
  readonly timestamp: string;
  readonly approvalHash?: string;
  readonly transactionId?: string;
  readonly errorCode?: string;
  readonly authoritySource?: RemediationAuthoritySource;
}

export interface RemediationStateSnapshot {
  readonly remediationId: string;
  readonly recommendationKey: string;
  readonly planHash: string;
  readonly state: RemediationState;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly approvalHash?: string;
  readonly transactionId?: string;
  readonly errorCode?: string;
  readonly transitions: readonly RemediationStateTransition[];
}

export interface RemediationStateMachineOptions {
  readonly remediationId: string;
  readonly recommendationKey: string;
  readonly planHash: string;
  readonly clock?: () => number;
}

export interface RemediationStateRegistryOptions {
  readonly clock?: () => number;
  readonly maximumRecords?: number;
}

const HASH = /^[a-f0-9]{64}$/u;
const UNSAFE_IDENTIFIER =
  /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u;
const SAFE_SHORT_VALUE = /^[A-Za-z0-9._:@/\\+\-=]{1,512}$/u;
const MAXIMUM_TRANSITIONS = 32;
export const MAXIMUM_REMEDIATION_STATE_RECORDS = 100;

const ALLOWED_TRANSITIONS: Readonly<Record<RemediationState, ReadonlySet<RemediationState>>> =
  Object.freeze({
    preview: new Set<RemediationState>([
      "awaitingApproval",
      "rejected",
      "stale",
      "unsupported",
      "manualReviewRequired",
      "manualActionRequired",
    ]),
    awaitingApproval: new Set<RemediationState>([
      "approved",
      "rejected",
      "stale",
      "unsupported",
      "manualReviewRequired",
      "manualActionRequired",
    ]),
    approved: new Set<RemediationState>(["validating", "rejected", "stale"]),
    validating: new Set<RemediationState>(["applying", "failed", "stale"]),
    applying: new Set<RemediationState>(["verifying", "failed"]),
    verifying: new Set<RemediationState>([
      "applied",
      "failed",
      "verifiedFixed",
      "stillVulnerable",
      "incompleteCoverage",
      "providerUnavailable",
    ]),
    failed: new Set<RemediationState>(["rolledBack"]),
    applied: new Set<RemediationState>(),
    rejected: new Set<RemediationState>(),
    stale: new Set<RemediationState>(),
    rolledBack: new Set<RemediationState>(),
    unsupported: new Set<RemediationState>(),
    manualReviewRequired: new Set<RemediationState>(),
    manualActionRequired: new Set<RemediationState>(),
    verifiedFixed: new Set<RemediationState>(),
    stillVulnerable: new Set<RemediationState>(),
    incompleteCoverage: new Set<RemediationState>(),
    providerUnavailable: new Set<RemediationState>(),
  });

const REASONS_BY_TARGET: Readonly<
  Record<RemediationState, ReadonlySet<RemediationTransitionReason>>
> = Object.freeze({
  preview: new Set<RemediationTransitionReason>(["preview-created"]),
  awaitingApproval: new Set<RemediationTransitionReason>(["approval-requested"]),
  approved: new Set<RemediationTransitionReason>(["user-approved"]),
  validating: new Set<RemediationTransitionReason>(["validation-started"]),
  applying: new Set<RemediationTransitionReason>(["apply-started"]),
  verifying: new Set<RemediationTransitionReason>(["verification-started"]),
  applied: new Set<RemediationTransitionReason>(["verification-succeeded"]),
  rejected: new Set<RemediationTransitionReason>([
    "user-rejected",
    "cancelled-before-apply",
  ]),
  stale: new Set<RemediationTransitionReason>([
    "authority-changed",
    "approval-expired",
    "approval-mismatch",
  ]),
  failed: new Set<RemediationTransitionReason>([
    "operation-failed",
    "verification-failed",
  ]),
  rolledBack: new Set<RemediationTransitionReason>(["rollback-verified"]),
  unsupported: new Set<RemediationTransitionReason>(["capability-unsupported"]),
  manualReviewRequired: new Set<RemediationTransitionReason>([
    "manual-review-required",
  ]),
  manualActionRequired: new Set<RemediationTransitionReason>([
    "manual-action-required",
  ]),
  verifiedFixed: new Set<RemediationTransitionReason>(["verified-fixed"]),
  stillVulnerable: new Set<RemediationTransitionReason>(["still-vulnerable"]),
  incompleteCoverage: new Set<RemediationTransitionReason>([
    "incomplete-coverage",
  ]),
  providerUnavailable: new Set<RemediationTransitionReason>([
    "provider-unavailable",
  ]),
});

const TERMINAL_STATES: ReadonlySet<RemediationState> = new Set([
  "applied",
  "rejected",
  "stale",
  "rolledBack",
  "unsupported",
  "manualReviewRequired",
  "manualActionRequired",
  "verifiedFixed",
  "stillVulnerable",
  "incompleteCoverage",
  "providerUnavailable",
]);

const INVALIDATABLE_STATES: ReadonlySet<RemediationState> = new Set([
  "preview",
  "awaitingApproval",
  "approved",
  "validating",
]);

export class RemediationStateError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "RemediationStateError";
  }
}

function requireIdentifier(value: string, label: string): string {
  if (
    value.length === 0 ||
    value.length > 32_768 ||
    UNSAFE_IDENTIFIER.test(value)
  ) {
    throw new RemediationStateError(`${label} is invalid`);
  }
  return value;
}

function requireShortValue(value: string, label: string): string {
  if (!SAFE_SHORT_VALUE.test(value)) {
    throw new RemediationStateError(`${label} is invalid`);
  }
  return value;
}

function requireHash(value: string, label: string): string {
  if (!HASH.test(value)) {
    throw new RemediationStateError(`${label} is invalid`);
  }
  return value;
}

function boundedMaximum(value: number | undefined): number {
  const selected = value ?? MAXIMUM_REMEDIATION_STATE_RECORDS;
  if (
    !Number.isSafeInteger(selected) ||
    selected < 1 ||
    selected > MAXIMUM_REMEDIATION_STATE_RECORDS
  ) {
    throw new RangeError(
      `maximumRecords must be between 1 and ${MAXIMUM_REMEDIATION_STATE_RECORDS.toString()}`,
    );
  }
  return selected;
}

function timestamp(clock: () => number, minimum?: number): {
  readonly numeric: number;
  readonly iso: string;
} {
  const numeric = clock();
  if (
    !Number.isFinite(numeric) ||
    (minimum !== undefined && numeric < minimum)
  ) {
    throw new RemediationStateError("remediation state clock is invalid");
  }
  return { numeric, iso: new Date(numeric).toISOString() };
}

function freezeTransition(
  sequence: number,
  from: RemediationState | undefined,
  to: RemediationState,
  context: RemediationTransitionContext,
  at: string,
): RemediationStateTransition {
  return Object.freeze({
    sequence,
    ...(from === undefined ? {} : { from }),
    to,
    reason: context.reason,
    timestamp: at,
    ...(context.approvalHash === undefined
      ? {}
      : { approvalHash: context.approvalHash }),
    ...(context.transactionId === undefined
      ? {}
      : { transactionId: context.transactionId }),
    ...(context.errorCode === undefined ? {} : { errorCode: context.errorCode }),
    ...(context.authoritySource === undefined
      ? {}
      : { authoritySource: context.authoritySource }),
  });
}

/**
 * One strict remediation lifecycle. The constructor records `preview`; every
 * later state must follow the explicit allowlist above.
 */
export class RemediationStateMachine {
  private readonly clock: () => number;
  private readonly records: RemediationStateTransition[];
  private currentState: RemediationState = "preview";
  private lastTimestamp: number;
  private boundApprovalHash: string | undefined;
  private boundTransactionId: string | undefined;
  private lastErrorCode: string | undefined;

  public readonly remediationId: string;
  public readonly recommendationKey: string;
  public readonly planHash: string;
  public readonly createdAt: string;

  public constructor(options: RemediationStateMachineOptions) {
    this.remediationId = requireIdentifier(
      options.remediationId,
      "remediationId",
    );
    this.recommendationKey = requireIdentifier(
      options.recommendationKey,
      "recommendationKey",
    );
    this.planHash = requireHash(options.planHash, "planHash");
    this.clock = options.clock ?? Date.now;
    const created = timestamp(this.clock);
    this.lastTimestamp = created.numeric;
    this.createdAt = created.iso;
    this.records = [
      freezeTransition(
        0,
        undefined,
        "preview",
        { reason: "preview-created" },
        created.iso,
      ),
    ];
  }

  public get state(): RemediationState {
    return this.currentState;
  }

  public get terminal(): boolean {
    return TERMINAL_STATES.has(this.currentState);
  }

  public get invalidatable(): boolean {
    return INVALIDATABLE_STATES.has(this.currentState);
  }

  public transition(
    to: RemediationState,
    context: RemediationTransitionContext,
  ): RemediationStateSnapshot {
    if (
      this.records.length >= MAXIMUM_TRANSITIONS ||
      !ALLOWED_TRANSITIONS[this.currentState].has(to) ||
      !REASONS_BY_TARGET[to].has(context.reason)
    ) {
      throw new RemediationStateError(
        `invalid remediation transition ${this.currentState} -> ${to}`,
      );
    }
    let approvalHash = context.approvalHash;
    if (approvalHash !== undefined) {
      approvalHash = requireHash(approvalHash, "approvalHash");
    }
    if (to === "approved" && approvalHash === undefined) {
      throw new RemediationStateError("approved requires an approval hash");
    }
    if (
      this.boundApprovalHash !== undefined &&
      approvalHash !== undefined &&
      approvalHash !== this.boundApprovalHash
    ) {
      throw new RemediationStateError("approval hash changed during remediation");
    }
    const transactionId =
      context.transactionId === undefined
        ? undefined
        : requireShortValue(context.transactionId, "transactionId");
    if (
      this.boundTransactionId !== undefined &&
      transactionId !== undefined &&
      transactionId !== this.boundTransactionId
    ) {
      throw new RemediationStateError("transaction ID changed during remediation");
    }
    if (
      (to === "applied" ||
        to === "rolledBack" ||
        to === "verifiedFixed" ||
        to === "stillVulnerable" ||
        to === "incompleteCoverage" ||
        to === "providerUnavailable") &&
      (transactionId ?? this.boundTransactionId) === undefined
    ) {
      throw new RemediationStateError(`${to} requires a transaction ID`);
    }
    const errorCode =
      context.errorCode === undefined
        ? undefined
        : requireShortValue(context.errorCode, "errorCode");
    if (to === "failed" && errorCode === undefined) {
      throw new RemediationStateError("failed requires an error code");
    }
    if (
      context.authoritySource !== undefined &&
      (to !== "stale" || context.reason !== "authority-changed")
    ) {
      throw new RemediationStateError(
        "authority source is only valid for authority invalidation",
      );
    }
    const at = timestamp(this.clock, this.lastTimestamp);
    const from = this.currentState;
    this.currentState = to;
    this.lastTimestamp = at.numeric;
    this.boundApprovalHash = approvalHash ?? this.boundApprovalHash;
    this.boundTransactionId = transactionId ?? this.boundTransactionId;
    this.lastErrorCode = errorCode ?? this.lastErrorCode;
    this.records.push(
      freezeTransition(
        this.records.length,
        from,
        to,
        {
          ...context,
          ...(this.boundApprovalHash === undefined
            ? {}
            : { approvalHash: this.boundApprovalHash }),
          ...(this.boundTransactionId === undefined
            ? {}
            : { transactionId: this.boundTransactionId }),
          ...(errorCode === undefined ? {} : { errorCode }),
        },
        at.iso,
      ),
    );
    return this.getSnapshot();
  }

  public getSnapshot(): RemediationStateSnapshot {
    const last = this.records.at(-1);
    if (last === undefined) {
      throw new RemediationStateError("remediation state history is empty");
    }
    return Object.freeze({
      remediationId: this.remediationId,
      recommendationKey: this.recommendationKey,
      planHash: this.planHash,
      state: this.currentState,
      createdAt: this.createdAt,
      updatedAt: last.timestamp,
      ...(this.boundApprovalHash === undefined
        ? {}
        : { approvalHash: this.boundApprovalHash }),
      ...(this.boundTransactionId === undefined
        ? {}
        : { transactionId: this.boundTransactionId }),
      ...(this.lastErrorCode === undefined
        ? {}
        : { errorCode: this.lastErrorCode }),
      transitions: Object.freeze([...this.records]),
    });
  }
}

/** Bounded session history for multiple independent remediation proposals. */
export class RemediationStateRegistry {
  private readonly machines = new Map<string, RemediationStateMachine>();
  private readonly order: string[] = [];
  private readonly clock: () => number;
  private readonly maximumRecords: number;

  public constructor(options: RemediationStateRegistryOptions = {}) {
    this.clock = options.clock ?? Date.now;
    this.maximumRecords = boundedMaximum(options.maximumRecords);
  }

  public create(
    input: Omit<RemediationStateMachineOptions, "clock">,
  ): RemediationStateSnapshot {
    if (this.machines.has(input.remediationId)) {
      throw new RemediationStateError("remediation ID already exists");
    }
    this.makeRoom();
    const machine = new RemediationStateMachine({ ...input, clock: this.clock });
    this.machines.set(machine.remediationId, machine);
    this.order.unshift(machine.remediationId);
    return machine.getSnapshot();
  }

  public transition(
    remediationId: string,
    to: RemediationState,
    context: RemediationTransitionContext,
  ): RemediationStateSnapshot {
    const machine = this.machines.get(remediationId);
    if (machine === undefined) {
      throw new RemediationStateError("unknown remediation ID");
    }
    return machine.transition(to, context);
  }

  public get(remediationId: string): RemediationStateSnapshot | undefined {
    return this.machines.get(remediationId)?.getSnapshot();
  }

  public getAll(): readonly RemediationStateSnapshot[] {
    return Object.freeze(
      this.order.flatMap((id) => {
        const snapshot = this.machines.get(id)?.getSnapshot();
        return snapshot === undefined ? [] : [snapshot];
      }),
    );
  }

  public invalidateOpen(
    reason: Extract<
      RemediationTransitionReason,
      "authority-changed" | "approval-expired" | "approval-mismatch"
    > = "authority-changed",
  ): readonly RemediationStateSnapshot[] {
    const changed: RemediationStateSnapshot[] = [];
    for (const id of this.order) {
      const machine = this.machines.get(id);
      if (machine?.invalidatable === true) {
        changed.push(machine.transition("stale", { reason }));
      }
    }
    return Object.freeze(changed);
  }

  /**
   * Generic authority hook for file watchers, scan generations, workspace
   * changes, and a future read-only Git-state inspector.
   */
  public invalidate(
    remediationId: string,
    source: RemediationAuthoritySource,
  ): RemediationStateSnapshot | undefined {
    const machine = this.machines.get(remediationId);
    if (machine?.invalidatable !== true) return undefined;
    return machine.transition("stale", {
      reason: "authority-changed",
      authoritySource: source,
    });
  }

  public clear(): void {
    this.machines.clear();
    this.order.length = 0;
  }

  private makeRoom(): void {
    while (this.order.length >= this.maximumRecords) {
      let evictIndex = -1;
      for (let index = this.order.length - 1; index >= 0; index -= 1) {
        const id = this.order[index];
        if (id !== undefined && this.machines.get(id)?.terminal === true) {
          evictIndex = index;
          break;
        }
      }
      if (evictIndex === -1) {
        throw new RemediationStateError(
          "remediation state history has no evictable terminal record",
        );
      }
      const id = this.order[evictIndex];
      if (id !== undefined) {
        this.machines.delete(id);
      }
      this.order.splice(evictIndex, 1);
    }
  }
}
