interface ActiveDependencyRecordBudget {
  readonly maximumRecords: number;
  references: number;
  retainedRecords: number;
}

export interface DependencyRecordClaim {
  readonly accepted: number;
  readonly omitted: number;
  readonly remaining: number;
}

const ACTIVE_BUDGETS = new WeakMap<AbortSignal, ActiveDependencyRecordBudget>();

/**
 * Bounds retained dependency objects, not merely provider query subjects.
 * Ten thousand leaves room for repeated project occurrences while keeping
 * retained UI/store state close to the provider's stricter 5,000-identity
 * query ceiling.
 */
export const MAX_WORKSPACE_DEPENDENCY_RECORDS = 10_000;

function validRecordCount(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

/** Registers one record budget shared by every workspace folder in a scan. */
export function registerDependencyRecordBudget(
  signal: AbortSignal,
  maximumRecords = MAX_WORKSPACE_DEPENDENCY_RECORDS,
): { dispose(): void } {
  if (
    !Number.isSafeInteger(maximumRecords) ||
    maximumRecords < 1 ||
    maximumRecords > MAX_WORKSPACE_DEPENDENCY_RECORDS
  ) {
    throw new RangeError(
      `maximumRecords must be between 1 and ${MAX_WORKSPACE_DEPENDENCY_RECORDS.toString()}`,
    );
  }

  const existing = ACTIVE_BUDGETS.get(signal);
  if (existing !== undefined) {
    existing.references += 1;
  } else {
    ACTIVE_BUDGETS.set(signal, {
      maximumRecords,
      references: 1,
      retainedRecords: 0,
    });
  }

  let active = true;
  return {
    dispose: (): void => {
      if (!active) {
        return;
      }
      active = false;
      const current = ACTIVE_BUDGETS.get(signal);
      if (current === undefined) {
        return;
      }
      current.references -= 1;
      if (current.references === 0) {
        ACTIVE_BUDGETS.delete(signal);
      }
    },
  };
}

/**
 * Atomically reserves space for dependency objects in the single-threaded
 * extension host. Invalid internal counts fail closed by exhausting the
 * active budget.
 */
export function claimDependencyRecords(
  signal: AbortSignal,
  requested: number,
): DependencyRecordClaim {
  const active = ACTIVE_BUDGETS.get(signal);
  if (active === undefined) {
    return validRecordCount(requested)
      ? { accepted: requested, omitted: 0, remaining: Number.MAX_SAFE_INTEGER }
      : { accepted: 0, omitted: 0, remaining: 0 };
  }
  if (!validRecordCount(requested)) {
    active.retainedRecords = active.maximumRecords;
    return { accepted: 0, omitted: 0, remaining: 0 };
  }

  const available = Math.max(
    0,
    active.maximumRecords - active.retainedRecords,
  );
  const accepted = Math.min(requested, available);
  active.retainedRecords += accepted;
  return {
    accepted,
    omitted: requested - accepted,
    remaining: active.maximumRecords - active.retainedRecords,
  };
}

export function remainingDependencyRecordCapacity(
  signal: AbortSignal,
): number | undefined {
  const active = ACTIVE_BUDGETS.get(signal);
  return active === undefined
    ? undefined
    : Math.max(0, active.maximumRecords - active.retainedRecords);
}
