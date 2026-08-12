import { ReadBudget } from "../discovery/readBudget";

interface ActiveBudget {
  readonly budget: ReadBudget;
  references: number;
}

const ACTIVE_BUDGETS = new WeakMap<AbortSignal, ActiveBudget>();
export const MAX_WORKSPACE_DEPENDENCY_METADATA_BYTES = 256 * 1024 * 1024;

/** Registers one scan-wide budget shared by every concurrently running adapter. */
export function registerDependencyMetadataBudget(
  signal: AbortSignal,
  maximumBytes = MAX_WORKSPACE_DEPENDENCY_METADATA_BYTES,
): { dispose(): void } {
  const existing = ACTIVE_BUDGETS.get(signal);
  if (existing !== undefined) {
    existing.references += 1;
  } else {
    ACTIVE_BUDGETS.set(signal, {
      budget: new ReadBudget(maximumBytes),
      references: 1,
    });
  }
  let active = true;
  return {
    dispose: (): void => {
      if (active) {
        active = false;
        const current = ACTIVE_BUDGETS.get(signal);
        if (current !== undefined) {
          current.references -= 1;
          if (current.references === 0) {
            ACTIVE_BUDGETS.delete(signal);
          }
        }
      }
    },
  };
}

export function consumeDependencyMetadataBytes(
  signal: AbortSignal | undefined,
  bytes: number,
): boolean {
  if (signal === undefined) {
    return true;
  }
  const active = ACTIVE_BUDGETS.get(signal);
  return active === undefined || active.budget.tryConsume(bytes);
}
