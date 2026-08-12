import type * as vscode from "vscode";

import type { Dependency } from "../models/Dependency";
import type { ProjectCoverage, ScanError } from "../models/ScanResult";
import type { Logger } from "../services/Logger";
import type {
  DependencyScanResult,
  DetectedDependencyProject,
  DetectionResult,
  PackageManagerAdapter,
  ScanOptions,
} from "./PackageManagerAdapter";
import { registerDependencyMetadataBudget } from "./dependencyMetadataBudget";
import {
  claimDependencyRecords,
  MAX_WORKSPACE_DEPENDENCY_RECORDS,
  registerDependencyRecordBudget,
  remainingDependencyRecordCapacity,
} from "./dependencyRecordBudget";

export interface WorkspaceDependencyScanOptions extends ScanOptions {
  readonly enabledEcosystems: ReadonlySet<string>;
}

export interface WorkspaceDependencyScanResult {
  readonly dependencies: readonly Dependency[];
  readonly errors: readonly ScanError[];
  readonly projectCoverage: readonly ProjectCoverage[];
  readonly packageManagers: readonly string[];
  readonly cancelled: boolean;
}

interface DetectedAdapter {
  readonly adapter: PackageManagerAdapter;
  readonly detection: DetectionResult;
  readonly workspaceFolder: vscode.Uri;
}

interface ProjectScanWorkUnit {
  readonly adapter: PackageManagerAdapter;
  readonly detection: DetectionResult;
  readonly targetProject?: DetectedDependencyProject;
  readonly workspaceFolder: vscode.Uri;
}

interface CancellationBridge {
  readonly token: vscode.CancellationToken;
  dispose(): void;
}

type ProjectScanOutcome =
  | {
      readonly kind: "completed";
      readonly index: number;
      readonly unit: ProjectScanWorkUnit;
      readonly result: DependencyScanResult;
    }
  | {
      readonly kind: "failed";
      readonly index: number;
      readonly unit: ProjectScanWorkUnit;
      readonly error: unknown;
    };

const DEFAULT_MAXIMUM_PROJECT_SCANS = 4;
const HARD_MAXIMUM_PROJECT_SCANS = 4;

function cancellationRequested(
  signal: AbortSignal,
  token?: vscode.CancellationToken,
): boolean {
  return signal.aborted || token?.isCancellationRequested === true;
}

function throwIfAborted(
  signal: AbortSignal,
  token?: vscode.CancellationToken,
): void {
  if (cancellationRequested(signal, token)) {
    throw new DOMException("Dependency project scan cancelled", "AbortError");
  }
}

function safeWorkspacePath(uri: vscode.Uri): string {
  return uri.scheme === "file" ? uri.fsPath : `${uri.scheme}:${uri.path}`;
}

function normalizedUriIdentity(uri: vscode.Uri): string {
  if (uri.scheme === "file" && process.platform === "win32") {
    return JSON.stringify([
      "file",
      (uri.authority ?? "").toLocaleLowerCase("en-US"),
      uri.path.toLocaleLowerCase("en-US"),
    ]);
  }
  return uri.toString();
}

function comparableUriPart(uri: vscode.Uri, value: string): string {
  return uri.scheme === "file" && process.platform === "win32"
    ? value.toLocaleLowerCase("en-US")
    : value;
}

function uriContains(container: vscode.Uri, candidate: vscode.Uri): boolean {
  const containerScheme = comparableUriPart(container, container.scheme);
  const candidateScheme = comparableUriPart(candidate, candidate.scheme);
  const containerAuthority = comparableUriPart(
    container,
    container.authority ?? "",
  );
  const candidateAuthority = comparableUriPart(
    candidate,
    candidate.authority ?? "",
  );
  if (
    containerScheme !== candidateScheme ||
    containerAuthority !== candidateAuthority
  ) {
    return false;
  }
  const containerPath = comparableUriPart(container, container.path);
  const candidatePath = comparableUriPart(candidate, candidate.path);
  const prefix = containerPath.endsWith("/")
    ? containerPath
    : `${containerPath}/`;
  return candidatePath === containerPath || candidatePath.startsWith(prefix);
}

function preferWorkspaceOwner(
  candidate: vscode.Uri,
  current: vscode.Uri,
  projectRoot: vscode.Uri,
): boolean {
  const candidateContains = uriContains(candidate, projectRoot);
  const currentContains = uriContains(current, projectRoot);
  if (candidateContains !== currentContains) {
    return candidateContains;
  }
  if (candidate.path.length !== current.path.length) {
    return candidate.path.length < current.path.length;
  }
  return candidate.toString().localeCompare(current.toString()) < 0;
}

function projectWorkKey(
  adapter: PackageManagerAdapter,
  project: DetectedDependencyProject,
): string {
  const projectId =
    project.rootUri.scheme === "file" && process.platform === "win32"
      ? project.id.toLocaleLowerCase("en-US")
      : project.id;
  return JSON.stringify([
    adapter.id,
    projectId,
    normalizedUriIdentity(project.rootUri),
  ]);
}

function isCancellation(
  error: unknown,
  signal: AbortSignal,
  token?: vscode.CancellationToken,
): boolean {
  return (
    cancellationRequested(signal, token) ||
    (error instanceof Error && error.name === "AbortError")
  );
}

function bridgeCancellation(
  signal: AbortSignal,
  token?: vscode.CancellationToken,
): CancellationBridge {
  let cancelled = signal.aborted || token?.isCancellationRequested === true;
  const listeners = new Set<(event: unknown) => unknown>();
  const notify = (): void => {
    if (cancelled) {
      return;
    }
    cancelled = true;
    for (const listener of [...listeners]) {
      try {
        listener(undefined);
      } catch {
        // Cancellation listeners are isolated like VS Code Event listeners.
      }
    }
  };
  signal.addEventListener("abort", notify);
  const onCancellationRequested = token?.onCancellationRequested;
  const tokenSubscription =
    typeof onCancellationRequested === "function"
      ? onCancellationRequested(notify)
      : undefined;
  const event = ((
    listener: (event: unknown) => unknown,
    thisArgs?: unknown,
    disposables?: vscode.Disposable[],
  ): vscode.Disposable => {
    const bound =
      thisArgs === undefined
        ? listener
        : (eventValue: unknown): unknown =>
            listener.call(thisArgs, eventValue);
    const disposable: vscode.Disposable = {
      dispose: (): void => {
        listeners.delete(bound);
      },
    };
    if (cancelled) {
      queueMicrotask(() => {
        try {
          bound(undefined);
        } catch {
          // Cancellation listeners are isolated like VS Code Event listeners.
        }
      });
    } else {
      listeners.add(bound);
    }
    disposables?.push(disposable);
    return disposable;
  }) as vscode.Event<unknown>;
  return {
    token: {
      get isCancellationRequested(): boolean {
        return cancelled || signal.aborted || token?.isCancellationRequested === true;
      },
      onCancellationRequested: event,
    },
    dispose: (): void => {
      signal.removeEventListener("abort", notify);
      tokenSubscription?.dispose();
      listeners.clear();
    },
  };
}

export class WorkspaceDependencyScanner {
  private readonly maximumConcurrency: number;
  private readonly maximumDependencyRecords: number;
  private readonly adapters: readonly PackageManagerAdapter[];

  public constructor(
    adapters: readonly PackageManagerAdapter[],
    private readonly logger: Logger,
    maximumConcurrency = DEFAULT_MAXIMUM_PROJECT_SCANS,
    maximumDependencyRecords = MAX_WORKSPACE_DEPENDENCY_RECORDS,
  ) {
    if (
      !Number.isSafeInteger(maximumConcurrency) ||
      maximumConcurrency < 1 ||
      maximumConcurrency > HARD_MAXIMUM_PROJECT_SCANS
    ) {
      throw new RangeError("maximumConcurrency must be between 1 and 4");
    }
    if (
      !Number.isSafeInteger(maximumDependencyRecords) ||
      maximumDependencyRecords < 1 ||
      maximumDependencyRecords > MAX_WORKSPACE_DEPENDENCY_RECORDS
    ) {
      throw new RangeError(
        `maximumDependencyRecords must be between 1 and ${MAX_WORKSPACE_DEPENDENCY_RECORDS.toString()}`,
      );
    }
    const ids = new Set<string>();
    for (const adapter of adapters) {
      if (ids.has(adapter.id)) {
        throw new TypeError(`Duplicate package manager adapter id: ${adapter.id}`);
      }
      ids.add(adapter.id);
    }
    this.adapters = [...adapters].sort((left, right) =>
      left.id.localeCompare(right.id),
    );
    this.maximumConcurrency = maximumConcurrency;
    this.maximumDependencyRecords = maximumDependencyRecords;
  }

  public async scan(
    workspaceFolder: vscode.Uri,
    options: WorkspaceDependencyScanOptions,
    signal: AbortSignal,
  ): Promise<WorkspaceDependencyScanResult> {
    return this.scanMany([workspaceFolder], options, signal);
  }

  /**
   * Scans every workspace root through one deterministic global project queue.
   * This keeps the four-project bound global in multi-root workspaces and
   * makes dependency-record budget winners independent of task completion
   * timing.
   */
  public async scanMany(
    workspaceFolders: readonly vscode.Uri[],
    options: WorkspaceDependencyScanOptions,
    signal: AbortSignal,
  ): Promise<WorkspaceDependencyScanResult> {
    throwIfAborted(signal, options.cancellationToken);
    const cancellationBridge = bridgeCancellation(
      signal,
      options.cancellationToken,
    );
    const effectiveOptions: WorkspaceDependencyScanOptions = {
      ...options,
      cancellationToken: cancellationBridge.token,
    };
    const metadataBudgetRegistration = registerDependencyMetadataBudget(signal);
    const recordBudgetRegistration = registerDependencyRecordBudget(
      signal,
      this.maximumDependencyRecords,
    );
    try {
      const errors: ScanError[] = [];
      const candidates = this.adapters.filter((adapter) =>
        adapter.ecosystems.some((ecosystem) =>
          effectiveOptions.enabledEcosystems.has(ecosystem),
        ),
      );
      const detectionUnits = workspaceFolders.flatMap((workspaceFolder) =>
        candidates.map((adapter) => ({ adapter, workspaceFolder })),
      );
      const detected: Array<DetectedAdapter | undefined> = new Array(
        detectionUnits.length,
      );
      const detectionErrors: Array<readonly ScanError[] | undefined> =
        new Array(detectionUnits.length);
      let nextDetection = 0;
      const detectWorker = async (): Promise<void> => {
        while (
          !cancellationRequested(signal, effectiveOptions.cancellationToken)
        ) {
          const index = nextDetection;
          nextDetection += 1;
          const unit = detectionUnits[index];
          if (unit === undefined) {
            return;
          }
          const { adapter, workspaceFolder } = unit;
          try {
            const detection = await adapter.detect(
              workspaceFolder,
              effectiveOptions.cancellationToken,
            );
            throwIfAborted(signal, effectiveOptions.cancellationToken);
            detectionErrors[index] = detection.errors;
            if (detection.detected) {
              detected[index] = { adapter, detection, workspaceFolder };
            }
          } catch (error: unknown) {
            if (isCancellation(error, signal, effectiveOptions.cancellationToken)) {
              return;
            }
            this.logger.error(
              `Package manager detection failed for ${adapter.displayName}`,
              error,
            );
            detectionErrors[index] = [
              {
                code: "WORKSPACE_ERROR",
                message: `${adapter.displayName} project detection failed`,
                path: safeWorkspacePath(workspaceFolder),
              },
            ];
          }
        }
      };
      await Promise.all(
        Array.from(
          {
            length: Math.min(
              this.maximumConcurrency,
              detectionUnits.length,
            ),
          },
          detectWorker,
        ),
      );
      for (const perDetectionErrors of detectionErrors) {
        if (perDetectionErrors !== undefined) {
          errors.push(...perDetectionErrors);
        }
      }
      if (cancellationRequested(signal, effectiveOptions.cancellationToken)) {
        return {
          dependencies: [],
          errors,
          projectCoverage: [],
          packageManagers: [],
          cancelled: true,
        };
      }

      const detectedAdapters = detected.filter(
        (value): value is DetectedAdapter => value !== undefined,
      );
      const workUnits: ProjectScanWorkUnit[] = [];
      const projectWorkIndexes = new Map<string, number>();
      for (const entry of detectedAdapters) {
        if (entry.detection.projects.length === 0) {
          // Preserve the adapter contract for unusual detections that do not
          // expose explicit projects (and for backwards-compatible adapters).
          workUnits.push({
            ...entry,
            detection:
              entry.detection.errors.length === 0
                ? entry.detection
                : { ...entry.detection, errors: [] },
          });
          continue;
        }
        const detectionContext: DetectionResult = {
          ...entry.detection,
          // Detection errors are published once above. Keeping the complete
          // project list here preserves nested-lock/workspace ownership while
          // targetProject selects the single bounded work unit.
          errors: [],
        };
        for (const project of entry.detection.projects) {
          const unit: ProjectScanWorkUnit = {
            adapter: entry.adapter,
            workspaceFolder: entry.workspaceFolder,
            detection: detectionContext,
            targetProject: project,
          };
          const key = projectWorkKey(entry.adapter, project);
          const existingIndex = projectWorkIndexes.get(key);
          if (existingIndex === undefined) {
            projectWorkIndexes.set(key, workUnits.length);
            workUnits.push(unit);
            continue;
          }
          const existing = workUnits[existingIndex];
          if (
            existing !== undefined &&
            preferWorkspaceOwner(
              entry.workspaceFolder,
              existing.workspaceFolder,
              project.rootUri,
            )
          ) {
            // Overlapping workspace folders can discover the same project.
            // Prefer the shallowest containing root so ancestor source-policy
            // files remain visible, but keep the first ordinal deterministic.
            workUnits[existingIndex] = unit;
          }
        }
      }

      const dependencies: Dependency[] = [];
      const projectCoverage: ProjectCoverage[] = [];
      const packageManagers = new Set<string>();
      const active = new Map<number, Promise<ProjectScanOutcome>>();
      const ready = new Map<number, ProjectScanOutcome>();
      let nextToLaunch = 0;
      let nextToCommit = 0;
      let cancelled = false;
      let recordLimitReached =
        workUnits.length > 0 &&
        remainingDependencyRecordCapacity(signal) === 0;
      let omittedRecords = 0;

      const launch = (index: number, unit: ProjectScanWorkUnit): void => {
        const pending = unit.adapter
          .scan(
            unit.workspaceFolder,
            {
              ...effectiveOptions,
              preDetectedResult: unit.detection,
              ...(unit.targetProject === undefined
                ? {}
                : { targetProject: unit.targetProject }),
            },
            signal,
          )
          .then<ProjectScanOutcome>((result) => ({
            kind: "completed",
            index,
            unit,
            result,
          }))
          .catch<ProjectScanOutcome>((error: unknown) => ({
            kind: "failed",
            index,
            unit,
            error,
          }));
        active.set(index, pending);
      };

      while (
        active.size > 0 ||
        ready.size > 0 ||
        (!recordLimitReached && nextToLaunch < workUnits.length)
      ) {
        if (cancellationRequested(signal, effectiveOptions.cancellationToken)) {
          cancelled = true;
          recordLimitReached = true;
        }
        while (
          !recordLimitReached &&
          nextToLaunch < workUnits.length &&
          // Completed out-of-order results still occupy the ordered window.
          // This intentionally trades some utilization behind a slow earlier
          // project for a hard bound on pending dependency-object arrays.
          nextToLaunch - nextToCommit < this.maximumConcurrency
        ) {
          const index = nextToLaunch;
          const unit = workUnits[index];
          nextToLaunch += 1;
          if (unit !== undefined) {
            launch(index, unit);
          }
        }

        const outcome = ready.get(nextToCommit);
        if (outcome === undefined) {
          if (active.size === 0) {
            break;
          }
          const settled = await Promise.race(active.values());
          active.delete(settled.index);
          ready.set(settled.index, settled);
          continue;
        }

        ready.delete(nextToCommit);
        nextToCommit += 1;
        if (outcome.kind === "failed") {
          if (
            isCancellation(
              outcome.error,
              signal,
              effectiveOptions.cancellationToken,
            )
          ) {
            cancelled = true;
            recordLimitReached = true;
            continue;
          }
          this.logger.error(
            `Dependency metadata scan failed for ${outcome.unit.adapter.displayName}`,
            outcome.error,
          );
          errors.push({
            code: "WORKSPACE_ERROR",
            message: `${outcome.unit.adapter.displayName} dependency metadata scan failed`,
            path: safeWorkspacePath(outcome.unit.workspaceFolder),
          });
          continue;
        }

        if (
          outcome.result.cancelled ||
          cancellationRequested(signal, effectiveOptions.cancellationToken)
        ) {
          cancelled = true;
          recordLimitReached = true;
          continue;
        }
        packageManagers.add(outcome.result.adapterId);
        errors.push(...outcome.result.errors);
        projectCoverage.push(...outcome.result.projectCoverage);

        const claim = claimDependencyRecords(
          signal,
          outcome.result.dependencies.length,
        );
        dependencies.push(...outcome.result.dependencies.slice(0, claim.accepted));
        omittedRecords += claim.omitted;
        if (claim.omitted > 0) {
          recordLimitReached = true;
        } else if (
          claim.remaining === 0 &&
          (active.size > 0 ||
            ready.size > 0 ||
            nextToLaunch < workUnits.length)
        ) {
          recordLimitReached = true;
        }
      }

      if (cancelled) {
        return {
          dependencies: [],
          errors,
          projectCoverage: [],
          packageManagers: [],
          cancelled: true,
        };
      }

      const omittedProjects = Math.max(0, workUnits.length - nextToLaunch);
      if (recordLimitReached && workUnits.length > 0) {
        const limitError: ScanError = {
          code: "DEPENDENCY_LIMIT",
          message: `Workspace dependency record limit of ${this.maximumDependencyRecords.toString()} was reached; ${omittedRecords.toString()} loaded record(s) and ${omittedProjects.toString()} additional project scan(s) were omitted before publication`,
          ...(workspaceFolders.length === 1 && workspaceFolders[0] !== undefined
            ? { path: safeWorkspacePath(workspaceFolders[0]) }
            : {}),
        };
        errors.push(limitError);
      }
      return {
        dependencies,
        errors,
        projectCoverage,
        packageManagers: [...packageManagers].sort(),
        cancelled: false,
      };
    } finally {
      recordBudgetRegistration.dispose();
      metadataBudgetRegistration.dispose();
      cancellationBridge.dispose();
    }
  }
}
