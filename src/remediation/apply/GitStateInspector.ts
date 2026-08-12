import type * as vscode from "vscode";

export type GitTargetState =
  | "clean"
  | "modified"
  | "untracked"
  | "conflicted"
  | "partially-staged"
  | "unavailable";

export interface GitTargetAssessment {
  readonly available: boolean;
  readonly state: GitTargetState;
  readonly blocked: boolean;
  readonly fingerprint: string;
}

interface GitChangeLike {
  readonly uri: vscode.Uri;
  readonly originalUri?: vscode.Uri;
  readonly renameUri?: vscode.Uri;
  readonly status: number;
}

interface GitRepositoryStateLike {
  readonly indexChanges: readonly GitChangeLike[];
  readonly workingTreeChanges: readonly GitChangeLike[];
  readonly mergeChanges: readonly GitChangeLike[];
  readonly onDidChange?: (listener: () => unknown) => { dispose(): unknown };
}

interface GitRepositoryLike {
  readonly rootUri: vscode.Uri;
  readonly state: GitRepositoryStateLike;
}

interface GitApiLike {
  readonly repositories: readonly GitRepositoryLike[];
  readonly onDidOpenRepository?: (
    listener: (repository: GitRepositoryLike) => unknown,
  ) => { dispose(): unknown };
  readonly onDidCloseRepository?: (
    listener: (repository: GitRepositoryLike) => unknown,
  ) => { dispose(): unknown };
}

interface GitExtensionExportsLike {
  readonly enabled?: boolean;
  getAPI(version: 1): GitApiLike;
}

export interface GitExtensionLike {
  readonly isActive: boolean;
  readonly exports: GitExtensionExportsLike;
}

export interface GitStateInspector {
  assess(uri: vscode.Uri): GitTargetAssessment;
  readonly onDidChange?: (
    listener: () => unknown,
  ) => { dispose(): unknown };
  readonly dispose?: () => void;
}

const STATUS_UNTRACKED = 7;
const CONFLICT_STATUSES = new Set([12, 13, 14, 15, 16, 17, 18]);

function uriKey(uri: vscode.Uri): string {
  const value = uri.toString();
  return process.platform === "win32" && uri.scheme === "file"
    ? value.toLowerCase()
    : value;
}

function changeMatches(change: GitChangeLike, key: string): boolean {
  return [change.uri, change.originalUri, change.renameUri].some(
    (candidate) => candidate !== undefined && uriKey(candidate) === key,
  );
}

function changesFor(
  changes: readonly GitChangeLike[],
  key: string,
): readonly GitChangeLike[] {
  return changes.filter((change) => changeMatches(change, key));
}

function unavailableAssessment(): GitTargetAssessment {
  return Object.freeze({
    available: false,
    state: "unavailable",
    blocked: false,
    fingerprint: "git-unavailable",
  });
}

function assessmentFor(
  repository: GitRepositoryLike,
  uri: vscode.Uri,
): GitTargetAssessment {
  const key = uriKey(uri);
  const index = changesFor(repository.state.indexChanges, key);
  const working = changesFor(repository.state.workingTreeChanges, key);
  const merge = changesFor(repository.state.mergeChanges, key);
  const statuses = [...index, ...working, ...merge]
    .map((change) => change.status)
    .sort((left, right) => left - right);
  let state: GitTargetState = "clean";
  if (merge.length > 0 || statuses.some((status) => CONFLICT_STATUSES.has(status))) {
    state = "conflicted";
  } else if (index.length > 0 && working.length > 0) {
    state = "partially-staged";
  } else if (statuses.includes(STATUS_UNTRACKED)) {
    state = "untracked";
  } else if (statuses.length > 0) {
    state = "modified";
  }
  return Object.freeze({
    available: true,
    state,
    blocked: state !== "clean",
    fingerprint: JSON.stringify([
      uriKey(repository.rootUri),
      key,
      state,
      statuses,
    ]),
  });
}

/**
 * Read-only projection of VS Code's already-active built-in Git model. This
 * module never activates the Git extension and never calls a Git operation.
 */
export class VsCodeGitStateInspector implements GitStateInspector {
  private readonly listeners = new Set<() => unknown>();
  private readonly subscriptions: { dispose(): unknown }[] = [];

  public constructor(private readonly api: GitApiLike | undefined) {
    if (api === undefined) return;
    for (const repository of api.repositories) {
      this.observeRepository(repository);
    }
    const open = api.onDidOpenRepository?.((repository) => {
      this.observeRepository(repository);
      this.fire();
    });
    const close = api.onDidCloseRepository?.(() => this.fire());
    if (open !== undefined) this.subscriptions.push(open);
    if (close !== undefined) this.subscriptions.push(close);
  }

  public assess(uri: vscode.Uri): GitTargetAssessment {
    if (uri.scheme !== "file" || this.api === undefined) {
      return unavailableAssessment();
    }
    const key = uriKey(uri);
    const repositories = this.api.repositories.filter((repository) => {
      const root = uriKey(repository.rootUri);
      return key === root || key.startsWith(`${root.endsWith("/") ? root : `${root}/`}`);
    });
    if (repositories.length === 0) {
      return unavailableAssessment();
    }
    repositories.sort(
      (left, right) =>
        uriKey(right.rootUri).length - uriKey(left.rootUri).length,
    );
    const repository = repositories[0];
    return repository === undefined
      ? unavailableAssessment()
      : assessmentFor(repository, uri);
  }

  public onDidChange(listener: () => unknown): { dispose(): unknown } {
    this.listeners.add(listener);
    return { dispose: () => this.listeners.delete(listener) };
  }

  public dispose(): void {
    for (const subscription of this.subscriptions.splice(0)) {
      subscription.dispose();
    }
    this.listeners.clear();
  }

  private observeRepository(repository: GitRepositoryLike): void {
    const subscription = repository.state.onDidChange?.(() => this.fire());
    if (subscription !== undefined) this.subscriptions.push(subscription);
  }

  private fire(): void {
    for (const listener of [...this.listeners]) {
      try {
        listener();
      } catch {
        // Git observations cannot influence the SCM provider or other listeners.
      }
    }
  }
}

export function gitStateInspectorFromExtension(
  extension: GitExtensionLike | undefined,
): GitStateInspector {
  if (extension?.isActive !== true || extension.exports.enabled === false) {
    return new VsCodeGitStateInspector(undefined);
  }
  try {
    return new VsCodeGitStateInspector(extension.exports.getAPI(1));
  } catch {
    return new VsCodeGitStateInspector(undefined);
  }
}
