import * as vscode from "vscode";

import { GENERATED_DIRECTORY_GLOB } from "../../discovery/dependencyFiles";
import type {
  Dependency,
  DependencyEnvironment,
} from "../../models/Dependency";
import type { ProjectCoverage, ScanError } from "../../models/ScanResult";
import type {
  DetectedDependencyProject,
  ScanOptions,
} from "../PackageManagerAdapter";
import { consumeDependencyMetadataBytes } from "../dependencyMetadataBudget";

export const MAX_PROJECTS = 100;
export const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
export const MAX_LOCKFILE_BYTES = 32 * 1024 * 1024;
export const MAX_DEPENDENCIES = 10_000;

export function uriPath(uri: vscode.Uri): string {
  return uri.scheme === "file" ? uri.fsPath : uri.toString();
}

export function directoryUri(uri: vscode.Uri): vscode.Uri {
  return vscode.Uri.joinPath(uri, "..");
}

export function throwIfCancelled(
  signal?: AbortSignal,
  token?: vscode.CancellationToken,
): void {
  if (signal?.aborted === true || token?.isCancellationRequested === true) {
    throw new DOMException("dependency metadata scan cancelled", "AbortError");
  }
}

export function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

export async function readBoundedText(
  uri: vscode.Uri,
  maximumBytes: number,
  signal?: AbortSignal,
  token?: vscode.CancellationToken,
): Promise<string> {
  throwIfCancelled(signal, token);
  const stat = await vscode.workspace.fs.stat(uri);
  throwIfCancelled(signal, token);
  if (
    !Number.isSafeInteger(stat.size) ||
    stat.size < 0 ||
    stat.size > maximumBytes
  ) {
    throw new RangeError("dependency metadata file exceeds its size limit");
  }
  if (!consumeDependencyMetadataBytes(signal, stat.size)) {
    throw new RangeError(
      "workspace dependency metadata exceeds its aggregate read limit",
    );
  }
  const bytes = await vscode.workspace.fs.readFile(uri);
  throwIfCancelled(signal, token);
  if (bytes.byteLength > maximumBytes) {
    throw new RangeError("dependency metadata file exceeds its size limit");
  }
  const extraBytes = Math.max(0, bytes.byteLength - stat.size);
  if (!consumeDependencyMetadataBytes(signal, extraBytes)) {
    throw new RangeError(
      "workspace dependency metadata exceeds its aggregate read limit",
    );
  }
  return new TextDecoder("utf-8", { fatal: true })
    .decode(bytes)
    .replace(/^\uFEFF/u, "");
}

export async function findFiles(
  workspaceFolder: vscode.Uri,
  pattern: string,
  maximum = MAX_PROJECTS * 4,
  token?: vscode.CancellationToken,
): Promise<{ readonly files: readonly vscode.Uri[]; readonly truncated: boolean }> {
  throwIfCancelled(undefined, token);
  const files = await vscode.workspace.findFiles(
    new vscode.RelativePattern(workspaceFolder, pattern),
    GENERATED_DIRECTORY_GLOB,
    maximum + 1,
    token,
  );
  throwIfCancelled(undefined, token);
  return {
    files: [...files]
      .sort((left, right) => left.path.localeCompare(right.path))
      .slice(0, maximum),
    truncated: files.length > maximum,
  };
}

export function groupProjectsByDirectory(
  adapterId: string,
  files: readonly vscode.Uri[],
  manifestNames: ReadonlySet<string>,
  lockfileNames: ReadonlySet<string>,
): readonly DetectedDependencyProject[] {
  const groups = new Map<
    string,
    {
      readonly rootUri: vscode.Uri;
      readonly manifests: vscode.Uri[];
      readonly locks: vscode.Uri[];
    }
  >();
  for (const uri of files) {
    const rootUri = directoryUri(uri);
    const key = rootUri.toString();
    const group = groups.get(key) ?? {
      rootUri,
      manifests: [],
      locks: [],
    };
    const name = uri.path.split("/").at(-1)?.toLowerCase() ?? "";
    if (manifestNames.has(name)) {
      group.manifests.push(uri);
    }
    if (lockfileNames.has(name)) {
      group.locks.push(uri);
    }
    groups.set(key, group);
  }
  return [...groups.values()]
    .sort((left, right) => left.rootUri.path.localeCompare(right.rootUri.path))
    .slice(0, MAX_PROJECTS)
    .map((group) => ({
      id: `${adapterId}:${group.rootUri.toString()}`,
      rootUri: group.rootUri,
      manifestUris: group.manifests.sort((left, right) =>
        left.path.localeCompare(right.path),
      ),
      lockfileUris: group.locks.sort((left, right) =>
        left.path.localeCompare(right.path),
      ),
    }));
}

export function environmentForRequirementsFile(
  manifestPath: string,
): DependencyEnvironment {
  const name = manifestPath.split(/[\\/]/u).at(-1)?.toLowerCase() ?? "";
  return /(?:^|[-_.])(dev|development|test|tests|lint|docs)(?:[-_.]|$)/u.test(
    name,
  )
    ? "development"
    : "production";
}

export function filterDependencies(
  dependencies: readonly Dependency[],
  options: ScanOptions,
): readonly Dependency[] {
  return dependencies.filter(
    (dependency) =>
      (options.includeDevDependencies ||
        dependency.environment !== "development") &&
      (options.includeTransitiveDependencies ||
        dependency.dependencyType !== "transitive"),
  );
}

export function deduplicateDependencies(
  dependencies: readonly Dependency[],
): readonly Dependency[] {
  return [
    ...new Map(
      dependencies.map((dependency) => [
        [
          dependency.projectPath ?? "",
          dependency.manifestPath ?? "",
          dependency.lockfilePath ?? "",
          dependency.name,
          dependency.installedVersion,
          dependency.requestedVersion ?? "",
          dependency.resolutionStatus ?? "resolved",
          dependency.dependencyType,
          dependency.environment,
        ].join("\u0000"),
        dependency,
      ]),
    ).values(),
  ];
}

export function coverageForProject(
  ecosystem: string,
  packageManager: string,
  workspacePath: string,
  project: DetectedDependencyProject,
  dependencies: readonly Dependency[],
): ProjectCoverage {
  return {
    ecosystem,
    packageManagers: [packageManager],
    workspacePath,
    projectPath: uriPath(project.rootUri),
    manifestPaths: project.manifestUris.map(uriPath),
    discovered: dependencies.length,
    resolved: dependencies.filter(
      (dependency) =>
        dependency.resolutionStatus === "resolved" &&
        dependency.installedVersion.length > 0,
    ).length,
    checked: 0,
    vulnerable: 0,
    unresolved: dependencies.filter(
      (dependency) => dependency.resolutionStatus === "unresolved",
    ).length,
    unsupported: dependencies.filter(
      (dependency) => dependency.resolutionStatus === "unsupported",
    ).length,
  };
}

export function discoveryLimitError(
  adapterName: string,
  workspaceFolder: vscode.Uri,
): ScanError {
  return {
    code: "DEPENDENCY_LIMIT",
    message: `${adapterName} project discovery exceeded its bounded file limit`,
    path: uriPath(workspaceFolder),
  };
}
