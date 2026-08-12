import * as vscode from "vscode";

import { GENERATED_DIRECTORY_GLOB } from "../../discovery/dependencyFiles";
import type { Dependency } from "../../models/Dependency";
import type { ProjectCoverage, ScanError, ScanErrorCode } from "../../models/ScanResult";
import type {
  DependencyScanResult,
  DetectedDependencyProject,
  DetectionResult,
  ScanOptions,
} from "../PackageManagerAdapter";
import { consumeDependencyMetadataBytes } from "../dependencyMetadataBudget";
import {
  isSafeRelativePath,
  type JavaScriptParseIssue,
  type JavaScriptParseResult,
  type ManifestInput,
} from "./JavaScriptParserTypes";

export type {
  JavaScriptParseIssue,
  JavaScriptParseResult,
  ManifestInput,
} from "./JavaScriptParserTypes";

export const MAX_PROJECTS = 100;
export const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;
export const MAX_LOCKFILE_BYTES = 32 * 1024 * 1024;
const MAX_TOTAL_MANIFEST_CHARACTERS = 32 * 1024 * 1024;
export function uriPath(uri: vscode.Uri): string {
  return uri.scheme === "file" ? uri.fsPath : uri.toString();
}

export function rootRelativeDirectory(
  root: vscode.Uri,
  manifest: vscode.Uri,
): string | undefined {
  if (root.scheme !== manifest.scheme || root.authority !== manifest.authority) {
    return undefined;
  }
  const rootPath = root.path.endsWith("/") ? root.path : `${root.path}/`;
  if (!manifest.path.startsWith(rootPath)) {
    return undefined;
  }
  const relative = manifest.path.slice(rootPath.length);
  if (relative === "package.json") {
    return ".";
  }
  const suffix = "/package.json";
  if (!relative.endsWith(suffix)) {
    return undefined;
  }
  const directory = relative.slice(0, -suffix.length);
  return isSafeRelativePath(directory) ? directory : undefined;
}

export function throwIfCancelled(
  signal?: AbortSignal,
  cancellationToken?: vscode.CancellationToken,
): void {
  if (signal?.aborted === true || cancellationToken?.isCancellationRequested === true) {
    throw new DOMException("dependency metadata scan cancelled", "AbortError");
  }
}

export function isCancellation(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

async function exists(
  uri: vscode.Uri,
  cancellationToken?: vscode.CancellationToken,
): Promise<boolean> {
  throwIfCancelled(undefined, cancellationToken);
  try {
    const stat = await vscode.workspace.fs.stat(uri);
    throwIfCancelled(undefined, cancellationToken);
    return (stat.type & vscode.FileType.File) !== 0;
  } catch {
    throwIfCancelled(undefined, cancellationToken);
    return false;
  }
}

function folderPattern(root: vscode.Uri, pattern: string): vscode.RelativePattern {
  return new vscode.RelativePattern(
    { uri: root, name: root.path.split("/").at(-1) ?? "workspace", index: 0 },
    pattern,
  );
}

export async function detectJavaScriptProjects(
  workspaceFolder: vscode.Uri,
  adapterId: string,
  lockfileGlob: string,
  cancellationToken?: vscode.CancellationToken,
): Promise<DetectionResult> {
  throwIfCancelled(undefined, cancellationToken);
  const matches = await vscode.workspace.findFiles(
    folderPattern(workspaceFolder, lockfileGlob),
    GENERATED_DIRECTORY_GLOB,
    MAX_PROJECTS + 1,
    cancellationToken,
  );
  throwIfCancelled(undefined, cancellationToken);
  const truncated = matches.length > MAX_PROJECTS;
  const retained = [...matches]
    .sort((left, right) => left.path.localeCompare(right.path))
    .slice(0, MAX_PROJECTS);
  const grouped = new Map<string, vscode.Uri[]>();
  for (const lockfile of retained) {
    const root = vscode.Uri.joinPath(lockfile, "..");
    const key = root.toString();
    const locks = grouped.get(key) ?? [];
    locks.push(lockfile);
    grouped.set(key, locks);
  }

  const projects: DetectedDependencyProject[] = [];
  for (const [key, lockfileUris] of grouped) {
    const rootUri = vscode.Uri.parse(key);
    const manifestUri = vscode.Uri.joinPath(rootUri, "package.json");
    projects.push({
      id: `${adapterId}:${key}`,
      rootUri,
      manifestUris: (await exists(manifestUri, cancellationToken))
        ? [manifestUri]
        : [],
      lockfileUris: [...lockfileUris].sort((left, right) =>
        left.path.localeCompare(right.path),
      ),
    });
  }

  const errors: ScanError[] = truncated
    ? [
        {
          code: "DEPENDENCY_LIMIT",
          message: `${adapterId} project discovery exceeded the ${MAX_PROJECTS.toString()}-project limit`,
          path: uriPath(workspaceFolder),
        },
      ]
    : [];
  return {
    detected: projects.length > 0,
    projects,
    errors,
    truncated,
  };
}

export async function readBoundedText(
  uri: vscode.Uri,
  maximumBytes: number,
  signal?: AbortSignal,
  cancellationToken?: vscode.CancellationToken,
): Promise<string> {
  throwIfCancelled(signal, cancellationToken);
  const stat = await vscode.workspace.fs.stat(uri);
  if (!Number.isSafeInteger(stat.size) || stat.size < 0 || stat.size > maximumBytes) {
    throw new RangeError("Dependency metadata file exceeds its size limit");
  }
  if (!consumeDependencyMetadataBytes(signal, stat.size)) {
    throw new RangeError(
      "workspace dependency metadata exceeds its aggregate read limit",
    );
  }
  const bytes = await vscode.workspace.fs.readFile(uri);
  throwIfCancelled(signal, cancellationToken);
  if (bytes.byteLength > maximumBytes) {
    throw new RangeError("Dependency metadata file exceeds its size limit");
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

export async function discoverProjectManifests(
  project: DetectedDependencyProject,
  allProjects: readonly DetectedDependencyProject[],
  signal?: AbortSignal,
  cancellationToken?: vscode.CancellationToken,
): Promise<readonly vscode.Uri[]> {
  const matches = await vscode.workspace.findFiles(
    folderPattern(project.rootUri, "**/package.json"),
    GENERATED_DIRECTORY_GLOB,
    1_001,
    cancellationToken,
  );
  throwIfCancelled(signal, cancellationToken);
  if (matches.length > 1_000) {
    throw new RangeError(
      "JavaScript workspace manifest discovery exceeds the 1000-file limit",
    );
  }
  const otherRoots = allProjects
    .filter((candidate) => candidate.id !== project.id)
    .map((candidate) => candidate.rootUri.path.endsWith("/")
      ? candidate.rootUri.path
      : `${candidate.rootUri.path}/`);
  return [...matches]
    .filter(
      (manifest) =>
        !otherRoots.some(
          (rootPath) =>
            rootPath.startsWith(
              project.rootUri.path.endsWith("/")
                ? project.rootUri.path
                : `${project.rootUri.path}/`,
            ) && manifest.path.startsWith(rootPath),
        ),
    )
    .sort((left, right) => left.path.localeCompare(right.path))
    .slice(0, 1_000);
}

export async function readManifestInputs(
  project: DetectedDependencyProject,
  uris: readonly vscode.Uri[],
  signal?: AbortSignal,
  cancellationToken?: vscode.CancellationToken,
): Promise<readonly ManifestInput[]> {
  const inputs: ManifestInput[] = [];
  let totalCharacters = 0;
  for (const uri of uris) {
    throwIfCancelled(signal, cancellationToken);
    const relativeDirectory = rootRelativeDirectory(project.rootUri, uri);
    if (relativeDirectory === undefined) {
      continue;
    }
    const content = await readBoundedText(
      uri,
      MAX_MANIFEST_BYTES,
      signal,
      cancellationToken,
    );
    totalCharacters += content.length;
    if (totalCharacters > MAX_TOTAL_MANIFEST_CHARACTERS) {
      throw new RangeError(
        "JavaScript workspace manifests exceed their aggregate read limit",
      );
    }
    inputs.push({
      path: uriPath(uri),
      relativeDirectory,
      content,
    });
  }
  return inputs;
}

export function issueToScanError(
  issue: JavaScriptParseIssue,
  path: string,
): ScanError {
  const code: ScanErrorCode = issue.code;
  return {
    code,
    message: issue.message,
    path,
    ...(issue.packageName === undefined ? {} : { packageName: issue.packageName }),
  };
}

export function coverageFor(
  workspacePath: string,
  projectPath: string,
  manifestPaths: readonly string[],
  packageManager: string,
  result: JavaScriptParseResult,
): ProjectCoverage {
  return {
    ecosystem: "npm",
    packageManagers: [packageManager],
    discovered: result.discovered,
    resolved: result.resolved,
    checked: 0,
    vulnerable: 0,
    unresolved: result.unresolved,
    unsupported: result.unsupported,
    workspacePath,
    projectPath,
    manifestPaths,
  };
}

export function emptyScanResult(
  adapterId: string,
  displayName: string,
  errors: readonly ScanError[],
  cancelled: boolean,
): DependencyScanResult {
  return {
    adapterId,
    displayName,
    ecosystems: ["npm"],
    dependencies: [],
    errors,
    projectCoverage: [],
    cancelled,
  };
}

export function shouldIncludeEnvironment(
  environment: Dependency["environment"],
  options: ScanOptions,
): boolean {
  return environment !== "development" || options.includeDevDependencies;
}

export function makeUnresolvedDependency(input: {
  readonly name: string;
  readonly requestedVersion?: string;
  readonly manifestName?: string;
  readonly environment: Dependency["environment"];
  readonly manifestPath: string;
  readonly lockfilePath: string;
  readonly packageManager: string;
  readonly projectPath: string;
  readonly workspacePath: string;
  readonly unsupported?: boolean;
  readonly dependencyPath?: readonly string[];
}): Dependency {
  return {
    name: input.name,
    ecosystem: "npm",
    ...(input.requestedVersion === undefined
      ? {}
      : { requestedVersion: input.requestedVersion }),
    ...(input.manifestName === undefined ? {} : { manifestName: input.manifestName }),
    installedVersion: "",
    resolutionStatus: input.unsupported === true ? "unsupported" : "unresolved",
    dependencyType: "direct",
    environment: input.environment,
    declaredEnvironment: input.environment,
    ...(input.dependencyPath === undefined
      ? {}
      : { dependencyPath: [...input.dependencyPath] }),
    manifestPath: input.manifestPath,
    packageJsonPath: input.manifestPath,
    lockfilePath: input.lockfilePath,
    packageManager: input.packageManager,
    projectPath: input.projectPath,
    workspacePath: input.workspacePath,
  };
}
