import * as vscode from "vscode";

import { GENERATED_DIRECTORY_GLOB } from "../../discovery/dependencyFiles";
import {
  dependencyIsResolved,
  type Dependency,
} from "../../models/Dependency";
import type { ProjectCoverage, ScanError } from "../../models/ScanResult";
import type { Logger } from "../../services/Logger";
import type {
  DependencyScanResult,
  DetectionResult,
  PackageManagerAdapter,
  ScanOptions,
} from "../PackageManagerAdapter";
import {
  applyWorkspaceRegistryGate,
  workspaceRegistryCoverageError,
} from "./NpmRegistryProvenance";
import { discoverWorkspaceRegistrySnapshot } from "./NpmRegistryProvenanceReader";
import { NpmWorkspaceScanner } from "./NpmWorkspaceScanner";

const MAX_PROJECTS = 100;
const MAX_PACKAGE_JSON_FILES = 2_000;
const NPM_LOCK_GLOB = "**/{package-lock.json,npm-shrinkwrap.json}";
const OTHER_JAVASCRIPT_LOCK_GLOB =
  "**/{yarn.lock,pnpm-lock.yaml,bun.lock,bun.lockb}";

function storagePath(uri: vscode.Uri): string {
  return uri.scheme === "file" ? uri.fsPath : uri.toString();
}

function parentUri(uri: vscode.Uri): vscode.Uri {
  return vscode.Uri.joinPath(uri, "..");
}

function isWithin(candidate: vscode.Uri, root: vscode.Uri): boolean {
  if (candidate.scheme !== root.scheme || candidate.authority !== root.authority) {
    return false;
  }
  const prefix = root.path.endsWith("/") ? root.path : `${root.path}/`;
  return candidate.path === root.path || candidate.path.startsWith(prefix);
}

function throwIfCancelled(token?: vscode.CancellationToken): void {
  if (token?.isCancellationRequested === true) {
    throw new DOMException("npm project detection cancelled", "AbortError");
  }
}

function countFromError(error: ScanError): number {
  const match = /^(\d+)\b/u.exec(error.message);
  const value = match?.[1] === undefined ? 1 : Number(match[1]);
  return Number.isSafeInteger(value) && value > 0 ? value : 1;
}

function coverageGapCounts(errors: readonly ScanError[]): {
  readonly unresolved: number;
  readonly unsupported: number;
} {
  let unresolved = 0;
  let unsupported = 0;
  for (const error of errors) {
    const count = countFromError(error);
    if (
      error.code === "UNSUPPORTED_LOCKFILE" ||
      error.code === "UNSUPPORTED_PACKAGE_MANAGER" ||
      error.code === "UNSUPPORTED_PACKAGE_SOURCE" ||
      error.code === "UNSUPPORTED_PACKAGE_IDENTITY"
    ) {
      unsupported += count;
    } else if (
      error.code === "NO_LOCKFILE" ||
      error.code === "INVALID_MANIFEST" ||
      error.code === "INVALID_LOCKFILE" ||
      error.code === "DEPENDENCY_UNRESOLVED" ||
      error.code === "UNSUPPORTED_VERSION"
    ) {
      unresolved += count;
    }
  }
  return { unresolved, unsupported };
}

export class NpmAdapter implements PackageManagerAdapter {
  public readonly id = "npm";
  public readonly displayName = "npm";
  public readonly ecosystems = ["npm"] as const;
  private readonly scanner: NpmWorkspaceScanner;

  public constructor(logger: Logger) {
    this.scanner = new NpmWorkspaceScanner(logger);
  }

  public async detect(
    workspaceFolder: vscode.Uri,
    cancellationToken?: vscode.CancellationToken,
  ): Promise<DetectionResult> {
    throwIfCancelled(cancellationToken);
    const [locks, manifests, otherLocks] = await Promise.all([
      vscode.workspace.findFiles(
        new vscode.RelativePattern(workspaceFolder, NPM_LOCK_GLOB),
        GENERATED_DIRECTORY_GLOB,
        MAX_PROJECTS * 2 + 1,
        cancellationToken,
      ),
      vscode.workspace.findFiles(
        new vscode.RelativePattern(workspaceFolder, "**/package.json"),
        GENERATED_DIRECTORY_GLOB,
        MAX_PACKAGE_JSON_FILES + 1,
        cancellationToken,
      ),
      vscode.workspace.findFiles(
        new vscode.RelativePattern(
          workspaceFolder,
          OTHER_JAVASCRIPT_LOCK_GLOB,
        ),
        GENERATED_DIRECTORY_GLOB,
        MAX_PACKAGE_JSON_FILES + 1,
        cancellationToken,
      ),
    ]);
    throwIfCancelled(cancellationToken);
    const otherRoots = otherLocks.map(parentUri);
    const lockByRoot = new Map<string, vscode.Uri>();
    for (const lockUri of [...locks].sort((left, right) =>
      left.path.localeCompare(right.path),
    )) {
      const rootUri = parentUri(lockUri);
      const key = rootUri.toString();
      const existing = lockByRoot.get(key);
      if (
        existing === undefined ||
        (lockUri.path.endsWith("/npm-shrinkwrap.json") &&
          !existing.path.endsWith("/npm-shrinkwrap.json"))
      ) {
        lockByRoot.set(key, lockUri);
      }
    }
    const projects: Array<{
      readonly id: string;
      readonly rootUri: vscode.Uri;
      readonly manifestUris: vscode.Uri[];
      readonly lockfileUris: vscode.Uri[];
    }> = [...lockByRoot.values()]
      .sort((left, right) => left.path.localeCompare(right.path))
      .slice(0, MAX_PROJECTS)
      .map((lockUri) => {
        const rootUri = parentUri(lockUri);
        return {
          id: storagePath(rootUri),
          rootUri,
          manifestUris: [vscode.Uri.joinPath(rootUri, "package.json")],
          lockfileUris: [lockUri],
        };
      });
    const lockRoots = projects.map((project) => project.rootUri);
    let omittedProject = false;
    for (const manifestUri of [...manifests].sort((left, right) =>
      left.path.localeCompare(right.path),
    )) {
      throwIfCancelled(cancellationToken);
      const owner = projects
        .filter(
          (project) =>
            project.lockfileUris.length > 0 &&
            isWithin(manifestUri, project.rootUri),
        )
        .sort((left, right) => right.rootUri.path.length - left.rootUri.path.length)[0];
      if (owner !== undefined) {
        if (
          !owner.manifestUris.some(
            (candidate) => candidate.toString() === manifestUri.toString(),
          )
        ) {
          owner.manifestUris.push(manifestUri);
        }
        continue;
      }
      if (projects.length >= MAX_PROJECTS) {
        omittedProject = true;
        continue;
      }
      if (
        lockRoots.some((root) => isWithin(manifestUri, root)) ||
        otherRoots.some((root) => isWithin(manifestUri, root))
      ) {
        continue;
      }
      const rootUri = parentUri(manifestUri);
      projects.push({
        id: storagePath(rootUri),
        rootUri,
        manifestUris: [manifestUri],
        lockfileUris: [],
      });
    }
    const truncated =
      locks.length > MAX_PROJECTS * 2 ||
      manifests.length > MAX_PACKAGE_JSON_FILES ||
      otherLocks.length > MAX_PACKAGE_JSON_FILES ||
      lockByRoot.size > MAX_PROJECTS ||
      omittedProject;
    const errors: ScanError[] = truncated
      ? [
          {
            code: "DEPENDENCY_LIMIT",
            message: `npm project detection exceeded the ${MAX_PROJECTS.toString()}-project limit`,
            path: storagePath(workspaceFolder),
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

  public async scan(
    workspaceFolder: vscode.Uri,
    options: ScanOptions,
    signal: AbortSignal = new AbortController().signal,
  ): Promise<DependencyScanResult> {
    const detection =
      options.preDetectedResult ??
      (await this.detect(workspaceFolder, options.cancellationToken));
    if (!detection.detected) {
      return {
        adapterId: this.id,
        displayName: this.displayName,
        ecosystems: this.ecosystems,
        dependencies: [],
        errors: detection.errors,
        projectCoverage: [],
        cancelled: false,
      };
    }
    const folder: vscode.WorkspaceFolder = {
      uri: workspaceFolder,
      name: workspaceFolder.path.split("/").at(-1) ?? "workspace",
      index: 0,
    };
    const registrySnapshot = await discoverWorkspaceRegistrySnapshot(
      workspaceFolder,
      signal,
      options.cancellationToken,
    );
    const result = await this.scanner.scan(
      folder,
      signal,
      options.cancellationToken,
      detection.projects,
      options.targetProject,
    );
    const workspacePath = storagePath(workspaceFolder);
    const coverageRootPath =
      options.targetProject === undefined
        ? workspacePath
        : storagePath(options.targetProject.rootUri);
    const registryGate = applyWorkspaceRegistryGate(
      result.dependencies,
      registrySnapshot,
      workspacePath,
    );
    const registryErrors = registryGate.affectedByProject.map(
      ({ projectPath, count }) =>
        workspaceRegistryCoverageError(count, projectPath),
    );
    const byProject = new Map<
      string,
      { dependencies: Dependency[]; manifests: Set<string> }
    >();
    for (const dependency of registryGate.dependencies) {
      const projectPath = dependency.projectPath ?? workspacePath;
      const entry = byProject.get(projectPath) ?? {
        dependencies: [],
        manifests: new Set<string>(),
      };
      entry.dependencies.push(dependency);
      const manifestPath = dependency.manifestPath ?? dependency.packageJsonPath;
      if (manifestPath !== undefined) {
        entry.manifests.add(manifestPath);
      }
      byProject.set(projectPath, entry);
    }
    const gaps = coverageGapCounts(result.errors);
    const projectCoverage: ProjectCoverage[] = [...byProject].map(
      ([projectPath, entry]) => ({
        workspacePath: storagePath(workspaceFolder),
        projectPath,
        manifestPaths: [...entry.manifests].sort(),
        ecosystem: "npm",
        packageManagers: ["npm"],
        discovered: entry.dependencies.length,
        resolved: entry.dependencies.filter(dependencyIsResolved).length,
        checked: 0,
        vulnerable: 0,
        unresolved: entry.dependencies.filter(
          (dependency) => dependency.resolutionStatus === "unresolved",
        ).length,
        unsupported: entry.dependencies.filter(
          (dependency) => dependency.resolutionStatus === "unsupported",
        ).length,
      }),
    );
    const rootCoverageIndex = projectCoverage.findIndex(
      (coverage) => coverage.projectPath === coverageRootPath,
    );
    if (rootCoverageIndex !== -1) {
      const rootCoverage = projectCoverage[rootCoverageIndex];
      if (rootCoverage !== undefined) {
        const unresolved = Math.max(rootCoverage.unresolved, gaps.unresolved);
        const unsupported = Math.max(rootCoverage.unsupported, gaps.unsupported);
        projectCoverage[rootCoverageIndex] = {
          ...rootCoverage,
          discovered: rootCoverage.resolved + unresolved + unsupported,
          unresolved,
          unsupported,
        };
      }
    } else if (
      gaps.unresolved > 0 ||
      gaps.unsupported > 0 ||
      projectCoverage.length === 0
    ) {
      projectCoverage.push({
        workspacePath,
        projectPath: coverageRootPath,
        manifestPaths: [],
        ecosystem: "npm",
        packageManagers: ["npm"],
        discovered: gaps.unresolved + gaps.unsupported,
        resolved: 0,
        checked: 0,
        vulnerable: 0,
        unresolved: gaps.unresolved,
        unsupported: gaps.unsupported,
      });
    }
    return {
      adapterId: this.id,
      displayName: this.displayName,
      ecosystems: this.ecosystems,
      dependencies: registryGate.dependencies,
      errors: [...detection.errors, ...result.errors, ...registryErrors],
      projectCoverage,
      cancelled: result.cancelled,
    };
  }
}
