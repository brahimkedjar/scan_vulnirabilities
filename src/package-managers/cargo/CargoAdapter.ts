import type * as vscode from "vscode";

import type { Dependency } from "../../models/Dependency";
import type { ProjectCoverage, ScanError, ScanErrorCode } from "../../models/ScanResult";
import {
  projectsSelectedForScan,
  type DependencyScanResult,
  type DetectedDependencyProject,
  type DetectionResult,
  type PackageManagerAdapter,
  type ScanOptions,
} from "../PackageManagerAdapter";
import {
  MAX_LOCKFILE_BYTES,
  MAX_MANIFEST_BYTES,
  MAX_PROJECTS,
  coverageForProject,
  deduplicateDependencies,
  directoryUri,
  discoveryLimitError,
  filterDependencies,
  findFiles,
  isAbortError,
  readBoundedText,
  throwIfCancelled,
  uriPath,
} from "../python/adapterSupport";
import {
  parseCargoDependencies,
  type CargoParseIssue,
} from "./CargoDependencyParser";

function directoryPath(uri: vscode.Uri): string {
  return directoryUri(uri).path.replace(/\/$/u, "");
}

function withinDirectory(childPath: string, parentPath: string): boolean {
  return childPath === parentPath || childPath.startsWith(`${parentPath}/`);
}

function nearestLock(
  manifest: vscode.Uri,
  locks: readonly vscode.Uri[],
): vscode.Uri | undefined {
  const manifestRoot = directoryPath(manifest);
  return locks
    .filter(
      (lock) =>
        lock.scheme === manifest.scheme &&
        lock.authority === manifest.authority &&
        withinDirectory(manifestRoot, directoryPath(lock)),
    )
    .sort((left, right) => directoryPath(right).length - directoryPath(left).length)[0];
}

function issueCode(issue: CargoParseIssue): ScanErrorCode {
  switch (issue.code) {
    case "NO_LOCKFILE":
      return "NO_LOCKFILE";
    case "INVALID_MANIFEST":
      return "INVALID_MANIFEST";
    case "INVALID_LOCKFILE":
      return "INVALID_LOCKFILE";
    case "UNSUPPORTED_LOCKFILE":
      return "UNSUPPORTED_LOCKFILE";
    case "UNSUPPORTED_PACKAGE_SOURCE":
      return "UNSUPPORTED_PACKAGE_SOURCE";
    case "DEPENDENCY_LIMIT":
      return "DEPENDENCY_LIMIT";
    default:
      return "DEPENDENCY_UNRESOLVED";
  }
}

export class CargoAdapter implements PackageManagerAdapter {
  public readonly id = "cargo";
  public readonly displayName = "Cargo";
  public readonly ecosystems = ["crates.io"] as const;

  public async detect(
    workspaceFolder: vscode.Uri,
    cancellationToken?: vscode.CancellationToken,
  ): Promise<DetectionResult> {
    const [manifestMatches, lockMatches] = await Promise.all([
      findFiles(
        workspaceFolder,
        "**/Cargo.toml",
        MAX_PROJECTS,
        cancellationToken,
      ),
      findFiles(
        workspaceFolder,
        "**/Cargo.lock",
        MAX_PROJECTS,
        cancellationToken,
      ),
    ]);
    const projects: DetectedDependencyProject[] = manifestMatches.files.map(
      (manifest) => {
        const lock = nearestLock(manifest, lockMatches.files);
        const workspaceManifest =
          lock === undefined
            ? undefined
            : manifestMatches.files.find(
                (candidate) => directoryPath(candidate) === directoryPath(lock),
              );
        return {
          id: `${this.id}:${manifest.toString()}`,
          rootUri: directoryUri(manifest),
          manifestUris: [
            manifest,
            ...(workspaceManifest === undefined ||
            workspaceManifest.toString() === manifest.toString()
              ? []
              : [workspaceManifest]),
          ],
          lockfileUris: lock === undefined ? [] : [lock],
        };
      },
    );
    const truncated = manifestMatches.truncated || lockMatches.truncated;
    return {
      detected: projects.length > 0,
      projects,
      errors: truncated
        ? [discoveryLimitError(this.displayName, workspaceFolder)]
        : [],
      truncated,
    };
  }

  public async scan(
    workspaceFolder: vscode.Uri,
    options: ScanOptions,
    signal?: AbortSignal,
  ): Promise<DependencyScanResult> {
    const errors: ScanError[] = [];
    const dependencies: Dependency[] = [];
    const coverage: ProjectCoverage[] = [];
    const textCache = new Map<string, Promise<string>>();
    const readCached = (
      uri: vscode.Uri,
      maximum: number,
    ): Promise<string> => {
      const key = uri.toString();
      const existing = textCache.get(key);
      if (existing !== undefined) {
        return existing;
      }
      const value = readBoundedText(
        uri,
        maximum,
        signal,
        options.cancellationToken,
      );
      textCache.set(key, value);
      return value;
    };
    try {
      const detection =
        options.preDetectedResult ??
        (await this.detect(workspaceFolder, options.cancellationToken));
      errors.push(...detection.errors);
      const manifestsByDirectory = new Map(
        detection.projects.flatMap((project) =>
          project.manifestUris.map((uri) => [directoryPath(uri), uri] as const),
        ),
      );
      for (const project of projectsSelectedForScan(detection, options)) {
        throwIfCancelled(signal, options.cancellationToken);
        const manifest = project.manifestUris[0];
        if (manifest === undefined) {
          continue;
        }
        const lock = project.lockfileUris[0];
        try {
          const cargoToml = await readCached(manifest, MAX_MANIFEST_BYTES);
          const cargoLock =
            lock === undefined
              ? undefined
              : await readCached(lock, MAX_LOCKFILE_BYTES);
          const workspaceManifest =
            lock === undefined
              ? undefined
              : manifestsByDirectory.get(directoryPath(lock));
          const workspaceToml =
            workspaceManifest === undefined ||
            workspaceManifest.toString() === manifest.toString()
              ? undefined
              : await readCached(workspaceManifest, MAX_MANIFEST_BYTES);
          const parsed = parseCargoDependencies({
            cargoToml,
            manifestPath: uriPath(manifest),
            ...(cargoLock === undefined ? {} : { cargoLock }),
            ...(lock === undefined ? {} : { lockfilePath: uriPath(lock) }),
            ...(workspaceToml === undefined ? {} : { workspaceToml }),
            ...(workspaceManifest === undefined
              ? {}
              : { workspaceManifestPath: uriPath(workspaceManifest) }),
            projectPath: uriPath(project.rootUri),
            workspacePath: uriPath(workspaceFolder),
            ...(signal === undefined ? {} : { signal }),
          });
          if (parsed.cancelled) {
            throw new DOMException("Cargo scan cancelled", "AbortError");
          }
          const retained = filterDependencies(
            deduplicateDependencies(parsed.dependencies),
            options,
          );
          dependencies.push(...retained);
          coverage.push(
            coverageForProject(
              "crates.io",
              this.id,
              uriPath(workspaceFolder),
              project,
              retained,
            ),
          );
          for (const issue of parsed.issues) {
            errors.push({
              code: issueCode(issue),
              message: issue.message,
              path:
                issue.code.includes("LOCKFILE") && lock !== undefined
                  ? uriPath(lock)
                  : uriPath(manifest),
            });
          }
        } catch (error: unknown) {
          if (isAbortError(error)) {
            throw error;
          }
          errors.push({
            code: error instanceof RangeError ? "DEPENDENCY_LIMIT" : "INVALID_MANIFEST",
            message:
              error instanceof Error
                ? error.message
                : "Could not read Cargo dependency metadata",
            path: uriPath(manifest),
          });
        }
      }
      return {
        adapterId: this.id,
        displayName: this.displayName,
        ecosystems: this.ecosystems,
        dependencies: deduplicateDependencies(dependencies),
        errors,
        projectCoverage: coverage,
        cancelled: false,
      };
    } catch (error: unknown) {
      if (!isAbortError(error)) {
        throw error;
      }
      return {
        adapterId: this.id,
        displayName: this.displayName,
        ecosystems: this.ecosystems,
        dependencies: [],
        errors,
        projectCoverage: coverage,
        cancelled: true,
      };
    }
  }
}
