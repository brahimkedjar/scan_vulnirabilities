import type * as vscode from "vscode";

import type { Dependency } from "../../models/Dependency";
import type { ProjectCoverage, ScanError, ScanErrorCode } from "../../models/ScanResult";
import {
  projectsSelectedForScan,
  type DependencyScanResult,
  type DetectionResult,
  type PackageManagerAdapter,
  type ScanOptions,
} from "../PackageManagerAdapter";
import {
  MAX_LOCKFILE_BYTES,
  MAX_MANIFEST_BYTES,
  coverageForProject,
  deduplicateDependencies,
  discoveryLimitError,
  filterDependencies,
  findFiles,
  groupProjectsByDirectory,
  isAbortError,
  readBoundedText,
  throwIfCancelled,
  uriPath,
} from "../python/adapterSupport";
import {
  parseComposerDependencies,
  type ComposerParseIssue,
} from "./ComposerDependencyParser";

function issueCode(issue: ComposerParseIssue): ScanErrorCode {
  switch (issue.code) {
    case "NO_LOCKFILE":
      return "NO_LOCKFILE";
    case "INVALID_MANIFEST":
      return "INVALID_MANIFEST";
    case "INVALID_LOCKFILE":
      return "INVALID_LOCKFILE";
    case "UNSUPPORTED_PACKAGE_SOURCE":
      return "UNSUPPORTED_PACKAGE_SOURCE";
    case "DEPENDENCY_LIMIT":
      return "DEPENDENCY_LIMIT";
    default:
      return "DEPENDENCY_UNRESOLVED";
  }
}

export class ComposerAdapter implements PackageManagerAdapter {
  public readonly id = "composer";
  public readonly displayName = "Composer";
  public readonly ecosystems = ["Packagist"] as const;

  public async detect(
    workspaceFolder: vscode.Uri,
    cancellationToken?: vscode.CancellationToken,
  ): Promise<DetectionResult> {
    const matches = await findFiles(
      workspaceFolder,
      "**/{composer.json,composer.lock}",
      undefined,
      cancellationToken,
    );
    const projects = groupProjectsByDirectory(
      this.id,
      matches.files,
      new Set(["composer.json"]),
      new Set(["composer.lock"]),
    ).filter((project) => project.manifestUris.length > 0);
    return {
      detected: projects.length > 0,
      projects,
      errors: matches.truncated
        ? [discoveryLimitError(this.displayName, workspaceFolder)]
        : [],
      truncated: matches.truncated,
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
    try {
      const detection =
        options.preDetectedResult ??
        (await this.detect(workspaceFolder, options.cancellationToken));
      errors.push(...detection.errors);
      for (const project of projectsSelectedForScan(detection, options)) {
        throwIfCancelled(signal, options.cancellationToken);
        const manifest = project.manifestUris[0];
        const lock = project.lockfileUris[0];
        if (manifest === undefined) {
          continue;
        }
        try {
          const [composerJson, composerLock] = await Promise.all([
            readBoundedText(
              manifest,
              MAX_MANIFEST_BYTES,
              signal,
              options.cancellationToken,
            ),
            lock === undefined
              ? Promise.resolve(undefined)
              : readBoundedText(
                  lock,
                  MAX_LOCKFILE_BYTES,
                  signal,
                  options.cancellationToken,
                ),
          ]);
          const parsed = parseComposerDependencies({
            composerJson,
            manifestPath: uriPath(manifest),
            ...(composerLock === undefined ? {} : { composerLock }),
            ...(lock === undefined ? {} : { lockfilePath: uriPath(lock) }),
            projectPath: uriPath(project.rootUri),
            workspacePath: uriPath(workspaceFolder),
            ...(signal === undefined ? {} : { signal }),
          });
          if (parsed.cancelled) {
            throw new DOMException("Composer scan cancelled", "AbortError");
          }
          const retained = filterDependencies(
            deduplicateDependencies(parsed.dependencies),
            options,
          );
          dependencies.push(...retained);
          coverage.push(
            coverageForProject(
              "Packagist",
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
                : "Could not read Composer dependency metadata",
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
