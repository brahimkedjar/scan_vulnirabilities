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
import { parseGoModules, type GoModulesParseIssue } from "./GoModulesParser";

function issueCode(issue: GoModulesParseIssue): ScanErrorCode {
  switch (issue.code) {
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

export class GoModulesAdapter implements PackageManagerAdapter {
  public readonly id = "go";
  public readonly displayName = "Go Modules";
  public readonly ecosystems = ["Go"] as const;

  public async detect(
    workspaceFolder: vscode.Uri,
    cancellationToken?: vscode.CancellationToken,
  ): Promise<DetectionResult> {
    const matches = await findFiles(
      workspaceFolder,
      "**/{go.mod,go.sum}",
      undefined,
      cancellationToken,
    );
    const projects = groupProjectsByDirectory(
      this.id,
      matches.files,
      new Set(["go.mod"]),
      new Set(["go.sum"]),
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
        const sum = project.lockfileUris[0];
        if (manifest === undefined) {
          continue;
        }
        try {
          const [goMod, goSum] = await Promise.all([
            readBoundedText(
              manifest,
              MAX_MANIFEST_BYTES,
              signal,
              options.cancellationToken,
            ),
            sum === undefined
              ? Promise.resolve(undefined)
              : readBoundedText(
                  sum,
                  MAX_LOCKFILE_BYTES,
                  signal,
                  options.cancellationToken,
                ),
          ]);
          const parsed = parseGoModules({
            goMod,
            manifestPath: uriPath(manifest),
            ...(goSum === undefined ? {} : { goSum }),
            ...(sum === undefined ? {} : { sumPath: uriPath(sum) }),
            projectPath: uriPath(project.rootUri),
            workspacePath: uriPath(workspaceFolder),
            ...(signal === undefined ? {} : { signal }),
          });
          if (parsed.cancelled) {
            throw new DOMException("Go module scan cancelled", "AbortError");
          }
          const retained = filterDependencies(
            deduplicateDependencies(parsed.dependencies),
            options,
          );
          dependencies.push(...retained);
          coverage.push(
            coverageForProject(
              "Go",
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
              path: issue.code === "INVALID_LOCKFILE" && sum !== undefined
                ? uriPath(sum)
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
                : "Could not read Go module metadata",
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
