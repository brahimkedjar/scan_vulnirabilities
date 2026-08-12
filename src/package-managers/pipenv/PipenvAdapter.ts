import type * as vscode from "vscode";

import type { Dependency } from "../../models/Dependency";
import type { ProjectCoverage, ScanError } from "../../models/ScanResult";
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
import { parsePipenvProject } from "./pipenvParser";

export class PipenvAdapter implements PackageManagerAdapter {
  public readonly id = "pipenv";
  public readonly displayName = "Pipenv";
  public readonly ecosystems = ["PyPI"] as const;

  public async detect(
    workspaceFolder: vscode.Uri,
    cancellationToken?: vscode.CancellationToken,
  ): Promise<DetectionResult> {
    const matches = await findFiles(
      workspaceFolder,
      "**/{Pipfile,Pipfile.lock}",
      undefined,
      cancellationToken,
    );
    const projects = groupProjectsByDirectory(
      this.id,
      matches.files,
      new Set(["pipfile"]),
      new Set(["pipfile.lock"]),
    );
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
        const lockfile = project.lockfileUris[0];
        const projectDependencies: Dependency[] = [];
        if (manifest === undefined) {
          errors.push({
            code: "INVALID_MANIFEST",
            message: "Pipfile.lock has no sibling Pipfile",
            path: uriPath(project.rootUri),
          });
        } else {
          try {
            const pipfileText = await readBoundedText(
              manifest,
              MAX_MANIFEST_BYTES,
              signal,
              options.cancellationToken,
            );
            const lockfileText =
              lockfile === undefined
                ? undefined
                : await readBoundedText(
                    lockfile,
                    MAX_LOCKFILE_BYTES,
                    signal,
                    options.cancellationToken,
                  );
            if (lockfile === undefined) {
              errors.push({
                code: "NO_LOCKFILE",
                message: "Pipenv project has no Pipfile.lock",
                path: uriPath(manifest),
              });
            }
            const parsed = await parsePipenvProject({
              pipfileText,
              ...(lockfileText === undefined ? {} : { lockfileText }),
              manifestPath: uriPath(manifest),
              ...(lockfile === undefined
                ? {}
                : { lockfilePath: uriPath(lockfile) }),
              projectPath: uriPath(project.rootUri),
              workspacePath: uriPath(workspaceFolder),
              ...(signal === undefined ? {} : { signal }),
            });
            projectDependencies.push(...parsed.dependencies);
            errors.push(...parsed.errors);
          } catch (error: unknown) {
            if (isAbortError(error)) {
              throw error;
            }
            errors.push({
              code:
                error instanceof RangeError
                  ? "DEPENDENCY_LIMIT"
                  : lockfile === undefined
                    ? "INVALID_MANIFEST"
                    : "INVALID_LOCKFILE",
              message:
                error instanceof Error
                  ? error.message
                  : "could not read Pipenv dependency metadata",
              path: uriPath(lockfile ?? manifest),
            });
          }
        }
        const retained = filterDependencies(
          deduplicateDependencies(projectDependencies),
          options,
        );
        dependencies.push(...retained);
        coverage.push(
          coverageForProject(
            "PyPI",
            this.id,
            uriPath(workspaceFolder),
            project,
            retained,
          ),
        );
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
