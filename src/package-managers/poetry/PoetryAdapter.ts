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
  MAX_PROJECTS,
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
import { parsePoetryManifest, parsePoetryProject } from "./poetryParser";
import { detectPoetryManifest } from "./poetryManifestDetection";

const POETRY_GLOB = "**/{pyproject.toml,poetry.lock}";

export class PoetryAdapter implements PackageManagerAdapter {
  public readonly id = "poetry";
  public readonly displayName = "Poetry";
  public readonly ecosystems = ["PyPI"] as const;

  public async detect(
    workspaceFolder: vscode.Uri,
    cancellationToken?: vscode.CancellationToken,
  ): Promise<DetectionResult> {
    const matches = await findFiles(
      workspaceFolder,
      POETRY_GLOB,
      MAX_PROJECTS * 4,
      cancellationToken,
    );
    const projects = groupProjectsByDirectory(
      this.id,
      matches.files,
      new Set(["pyproject.toml"]),
      new Set(["poetry.lock"]),
    );
    const errors: ScanError[] = [];
    if (matches.truncated || projects.length >= MAX_PROJECTS) {
      errors.push(discoveryLimitError(this.displayName, workspaceFolder));
    }
    return {
      detected: projects.length > 0,
      projects,
      errors,
      truncated: matches.truncated || projects.length >= MAX_PROJECTS,
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
            message: "poetry.lock has no sibling pyproject.toml",
            path: uriPath(project.rootUri),
          });
        } else {
          try {
            const pyprojectText = await readBoundedText(
              manifest,
              MAX_MANIFEST_BYTES,
              signal,
              options.cancellationToken,
            );
            // Detection deliberately performs no file reads so every byte is
            // charged to the scan-wide budget. Ignore a pyproject.toml only
            // after bounded inspection proves it unrelated; an inspection
            // limit remains visible as incomplete project coverage.
            if (lockfile === undefined) {
              const manifestDetection = detectPoetryManifest(pyprojectText);
              if (manifestDetection === "not-poetry") {
                continue;
              }
              if (manifestDetection === "indeterminate") {
                errors.push({
                  code: "DEPENDENCY_LIMIT",
                  message:
                    "Poetry project status could not be determined within bounded static manifest inspection",
                  path: uriPath(manifest),
                });
              } else {
                errors.push({
                  code: "NO_LOCKFILE",
                  message: "Poetry project has no poetry.lock; declared ranges are not installed versions",
                  path: uriPath(manifest),
                });
                const parsed = await parsePoetryManifest({
                  pyprojectText,
                  manifestPath: uriPath(manifest),
                  projectPath: uriPath(project.rootUri),
                  workspacePath: uriPath(workspaceFolder),
                });
                projectDependencies.push(...parsed.dependencies);
                errors.push(...parsed.errors);
              }
            } else {
              const lockfileText = await readBoundedText(
                lockfile,
                MAX_LOCKFILE_BYTES,
                signal,
                options.cancellationToken,
              );
              const parsed = await parsePoetryProject({
                pyprojectText,
                lockfileText,
                manifestPath: uriPath(manifest),
                lockfilePath: uriPath(lockfile),
                projectPath: uriPath(project.rootUri),
                workspacePath: uriPath(workspaceFolder),
                ...(signal === undefined ? {} : { signal }),
              });
              projectDependencies.push(...parsed.dependencies);
              errors.push(...parsed.errors);
            }
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
                  : "could not read Poetry dependency metadata",
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
