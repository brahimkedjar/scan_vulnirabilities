import type * as vscode from "vscode";

import type { Dependency } from "../../models/Dependency";
import type { ProjectCoverage, ScanError } from "../../models/ScanResult";
import {
  projectsSelectedForScan,
  type DependencyScanResult,
  type DetectionResult,
  type DetectedDependencyProject,
  type PackageManagerAdapter,
  type ScanOptions,
} from "../PackageManagerAdapter";
import {
  MAX_MANIFEST_BYTES,
  MAX_PROJECTS,
  coverageForProject,
  deduplicateDependencies,
  directoryUri,
  discoveryLimitError,
  environmentForRequirementsFile,
  filterDependencies,
  findFiles,
  isAbortError,
  readBoundedText,
  throwIfCancelled,
  uriPath,
} from "./adapterSupport";
import { parseRequirements } from "./requirementsParser";

const REQUIREMENTS_GLOB =
  "**/{requirements.txt,requirements-*.txt,requirements_*.txt,*-requirements.txt,requirements/*.txt}";

function projectsFromFiles(
  files: readonly vscode.Uri[],
): readonly DetectedDependencyProject[] {
  const grouped = new Map<string, { rootUri: vscode.Uri; files: vscode.Uri[] }>();
  for (const file of files) {
    const rootUri = directoryUri(file);
    const key = rootUri.toString();
    const group = grouped.get(key) ?? { rootUri, files: [] };
    group.files.push(file);
    grouped.set(key, group);
  }
  return [...grouped.values()]
    .sort((left, right) => left.rootUri.path.localeCompare(right.rootUri.path))
    .slice(0, MAX_PROJECTS)
    .map((group) => ({
      id: `pip:${group.rootUri.toString()}`,
      rootUri: group.rootUri,
      manifestUris: group.files.sort((left, right) =>
        left.path.localeCompare(right.path),
      ),
      lockfileUris: [],
    }));
}

export class PythonRequirementsAdapter implements PackageManagerAdapter {
  public readonly id = "pip";
  public readonly displayName = "Python requirements";
  public readonly ecosystems = ["PyPI"] as const;

  public async detect(
    workspaceFolder: vscode.Uri,
    cancellationToken?: vscode.CancellationToken,
  ): Promise<DetectionResult> {
    const matches = await findFiles(
      workspaceFolder,
      REQUIREMENTS_GLOB,
      MAX_PROJECTS * 4,
      cancellationToken,
    );
    const projects = projectsFromFiles(matches.files);
    return {
      detected: projects.length > 0,
      projects,
      errors: matches.truncated
        ? [discoveryLimitError(this.displayName, workspaceFolder)]
        : [],
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
      throwIfCancelled(signal, options.cancellationToken);
      const detection =
        options.preDetectedResult ??
        (await this.detect(workspaceFolder, options.cancellationToken));
      errors.push(...detection.errors);
      for (const project of projectsSelectedForScan(detection, options)) {
        throwIfCancelled(signal, options.cancellationToken);
        const projectDependencies: Dependency[] = [];
        for (const manifestUri of project.manifestUris) {
          throwIfCancelled(signal, options.cancellationToken);
          const manifestPath = uriPath(manifestUri);
          try {
            const text = await readBoundedText(
              manifestUri,
              MAX_MANIFEST_BYTES,
              signal,
              options.cancellationToken,
            );
            const parsed = parseRequirements({
              text,
              manifestPath,
              projectPath: uriPath(project.rootUri),
              workspacePath: uriPath(workspaceFolder),
              environment: environmentForRequirementsFile(manifestPath),
              ...(signal === undefined ? {} : { signal }),
            });
            projectDependencies.push(...parsed.dependencies);
            errors.push(...parsed.errors);
            for (const include of parsed.includes) {
              errors.push({
                code: "DEPENDENCY_UNRESOLVED",
                message: `nested requirements include '${include}' is not followed automatically`,
                path: manifestPath,
              });
            }
          } catch (error: unknown) {
            if (isAbortError(error)) {
              throw error;
            }
            errors.push({
              code:
                error instanceof RangeError
                  ? "DEPENDENCY_LIMIT"
                  : "INVALID_MANIFEST",
              message:
                error instanceof Error
                  ? error.message
                  : "could not read Python requirements file",
              path: manifestPath,
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
