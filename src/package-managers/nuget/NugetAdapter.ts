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
import { parseNugetDependencies, type NugetParseIssue } from "./NugetDependencyParser";

function fileName(uri: vscode.Uri): string {
  return uri.path.split("/").at(-1) ?? "";
}

function isNugetConfig(uri: vscode.Uri): boolean {
  return fileName(uri).toLowerCase() === "nuget.config";
}

function isDirectoryPackagesProps(uri: vscode.Uri): boolean {
  return fileName(uri).toLowerCase() === "directory.packages.props";
}

function isDirectoryBuildConfiguration(uri: vscode.Uri): boolean {
  const name = fileName(uri).toLowerCase();
  return name === "directory.build.props" || name === "directory.build.targets";
}

const MAX_ASSOCIATED_CONFIGURATION_FILES = 33;

function failClosedDependencies(
  dependencies: readonly Dependency[],
  provenanceDiscoveryTruncated: boolean,
): readonly Dependency[] {
  return provenanceDiscoveryTruncated
    ? dependencies.map((dependency) => ({
        ...dependency,
        installedVersion: "",
        resolutionStatus: "unsupported" as const,
        metadata: {
          ...dependency.metadata,
          repositorySource: "workspace-discovery-truncated",
        },
      }))
    : dependencies;
}

function configsForProject(
  configs: readonly vscode.Uri[],
  projectRoot: vscode.Uri,
): readonly vscode.Uri[] {
  const applicable = configs
    .filter((uri) => {
      const root = directoryUri(uri);
      if (
        root.scheme !== projectRoot.scheme ||
        root.authority !== projectRoot.authority
      ) {
        return false;
      }
      const prefix = root.path.endsWith("/") ? root.path : `${root.path}/`;
      return projectRoot.path === root.path || projectRoot.path.startsWith(prefix);
    })
    .sort((left, right) => {
      const depth = directoryUri(left).path.length - directoryUri(right).path.length;
      return depth === 0 ? left.path.localeCompare(right.path) : depth;
    });
  if (applicable.length <= MAX_ASSOCIATED_CONFIGURATION_FILES) {
    return applicable;
  }
  // Preserve the over-limit sentinel (33 inputs makes the parser fail closed)
  // and the nearest configuration, which has the highest effective precedence.
  const nearest = applicable.at(-1);
  return nearest === undefined
    ? []
    : [
        ...applicable.slice(0, MAX_ASSOCIATED_CONFIGURATION_FILES - 1),
        nearest,
      ];
}

function withApplicableNugetMetadata(
  projects: readonly DetectedDependencyProject[],
  configs: readonly vscode.Uri[],
  centralPackageFiles: readonly vscode.Uri[],
  restoreConfigurationFiles: readonly vscode.Uri[],
): readonly DetectedDependencyProject[] {
  return projects.map((project) => ({
    ...project,
    manifestUris: [
      ...new Map(
        [
          ...project.manifestUris,
          ...configsForProject(configs, project.rootUri),
          ...configsForProject(centralPackageFiles, project.rootUri),
          ...configsForProject(restoreConfigurationFiles, project.rootUri),
        ].map((uri) => [uri.toString(), uri]),
      ).values(),
    ],
  }));
}

function issueCode(issue: NugetParseIssue): ScanErrorCode {
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

function buildProjects(files: readonly vscode.Uri[]): readonly DetectedDependencyProject[] {
  const groups = new Map<
    string,
    {
      readonly rootUri: vscode.Uri;
      readonly projects: vscode.Uri[];
      readonly configs: vscode.Uri[];
      readonly locks: vscode.Uri[];
    }
  >();
  for (const uri of files) {
    const rootUri = directoryUri(uri);
    const key = rootUri.toString();
    const group = groups.get(key) ?? {
      rootUri,
      projects: [],
      configs: [],
      locks: [],
    };
    const name = fileName(uri).toLowerCase();
    if (name.endsWith(".csproj")) {
      group.projects.push(uri);
    } else if (name === "packages.config") {
      group.configs.push(uri);
    } else if (/^packages(?:\..+)?\.lock\.json$/u.test(name)) {
      group.locks.push(uri);
    }
    groups.set(key, group);
  }
  const output: DetectedDependencyProject[] = [];
  for (const group of groups.values()) {
    for (const project of group.projects) {
      const stem = fileName(project).replace(/\.csproj$/iu, "").toLowerCase();
      const lock =
        group.locks.find(
          (candidate) => fileName(candidate).toLowerCase() === `packages.${stem}.lock.json`,
        ) ??
        group.locks.find(
          (candidate) => fileName(candidate).toLowerCase() === "packages.lock.json",
        );
      output.push({
        id: `nuget:${project.toString()}`,
        rootUri: group.rootUri,
        manifestUris: [project, ...group.configs],
        lockfileUris: lock === undefined ? [] : [lock],
      });
    }
    if (group.projects.length === 0 && group.configs.length > 0) {
      output.push({
        id: `nuget:${group.rootUri.toString()}:packages.config`,
        rootUri: group.rootUri,
        manifestUris: [group.configs[0]].filter(
          (uri): uri is vscode.Uri => uri !== undefined,
        ),
        lockfileUris: [],
      });
    }
  }
  return output
    .sort((left, right) => left.id.localeCompare(right.id))
    .slice(0, MAX_PROJECTS);
}

export class NugetAdapter implements PackageManagerAdapter {
  public readonly id = "nuget";
  public readonly displayName = "NuGet";
  public readonly ecosystems = ["NuGet"] as const;

  public async detect(
    workspaceFolder: vscode.Uri,
    cancellationToken?: vscode.CancellationToken,
  ): Promise<DetectionResult> {
    const matches = await findFiles(
      workspaceFolder,
      "**/{*.csproj,packages.config,packages.lock.json,packages.*.lock.json,NuGet.Config,NuGet.config,nuget.config,Directory.Packages.props,directory.packages.props,Directory.Build.props,directory.build.props,Directory.Build.targets,directory.build.targets}",
      MAX_PROJECTS * 4,
      cancellationToken,
    );
    const configs = matches.files.filter(isNugetConfig);
    const centralPackageFiles = matches.files.filter(isDirectoryPackagesProps);
    const restoreConfigurationFiles = matches.files.filter(
      isDirectoryBuildConfiguration,
    );
    const projects = withApplicableNugetMetadata(
      buildProjects(
        matches.files.filter(
          (uri) =>
            !isNugetConfig(uri) &&
            !isDirectoryPackagesProps(uri) &&
            !isDirectoryBuildConfiguration(uri),
        ),
      ),
      configs,
      centralPackageFiles,
      restoreConfigurationFiles,
    );
    const truncated = matches.truncated || projects.length >= MAX_PROJECTS;
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
    try {
      const detection =
        options.preDetectedResult ??
        (await this.detect(workspaceFolder, options.cancellationToken));
      errors.push(...detection.errors);
      if (detection.truncated) {
        errors.push({
          code: "UNSUPPORTED_PACKAGE_SOURCE",
          message:
            "NuGet workspace discovery was truncated; package-source provenance is incomplete",
          path: uriPath(workspaceFolder),
        });
      }
      for (const project of projectsSelectedForScan(detection, options)) {
        throwIfCancelled(signal, options.cancellationToken);
        const projectFile = project.manifestUris.find((uri) =>
          fileName(uri).toLowerCase().endsWith(".csproj"),
        );
        const packagesConfig = project.manifestUris.find(
          (uri) => fileName(uri).toLowerCase() === "packages.config",
        );
        const nugetConfigs = project.manifestUris.filter(isNugetConfig);
        const directoryPackagesProps = project.manifestUris.filter(
          isDirectoryPackagesProps,
        );
        const restoreConfigurationProps = project.manifestUris.filter(
          isDirectoryBuildConfiguration,
        );
        const lock = project.lockfileUris[0];
        const primaryManifest = projectFile ?? packagesConfig;
        if (primaryManifest === undefined) {
          continue;
        }
        try {
          const projectXmlRead =
            projectFile === undefined
              ? Promise.resolve(undefined)
              : readBoundedText(
                  projectFile,
                  MAX_MANIFEST_BYTES,
                  signal,
                  options.cancellationToken,
                );
          const packagesConfigXmlRead =
            packagesConfig === undefined
              ? Promise.resolve(undefined)
              : readBoundedText(
                  packagesConfig,
                  MAX_MANIFEST_BYTES,
                  signal,
                  options.cancellationToken,
                );
          const lockfileRead =
            lock === undefined
              ? Promise.resolve(undefined)
              : readBoundedText(
                  lock,
                  MAX_LOCKFILE_BYTES,
                  signal,
                  options.cancellationToken,
                );
          const nugetConfigXmlsRead = Promise.all(
            nugetConfigs.map((uri) =>
              readBoundedText(
                uri,
                MAX_MANIFEST_BYTES,
                signal,
                options.cancellationToken,
              ),
            ),
          );
          const directoryPackagesPropsXmlsRead = Promise.all(
            directoryPackagesProps.map((uri) =>
              readBoundedText(
                uri,
                MAX_MANIFEST_BYTES,
                signal,
                options.cancellationToken,
              ),
            ),
          );
          const restoreConfigurationXmlsRead = Promise.all(
            restoreConfigurationProps.map((uri) =>
              readBoundedText(
                uri,
                MAX_MANIFEST_BYTES,
                signal,
                options.cancellationToken,
              ),
            ),
          );
          const projectXml = await projectXmlRead;
          const packagesConfigXml = await packagesConfigXmlRead;
          const lockfile = await lockfileRead;
          const nugetConfigXmls = await nugetConfigXmlsRead;
          const directoryPackagesPropsXmls =
            await directoryPackagesPropsXmlsRead;
          const restoreConfigurationXmls = await restoreConfigurationXmlsRead;
          const parsed = parseNugetDependencies({
            ...(projectXml === undefined ? {} : { projectXml }),
            manifestPath: uriPath(primaryManifest),
            ...(lockfile === undefined ? {} : { lockfile }),
            ...(lock === undefined ? {} : { lockfilePath: uriPath(lock) }),
            ...(packagesConfigXml === undefined
              ? {}
              : { packagesConfigXml }),
            nugetConfigXmls,
            directoryPackagesPropsXmls,
            restoreConfigurationXmls,
            projectPath: uriPath(project.rootUri),
            workspacePath: uriPath(workspaceFolder),
            ...(signal === undefined ? {} : { signal }),
          });
          if (parsed.cancelled) {
            throw new DOMException("NuGet scan cancelled", "AbortError");
          }
          const retained = filterDependencies(
            deduplicateDependencies(
              failClosedDependencies(parsed.dependencies, detection.truncated),
            ),
            options,
          );
          dependencies.push(...retained);
          coverage.push(
            coverageForProject(
              "NuGet",
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
                  : uriPath(primaryManifest),
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
                : "Could not read NuGet dependency metadata",
            path: uriPath(primaryManifest),
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
