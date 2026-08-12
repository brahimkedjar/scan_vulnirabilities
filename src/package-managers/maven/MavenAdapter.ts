import * as vscode from "vscode";

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
import { parseMavenPom } from "./mavenParser";

const MAX_ANCESTOR_POMS = 17;
const MAX_MAVEN_CONFIGURATION_FILES = 17;

function uriName(uri: vscode.Uri): string {
  return uri.path.split("/").at(-1)?.toLowerCase() ?? "";
}

function isPom(uri: vscode.Uri): boolean {
  return uriName(uri) === "pom.xml";
}

function isMavenCliConfiguration(uri: vscode.Uri): boolean {
  const lowerPath = uri.path.toLowerCase();
  return (
    lowerPath.endsWith("/.mvn/maven.config") ||
    lowerPath.endsWith("/.mvn/jvm.config")
  );
}

function isMavenExtensionConfiguration(uri: vscode.Uri): boolean {
  return uri.path.toLowerCase().endsWith("/.mvn/extensions.xml");
}

function isMavenConfiguration(uri: vscode.Uri): boolean {
  return isMavenCliConfiguration(uri) || isMavenExtensionConfiguration(uri);
}

function mavenConfigurationRoot(uri: vscode.Uri): vscode.Uri {
  return vscode.Uri.joinPath(uri, "..", "..");
}

function configurationAppliesToProject(
  configuration: vscode.Uri,
  projectRoot: vscode.Uri,
): boolean {
  const root = mavenConfigurationRoot(configuration);
  if (
    root.scheme !== projectRoot.scheme ||
    root.authority !== projectRoot.authority
  ) {
    return false;
  }
  const prefix = root.path.endsWith("/") ? root.path : `${root.path}/`;
  return projectRoot.path === root.path || projectRoot.path.startsWith(prefix);
}

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

function uriDirectory(uri: vscode.Uri): vscode.Uri {
  return vscode.Uri.joinPath(uri, "..");
}

function isOwnedByProject(uri: vscode.Uri, projectRoot: vscode.Uri): boolean {
  const directory = uriDirectory(uri);
  return (
    directory.scheme === projectRoot.scheme &&
    directory.authority === projectRoot.authority &&
    directory.path === projectRoot.path
  );
}

function ancestorPomsForProject(
  poms: readonly vscode.Uri[],
  projectRoot: vscode.Uri,
): readonly vscode.Uri[] {
  return poms
    .filter((uri) => {
      const root = uriDirectory(uri);
      if (
        root.scheme !== projectRoot.scheme ||
        root.authority !== projectRoot.authority ||
        root.path === projectRoot.path
      ) {
        return false;
      }
      const prefix = root.path.endsWith("/") ? root.path : `${root.path}/`;
      return projectRoot.path.startsWith(prefix);
    })
    .sort((left, right) => right.path.length - left.path.length)
    .slice(0, MAX_ANCESTOR_POMS);
}

function withAncestorPoms(
  projects: readonly DetectedDependencyProject[],
  poms: readonly vscode.Uri[],
  configurations: readonly vscode.Uri[],
): readonly DetectedDependencyProject[] {
  return projects.map((project) => {
    const applicableConfigurations = configurations
      .filter((uri) => configurationAppliesToProject(uri, project.rootUri))
      .sort((left, right) => left.path.localeCompare(right.path))
      .slice(0, MAX_MAVEN_CONFIGURATION_FILES);
    return {
      ...project,
      manifestUris: [
        ...project.manifestUris,
        ...ancestorPomsForProject(poms, project.rootUri),
        ...applicableConfigurations,
      ],
    };
  });
}

export class MavenAdapter implements PackageManagerAdapter {
  public readonly id = "maven";
  public readonly displayName = "Maven";
  public readonly ecosystems = ["Maven"] as const;

  public async detect(
    workspaceFolder: vscode.Uri,
    cancellationToken?: vscode.CancellationToken,
  ): Promise<DetectionResult> {
    const matches = await findFiles(
      workspaceFolder,
      "**/{pom.xml,.mvn/maven.config,.mvn/jvm.config,.mvn/extensions.xml}",
      undefined,
      cancellationToken,
    );
    const poms = matches.files.filter(isPom);
    const configurations = matches.files.filter(isMavenConfiguration);
    const pomProjects = withAncestorPoms(
      groupProjectsByDirectory(
        this.id,
        poms,
        new Set(["pom.xml"]),
        new Set(),
      ),
      poms,
      configurations,
    );
    const orphanConfigurations = configurations.filter(
      (configuration) =>
        !pomProjects.some((project) =>
          configurationAppliesToProject(configuration, project.rootUri),
        ),
    );
    const projects: readonly DetectedDependencyProject[] = [
      ...pomProjects,
      ...orphanConfigurations.map((configuration) => ({
        id: `${this.id}:${configuration.toString()}:missing-pom`,
        rootUri: mavenConfigurationRoot(configuration),
        manifestUris: [configuration],
        lockfileUris: [],
      })),
    ].sort((left, right) => left.id.localeCompare(right.id));
    const orphanErrors: readonly ScanError[] = orphanConfigurations.map(
      (configuration) => ({
        code: "INVALID_MANIFEST",
        message:
          ".mvn Maven configuration has no discoverable pom.xml; alternate project files are not parsed",
        path: uriPath(configuration),
      }),
    );
    return {
      detected: projects.length > 0,
      projects,
      errors: [
        ...orphanErrors,
        ...(matches.truncated
          ? [discoveryLimitError(this.displayName, workspaceFolder)]
          : []),
      ],
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
      if (detection.truncated) {
        errors.push({
          code: "UNSUPPORTED_PACKAGE_SOURCE",
          message:
            "Maven workspace discovery was truncated; repository provenance is incomplete",
          path: uriPath(workspaceFolder),
        });
      }
      for (const project of projectsSelectedForScan(detection, options)) {
        throwIfCancelled(signal, options.cancellationToken);
        const manifest = project.manifestUris.find(
          (uri) => isPom(uri) && isOwnedByProject(uri, project.rootUri),
        );
        const ancestorPoms = project.manifestUris.filter(
          (uri) => isPom(uri) && !isOwnedByProject(uri, project.rootUri),
        );
        const mavenConfigurations = project.manifestUris.filter(
          isMavenCliConfiguration,
        );
        const mavenExtensions = project.manifestUris.filter(
          isMavenExtensionConfiguration,
        );
        const projectDependencies: Dependency[] = [];
        if (manifest !== undefined) {
          try {
            const text = await readBoundedText(
              manifest,
              MAX_MANIFEST_BYTES,
              signal,
              options.cancellationToken,
            );
            const repositoryConfigurationTexts = await Promise.all(
              ancestorPoms.map((uri) =>
                readBoundedText(
                  uri,
                  MAX_MANIFEST_BYTES,
                  signal,
                  options.cancellationToken,
                ),
              ),
            );
            const mavenConfigurationTexts = await Promise.all(
              mavenConfigurations.map((uri) =>
                readBoundedText(
                  uri,
                  MAX_MANIFEST_BYTES,
                  signal,
                  options.cancellationToken,
                ),
              ),
            );
            const mavenExtensionTexts = await Promise.all(
              mavenExtensions.map((uri) =>
                readBoundedText(
                  uri,
                  MAX_MANIFEST_BYTES,
                  signal,
                  options.cancellationToken,
                ),
              ),
            );
            const parsed = parseMavenPom({
              text,
              repositoryConfigurationTexts,
              mavenConfigurationTexts,
              mavenExtensionTexts,
              manifestPath: uriPath(manifest),
              projectPath: uriPath(project.rootUri),
              workspacePath: uriPath(workspaceFolder),
              ...(signal === undefined ? {} : { signal }),
            });
            projectDependencies.push(
              ...failClosedDependencies(parsed.dependencies, detection.truncated),
            );
            errors.push(...parsed.errors);
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
                error instanceof Error ? error.message : "could not read pom.xml",
              path: uriPath(manifest),
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
            "Maven",
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
