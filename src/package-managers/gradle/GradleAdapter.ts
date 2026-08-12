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
import { parseGradleProject } from "./gradleParser";

const BUILD_MANIFEST_NAMES = new Set(["build.gradle", "build.gradle.kts"]);
const SETTINGS_MANIFEST_NAMES = new Set([
  "settings.gradle",
  "settings.gradle.kts",
]);

function uriName(uri: vscode.Uri): string {
  return uri.path.split("/").at(-1)?.toLowerCase() ?? "";
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

function isBuildManifest(uri: vscode.Uri): boolean {
  return BUILD_MANIFEST_NAMES.has(uriName(uri));
}

function isSettingsManifest(uri: vscode.Uri): boolean {
  return SETTINGS_MANIFEST_NAMES.has(uriName(uri));
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

function ancestorBuildsForProject(
  builds: readonly vscode.Uri[],
  projectRoot: vscode.Uri,
): readonly vscode.Uri[] {
  return builds
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
    .sort((left, right) => left.path.localeCompare(right.path));
}

function settingsForProject(
  settings: readonly vscode.Uri[],
  projectRoot: vscode.Uri,
): readonly vscode.Uri[] {
  const candidates = settings
    .map((uri) => ({ uri, root: vscode.Uri.joinPath(uri, "..") }))
    .filter(({ root }) => {
      if (
        root.scheme !== projectRoot.scheme ||
        root.authority !== projectRoot.authority
      ) {
        return false;
      }
      const prefix = root.path.endsWith("/") ? root.path : `${root.path}/`;
      return projectRoot.path === root.path || projectRoot.path.startsWith(prefix);
    });
  const nearestLength = Math.max(
    -1,
    ...candidates.map(({ root }) => root.path.length),
  );
  return candidates
    .filter(({ root }) => root.path.length === nearestLength)
    .map(({ uri }) => uri)
    .sort((left, right) => left.path.localeCompare(right.path));
}

function withInheritedSettings(
  projects: readonly DetectedDependencyProject[],
  settings: readonly vscode.Uri[],
  builds: readonly vscode.Uri[],
): readonly DetectedDependencyProject[] {
  return projects.map((project) => {
    const inherited = settingsForProject(settings, project.rootUri);
    const ancestorBuilds = ancestorBuildsForProject(builds, project.rootUri);
    const manifestUris = [
      ...new Map(
        [...project.manifestUris, ...inherited, ...ancestorBuilds].map((uri) => [
          uri.toString(),
          uri,
        ]),
      ).values(),
    ].sort((left, right) => left.path.localeCompare(right.path));
    return { ...project, manifestUris };
  });
}

export class GradleAdapter implements PackageManagerAdapter {
  public readonly id = "gradle";
  public readonly displayName = "Gradle";
  public readonly ecosystems = ["Maven"] as const;

  public async detect(
    workspaceFolder: vscode.Uri,
    cancellationToken?: vscode.CancellationToken,
  ): Promise<DetectionResult> {
    const matches = await findFiles(
      workspaceFolder,
      "**/{build.gradle,build.gradle.kts,settings.gradle,settings.gradle.kts,gradle.lockfile}",
      undefined,
      cancellationToken,
    );
    const settings = matches.files.filter(isSettingsManifest);
    const builds = matches.files.filter(isBuildManifest);
    const projects = withInheritedSettings(
      groupProjectsByDirectory(
        this.id,
        matches.files.filter((uri) => !isSettingsManifest(uri)),
        BUILD_MANIFEST_NAMES,
        new Set(["gradle.lockfile"]),
      ),
      settings,
      builds,
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
      if (detection.truncated) {
        errors.push({
          code: "UNSUPPORTED_PACKAGE_SOURCE",
          message:
            "Gradle workspace discovery was truncated; repository provenance is incomplete",
          path: uriPath(workspaceFolder),
        });
      }
      for (const project of projectsSelectedForScan(detection, options)) {
        throwIfCancelled(signal, options.cancellationToken);
        const manifest = project.manifestUris.find(
          (uri) => isBuildManifest(uri) && isOwnedByProject(uri, project.rootUri),
        );
        const repositoryManifests = project.manifestUris.filter(
          (uri) =>
            isSettingsManifest(uri) ||
            (isBuildManifest(uri) && !isOwnedByProject(uri, project.rootUri)),
        );
        const lockfile = project.lockfileUris[0];
        const projectDependencies: Dependency[] = [];
        if (manifest === undefined) {
          errors.push({
            code: "INVALID_MANIFEST",
            message: "gradle.lockfile has no sibling build.gradle or build.gradle.kts",
            path: uriPath(project.rootUri),
          });
        } else {
          try {
            const scriptText = await readBoundedText(
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
            const repositoryConfigurationTexts = await Promise.all(
              repositoryManifests.map((uri) =>
                readBoundedText(
                  uri,
                  MAX_MANIFEST_BYTES,
                  signal,
                  options.cancellationToken,
                ),
              ),
            );
            const parsed = parseGradleProject({
              scriptText,
              repositoryConfigurationTexts,
              manifestPath: uriPath(manifest),
              ...(lockfileText === undefined ? {} : { lockfileText }),
              ...(lockfile === undefined
                ? {}
                : { lockfilePath: uriPath(lockfile) }),
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
                  : lockfile === undefined
                    ? "INVALID_MANIFEST"
                    : "INVALID_LOCKFILE",
              message:
                error instanceof Error
                  ? error.message
                  : "could not read Gradle dependency metadata",
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
