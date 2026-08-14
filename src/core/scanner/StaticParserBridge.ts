import { basename, dirname, relative, sep } from "node:path";

import type { Dependency, DependencyEnvironment } from "../../models/Dependency";
import type { ScanError, ScanErrorCode } from "../../models/ScanResult";
import { parseBunDependencies } from "../../package-managers/bun/BunDependencyParser";
import { parseCargoDependencies } from "../../package-managers/cargo/CargoDependencyParser";
import { parseComposerDependencies } from "../../package-managers/composer/ComposerDependencyParser";
import { parseGoModules } from "../../package-managers/go/GoModulesParser";
import { parseGradleProject } from "../../package-managers/gradle/gradleParser";
import { parseMavenPom } from "../../package-managers/maven/mavenParser";
import { parseNpmDependencies } from "../../package-managers/npm/NpmDependencyParser";
import { parseNugetDependencies } from "../../package-managers/nuget/NugetDependencyParser";
import { parsePipenvProject } from "../../package-managers/pipenv/pipenvParser";
import { parsePnpmDependencies } from "../../package-managers/pnpm/PnpmDependencyParser";
import { detectPoetryManifest } from "../../package-managers/poetry/poetryManifestDetection";
import {
  parsePoetryManifest,
  parsePoetryProject,
} from "../../package-managers/poetry/poetryParser";
import { parseRequirements } from "../../package-managers/python/requirementsParser";
import { parseYarnDependencies } from "../../package-managers/yarn/YarnDependencyParser";
import type { ManifestInput } from "../../package-managers/yarn/JavaScriptParserTypes";
import type {
  DiscoveredDependencyFile,
  DiscoveredDependencyProject,
} from "../discovery/StaticDependencyDiscovery";
import { isCoreCancellation } from "../host/HostContracts";

export interface StaticParserOptions {
  readonly includeDevelopment: boolean;
  readonly includeProduction: boolean;
  readonly includeTransitive: boolean;
  readonly signal?: AbortSignal;
}

export interface StaticProjectParseResult {
  readonly dependencies: readonly Dependency[];
  readonly errors: readonly ScanError[];
  readonly truncated: boolean;
  readonly cancelled: boolean;
}

export type StaticTextReader = (path: string) => Promise<string>;

const SCAN_ERROR_CODES: ReadonlySet<string> = new Set<ScanErrorCode>([
  "NO_LOCKFILE",
  "INVALID_MANIFEST",
  "INVALID_LOCKFILE",
  "UNSUPPORTED_LOCKFILE",
  "UNSUPPORTED_PACKAGE_MANAGER",
  "UNSUPPORTED_PACKAGE_SOURCE",
  "UNSUPPORTED_PACKAGE_IDENTITY",
  "DEPENDENCY_UNRESOLVED",
  "DEPENDENCY_LIMIT",
  "UNSUPPORTED_VERSION",
  "PROVIDER_ERROR",
  "CACHE_ERROR",
  "WORKSPACE_ERROR",
]);

function scanError(
  code: string,
  message: string,
  path: string,
  packageName?: string,
): ScanError {
  const normalizedCode: ScanErrorCode = SCAN_ERROR_CODES.has(code)
    ? (code as ScanErrorCode)
    : code.includes("LOCK")
      ? "INVALID_LOCKFILE"
      : code.includes("MANIFEST") || code.includes("PACKAGE_JSON")
        ? "INVALID_MANIFEST"
        : "WORKSPACE_ERROR";
  return {
    code: normalizedCode,
    message,
    path,
    ...(packageName === undefined ? {} : { packageName }),
  };
}

function issueErrors(
  issues: readonly {
    readonly code: string;
    readonly message: string;
    readonly packageName?: string;
  }[],
  path: string,
): ScanError[] {
  return issues.map((issue) =>
    scanError(issue.code, issue.message, path, issue.packageName),
  );
}

function environmentIncluded(
  environment: DependencyEnvironment,
  options: StaticParserOptions,
): boolean {
  return environment === "development"
    ? options.includeDevelopment
    : options.includeProduction;
}

function decorateAndFilter(
  dependencies: readonly Dependency[],
  project: DiscoveredDependencyProject,
  workspacePath: string,
  options: StaticParserOptions,
): Dependency[] {
  return dependencies
    .filter(
      (dependency) =>
        environmentIncluded(dependency.environment, options) &&
        (options.includeTransitive || dependency.dependencyType === "direct"),
    )
    .map((dependency) => ({
      ...dependency,
      packageManager: dependency.packageManager ?? project.packageManager,
      projectPath: dependency.projectPath ?? project.rootPath,
      workspacePath: dependency.workspacePath ?? workspacePath,
    }));
}

function relativeDirectory(root: string, manifest: string): string {
  const value = relative(root, dirname(manifest)).split(sep).join("/");
  return value.length === 0 ? "." : value;
}

function requirementsEnvironment(path: string): DependencyEnvironment {
  return /(?:^|[._-])(?:dev|develop|development|test|tests)(?:[._-]|\.txt$)/iu.test(
    basename(path),
  )
    ? "development"
    : "production";
}

function parseFailure(
  project: DiscoveredDependencyProject,
  error: unknown,
): StaticProjectParseResult {
  if (isCoreCancellation(error)) {
    return { dependencies: [], errors: [], truncated: false, cancelled: true };
  }
  return {
    dependencies: [],
    errors: [
      {
        code: "WORKSPACE_ERROR",
        message: `The ${project.packageManager} dependency project could not be parsed safely.`,
        path: project.manifestPaths[0] ?? project.rootPath,
      },
    ],
    truncated: false,
    cancelled: false,
  };
}

function transitiveEvidenceGap(
  project: DiscoveredDependencyProject,
  options: StaticParserOptions,
): ScanError[] {
  if (!options.includeTransitive || project.packageManager !== "maven") {
    return [];
  }
  return [
    {
      code: "UNSUPPORTED_PACKAGE_MANAGER",
      message:
        "Static Maven POM analysis covers declared coordinates only; it cannot prove the selected transitive graph without executing Maven.",
      path: project.manifestPaths[0] ?? project.rootPath,
    },
  ];
}

export async function parseStaticDependencyProject(
  project: DiscoveredDependencyProject,
  workspacePath: string,
  files: readonly DiscoveredDependencyFile[],
  readText: StaticTextReader,
  options: StaticParserOptions,
): Promise<StaticProjectParseResult> {
  const manifest = project.manifestPaths[0];
  const lockfile = project.lockfilePaths[0];
  if (manifest === undefined) {
    return {
      dependencies: [],
      errors: [
        {
          code: "INVALID_MANIFEST",
          message: `The ${project.packageManager} project has no readable manifest.`,
          path: project.rootPath,
        },
      ],
      truncated: false,
      cancelled: false,
    };
  }

  try {
    const parserOptions = {
      includeDevDependencies: options.includeDevelopment,
      includeTransitiveDependencies: options.includeTransitive,
    };
    switch (project.packageManager) {
      case "npm": {
        const manifests = await Promise.all(
          project.manifestPaths.map(async (path) => ({
            path,
            text: await readText(path),
          })),
        );
        const rootManifest =
          manifests.find((entry) => dirname(entry.path) === project.rootPath) ??
          manifests[0];
        if (rootManifest === undefined) {
          return parseFailure(project, new Error("missing package.json"));
        }
        const parsed = parseNpmDependencies({
          packageJson: rootManifest.text,
          packageJsonPath: rootManifest.path,
          workspaceManifests: manifests
            .filter((entry) => entry !== rootManifest)
            .map((entry) => ({
              location: relativeDirectory(project.rootPath, entry.path),
              packageJson: entry.text,
              packageJsonPath: entry.path,
            })),
          ...(lockfile === undefined
            ? {}
            : { lockfile: await readText(lockfile), lockfilePath: lockfile }),
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
        return {
          dependencies: decorateAndFilter(
            parsed.dependencies,
            project,
            workspacePath,
            options,
          ),
          errors: issueErrors(parsed.issues, lockfile ?? manifest),
          truncated: parsed.truncated,
          cancelled: parsed.cancelled,
        };
      }
      case "yarn":
      case "pnpm":
      case "bun": {
        if (lockfile === undefined) {
          return {
            dependencies: [],
            errors: [
              {
                code: "NO_LOCKFILE",
                message: `${project.packageManager} requires its text lockfile to prove installed versions.`,
                path: manifest,
              },
            ],
            truncated: false,
            cancelled: false,
          };
        }
        const manifests: ManifestInput[] = await Promise.all(
          project.manifestPaths.map(async (path) => ({
            path,
            relativeDirectory: relativeDirectory(project.rootPath, path),
            content: await readText(path),
          })),
        );
        const common = {
          manifests,
          lockfile: await readText(lockfile),
          lockfilePath: lockfile,
          projectPath: project.rootPath,
          workspacePath,
          options: parserOptions,
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        };
        const parsed =
          project.packageManager === "yarn"
            ? parseYarnDependencies(common)
            : project.packageManager === "pnpm"
              ? parsePnpmDependencies(common)
              : parseBunDependencies(common);
        return {
          dependencies: decorateAndFilter(
            parsed.dependencies,
            project,
            workspacePath,
            options,
          ),
          errors: issueErrors(parsed.issues, lockfile),
          truncated: parsed.truncated,
          cancelled: parsed.cancelled,
        };
      }
      case "pip": {
        const parsed = parseRequirements({
          text: await readText(manifest),
          manifestPath: manifest,
          projectPath: project.rootPath,
          workspacePath,
          environment: requirementsEnvironment(manifest),
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
        const knownFiles = new Set(files.map((file) => file.path));
        const includeErrors: ScanError[] = parsed.includes.map((include) => ({
          code: "UNSUPPORTED_PACKAGE_MANAGER",
          message: knownFiles.has(include)
            ? "A requirements include is scanned as an independent file; its conditional include relationship is not proven."
            : "A requirements include could not be resolved within bounded discovered metadata.",
          path: manifest,
        }));
        return {
          dependencies: decorateAndFilter(
            parsed.dependencies,
            project,
            workspacePath,
            options,
          ),
          errors: [...parsed.errors, ...includeErrors],
          truncated: parsed.truncated,
          cancelled: false,
        };
      }
      case "poetry": {
        const manifestText = await readText(manifest);
        const detection = detectPoetryManifest(manifestText);
        if (detection !== "poetry") {
          return {
            dependencies: [],
            errors: [
              {
                code: "UNSUPPORTED_PACKAGE_MANAGER",
                message:
                  detection === "indeterminate"
                    ? "pyproject.toml could not be classified within bounded Poetry detection limits."
                    : "Generic PEP 621 pyproject dependency resolution is not implemented; this is not proven to be a Poetry project.",
                path: manifest,
              },
            ],
            truncated: detection === "indeterminate",
            cancelled: false,
          };
        }
        const parsed =
          lockfile === undefined
            ? await parsePoetryManifest({
                pyprojectText: manifestText,
                manifestPath: manifest,
                projectPath: project.rootPath,
                workspacePath,
              })
            : await parsePoetryProject({
                pyprojectText: manifestText,
                lockfileText: await readText(lockfile),
                manifestPath: manifest,
                lockfilePath: lockfile,
                projectPath: project.rootPath,
                workspacePath,
                ...(options.signal === undefined
                  ? {}
                  : { signal: options.signal }),
              });
        return {
          dependencies: decorateAndFilter(
            parsed.dependencies,
            project,
            workspacePath,
            options,
          ),
          errors: parsed.errors,
          truncated: parsed.truncated,
          cancelled: false,
        };
      }
      case "pipenv": {
        const parsed = await parsePipenvProject({
          pipfileText: await readText(manifest),
          manifestPath: manifest,
          projectPath: project.rootPath,
          workspacePath,
          ...(lockfile === undefined
            ? {}
            : { lockfileText: await readText(lockfile), lockfilePath: lockfile }),
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
        return {
          dependencies: decorateAndFilter(
            parsed.dependencies,
            project,
            workspacePath,
            options,
          ),
          errors: parsed.errors,
          truncated: parsed.truncated,
          cancelled: false,
        };
      }
      case "maven": {
        const parsed = parseMavenPom({
          text: await readText(manifest),
          manifestPath: manifest,
          projectPath: project.rootPath,
          workspacePath,
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
        return {
          dependencies: decorateAndFilter(
            parsed.dependencies,
            project,
            workspacePath,
            options,
          ),
          errors: [
            ...parsed.errors,
            ...transitiveEvidenceGap(project, options),
          ],
          truncated: parsed.truncated,
          cancelled: false,
        };
      }
      case "gradle": {
        const settings = await Promise.all(
          project.auxiliaryPaths.map((path) => readText(path)),
        );
        const parsed = parseGradleProject({
          scriptText: await readText(manifest),
          repositoryConfigurationTexts: settings,
          manifestPath: manifest,
          projectPath: project.rootPath,
          workspacePath,
          ...(lockfile === undefined
            ? {}
            : { lockfileText: await readText(lockfile), lockfilePath: lockfile }),
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
        return {
          dependencies: decorateAndFilter(
            parsed.dependencies,
            project,
            workspacePath,
            options,
          ),
          errors: parsed.errors,
          truncated: parsed.truncated,
          cancelled: false,
        };
      }
      case "nuget": {
        const auxiliary = await Promise.all(
          project.auxiliaryPaths.map(async (path) => ({
            path,
            text: await readText(path),
          })),
        );
        const packagesConfig = basename(manifest).toLowerCase() === "packages.config";
        const parsed = parseNugetDependencies({
          ...(packagesConfig
            ? { packagesConfigXml: await readText(manifest) }
            : { projectXml: await readText(manifest) }),
          manifestPath: manifest,
          projectPath: project.rootPath,
          workspacePath,
          ...(lockfile === undefined
            ? {}
            : { lockfile: await readText(lockfile), lockfilePath: lockfile }),
          nugetConfigXmls: auxiliary
            .filter((entry) => basename(entry.path).toLowerCase() === "nuget.config")
            .map((entry) => entry.text),
          directoryPackagesPropsXmls: auxiliary
            .filter(
              (entry) =>
                basename(entry.path).toLowerCase() === "directory.packages.props",
            )
            .map((entry) => entry.text),
          restoreConfigurationXmls: auxiliary
            .filter(
              (entry) =>
                basename(entry.path).toLowerCase() === "directory.build.props",
            )
            .map((entry) => entry.text),
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
        return {
          dependencies: decorateAndFilter(
            parsed.dependencies,
            project,
            workspacePath,
            options,
          ),
          errors: issueErrors(parsed.issues, lockfile ?? manifest),
          truncated: parsed.truncated,
          cancelled: parsed.cancelled,
        };
      }
      case "cargo": {
        const workspaceManifest = project.auxiliaryPaths[0];
        const parsed = parseCargoDependencies({
          cargoToml: await readText(manifest),
          manifestPath: manifest,
          projectPath: project.rootPath,
          workspacePath,
          ...(lockfile === undefined
            ? {}
            : { cargoLock: await readText(lockfile), lockfilePath: lockfile }),
          ...(workspaceManifest === undefined
            ? {}
            : {
                workspaceToml: await readText(workspaceManifest),
                workspaceManifestPath: workspaceManifest,
              }),
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
        return {
          dependencies: decorateAndFilter(
            parsed.dependencies,
            project,
            workspacePath,
            options,
          ),
          errors: issueErrors(parsed.issues, lockfile ?? manifest),
          truncated: parsed.truncated,
          cancelled: parsed.cancelled,
        };
      }
      case "go": {
        const parsed = parseGoModules({
          goMod: await readText(manifest),
          manifestPath: manifest,
          projectPath: project.rootPath,
          workspacePath,
          ...(lockfile === undefined
            ? {}
            : { goSum: await readText(lockfile), sumPath: lockfile }),
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
        return {
          dependencies: decorateAndFilter(
            parsed.dependencies,
            project,
            workspacePath,
            options,
          ),
          errors: issueErrors(parsed.issues, lockfile ?? manifest),
          truncated: parsed.truncated,
          cancelled: parsed.cancelled,
        };
      }
      case "composer": {
        const parsed = parseComposerDependencies({
          composerJson: await readText(manifest),
          manifestPath: manifest,
          projectPath: project.rootPath,
          workspacePath,
          ...(lockfile === undefined
            ? {}
            : { composerLock: await readText(lockfile), lockfilePath: lockfile }),
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
        return {
          dependencies: decorateAndFilter(
            parsed.dependencies,
            project,
            workspacePath,
            options,
          ),
          errors: issueErrors(parsed.issues, lockfile ?? manifest),
          truncated: parsed.truncated,
          cancelled: parsed.cancelled,
        };
      }
    }
  } catch (error: unknown) {
    return parseFailure(project, error);
  }
}
