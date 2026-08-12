import * as vscode from "vscode";

import { GENERATED_DIRECTORY_GLOB } from "../../discovery/dependencyFiles";
import { ReadBudget } from "../../discovery/readBudget";
import { consumeDependencyMetadataBytes } from "../dependencyMetadataBudget";
import type { Dependency } from "../../models/Dependency";
import type { ScanError, ScanErrorCode } from "../../models/ScanResult";
import type { Logger } from "../../services/Logger";
import type { DetectedDependencyProject } from "../PackageManagerAdapter";
import {
  parseNpmDependencies,
  type NpmDependencyParseIssue,
  type NpmWorkspaceManifestInput,
} from "./NpmDependencyParser";

const NPM_LOCKFILE_GLOB = "**/{npm-shrinkwrap.json,package-lock.json}";
const PACKAGE_JSON_GLOB = "**/package.json";
const OTHER_JAVASCRIPT_LOCK_GLOB =
  "**/{yarn.lock,pnpm-lock.yaml,bun.lock,bun.lockb}";
const MAX_NPM_PROJECTS = 100;
const MAX_PACKAGE_JSON_BYTES = 2 * 1024 * 1024;
const MAX_LOCKFILE_BYTES = 32 * 1024 * 1024;
const MAX_TOTAL_METADATA_BYTES = 128 * 1024 * 1024;
const MAX_PACKAGE_JSON_FILES = 2_000;
const MAX_WORKSPACE_MANIFESTS_PER_PROJECT = 1_000;
const WORKSPACE_MANIFEST_READ_CONCURRENCY = 8;
const NON_COVERAGE_PARSER_WARNINGS = new Set(["MISSING_ROOT_PACKAGE"]);

export interface NpmWorkspaceScanResult {
  readonly dependencies: readonly Dependency[];
  readonly errors: readonly ScanError[];
  readonly npmDetected: boolean;
  readonly otherPackageManagers: readonly string[];
  readonly projectCount: number;
  readonly cancelled: boolean;
}

function otherJavaScriptManager(uri: vscode.Uri): string {
  const fileName = uri.path.split("/").at(-1)?.toLowerCase();
  if (fileName === "yarn.lock") {
    return "yarn";
  }
  if (fileName === "pnpm-lock.yaml") {
    return "pnpm";
  }
  return "bun";
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) {
    throw new DOMException("npm workspace scan cancelled", "AbortError");
  }
}

function uriStoragePath(uri: vscode.Uri): string {
  return uri.scheme === "file" ? uri.fsPath : uri.toString();
}

function safeUriLocation(uri: vscode.Uri): string {
  return uri.scheme === "file" ? uri.fsPath : `${uri.scheme}:${uri.path}`;
}

function directoryKey(uri: vscode.Uri): string {
  const path = uri.path.slice(0, Math.max(0, uri.path.lastIndexOf("/")));
  return `${uri.scheme}\u0000${uri.authority}\u0000${path}`;
}

function isWithinDirectory(candidate: vscode.Uri, directory: vscode.Uri): boolean {
  if (
    candidate.scheme !== directory.scheme ||
    candidate.authority !== directory.authority
  ) {
    return false;
  }
  const root = directory.path.endsWith("/")
    ? directory.path
    : `${directory.path}/`;
  return candidate.path === directory.path || candidate.path.startsWith(root);
}

function relativeManifestLocation(
  root: vscode.Uri,
  manifest: vscode.Uri,
): string | undefined {
  if (!isWithinDirectory(manifest, root)) {
    return undefined;
  }
  const rootPath = root.path.endsWith("/") ? root.path : `${root.path}/`;
  const relativePath = manifest.path.slice(rootPath.length);
  if (relativePath === "package.json") {
    return "";
  }
  const suffix = "/package.json";
  return relativePath.endsWith(suffix)
    ? relativePath.slice(0, -suffix.length)
    : undefined;
}

function owningLockRoot(
  manifest: vscode.Uri,
  roots: readonly vscode.Uri[],
): vscode.Uri | undefined {
  return roots
    .filter((root) => isWithinDirectory(manifest, root))
    .sort((left, right) => right.path.length - left.path.length)[0];
}

function issueCode(issue: NpmDependencyParseIssue): ScanErrorCode {
  if (issue.code === "UNSUPPORTED_PACKAGE_SOURCE") {
    return "UNSUPPORTED_PACKAGE_SOURCE";
  }
  if (issue.code.includes("UNSUPPORTED_LOCKFILE")) {
    return "UNSUPPORTED_LOCKFILE";
  }
  if (issue.code.includes("PACKAGE_JSON")) {
    return "INVALID_MANIFEST";
  }
  if (issue.code.includes("LOCKFILE") || issue.code.includes("PACKAGES_MAP")) {
    return "INVALID_LOCKFILE";
  }
  if (issue.code.includes("LIMIT") || issue.code.includes("MAXIMUM")) {
    return "DEPENDENCY_LIMIT";
  }
  return "DEPENDENCY_UNRESOLVED";
}

async function readBoundedText(
  uri: vscode.Uri,
  perFileLimit: number,
  budget: ReadBudget,
  signal: AbortSignal,
): Promise<string> {
  throwIfAborted(signal);
  const stat = await vscode.workspace.fs.stat(uri);
  throwIfAborted(signal);
  if (
    !Number.isSafeInteger(stat.size) ||
    stat.size < 0 ||
    stat.size > perFileLimit
  ) {
    throw new RangeError("Dependency metadata file exceeds its size limit");
  }
  if (!budget.tryConsume(stat.size)) {
    throw new RangeError("Workspace dependency metadata exceeds its byte budget");
  }
  if (!consumeDependencyMetadataBytes(signal, stat.size)) {
    throw new RangeError(
      "Workspace dependency metadata exceeds its aggregate byte budget",
    );
  }

  const bytes = await vscode.workspace.fs.readFile(uri);
  throwIfAborted(signal);
  const extraBytes = Math.max(0, bytes.byteLength - stat.size);
  if (extraBytes > 0 && !budget.tryConsume(extraBytes)) {
    throw new RangeError("Workspace dependency metadata exceeds its byte budget");
  }
  if (!consumeDependencyMetadataBytes(signal, extraBytes)) {
    throw new RangeError(
      "Workspace dependency metadata exceeds its aggregate byte budget",
    );
  }
  if (bytes.byteLength > perFileLimit) {
    throw new RangeError("Dependency metadata file exceeds its size limit");
  }
  return new TextDecoder("utf-8", { fatal: true })
    .decode(bytes)
    .replace(/^\uFEFF/u, "");
}

function deduplicateDependencies(
  dependencies: readonly Dependency[],
): readonly Dependency[] {
  return [
    ...new Map(
      dependencies.map((dependency) => [
        `${dependency.lockfilePath ?? ""}\u0000${dependency.name}\u0000${dependency.installedVersion}\u0000${dependency.dependencyPath?.join("\u0000") ?? ""}`,
        dependency,
      ]),
    ).values(),
  ];
}

function uniqueUris(uris: readonly vscode.Uri[]): readonly vscode.Uri[] {
  return [
    ...new Map(uris.map((uri) => [uri.toString(), uri])).values(),
  ];
}

async function readWorkspaceManifests(
  rootUri: vscode.Uri,
  allLockRoots: readonly vscode.Uri[],
  manifestMatches: readonly vscode.Uri[],
  budget: ReadBudget,
  signal: AbortSignal,
  errors: ScanError[],
): Promise<readonly NpmWorkspaceManifestInput[]> {
  const candidates = manifestMatches
    .filter((manifestUri) => {
      const location = relativeManifestLocation(rootUri, manifestUri);
      return (
        location !== undefined &&
        location.length > 0 &&
        owningLockRoot(manifestUri, allLockRoots)?.toString() ===
          rootUri.toString()
      );
    })
    .sort((left, right) => left.path.localeCompare(right.path));
  if (candidates.length > MAX_WORKSPACE_MANIFESTS_PER_PROJECT) {
    errors.push({
      code: "DEPENDENCY_LIMIT",
      message: `Only the first ${MAX_WORKSPACE_MANIFESTS_PER_PROJECT.toString()} nested package.json files were inspected for this npm project`,
      path: safeUriLocation(rootUri),
    });
  }

  const retained = candidates.slice(0, MAX_WORKSPACE_MANIFESTS_PER_PROJECT);
  const results: Array<NpmWorkspaceManifestInput | undefined> = new Array(
    retained.length,
  );
  let nextIndex = 0;
  const worker = async (): Promise<void> => {
    while (!signal.aborted) {
      const index = nextIndex;
      nextIndex += 1;
      const manifestUri = retained[index];
      if (manifestUri === undefined) {
        return;
      }
      const location = relativeManifestLocation(rootUri, manifestUri);
      if (location === undefined || location.length === 0) {
        continue;
      }
      try {
        const packageJson = await readBoundedText(
          manifestUri,
          MAX_PACKAGE_JSON_BYTES,
          budget,
          signal,
        );
        results[index] = {
          location,
          packageJson,
          packageJsonPath: uriStoragePath(manifestUri),
        };
      } catch (error: unknown) {
        throwIfAborted(signal);
        errors.push({
          code:
            error instanceof RangeError
              ? "DEPENDENCY_LIMIT"
              : "INVALID_MANIFEST",
          message:
            error instanceof RangeError
              ? error.message
              : "Could not read a nested npm package.json",
          path: uriStoragePath(manifestUri),
        });
      }
    }
  };
  await Promise.all(
    Array.from(
      {
        length: Math.min(
          WORKSPACE_MANIFEST_READ_CONCURRENCY,
          retained.length,
        ),
      },
      worker,
    ),
  );
  throwIfAborted(signal);
  return results.filter(
    (manifest): manifest is NpmWorkspaceManifestInput => manifest !== undefined,
  );
}

export class NpmWorkspaceScanner {
  public constructor(private readonly logger: Logger) {}

  public async scan(
    folder: vscode.WorkspaceFolder,
    signal: AbortSignal,
    cancellationToken?: vscode.CancellationToken,
    preDetectedProjects?: readonly DetectedDependencyProject[],
    targetProject?: DetectedDependencyProject,
  ): Promise<NpmWorkspaceScanResult> {
    const budget = new ReadBudget(MAX_TOTAL_METADATA_BYTES);
    const errors: ScanError[] = [];
    const dependencies: Dependency[] = [];
    const lockMatches =
      preDetectedProjects === undefined
        ? await vscode.workspace.findFiles(
            new vscode.RelativePattern(folder, NPM_LOCKFILE_GLOB),
            GENERATED_DIRECTORY_GLOB,
            MAX_NPM_PROJECTS * 2 + 1,
            cancellationToken,
          )
        : uniqueUris(
            preDetectedProjects.flatMap((project) => project.lockfileUris),
          );
    throwIfAborted(signal);

    const locksByDirectory = new Map<string, vscode.Uri>();
    for (const lockUri of [...lockMatches]
      .sort((left, right) => left.path.localeCompare(right.path))
      .slice(0, MAX_NPM_PROJECTS * 2)) {
      const key = directoryKey(lockUri);
      const existing = locksByDirectory.get(key);
      const isShrinkwrap = lockUri.path.endsWith("/npm-shrinkwrap.json");
      if (
        existing === undefined ||
        (isShrinkwrap && !existing.path.endsWith("/npm-shrinkwrap.json"))
      ) {
        locksByDirectory.set(key, lockUri);
      }
    }

    if (
      locksByDirectory.size > MAX_NPM_PROJECTS ||
      lockMatches.length > MAX_NPM_PROJECTS * 2
    ) {
      errors.push({
        code: "DEPENDENCY_LIMIT",
        message: `npm project discovery exceeded the ${MAX_NPM_PROJECTS.toString()}-project limit`,
        path: safeUriLocation(folder.uri),
      });
    }

    const allLockUris = [...locksByDirectory.values()]
      .sort((left, right) => left.path.localeCompare(right.path))
      .slice(0, MAX_NPM_PROJECTS);
    const allLockRootUris = allLockUris.map((lockUri) =>
      vscode.Uri.joinPath(lockUri, ".."),
    );
    const selectedLockKeys =
      targetProject === undefined
        ? undefined
        : new Set(targetProject.lockfileUris.map((uri) => uri.toString()));
    const lockUris =
      selectedLockKeys === undefined
        ? allLockUris
        : allLockUris.filter((uri) => selectedLockKeys.has(uri.toString()));
    const manifestMatches =
      preDetectedProjects === undefined
        ? await vscode.workspace.findFiles(
            new vscode.RelativePattern(folder, PACKAGE_JSON_GLOB),
            GENERATED_DIRECTORY_GLOB,
            MAX_PACKAGE_JSON_FILES + 1,
            cancellationToken,
          )
        : uniqueUris(
            preDetectedProjects.flatMap((project) => project.manifestUris),
          );
    throwIfAborted(signal);
    if (manifestMatches.length > MAX_PACKAGE_JSON_FILES) {
      errors.push({
        code: "DEPENDENCY_LIMIT",
        message: `package.json discovery exceeded the ${MAX_PACKAGE_JSON_FILES.toString()}-file limit`,
        path: safeUriLocation(folder.uri),
      });
    }
    const retainedManifestMatches = [...manifestMatches]
      .sort((left, right) => left.path.localeCompare(right.path))
      .slice(0, MAX_PACKAGE_JSON_FILES);
    const otherJavaScriptLocks =
      preDetectedProjects === undefined
        ? await vscode.workspace.findFiles(
            new vscode.RelativePattern(folder, OTHER_JAVASCRIPT_LOCK_GLOB),
            GENERATED_DIRECTORY_GLOB,
            MAX_PACKAGE_JSON_FILES + 1,
            cancellationToken,
          )
        : [];
    throwIfAborted(signal);
    const otherManagerRoots = otherJavaScriptLocks.map((lockUri) =>
      vscode.Uri.joinPath(lockUri, ".."),
    );

    for (let projectIndex = 0; projectIndex < lockUris.length; projectIndex += 1) {
      throwIfAborted(signal);
      const lockUri = lockUris[projectIndex];
      if (lockUri === undefined) {
        continue;
      }
      const rootUri = vscode.Uri.joinPath(lockUri, "..");
      const packageJsonUri = vscode.Uri.joinPath(rootUri, "package.json");
      const packageJsonPath = uriStoragePath(packageJsonUri);
      const lockfilePath = uriStoragePath(lockUri);

      try {
        const [packageJsonText, lockfileText] = await Promise.all([
          readBoundedText(
            packageJsonUri,
            MAX_PACKAGE_JSON_BYTES,
            budget,
            signal,
          ),
          readBoundedText(lockUri, MAX_LOCKFILE_BYTES, budget, signal),
        ]);
        const workspaceManifests = await readWorkspaceManifests(
          rootUri,
          allLockRootUris,
          retainedManifestMatches,
          budget,
          signal,
          errors,
        );
        throwIfAborted(signal);
        const parsed = parseNpmDependencies({
          packageJson: packageJsonText,
          packageJsonPath,
          workspaceManifests,
          lockfile: lockfileText,
          lockfilePath,
          signal,
        });
        if (parsed.cancelled) {
          throw new DOMException("npm dependency parsing cancelled", "AbortError");
        }
        dependencies.push(
          ...parsed.dependencies.map((dependency) => {
            const manifestPath =
              dependency.manifestPath ?? dependency.packageJsonPath;
            return {
              ...dependency,
              resolutionStatus: "resolved" as const,
              ...(manifestPath === undefined ? {} : { manifestPath }),
              packageManager: "npm",
              projectPath: safeUriLocation(rootUri),
              workspacePath: safeUriLocation(folder.uri),
            };
          }),
        );
        for (const issue of parsed.issues) {
          if (issue.level === "warning") {
            this.logger.warn(`npm parser: ${issue.message}`);
          }
          if (
            issue.level === "error" ||
            !NON_COVERAGE_PARSER_WARNINGS.has(issue.code)
          ) {
            errors.push({
              code: issueCode(issue),
              message: issue.message,
              path: lockfilePath,
            });
          }
        }
        if (parsed.unresolvedDependencies > 0) {
          errors.push({
            code: "DEPENDENCY_UNRESOLVED",
            message: `${parsed.unresolvedDependencies.toString()} npm dependency edge(s) could not be resolved from the lockfile`,
            path: lockfilePath,
          });
        }
        if (parsed.truncated) {
          errors.push({
            code: "DEPENDENCY_LIMIT",
            message: "npm dependency parsing was truncated by a safety limit",
            path: lockfilePath,
          });
        }
      } catch (error: unknown) {
        throwIfAborted(signal);
        errors.push({
          code:
            error instanceof RangeError
              ? "DEPENDENCY_LIMIT"
              : "INVALID_LOCKFILE",
          message:
            error instanceof RangeError
              ? error.message
              : "Could not read or parse npm dependency metadata",
          path: lockfilePath,
        });
      }
      await new Promise<void>((resolve) => setImmediate(resolve));
    }

    const targetManifestKeys =
      targetProject === undefined
        ? undefined
        : new Set(targetProject.manifestUris.map((uri) => uri.toString()));
    const orphanManifests = retainedManifestMatches.filter(
      (manifestUri) =>
        (targetManifestKeys === undefined ||
          targetManifestKeys.has(manifestUri.toString())) &&
        !allLockRootUris.some((rootUri) =>
          isWithinDirectory(manifestUri, rootUri),
        ) &&
        !otherManagerRoots.some((rootUri) =>
          isWithinDirectory(manifestUri, rootUri),
        ),
    );
    for (const manifestUri of orphanManifests.slice(0, 100)) {
      errors.push({
        code: "NO_LOCKFILE",
        message:
          "package.json has no package-lock.json; requested ranges were not submitted to OSV as resolved versions",
        path: uriStoragePath(manifestUri),
      });
    }
    if (orphanManifests.length > 100) {
      errors.push({
        code: "DEPENDENCY_LIMIT",
        message: `${(orphanManifests.length - 100).toString()} additional lockless npm manifests were omitted from error output`,
        path: safeUriLocation(folder.uri),
      });
    }

    return {
      dependencies: deduplicateDependencies(dependencies),
      errors,
      npmDetected: lockUris.length > 0 || orphanManifests.length > 0,
      otherPackageManagers: [
        ...new Set(otherJavaScriptLocks.map(otherJavaScriptManager)),
      ].sort(),
      projectCount: lockUris.length,
      cancelled: false,
    };
  }
}
