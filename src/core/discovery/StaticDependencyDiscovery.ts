import { basename, dirname, extname, relative, resolve, sep } from "node:path";

import {
  isCoreCancellation,
  throwIfCoreCancelled,
  type CoreFileSystem,
  type CoreFileSystemRoot,
} from "../host/HostContracts";

export const HEADLESS_PACKAGE_MANAGER_IDS = [
  "npm",
  "yarn",
  "pnpm",
  "bun",
  "pip",
  "poetry",
  "pipenv",
  "maven",
  "gradle",
  "nuget",
  "cargo",
  "go",
  "composer",
] as const;

export type HeadlessPackageManagerId =
  (typeof HEADLESS_PACKAGE_MANAGER_IDS)[number];

export type DependencyFileKind =
  | "package-json"
  | "npm-lock"
  | "yarn-lock"
  | "pnpm-lock"
  | "bun-lock"
  | "bun-binary-lock"
  | "requirements"
  | "pyproject"
  | "poetry-lock"
  | "pipfile"
  | "pipfile-lock"
  | "maven-pom"
  | "gradle-build"
  | "gradle-settings"
  | "gradle-lock"
  | "nuget-project"
  | "nuget-lock"
  | "nuget-packages-config"
  | "nuget-central-props"
  | "nuget-build-props"
  | "nuget-config"
  | "cargo-manifest"
  | "cargo-lock"
  | "go-mod"
  | "go-sum"
  | "composer-manifest"
  | "composer-lock";

export interface DiscoveredDependencyFile {
  readonly path: string;
  readonly relativePath: string;
  readonly kind: DependencyFileKind;
  readonly bytes: number;
}

export interface DiscoveredDependencyProject {
  readonly id: string;
  readonly packageManager: HeadlessPackageManagerId;
  readonly rootPath: string;
  readonly manifestPaths: readonly string[];
  readonly lockfilePaths: readonly string[];
  readonly auxiliaryPaths: readonly string[];
}

export type StaticDiscoveryIssueCode =
  | "INVALID_ROOT"
  | "FILESYSTEM_ERROR"
  | "SYMLINK_SKIPPED"
  | "SPECIAL_FILE_SKIPPED"
  | "FILE_LIMIT"
  | "BYTE_LIMIT"
  | "UNSUPPORTED_FORMAT"
  | "AMBIGUOUS_PROJECT"
  | "NO_LOCKFILE";

export interface StaticDiscoveryIssue {
  readonly code: StaticDiscoveryIssueCode;
  readonly message: string;
  readonly path?: string;
}

export interface StaticDependencyDiscoveryOptions {
  readonly maximumFiles: number;
  readonly maximumBytes: number;
  readonly signal?: AbortSignal;
}

export interface StaticDependencyDiscoveryResult {
  readonly root: CoreFileSystemRoot;
  readonly files: readonly DiscoveredDependencyFile[];
  readonly projects: readonly DiscoveredDependencyProject[];
  readonly issues: readonly StaticDiscoveryIssue[];
  readonly entriesVisited: number;
  readonly candidateBytes: number;
  readonly complete: boolean;
  readonly cancelled: boolean;
}

const HARD_MAXIMUM_FILES = 2_000_000;
const HARD_MAXIMUM_BYTES = 2 * 1024 * 1024 * 1024;
const MAXIMUM_ISSUES = 2_000;
const EXCLUDED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  ".yarn",
  "__pycache__",
  "bower_components",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "obj",
  "out",
  "target",
  "vendor",
  "venv",
  ".venv",
]);

function checkedLimit(value: number, hardMaximum: number, name: string): number {
  if (
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > hardMaximum
  ) {
    throw new RangeError(`${name} is outside the supported safety range`);
  }
  return value;
}

function forwardRelative(root: string, path: string): string {
  return relative(root, path).split(sep).join("/");
}

function classifyFile(name: string): DependencyFileKind | undefined {
  const lower = name.toLowerCase();
  if (lower === "package.json") return "package-json";
  if (lower === "package-lock.json" || lower === "npm-shrinkwrap.json") {
    return "npm-lock";
  }
  if (lower === "yarn.lock") return "yarn-lock";
  if (lower === "pnpm-lock.yaml") return "pnpm-lock";
  if (lower === "bun.lock") return "bun-lock";
  if (lower === "bun.lockb") return "bun-binary-lock";
  if (/^requirements(?:[._-][a-z0-9._-]+)?\.txt$/iu.test(name)) {
    return "requirements";
  }
  if (lower === "pyproject.toml") return "pyproject";
  if (lower === "poetry.lock") return "poetry-lock";
  if (name === "Pipfile") return "pipfile";
  if (name === "Pipfile.lock") return "pipfile-lock";
  if (lower === "pom.xml") return "maven-pom";
  if (lower === "build.gradle" || lower === "build.gradle.kts") {
    return "gradle-build";
  }
  if (lower === "settings.gradle" || lower === "settings.gradle.kts") {
    return "gradle-settings";
  }
  if (lower === "gradle.lockfile") return "gradle-lock";
  if ([".csproj", ".fsproj", ".vbproj"].includes(extname(lower))) {
    return "nuget-project";
  }
  if (lower === "packages.lock.json") return "nuget-lock";
  if (lower === "packages.config") return "nuget-packages-config";
  if (lower === "directory.packages.props") return "nuget-central-props";
  if (lower === "directory.build.props") return "nuget-build-props";
  if (lower === "nuget.config") return "nuget-config";
  if (name === "Cargo.toml") return "cargo-manifest";
  if (name === "Cargo.lock") return "cargo-lock";
  if (lower === "go.mod") return "go-mod";
  if (lower === "go.sum") return "go-sum";
  if (lower === "composer.json") return "composer-manifest";
  if (lower === "composer.lock") return "composer-lock";
  return undefined;
}

function projectId(
  manager: HeadlessPackageManagerId,
  root: string,
  manifests: readonly string[],
): string {
  return JSON.stringify([manager, root, ...manifests]);
}

function ancestors(path: string, root: string): string[] {
  const values: string[] = [];
  let current = resolve(path);
  const boundary = resolve(root);
  while (true) {
    values.push(current);
    if (current === boundary) {
      break;
    }
    const parent = dirname(current);
    if (parent === current) {
      break;
    }
    current = parent;
  }
  return values;
}

function closestAncestorFile(
  directory: string,
  root: string,
  candidates: ReadonlyMap<string, readonly string[]>,
): string | undefined {
  for (const ancestor of ancestors(directory, root)) {
    const values = candidates.get(ancestor);
    if (values?.[0] !== undefined) {
      return values[0];
    }
  }
  return undefined;
}

function groupByDirectory(
  files: readonly DiscoveredDependencyFile[],
  kind: DependencyFileKind,
): ReadonlyMap<string, readonly string[]> {
  const grouped = new Map<string, string[]>();
  for (const file of files) {
    if (file.kind !== kind) continue;
    const directory = dirname(file.path);
    const values = grouped.get(directory) ?? [];
    values.push(file.path);
    grouped.set(directory, values);
  }
  for (const values of grouped.values()) values.sort();
  return grouped;
}

function project(
  packageManager: HeadlessPackageManagerId,
  rootPath: string,
  manifestPaths: readonly string[],
  lockfilePaths: readonly string[] = [],
  auxiliaryPaths: readonly string[] = [],
): DiscoveredDependencyProject {
  const manifests = [...manifestPaths].sort();
  return {
    id: projectId(packageManager, rootPath, manifests),
    packageManager,
    rootPath,
    manifestPaths: manifests,
    lockfilePaths: [...lockfilePaths].sort(),
    auxiliaryPaths: [...auxiliaryPaths].sort(),
  };
}

function buildProjects(
  root: CoreFileSystemRoot,
  files: readonly DiscoveredDependencyFile[],
  addIssue: (issue: StaticDiscoveryIssue) => void,
): readonly DiscoveredDependencyProject[] {
  const result: DiscoveredDependencyProject[] = [];
  const byKind = new Map<DependencyFileKind, DiscoveredDependencyFile[]>();
  for (const file of files) {
    const values = byKind.get(file.kind) ?? [];
    values.push(file);
    byKind.set(file.kind, values);
  }
  const paths = (kind: DependencyFileKind): string[] =>
    (byKind.get(kind) ?? []).map((file) => file.path).sort();
  const sameDirectory = (
    kind: DependencyFileKind,
    directory: string,
  ): string[] =>
    (byKind.get(kind) ?? [])
      .filter((file) => dirname(file.path) === directory)
      .map((file) => file.path)
      .sort();

  const jsLockKinds = [
    ["npm", "npm-lock"],
    ["yarn", "yarn-lock"],
    ["pnpm", "pnpm-lock"],
    ["bun", "bun-lock"],
  ] as const;
  const jsRoots = new Map<
    string,
    Array<{ manager: HeadlessPackageManagerId; lock: string }>
  >();
  for (const [manager, kind] of jsLockKinds) {
    for (const lock of paths(kind)) {
      const directory = dirname(lock);
      const values = jsRoots.get(directory) ?? [];
      values.push({ manager, lock });
      jsRoots.set(directory, values);
    }
  }
  const usableJsRoots = new Map<string, { manager: HeadlessPackageManagerId; lock: string }>();
  for (const [directory, locks] of jsRoots) {
    const managers = new Set(locks.map((entry) => entry.manager));
    if (managers.size > 1) {
      addIssue({
        code: "AMBIGUOUS_PROJECT",
        message:
          "Multiple JavaScript package-manager lockfiles share one project root; no authoritative manager was selected.",
        path: directory,
      });
      continue;
    }
    const selected = locks.sort((left, right) => left.lock.localeCompare(right.lock, "en"))[0];
    if (selected !== undefined) usableJsRoots.set(directory, selected);
  }
  const manifestsByJsRoot = new Map<string, string[]>();
  for (const manifest of paths("package-json")) {
    const owner = ancestors(dirname(manifest), root.path).find((directory) =>
      usableJsRoots.has(directory),
    );
    if (owner === undefined) {
      addIssue({
        code: "NO_LOCKFILE",
        message:
          "package.json has no supported authoritative lockfile; installed versions cannot be proven.",
        path: manifest,
      });
      result.push(project("npm", dirname(manifest), [manifest]));
    } else {
      const values = manifestsByJsRoot.get(owner) ?? [];
      values.push(manifest);
      manifestsByJsRoot.set(owner, values);
    }
  }
  for (const [directory, selected] of usableJsRoots) {
    const manifests = manifestsByJsRoot.get(directory) ?? [];
    if (manifests.length === 0) {
      addIssue({
        code: "AMBIGUOUS_PROJECT",
        message: "A JavaScript lockfile has no package.json manifest in its owned tree.",
        path: selected.lock,
      });
    }
    result.push(project(selected.manager, directory, manifests, [selected.lock]));
  }
  for (const binaryLock of paths("bun-binary-lock")) {
    addIssue({
      code: "UNSUPPORTED_FORMAT",
      message:
        "Binary bun.lockb is intentionally unsupported by the static headless scanner; convert it to Bun's text lockfile format.",
      path: binaryLock,
    });
  }

  for (const manifest of paths("requirements")) {
    result.push(project("pip", dirname(manifest), [manifest]));
  }
  for (const manifest of paths("pyproject")) {
    const directory = dirname(manifest);
    result.push(
      project(
        "poetry",
        directory,
        [manifest],
        sameDirectory("poetry-lock", directory),
      ),
    );
  }
  for (const manifest of paths("pipfile")) {
    const directory = dirname(manifest);
    result.push(
      project(
        "pipenv",
        directory,
        [manifest],
        sameDirectory("pipfile-lock", directory),
      ),
    );
  }
  for (const manifest of paths("maven-pom")) {
    result.push(project("maven", dirname(manifest), [manifest]));
  }
  for (const manifest of paths("gradle-build")) {
    const directory = dirname(manifest);
    result.push(
      project(
        "gradle",
        directory,
        [manifest],
        sameDirectory("gradle-lock", directory),
        sameDirectory("gradle-settings", directory),
      ),
    );
  }

  const nugetLocks = groupByDirectory(files, "nuget-lock");
  const centralProps = groupByDirectory(files, "nuget-central-props");
  const buildProps = groupByDirectory(files, "nuget-build-props");
  const nugetConfigs = groupByDirectory(files, "nuget-config");
  for (const manifest of paths("nuget-project")) {
    const directory = dirname(manifest);
    const auxiliary = ancestors(directory, root.path).flatMap((ancestor) => [
      ...(centralProps.get(ancestor) ?? []),
      ...(buildProps.get(ancestor) ?? []),
      ...(nugetConfigs.get(ancestor) ?? []),
    ]);
    result.push(
      project(
        "nuget",
        directory,
        [manifest],
        nugetLocks.get(directory) ?? [],
        auxiliary,
      ),
    );
  }
  for (const manifest of paths("nuget-packages-config")) {
    result.push(project("nuget", dirname(manifest), [manifest]));
  }

  const cargoLocks = groupByDirectory(files, "cargo-lock");
  const cargoManifests = groupByDirectory(files, "cargo-manifest");
  for (const manifest of paths("cargo-manifest")) {
    const directory = dirname(manifest);
    const lock = closestAncestorFile(directory, root.path, cargoLocks);
    const workspaceManifest = lock === undefined
      ? undefined
      : cargoManifests.get(dirname(lock))?.[0];
    result.push(
      project(
        "cargo",
        directory,
        [manifest],
        lock === undefined ? [] : [lock],
        workspaceManifest === undefined || workspaceManifest === manifest
          ? []
          : [workspaceManifest],
      ),
    );
  }
  for (const manifest of paths("go-mod")) {
    const directory = dirname(manifest);
    result.push(
      project("go", directory, [manifest], sameDirectory("go-sum", directory)),
    );
  }
  for (const manifest of paths("composer-manifest")) {
    const directory = dirname(manifest);
    result.push(
      project(
        "composer",
        directory,
        [manifest],
        sameDirectory("composer-lock", directory),
      ),
    );
  }

  return result.sort((left, right) =>
    left.id.localeCompare(right.id, "en"),
  );
}

export async function discoverDependencyProjects(
  fileSystem: CoreFileSystem,
  rootPath: string,
  options: StaticDependencyDiscoveryOptions,
): Promise<StaticDependencyDiscoveryResult> {
  const maximumFiles = checkedLimit(
    options.maximumFiles,
    HARD_MAXIMUM_FILES,
    "maximumFiles",
  );
  const maximumBytes = checkedLimit(
    options.maximumBytes,
    HARD_MAXIMUM_BYTES,
    "maximumBytes",
  );
  const root = await fileSystem.openRoot(rootPath, options.signal);
  const files: DiscoveredDependencyFile[] = [];
  const issues: StaticDiscoveryIssue[] = [];
  const issueKeys = new Set<string>();
  const addIssue = (issue: StaticDiscoveryIssue): void => {
    const key = JSON.stringify([issue.code, issue.path ?? "", issue.message]);
    if (issueKeys.has(key)) return;
    issueKeys.add(key);
    if (issues.length < MAXIMUM_ISSUES) issues.push(issue);
  };
  const directories = [root.path];
  let directoryIndex = 0;
  let entriesVisited = 0;
  let candidateBytes = 0;
  let complete = true;
  let cancelled = false;

  try {
    while (directoryIndex < directories.length) {
      throwIfCoreCancelled(options.signal);
      const directory = directories[directoryIndex];
      directoryIndex += 1;
      if (directory === undefined) continue;
      let entries;
      try {
        entries = await fileSystem.readDirectory(root, directory, options.signal);
      } catch (error: unknown) {
        if (isCoreCancellation(error)) throw error;
        complete = false;
        addIssue({
          code: "FILESYSTEM_ERROR",
          message: "A workspace directory could not be enumerated safely.",
          path: directory,
        });
        continue;
      }
      for (const entry of entries) {
        throwIfCoreCancelled(options.signal);
        entriesVisited += 1;
        if (entriesVisited > maximumFiles) {
          complete = false;
          addIssue({
            code: "FILE_LIMIT",
            message: `Workspace discovery exceeded the ${maximumFiles.toString()}-entry safety limit.`,
            path: directory,
          });
          directoryIndex = directories.length;
          break;
        }
        const excluded = EXCLUDED_DIRECTORIES.has(entry.name.toLowerCase());
        if (entry.type === "directory") {
          if (!excluded) directories.push(entry.path);
          continue;
        }
        if (entry.type === "symlink") {
          if (!excluded) {
            complete = false;
            addIssue({
              code: "SYMLINK_SKIPPED",
              message:
                "A symbolic link or junction was not followed; dependency coverage may be incomplete.",
              path: entry.path,
            });
          }
          continue;
        }
        if (entry.type !== "file") {
          complete = false;
          addIssue({
            code: "SPECIAL_FILE_SKIPPED",
            message: "A non-regular workspace entry was not read.",
            path: entry.path,
          });
          continue;
        }
        const kind = classifyFile(entry.name);
        if (kind === undefined) continue;
        if (
          !Number.isSafeInteger(entry.size) ||
          entry.size < 0 ||
          entry.size > maximumBytes - candidateBytes
        ) {
          complete = false;
          addIssue({
            code: "BYTE_LIMIT",
            message:
              "Dependency metadata discovery exceeded the aggregate byte safety limit.",
            path: entry.path,
          });
          continue;
        }
        candidateBytes += entry.size;
        files.push({
          path: entry.path,
          relativePath: forwardRelative(root.path, entry.path),
          kind,
          bytes: entry.size,
        });
      }
    }
  } catch (error: unknown) {
    if (!isCoreCancellation(error)) throw error;
    complete = false;
    cancelled = true;
  }

  files.sort((left, right) => left.relativePath.localeCompare(right.relativePath, "en"));
  const projects = buildProjects(root, files, addIssue);
  if (issues.length >= MAXIMUM_ISSUES) complete = false;
  if (cancelled) {
    addIssue({
      code: "FILESYSTEM_ERROR",
      message: "Workspace discovery was cancelled before coverage completed.",
      path: root.path,
    });
  }
  issues.sort((left, right) =>
    JSON.stringify([left.code, left.path ?? "", left.message]).localeCompare(
      JSON.stringify([right.code, right.path ?? "", right.message]),
      "en",
    ),
  );
  return {
    root,
    files,
    projects,
    issues,
    entriesVisited,
    candidateBytes,
    complete: complete && issues.length === 0,
    cancelled,
  };
}

export function dependencyFileBasename(file: DiscoveredDependencyFile): string {
  return basename(file.path);
}
