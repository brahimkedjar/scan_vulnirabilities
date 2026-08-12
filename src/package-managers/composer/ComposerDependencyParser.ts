import type {
  Dependency,
  DependencyEnvironment,
} from "../../models/Dependency";
import { satisfies as satisfiesSemver } from "semver";

type UnknownRecord = Record<string, unknown>;

export interface ComposerParseIssue {
  readonly code: string;
  readonly message: string;
}

export interface ComposerParserLimits {
  readonly maxPackages: number;
  readonly maxEdges: number;
  readonly maxDepth: number;
  readonly maxIssues: number;
}

export interface ComposerParserInput {
  readonly composerJson: string;
  readonly manifestPath: string;
  readonly composerLock?: string;
  readonly lockfilePath?: string;
  readonly projectPath?: string;
  readonly workspacePath?: string;
  readonly signal?: AbortSignal;
  readonly limits?: Partial<ComposerParserLimits>;
}

export interface ComposerParseResult {
  readonly dependencies: readonly Dependency[];
  readonly issues: readonly ComposerParseIssue[];
  readonly truncated: boolean;
  readonly cancelled: boolean;
}

export const DEFAULT_COMPOSER_PARSER_LIMITS: ComposerParserLimits = {
  maxPackages: 10_000,
  maxEdges: 250_000,
  maxDepth: 512,
  maxIssues: 1_000,
};

interface RootRequirement {
  readonly name: string;
  readonly requestedVersion: string;
  readonly environment: DependencyEnvironment;
  readonly section: "require" | "require-dev";
}

interface LockedPackage {
  readonly name: string;
  readonly version: string;
  readonly environment: DependencyEnvironment;
  readonly dependencies: readonly {
    readonly name: string;
    readonly constraint: string;
  }[];
  readonly replacements: readonly {
    readonly name: string;
    readonly constraint: string;
  }[];
  readonly localPath: boolean;
  readonly sourceUnsupported: boolean;
}

interface QueueItem {
  readonly node: LockedPackage;
  readonly root: RootRequirement;
  readonly path: readonly string[];
  readonly depth: number;
  readonly direct: boolean;
}

class ComposerParseContext {
  public readonly issues: ComposerParseIssue[] = [];
  public truncated = false;
  public edges = 0;

  public constructor(
    public readonly limits: ComposerParserLimits,
    private readonly signal: AbortSignal | undefined,
  ) {}

  public checkCancellation(): void {
    if (this.signal?.aborted === true) {
      throw new DOMException("Composer parsing cancelled", "AbortError");
    }
  }

  public addIssue(code: string, message: string): void {
    if (this.issues.length < this.limits.maxIssues) {
      this.issues.push({ code, message });
    } else {
      this.truncated = true;
    }
  }

  public consumeEdge(): boolean {
    this.checkCancellation();
    if (this.edges >= this.limits.maxEdges) {
      this.truncated = true;
      this.addIssue(
        "DEPENDENCY_LIMIT",
        "Composer dependency graph exceeded its edge safety limit",
      );
      return false;
    }
    this.edges += 1;
    return true;
  }
}

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function positiveLimit(value: unknown, fallback: number): number {
  return Number.isSafeInteger(value) && Number(value) > 0
    ? Number(value)
    : fallback;
}

function parserLimits(
  supplied: Partial<ComposerParserLimits> | undefined,
): ComposerParserLimits {
  return {
    maxPackages: positiveLimit(
      supplied?.maxPackages,
      DEFAULT_COMPOSER_PARSER_LIMITS.maxPackages,
    ),
    maxEdges: positiveLimit(
      supplied?.maxEdges,
      DEFAULT_COMPOSER_PARSER_LIMITS.maxEdges,
    ),
    maxDepth: positiveLimit(
      supplied?.maxDepth,
      DEFAULT_COMPOSER_PARSER_LIMITS.maxDepth,
    ),
    maxIssues: positiveLimit(
      supplied?.maxIssues,
      DEFAULT_COMPOSER_PARSER_LIMITS.maxIssues,
    ),
  };
}

function safePackageName(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 2 &&
    value.length <= 256 &&
    /^[a-z0-9](?:[_.-]?[a-z0-9]+)*\/[a-z0-9](?:(?:[_.]|-{1,2})?[a-z0-9]+)*$/u.test(
      value,
    )
  );
}

function safeValue(value: unknown, maximum = 2_048): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    !/[\u0000-\u001F\u007F]/u.test(value)
  );
}

function safeLockedVersion(value: unknown): value is string {
  if (!safeValue(value, 256)) {
    return false;
  }
  const match = /^v?(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*))?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u.exec(
    value,
  );
  const numeric = [
    ...(match?.[1]?.split(".") ?? []),
    ...(match?.[2]?.split(/[.-]/u).filter((part) => /^\d+$/u.test(part)) ?? []),
  ];
  return (
    match !== null &&
    numeric.every((part) => part === "0" || !part.startsWith("0"))
  );
}

function canonicalPackagistRepository(value: unknown): boolean {
  if (
    !isRecord(value) ||
    value.type !== "composer" ||
    typeof value.url !== "string"
  ) {
    return false;
  }
  try {
    const url = new URL(value.url);
    return (
      url.protocol === "https:" &&
      url.hostname.toLowerCase() === "repo.packagist.org" &&
      url.username.length === 0 &&
      url.password.length === 0 &&
      url.port.length === 0 &&
      (url.pathname === "" || url.pathname === "/") &&
      url.search.length === 0 &&
      url.hash.length === 0
    );
  } catch {
    return false;
  }
}

function hasCustomRepositoryConfiguration(manifest: UnknownRecord): boolean {
  const repositories = manifest.repositories;
  if (repositories === undefined) {
    return false;
  }
  return (
    !Array.isArray(repositories) ||
    repositories.some(
      (repository) => !canonicalPackagistRepository(repository),
    )
  );
}

function parseJson(
  text: string,
  label: string,
  code: string,
  context: ComposerParseContext,
): UnknownRecord | undefined {
  try {
    const value: unknown = JSON.parse(text);
    if (!isRecord(value)) {
      context.addIssue(code, `${label} must contain a JSON object`);
      return undefined;
    }
    return value;
  } catch (_error: unknown) {
    context.addIssue(code, `${label} is not valid JSON`);
    return undefined;
  }
}

function platformRequirement(name: string): boolean {
  return (
    name === "php" ||
    name === "hhvm" ||
    name === "composer" ||
    name === "composer-plugin-api" ||
    name === "composer-runtime-api" ||
    name.startsWith("ext-") ||
    name.startsWith("lib-")
  );
}

function collectRootRequirements(
  manifest: UnknownRecord,
  context: ComposerParseContext,
): readonly RootRequirement[] {
  const output: RootRequirement[] = [];
  const sections: readonly ["require" | "require-dev", DependencyEnvironment][] = [
    ["require", "production"],
    ["require-dev", "development"],
  ];
  for (const [section, environment] of sections) {
    const table = manifest[section];
    if (table === undefined) {
      continue;
    }
    if (!isRecord(table)) {
      context.addIssue("INVALID_MANIFEST", `composer.json ${section} must be an object`);
      continue;
    }
    for (const [name, rawVersion] of Object.entries(table).sort(
      ([left], [right]) => left.localeCompare(right),
    )) {
      context.checkCancellation();
      if (platformRequirement(name)) {
        continue;
      }
      if (!safePackageName(name) || !safeValue(rawVersion)) {
        context.addIssue(
          "DEPENDENCY_UNRESOLVED",
          `composer.json contains an invalid ${section} package declaration`,
        );
        continue;
      }
      output.push({
        name,
        requestedVersion: rawVersion,
        environment,
        section,
      });
    }
  }
  return output;
}

function constraintEntries(
  value: unknown,
  context: ComposerParseContext,
): readonly {
  readonly name: string;
  readonly constraint: string;
}[] {
  if (value === undefined) {
    return [];
  }
  if (!isRecord(value)) {
    context.addIssue(
      "INVALID_LOCKFILE",
      "composer.lock contains a malformed package constraint table",
    );
    return [];
  }
  const output: Array<{ readonly name: string; readonly constraint: string }> = [];
  for (const [name, constraint] of Object.entries(value)) {
    if (!safePackageName(name) || !safeValue(constraint, 256)) {
      context.addIssue(
        "INVALID_LOCKFILE",
        "composer.lock contains an invalid package constraint",
      );
      continue;
    }
    output.push({ name, constraint });
  }
  return output;
}

function publicComposerArtifactUrl(value: unknown): boolean {
  if (typeof value !== "string" || value.length === 0 || value.length > 4_096) {
    return false;
  }
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.username.length === 0 &&
      url.password.length === 0 &&
      url.port.length === 0 &&
      [
        "api.bitbucket.org",
        "api.github.com",
        "bitbucket.org",
        "codeload.github.com",
        "github.com",
        "gitlab.com",
        "objects.githubusercontent.com",
        "repo.packagist.org",
      ].includes(url.hostname.toLowerCase())
    );
  } catch {
    return false;
  }
}

function packageArtifactUnsupported(
  candidate: UnknownRecord,
  localPath: boolean,
): boolean {
  if (localPath) {
    return true;
  }
  for (const field of ["dist", "source"] as const) {
    const artifact = candidate[field];
    if (artifact === undefined) {
      continue;
    }
    if (!isRecord(artifact)) {
      return true;
    }
    if (artifact.url !== undefined && !publicComposerArtifactUrl(artifact.url)) {
      return true;
    }
  }
  return false;
}

function lockedPackage(
  value: unknown,
  environment: DependencyEnvironment,
  context: ComposerParseContext,
): LockedPackage | undefined {
  const candidate = isRecord(value) ? value : undefined;
  const dist = isRecord(candidate?.dist) ? candidate.dist : undefined;
  const localPath = dist?.type === "path";
  if (
    candidate === undefined ||
    !safePackageName(candidate.name) ||
    !safeValue(candidate.version, 256) ||
    (!localPath && !safeLockedVersion(candidate.version))
  ) {
    context.addIssue(
      "INVALID_LOCKFILE",
      "composer.lock contains a package with an invalid identity or version",
    );
    return undefined;
  }
  return {
    name: candidate.name,
    version: candidate.version,
    environment,
    dependencies: constraintEntries(candidate.require, context),
    replacements: [
      ...constraintEntries(candidate.replace, context),
      ...constraintEntries(candidate.provide, context),
    ],
    localPath,
    sourceUnsupported: packageArtifactUnsupported(candidate, localPath),
  };
}

function collectLockedPackages(
  lock: UnknownRecord,
  context: ComposerParseContext,
): readonly LockedPackage[] | undefined {
  if (!Array.isArray(lock.packages) || !Array.isArray(lock["packages-dev"])) {
    context.addIssue(
      "INVALID_LOCKFILE",
      "composer.lock must contain packages and packages-dev arrays",
    );
    return undefined;
  }
  const entries: readonly [unknown, DependencyEnvironment][] = [
    ...lock.packages.map((entry): [unknown, DependencyEnvironment] => [
      entry,
      "production",
    ]),
    ...lock["packages-dev"].map((entry): [unknown, DependencyEnvironment] => [
      entry,
      "development",
    ]),
  ];
  if (entries.length > context.limits.maxPackages) {
    context.truncated = true;
    context.addIssue("DEPENDENCY_LIMIT", "composer.lock exceeded its package safety limit");
  }
  const output: LockedPackage[] = [];
  const seen = new Map<string, string>();
  for (const [entry, environment] of entries.slice(0, context.limits.maxPackages)) {
    context.checkCancellation();
    const parsed = lockedPackage(entry, environment, context);
    if (parsed === undefined) {
      continue;
    }
    const previousVersion = seen.get(parsed.name);
    if (previousVersion !== undefined && previousVersion !== parsed.version) {
      context.addIssue(
        "INVALID_LOCKFILE",
        `composer.lock contains conflicting versions of ${parsed.name}`,
      );
      continue;
    }
    seen.set(parsed.name, parsed.version);
    output.push(parsed);
  }
  return output;
}

function baseDependency(
  input: ComposerParserInput,
  root: RootRequirement,
  environment: DependencyEnvironment,
  section: string,
  source: string,
): Pick<
  Dependency,
  | "ecosystem"
  | "manifestName"
  | "requestedVersion"
  | "environment"
  | "declaredEnvironment"
  | "manifestPath"
  | "lockfilePath"
  | "packageManager"
  | "projectPath"
  | "workspacePath"
  | "metadata"
> {
  return {
    ecosystem: "Packagist",
    manifestName: root.name,
    requestedVersion: root.requestedVersion,
    environment,
    declaredEnvironment: root.environment,
    manifestPath: input.manifestPath,
    ...(input.lockfilePath === undefined
      ? {}
      : { lockfilePath: input.lockfilePath }),
    packageManager: "composer",
    ...(input.projectPath === undefined
      ? {}
      : { projectPath: input.projectPath }),
    ...(input.workspacePath === undefined
      ? {}
      : { workspacePath: input.workspacePath }),
    metadata: { manifestSection: section, composerSource: source },
  };
}

function unresolvedRequirement(
  input: ComposerParserInput,
  requirement: RootRequirement,
): Dependency {
  return {
    name: requirement.name,
    ...baseDependency(
      input,
      requirement,
      requirement.environment,
      requirement.section,
      "unresolved",
    ),
    installedVersion: "",
    resolutionStatus: "unresolved",
    dependencyType: "direct",
    dependencyPath: [requirement.name],
  };
}

function environmentRank(environment: DependencyEnvironment): number {
  return environment === "production" ? 2 : environment === "development" ? 1 : 0;
}

function normalizedComposerSemver(value: string): string | undefined {
  const match = /^v?(\d+(?:\.\d+){0,2})((?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?)$/u.exec(
    value.trim(),
  );
  if (match?.[1] === undefined) {
    return undefined;
  }
  const parts = match[1].split(".");
  while (parts.length < 3) {
    parts.push("0");
  }
  return `${parts.join(".")}${match[2] ?? ""}`;
}

function normalizedComposerConstraint(value: string): string | undefined {
  let constraint = value.trim();
  if (
    constraint.length === 0 ||
    constraint.length > 256 ||
    /(?:^|\s)dev-|@(?:dev|alpha|beta|rc|stable)\b|\bas\b/iu.test(constraint)
  ) {
    return undefined;
  }
  constraint = constraint
    .replace(/(?<!\|)\|(?!\|)/gu, "||")
    .replace(/\s*,\s*/gu, " ");
  const twoPartTilde = /^~(\d+)\.(\d+)$/u.exec(constraint);
  if (twoPartTilde !== null) {
    const major = Number(twoPartTilde[1]);
    const minor = Number(twoPartTilde[2]);
    return `>=${major.toString()}.${minor.toString()}.0 <${(
      major + 1
    ).toString()}.0.0`;
  }
  return constraint.replace(
    /(?<![0-9A-Za-z.-])v(?=\d)/gu,
    "",
  );
}

function composerRequirementSatisfied(
  requested: string,
  selected: string,
): boolean {
  if (requested.trim() === "*") {
    return true;
  }
  const selectedSemver = normalizedComposerSemver(selected);
  const constraint = normalizedComposerConstraint(requested);
  if (selectedSemver === undefined || constraint === undefined) {
    return requested.replace(/^v/u, "") === selected.replace(/^v/u, "");
  }
  try {
    return satisfiesSemver(selectedSemver, constraint, {
      includePrerelease: true,
    });
  } catch {
    return false;
  }
}

function lockedPackageSatisfiesRequirement(
  name: string,
  constraint: string,
  node: LockedPackage,
): boolean {
  const replacement = node.replacements.find(
    (candidate) => candidate.name === name,
  );
  return (
    (node.name === name || replacement?.constraint === "self.version") &&
    composerRequirementSatisfied(constraint, node.version)
  );
}

export function parseComposerDependencies(
  input: ComposerParserInput,
): ComposerParseResult {
  const context = new ComposerParseContext(
    parserLimits(input.limits),
    input.signal,
  );
  try {
    context.checkCancellation();
    const manifest = parseJson(
      input.composerJson,
      "composer.json",
      "INVALID_MANIFEST",
      context,
    );
    if (manifest === undefined) {
      return {
        dependencies: [],
        issues: context.issues,
        truncated: context.truncated,
        cancelled: false,
      };
    }
    const requirements = collectRootRequirements(manifest, context);
    const customRepositoryConfiguration =
      hasCustomRepositoryConfiguration(manifest);
    if (customRepositoryConfiguration) {
      context.addIssue(
        "UNSUPPORTED_PACKAGE_SOURCE",
        "composer.json configures a custom repository, so locked packages cannot be proven to originate from Packagist",
      );
    }
    if (input.composerLock === undefined) {
      if (requirements.length > 0) {
        context.addIssue(
          "NO_LOCKFILE",
          "composer.json constraints were not treated as installed versions without composer.lock",
        );
      }
      return {
        dependencies: requirements.map((requirement) =>
          unresolvedRequirement(input, requirement),
        ),
        issues: context.issues,
        truncated: context.truncated,
        cancelled: false,
      };
    }
    const lock = parseJson(
      input.composerLock,
      "composer.lock",
      "INVALID_LOCKFILE",
      context,
    );
    const packages = lock === undefined ? undefined : collectLockedPackages(lock, context);
    if (packages === undefined) {
      return {
        dependencies: requirements.map((requirement) =>
          unresolvedRequirement(input, requirement),
        ),
        issues: context.issues,
        truncated: context.truncated,
        cancelled: false,
      };
    }
    const byName = new Map(packages.map((entry) => [entry.name, entry]));
    const providers = new Map<string, LockedPackage[]>();
    for (const entry of packages) {
      for (const replacement of entry.replacements) {
        const values = providers.get(replacement.name) ?? [];
        values.push(entry);
        providers.set(replacement.name, values);
      }
    }
    const resolveName = (name: string): LockedPackage | undefined => {
      const direct = byName.get(name);
      if (direct !== undefined) {
        return direct;
      }
      const replacements = providers.get(name) ?? [];
      return replacements.length === 1 ? replacements[0] : undefined;
    };

    const queue: QueueItem[] = [];
    const missing: RootRequirement[] = [];
    for (const requirement of requirements) {
      const node = resolveName(requirement.name);
      if (node === undefined) {
        missing.push(requirement);
        context.addIssue(
          "DEPENDENCY_UNRESOLVED",
          `Composer requirement ${requirement.name} is absent or ambiguous in composer.lock`,
        );
        continue;
      }
      if (
        !lockedPackageSatisfiesRequirement(
          requirement.name,
          requirement.requestedVersion,
          node,
        )
      ) {
        missing.push(requirement);
        context.addIssue(
          "DEPENDENCY_UNRESOLVED",
          `Composer lock selection for ${requirement.name} does not satisfy the manifest constraint`,
        );
        continue;
      }
      queue.push({
        node,
        root: requirement,
        path: ["root", `${node.name}@${node.version}`],
        depth: 1,
        direct: true,
      });
    }
    const visited = new Map<string, number>();
    const output = new Map<string, Dependency>();
    let index = 0;
    while (index < queue.length) {
      context.checkCancellation();
      const item = queue[index];
      index += 1;
      if (item === undefined) {
        continue;
      }
      if (item.depth > context.limits.maxDepth) {
        context.truncated = true;
        context.addIssue(
          "DEPENDENCY_LIMIT",
          "Composer dependency traversal exceeded its depth safety limit",
        );
        continue;
      }
      const environment =
        item.root.environment === "production" || item.node.environment === "production"
          ? "production"
          : "development";
      const visitKey = `${item.node.name}\u0000${environment}`;
      const previousDepth = visited.get(visitKey);
      if (previousDepth !== undefined && previousDepth <= item.depth) {
        continue;
      }
      visited.set(visitKey, item.depth);
      const unsupportedSource =
        item.node.sourceUnsupported || customRepositoryConfiguration;
      const dependency: Dependency = {
        name: item.node.name,
        ...baseDependency(
          input,
          item.root,
          environment,
          item.direct ? item.root.section : "composer.lock",
          item.node.sourceUnsupported
            ? item.node.localPath
              ? "path"
              : "custom-artifact"
            : customRepositoryConfiguration
              ? "custom-repository"
              : "package",
        ),
        installedVersion: unsupportedSource ? "" : item.node.version,
        resolutionStatus: unsupportedSource ? "unsupported" : "resolved",
        dependencyType: item.direct ? "direct" : "transitive",
        ...(item.direct || item.path.length < 3
          ? {}
          : { parent: item.path[item.path.length - 2] }),
        dependencyPath: [...item.path],
      };
      if (item.node.sourceUnsupported) {
        context.addIssue(
          "UNSUPPORTED_PACKAGE_SOURCE",
          `Composer package ${item.node.name} has local or non-public artifact provenance and was not mapped to Packagist`,
        );
      }
      const previous = output.get(item.node.name);
      if (
        previous === undefined ||
        (item.direct && previous.dependencyType === "transitive") ||
        environmentRank(environment) > environmentRank(previous.environment)
      ) {
        output.set(item.node.name, dependency);
      }
      for (const dependencyRequirement of item.node.dependencies) {
        if (!context.consumeEdge()) {
          break;
        }
        if (platformRequirement(dependencyRequirement.name)) {
          continue;
        }
        const child = resolveName(dependencyRequirement.name);
        if (child === undefined) {
          context.addIssue(
            "DEPENDENCY_UNRESOLVED",
            `Composer dependency ${dependencyRequirement.name} required by ${item.node.name} is absent or ambiguous`,
          );
          output.set(dependencyRequirement.name, {
            name: dependencyRequirement.name,
            ...baseDependency(
              input,
              item.root,
              environment,
              "composer.lock",
              "unresolved",
            ),
            requestedVersion: dependencyRequirement.constraint,
            installedVersion: "",
            resolutionStatus: "unresolved",
            dependencyType: "transitive",
            parent: `${item.node.name}@${item.node.version}`,
            dependencyPath: [...item.path, dependencyRequirement.name],
          });
          continue;
        }
        if (
          !lockedPackageSatisfiesRequirement(
            dependencyRequirement.name,
            dependencyRequirement.constraint,
            child,
          )
        ) {
          context.addIssue(
            "DEPENDENCY_UNRESOLVED",
            `Composer lock selection for ${dependencyRequirement.name} does not satisfy ${item.node.name}'s constraint`,
          );
          output.set(child.name, {
            name: child.name,
            ...baseDependency(
              input,
              item.root,
              environment,
              "composer.lock",
              "unresolved",
            ),
            requestedVersion: dependencyRequirement.constraint,
            installedVersion: "",
            resolutionStatus: "unresolved",
            dependencyType: "transitive",
            parent: `${item.node.name}@${item.node.version}`,
            dependencyPath: [...item.path, child.name],
          });
          continue;
        }
        queue.push({
          node: child,
          root: item.root,
          path: [...item.path, `${child.name}@${child.version}`],
          depth: item.depth + 1,
          direct: false,
        });
      }
    }
    const missingNames = new Set(missing.map((requirement) => requirement.name));
    const orphans = packages.filter(
      (entry) => !output.has(entry.name) && !missingNames.has(entry.name),
    );
    if (orphans.length > 0) {
      context.addIssue(
        "DEPENDENCY_UNRESOLVED",
        `${orphans.length.toString()} composer.lock package(s) are unreachable from reconciled root requirements`,
      );
    }
    for (const orphan of orphans) {
      output.set(orphan.name, {
        name: orphan.name,
        ecosystem: "Packagist",
        manifestName: orphan.name,
        installedVersion: "",
        resolutionStatus: "unresolved",
        dependencyType: "transitive",
        environment: orphan.environment,
        manifestPath: input.manifestPath,
        ...(input.lockfilePath === undefined
          ? {}
          : { lockfilePath: input.lockfilePath }),
        packageManager: "composer",
        ...(input.projectPath === undefined
          ? {}
          : { projectPath: input.projectPath }),
        ...(input.workspacePath === undefined
          ? {}
          : { workspacePath: input.workspacePath }),
        metadata: {
          manifestSection: "composer.lock",
          composerSource: "unreachable-lock-package",
          lockedVersion: orphan.version,
        },
      });
    }
    return {
      dependencies: [
        ...output.values(),
        ...missing.map((requirement) => unresolvedRequirement(input, requirement)),
      ].sort((left, right) => left.name.localeCompare(right.name)),
      issues: context.issues,
      truncated: context.truncated,
      cancelled: false,
    };
  } catch (error: unknown) {
    if (error instanceof DOMException && error.name === "AbortError") {
      return {
        dependencies: [],
        issues: context.issues,
        truncated: context.truncated,
        cancelled: true,
      };
    }
    context.addIssue("INVALID_LOCKFILE", "Composer dependency parsing failed");
    return {
      dependencies: [],
      issues: context.issues,
      truncated: context.truncated,
      cancelled: false,
    };
  }
}
