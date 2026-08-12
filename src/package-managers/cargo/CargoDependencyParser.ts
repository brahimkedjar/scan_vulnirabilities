import type {
  Dependency,
  DependencyEnvironment,
} from "../../models/Dependency";
import { satisfies as satisfiesSemver, valid as validSemver } from "semver";

type UnknownRecord = Record<string, unknown>;

interface SmolTomlModule {
  readonly parse: (text: string) => unknown;
}

// A literal CommonJS require selects smol-toml's CJS export and lets esbuild
// include the parser in the dependency-free VSIX bundle.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const smolToml = require("smol-toml") as SmolTomlModule;

export interface CargoParseIssue {
  readonly code: string;
  readonly message: string;
}

export interface CargoParserLimits {
  readonly maxPackages: number;
  readonly maxEdges: number;
  readonly maxDepth: number;
  readonly maxIssues: number;
}

export interface CargoParserInput {
  readonly cargoToml: string;
  readonly manifestPath: string;
  readonly cargoLock?: string;
  readonly lockfilePath?: string;
  readonly workspaceToml?: string;
  readonly workspaceManifestPath?: string;
  readonly projectPath?: string;
  readonly workspacePath?: string;
  readonly signal?: AbortSignal;
  readonly limits?: Partial<CargoParserLimits>;
}

export interface CargoParseResult {
  readonly dependencies: readonly Dependency[];
  readonly issues: readonly CargoParseIssue[];
  readonly truncated: boolean;
  readonly cancelled: boolean;
}

export const DEFAULT_CARGO_PARSER_LIMITS: CargoParserLimits = {
  maxPackages: 10_000,
  maxEdges: 250_000,
  maxDepth: 512,
  maxIssues: 1_000,
};

interface CargoDeclaration {
  readonly manifestName: string;
  readonly name: string;
  readonly requestedVersion?: string;
  readonly environment: DependencyEnvironment;
  readonly section: string;
  readonly source: "registry" | "custom" | "git" | "path" | "unresolved";
}

interface CargoLockNode {
  readonly id: string;
  readonly name: string;
  readonly version: string;
  readonly source?: string;
  readonly dependencies: readonly string[];
}

interface QueueItem {
  readonly node: CargoLockNode;
  readonly declaration?: CargoDeclaration;
  readonly environment: DependencyEnvironment;
  readonly path: readonly string[];
  readonly depth: number;
  readonly direct: boolean;
}

class CargoParseContext {
  public readonly issues: CargoParseIssue[] = [];
  public truncated = false;
  public edges = 0;

  public constructor(
    public readonly limits: CargoParserLimits,
    private readonly signal: AbortSignal | undefined,
  ) {}

  public checkCancellation(): void {
    if (this.signal?.aborted === true) {
      throw new DOMException("Cargo parsing cancelled", "AbortError");
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
        "Cargo dependency graph exceeded its edge safety limit",
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
  supplied: Partial<CargoParserLimits> | undefined,
): CargoParserLimits {
  return {
    maxPackages: positiveLimit(
      supplied?.maxPackages,
      DEFAULT_CARGO_PARSER_LIMITS.maxPackages,
    ),
    maxEdges: positiveLimit(
      supplied?.maxEdges,
      DEFAULT_CARGO_PARSER_LIMITS.maxEdges,
    ),
    maxDepth: positiveLimit(
      supplied?.maxDepth,
      DEFAULT_CARGO_PARSER_LIMITS.maxDepth,
    ),
    maxIssues: positiveLimit(
      supplied?.maxIssues,
      DEFAULT_CARGO_PARSER_LIMITS.maxIssues,
    ),
  };
}

function safeName(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 128 &&
    /^[A-Za-z0-9][A-Za-z0-9_-]*$/u.test(value)
  );
}

function safeVersion(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 256 &&
    !/[\u0000-\u001F\u007F]/u.test(value)
  );
}

function safeLockedVersion(value: unknown): value is string {
  return safeVersion(value) && validSemver(value) === value;
}

function safeSource(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 4_096 &&
    !/[\u0000-\u001F\u007F]/u.test(value)
  );
}

function parseTomlDocument(
  text: string,
  label: string,
  context: CargoParseContext,
): UnknownRecord | undefined {
  try {
    const parsed: unknown = smolToml.parse(text);
    if (!isRecord(parsed)) {
      context.addIssue("INVALID_MANIFEST", `${label} must contain a TOML table`);
      return undefined;
    }
    return parsed;
  } catch (_error: unknown) {
    context.addIssue("INVALID_MANIFEST", `${label} is not valid TOML`);
    return undefined;
  }
}

function dependencySpec(
  manifestName: string,
  rawSpec: unknown,
  environment: DependencyEnvironment,
  section: string,
  workspaceDependencies: UnknownRecord | undefined,
  context: CargoParseContext,
): CargoDeclaration | undefined {
  let spec = rawSpec;
  if (isRecord(rawSpec) && rawSpec.workspace === true) {
    const inherited = workspaceDependencies?.[manifestName];
    if (inherited === undefined) {
      context.addIssue(
        "DEPENDENCY_UNRESOLVED",
        `Cargo workspace dependency ${manifestName} has no inherited declaration`,
      );
      return {
        manifestName,
        name: manifestName,
        environment,
        section,
        source: "unresolved",
      };
    }
    if (isRecord(inherited)) {
      spec = { ...inherited, ...rawSpec, workspace: undefined };
    } else {
      spec = inherited;
    }
  }

  if (typeof spec === "string") {
    return {
      manifestName,
      name: manifestName,
      requestedVersion: spec,
      environment,
      section,
      source: "registry",
    };
  }
  if (!isRecord(spec)) {
    context.addIssue(
      "DEPENDENCY_UNRESOLVED",
      `Cargo dependency ${manifestName} has an unsupported declaration`,
    );
    return undefined;
  }

  const canonicalName = safeName(spec.package) ? spec.package : manifestName;
  const optional = spec.optional === true;
  const effectiveEnvironment = optional ? "optional" : environment;
  const requestedVersion = safeVersion(spec.version) ? spec.version : undefined;
  let source: CargoDeclaration["source"] = "registry";
  if (typeof spec.path === "string") {
    source = "path";
  } else if (typeof spec.git === "string") {
    source = "git";
  } else if (typeof spec.registry === "string") {
    source = "custom";
  } else if (requestedVersion === undefined) {
    source = "unresolved";
  }

  return {
    manifestName,
    name: canonicalName,
    ...(requestedVersion === undefined ? {} : { requestedVersion }),
    environment: effectiveEnvironment,
    section,
    source,
  };
}

function collectTableDeclarations(
  table: unknown,
  environment: DependencyEnvironment,
  section: string,
  workspaceDependencies: UnknownRecord | undefined,
  context: CargoParseContext,
  output: CargoDeclaration[],
): void {
  if (table === undefined) {
    return;
  }
  if (!isRecord(table)) {
    context.addIssue(
      "INVALID_MANIFEST",
      `Cargo manifest section ${section} must be a table`,
    );
    return;
  }
  for (const [manifestName, rawSpec] of Object.entries(table).sort(
    ([left], [right]) => left.localeCompare(right),
  )) {
    context.checkCancellation();
    if (!safeName(manifestName)) {
      context.addIssue(
        "DEPENDENCY_UNRESOLVED",
        "Cargo manifest contains an invalid dependency name",
      );
      continue;
    }
    const declaration = dependencySpec(
      manifestName,
      rawSpec,
      environment,
      section,
      workspaceDependencies,
      context,
    );
    if (declaration !== undefined) {
      output.push(declaration);
    }
  }
}

function collectDeclarations(
  manifest: UnknownRecord,
  workspaceManifest: UnknownRecord | undefined,
  context: CargoParseContext,
): readonly CargoDeclaration[] {
  const workspace = isRecord(workspaceManifest?.workspace)
    ? workspaceManifest.workspace
    : isRecord(manifest.workspace)
      ? manifest.workspace
      : undefined;
  const workspaceDependencies = isRecord(workspace?.dependencies)
    ? workspace.dependencies
    : undefined;
  const output: CargoDeclaration[] = [];
  collectTableDeclarations(
    manifest.dependencies,
    "production",
    "dependencies",
    workspaceDependencies,
    context,
    output,
  );
  collectTableDeclarations(
    manifest["build-dependencies"],
    "production",
    "build-dependencies",
    workspaceDependencies,
    context,
    output,
  );
  collectTableDeclarations(
    manifest["dev-dependencies"],
    "development",
    "dev-dependencies",
    workspaceDependencies,
    context,
    output,
  );

  if (isRecord(manifest.target)) {
    for (const [target, targetTable] of Object.entries(manifest.target)) {
      if (!isRecord(targetTable)) {
        continue;
      }
      collectTableDeclarations(
        targetTable.dependencies,
        "production",
        `target.${target}.dependencies`,
        workspaceDependencies,
        context,
        output,
      );
      collectTableDeclarations(
        targetTable["build-dependencies"],
        "production",
        `target.${target}.build-dependencies`,
        workspaceDependencies,
        context,
        output,
      );
      collectTableDeclarations(
        targetTable["dev-dependencies"],
        "development",
        `target.${target}.dev-dependencies`,
        workspaceDependencies,
        context,
        output,
      );
    }
  }

  return output;
}

function lockNodeId(name: string, version: string, source?: string): string {
  return `${name}\u0000${version}\u0000${source ?? ""}`;
}

function parseLockNodes(
  lock: UnknownRecord,
  context: CargoParseContext,
): readonly CargoLockNode[] | undefined {
  const formatVersion = lock.version;
  if (
    formatVersion !== undefined &&
    (!Number.isSafeInteger(formatVersion) || Number(formatVersion) < 1 || Number(formatVersion) > 4)
  ) {
    context.addIssue(
      "UNSUPPORTED_LOCKFILE",
      "Cargo.lock uses an unsupported lockfile format version",
    );
    return undefined;
  }
  if (!Array.isArray(lock.package)) {
    context.addIssue("INVALID_LOCKFILE", "Cargo.lock has no package array");
    return undefined;
  }
  if (lock.package.length > context.limits.maxPackages) {
    context.truncated = true;
    context.addIssue(
      "DEPENDENCY_LIMIT",
      "Cargo.lock exceeded its package safety limit",
    );
  }

  const output: CargoLockNode[] = [];
  for (const rawNode of lock.package.slice(0, context.limits.maxPackages)) {
    context.checkCancellation();
    if (
      !isRecord(rawNode) ||
      !safeName(rawNode.name) ||
      !safeLockedVersion(rawNode.version)
    ) {
      context.addIssue(
        "INVALID_LOCKFILE",
        "Cargo.lock contains a package with an invalid identity or version",
      );
      continue;
    }
    const source = safeSource(rawNode.source) ? rawNode.source : undefined;
    const dependencies: string[] = [];
    if (rawNode.dependencies !== undefined) {
      if (!Array.isArray(rawNode.dependencies)) {
        context.addIssue(
          "INVALID_LOCKFILE",
          `Cargo.lock dependency list for ${rawNode.name} is malformed`,
        );
      } else {
        for (const dependency of rawNode.dependencies) {
          if (safeSource(dependency)) {
            dependencies.push(dependency);
          } else {
            context.addIssue(
              "INVALID_LOCKFILE",
              `Cargo.lock contains an invalid dependency edge for ${rawNode.name}`,
            );
          }
        }
      }
    }
    output.push({
      id: lockNodeId(rawNode.name, rawNode.version, source),
      name: rawNode.name,
      version: rawNode.version,
      ...(source === undefined ? {} : { source }),
      dependencies,
    });
  }
  return output;
}

function cratesIoSource(source: string | undefined): boolean {
  return (
    source === "registry+https://github.com/rust-lang/crates.io-index" ||
    source === "registry+https://index.crates.io/" ||
    source === "sparse+https://index.crates.io/"
  );
}

function edgeParts(edge: string): {
  readonly name: string;
  readonly version?: string;
  readonly source?: string;
} | undefined {
  const match = /^(\S+)(?:\s+(\S+))?(?:\s+\((.+)\))?$/u.exec(edge);
  if (
    match === null ||
    !safeName(match[1]) ||
    (match[2] !== undefined && !safeLockedVersion(match[2]))
  ) {
    return undefined;
  }
  const version = match[2];
  const source = match[3];
  return {
    name: match[1],
    ...(safeLockedVersion(version) ? { version } : {}),
    ...(safeSource(source) ? { source } : {}),
  };
}

function resolveEdge(
  edge: string,
  nodes: readonly CargoLockNode[],
  context: CargoParseContext,
): CargoLockNode | undefined {
  const parts = edgeParts(edge);
  if (parts === undefined) {
    context.addIssue("INVALID_LOCKFILE", "Cargo.lock contains an invalid edge");
    return undefined;
  }
  const candidates = nodes.filter(
    (node) =>
      node.name === parts.name &&
      (parts.version === undefined || node.version === parts.version) &&
      (parts.source === undefined || node.source === parts.source),
  );
  if (candidates.length !== 1) {
    context.addIssue(
      "DEPENDENCY_UNRESOLVED",
      `Cargo lock edge ${edge.slice(0, 200)} is ${candidates.length === 0 ? "missing" : "ambiguous"}`,
    );
    return undefined;
  }
  return candidates[0];
}

function environmentRank(environment: DependencyEnvironment): number {
  switch (environment) {
    case "production":
      return 3;
    case "optional":
      return 2;
    case "development":
      return 1;
    case "peer":
      return 0;
  }
}

function manifestPackageIdentity(
  manifest: UnknownRecord,
  workspaceManifest: UnknownRecord | undefined,
): { readonly name?: string; readonly version?: string } {
  const packageTable = isRecord(manifest.package) ? manifest.package : undefined;
  const workspace = isRecord(workspaceManifest?.workspace)
    ? workspaceManifest.workspace
    : isRecord(manifest.workspace)
      ? manifest.workspace
      : undefined;
  const workspacePackage = isRecord(workspace?.package)
    ? workspace.package
    : undefined;
  const name = safeName(packageTable?.name) ? packageTable.name : undefined;
  let version = safeVersion(packageTable?.version)
    ? packageTable.version
    : undefined;
  if (
    version === undefined &&
    isRecord(packageTable?.version) &&
    packageTable.version.workspace === true &&
    safeVersion(workspacePackage?.version)
  ) {
    version = workspacePackage.version;
  }
  return {
    ...(name === undefined ? {} : { name }),
    ...(version === undefined ? {} : { version }),
  };
}

function dependencyBase(
  input: CargoParserInput,
  declaration: CargoDeclaration,
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
    ecosystem: "crates.io",
    manifestName: declaration.manifestName,
    ...(declaration.requestedVersion === undefined
      ? {}
      : { requestedVersion: declaration.requestedVersion }),
    environment: declaration.environment,
    declaredEnvironment: declaration.environment,
    manifestPath: input.manifestPath,
    ...(input.lockfilePath === undefined
      ? {}
      : { lockfilePath: input.lockfilePath }),
    packageManager: "cargo",
    ...(input.projectPath === undefined
      ? {}
      : { projectPath: input.projectPath }),
    ...(input.workspacePath === undefined
      ? {}
      : { workspacePath: input.workspacePath }),
    metadata: {
      manifestSection: declaration.section,
      cargoSource: declaration.source,
    },
  };
}

function unresolvedDependency(
  input: CargoParserInput,
  declaration: CargoDeclaration,
  unsupported: boolean,
): Dependency {
  return {
    name: declaration.name,
    ...dependencyBase(input, declaration),
    installedVersion: "",
    resolutionStatus: unsupported ? "unsupported" : "unresolved",
    dependencyType: "direct",
    dependencyPath: [declaration.name],
  };
}

function cargoRequirementSatisfied(
  requested: string | undefined,
  selected: string,
): boolean {
  if (requested === undefined) {
    return false;
  }
  const trimmed = requested.trim();
  if (trimmed.length === 0 || trimmed.length > 256) {
    return false;
  }
  const bare = /^\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u.test(
    trimmed,
  );
  const normalized = (bare ? `^${trimmed}` : trimmed).replace(
    /\s*,\s*/gu,
    " ",
  );
  try {
    return satisfiesSemver(selected, normalized, { includePrerelease: true });
  } catch {
    return false;
  }
}

export function parseCargoDependencies(
  input: CargoParserInput,
): CargoParseResult {
  const context = new CargoParseContext(
    parserLimits(input.limits),
    input.signal,
  );
  try {
    context.checkCancellation();
    const manifest = parseTomlDocument(input.cargoToml, "Cargo.toml", context);
    if (manifest === undefined) {
      return {
        dependencies: [],
        issues: context.issues,
        truncated: context.truncated,
        cancelled: false,
      };
    }
    const workspaceManifest =
      input.workspaceToml === undefined
        ? undefined
        : parseTomlDocument(input.workspaceToml, "workspace Cargo.toml", context);
    const declarations = collectDeclarations(
      manifest,
      workspaceManifest,
      context,
    );
    const unresolved = declarations
      .filter((declaration) => declaration.source !== "registry")
      .map((declaration) =>
        unresolvedDependency(
          input,
          declaration,
          declaration.source !== "unresolved",
        ),
      );

    if (input.cargoLock === undefined) {
      context.addIssue(
        "NO_LOCKFILE",
        "Cargo.toml has no Cargo.lock; requested ranges are not resolved versions",
      );
      return {
        dependencies: [
          ...unresolved,
          ...declarations
            .filter((declaration) => declaration.source === "registry")
            .map((declaration) => unresolvedDependency(input, declaration, false)),
        ],
        issues: context.issues,
        truncated: context.truncated,
        cancelled: false,
      };
    }

    const lock = parseTomlDocument(input.cargoLock, "Cargo.lock", context);
    const nodes = lock === undefined ? undefined : parseLockNodes(lock, context);
    if (nodes === undefined) {
      return {
        dependencies: [
          ...unresolved,
          ...declarations
            .filter((declaration) => declaration.source === "registry")
            .map((declaration) => unresolvedDependency(input, declaration, false)),
        ],
        issues: context.issues,
        truncated: context.truncated,
        cancelled: false,
      };
    }

    const packageIdentity = manifestPackageIdentity(manifest, workspaceManifest);
    const rootCandidates = nodes.filter(
      (node) =>
        node.source === undefined &&
        (packageIdentity.name === undefined || node.name === packageIdentity.name) &&
        (packageIdentity.version === undefined || node.version === packageIdentity.version),
    );
    const rootNode = rootCandidates.length === 1 ? rootCandidates[0] : undefined;
    const rootEdges = rootNode?.dependencies ?? [];
    const queue: QueueItem[] = [];
    const resolvedDeclarations = new Set<CargoDeclaration>();

    for (const declaration of declarations.filter(
      (candidate) => candidate.source === "registry",
    )) {
      context.checkCancellation();
      const matchingRootEdges = rootEdges
        .map((edge) => ({ edge, parts: edgeParts(edge) }))
        .filter(({ parts }) => parts?.name === declaration.name);
      let node: CargoLockNode | undefined;
      if (matchingRootEdges.length === 1) {
        node = resolveEdge(matchingRootEdges[0]?.edge ?? "", nodes, context);
      }
      if (node === undefined) {
        context.addIssue(
          "DEPENDENCY_UNRESOLVED",
          `Cargo dependency ${declaration.name} could not be matched to one resolved lock entry`,
        );
        continue;
      }
      if (!cargoRequirementSatisfied(declaration.requestedVersion, node.version)) {
        context.addIssue(
          "DEPENDENCY_UNRESOLVED",
          `Cargo lock selection ${node.name}@${node.version} does not satisfy the manifest requirement`,
        );
        continue;
      }
      resolvedDeclarations.add(declaration);
      queue.push({
        node,
        declaration,
        environment: declaration.environment,
        path: [
          packageIdentity.name ?? "workspace",
          `${node.name}@${node.version}`,
        ],
        depth: 1,
        direct: true,
      });
    }

    // Local, git, and custom-registry roots are not valid crates.io query
    // subjects, but their lock nodes can still introduce crates.io children.
    for (const declaration of declarations.filter(
      (candidate) =>
        candidate.source !== "registry" && candidate.source !== "unresolved",
    )) {
      const matchingEdges = rootEdges
        .map((edge) => ({ edge, parts: edgeParts(edge) }))
        .filter(({ parts }) => parts?.name === declaration.name);
      const node =
        matchingEdges.length === 1
          ? resolveEdge(matchingEdges[0]?.edge ?? "", nodes, context)
          : undefined;
      if (node !== undefined) {
        queue.push({
          node,
          declaration,
          environment: declaration.environment,
          path: [
            packageIdentity.name ?? "workspace",
            `${node.name}@${node.version}`,
          ],
          depth: 1,
          direct: true,
        });
      }
    }

    const outputByNode = new Map<string, Dependency>();
    const visited = new Map<string, number>();
    let queueIndex = 0;
    while (queueIndex < queue.length) {
      context.checkCancellation();
      const item = queue[queueIndex];
      queueIndex += 1;
      if (item === undefined) {
        continue;
      }
      if (item.depth > context.limits.maxDepth) {
        context.truncated = true;
        context.addIssue(
          "DEPENDENCY_LIMIT",
          "Cargo dependency traversal exceeded its depth safety limit",
        );
        continue;
      }
      const visitKey = `${item.node.id}\u0000${item.environment}`;
      const previousDepth = visited.get(visitKey);
      if (previousDepth !== undefined && previousDepth <= item.depth) {
        continue;
      }
      visited.set(visitKey, item.depth);

      if (cratesIoSource(item.node.source)) {
        const declaration = item.declaration ?? {
          manifestName: item.node.name,
          name: item.node.name,
          environment: item.environment,
          section: "Cargo.lock",
          source: "registry" as const,
        };
        const dependency: Dependency = {
          name: item.node.name,
          ...dependencyBase(input, declaration),
          installedVersion: item.node.version,
          resolutionStatus: "resolved",
          dependencyType: item.direct ? "direct" : "transitive",
          ...(item.direct || item.path.length < 3
            ? {}
            : { parent: item.path[item.path.length - 2] }),
          dependencyPath: [...item.path],
        };
        const previous = outputByNode.get(item.node.id);
        if (
          previous === undefined ||
          (item.direct && previous.dependencyType === "transitive") ||
          environmentRank(item.environment) > environmentRank(previous.environment)
        ) {
          outputByNode.set(item.node.id, dependency);
        }
      } else {
        context.addIssue(
          "UNSUPPORTED_PACKAGE_SOURCE",
          item.node.source === undefined
            ? `Skipped local or patched Cargo package ${item.node.name}`
            : `Skipped non-crates.io Cargo package ${item.node.name}`,
        );
        if (item.declaration === undefined || item.declaration.source === "registry") {
          const declaration = item.declaration ?? {
            manifestName: item.node.name,
            name: item.node.name,
            environment: item.environment,
            section: "Cargo.lock",
            source: "path" as const,
          };
          outputByNode.set(item.node.id, {
            name: item.node.name,
            ...dependencyBase(input, declaration),
            installedVersion: "",
            resolutionStatus: "unsupported",
            dependencyType: item.direct ? "direct" : "transitive",
            ...(item.direct || item.path.length < 3
              ? {}
              : { parent: item.path[item.path.length - 2] }),
            dependencyPath: [...item.path],
          });
        }
      }

      for (const edge of item.node.dependencies) {
        if (!context.consumeEdge()) {
          break;
        }
        const child = resolveEdge(edge, nodes, context);
        if (child !== undefined) {
          queue.push({
            node: child,
            environment: item.environment,
            path: [...item.path, `${child.name}@${child.version}`],
            depth: item.depth + 1,
            direct: false,
          });
        }
      }
    }

    const missing = declarations
      .filter(
        (declaration) =>
          declaration.source === "registry" &&
          !resolvedDeclarations.has(declaration),
      )
      .map((declaration) => unresolvedDependency(input, declaration, false));
    return {
      dependencies: [
        ...outputByNode.values(),
        ...unresolved,
        ...missing,
      ].sort((left, right) =>
        `${left.name}\u0000${left.installedVersion}`.localeCompare(
          `${right.name}\u0000${right.installedVersion}`,
        ),
      ),
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
    context.addIssue("INVALID_LOCKFILE", "Cargo dependency parsing failed");
    return {
      dependencies: [],
      issues: context.issues,
      truncated: context.truncated,
      cancelled: false,
    };
  }
}
