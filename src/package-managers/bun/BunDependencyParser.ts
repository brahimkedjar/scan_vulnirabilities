import {
  getNodeValue,
  parseTree,
  type Node as JsonNode,
  type ParseError,
} from "jsonc-parser";
import semver from "semver";

import type { Dependency, DependencyEnvironment } from "../../models/Dependency";
import type { ScanOptions } from "../PackageManagerAdapter";
import {
  isRecord,
  isSafeRelativePath,
  MAX_DEPTH,
  MAX_EDGES,
  MAX_ISSUES,
  MAX_PACKAGES,
  parseManifestDependencyEdges,
  safeString,
  type JavaScriptParseIssue,
  type JavaScriptParseResult,
  type ManifestInput,
} from "../yarn/JavaScriptParserTypes";

const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/[a-z0-9][a-z0-9._~-]*|[a-z0-9][a-z0-9._~-]*)$/iu;
const REGISTRY_TAG = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/u;
const MAX_JSON_NODES = 1_000_000;

export interface BunDependencyParserInput {
  readonly lockfile: string;
  readonly lockfilePath: string;
  readonly projectPath: string;
  readonly workspacePath: string;
  readonly manifests: readonly ManifestInput[];
  readonly options: ScanOptions;
  readonly signal?: AbortSignal;
}

interface BunEdge {
  readonly name: string;
  readonly range: string;
  readonly optional: boolean;
}

interface BunNode {
  readonly key: string;
  readonly name: string;
  readonly version: string;
  readonly supported: boolean;
  readonly source: string;
  readonly edges: readonly BunEdge[];
}

interface DirectEdge {
  readonly name: string;
  readonly range: string;
  readonly environment: DependencyEnvironment;
}

interface QueueEntry {
  readonly workspace: string;
  readonly manifestPath: string;
  readonly rootLabel: string;
  readonly node: BunNode;
  readonly requestedVersion: string;
  readonly manifestName?: string;
  readonly environment: DependencyEnvironment;
  readonly declaredEnvironment?: DependencyEnvironment;
  readonly direct: boolean;
  readonly parent?: string;
  readonly path: readonly string[];
  readonly depth: number;
}

class ParserContext {
  public readonly issues: JavaScriptParseIssue[] = [];
  public truncated = false;
  public edges = 0;

  public constructor(public readonly signal?: AbortSignal) {}

  public check(): void {
    if (this.signal?.aborted === true) {
      throw new DOMException("Bun dependency parsing cancelled", "AbortError");
    }
  }

  public issue(issue: JavaScriptParseIssue): void {
    if (this.issues.length < MAX_ISSUES) {
      this.issues.push(issue);
    } else {
      this.truncated = true;
    }
  }
}

function reportDependencyLimit(context: ParserContext): void {
  if (
    !context.issues.some((issue) =>
      issue.message.includes("Bun dependency output exceeds"),
    )
  ) {
    context.issue({
      code: "DEPENDENCY_LIMIT",
      message: `Bun dependency output exceeds the ${MAX_PACKAGES.toString()}-dependency limit`,
    });
  }
  context.truncated = true;
}

function storeDependency(
  dependencies: Map<string, Dependency>,
  key: string,
  dependency: Dependency,
  context: ParserContext,
): boolean {
  if (!dependencies.has(key) && dependencies.size >= MAX_PACKAGES) {
    reportDependencyLimit(context);
    return false;
  }
  dependencies.set(key, dependency);
  return true;
}

function validateJsonTree(root: JsonNode, context: ParserContext): boolean {
  const queue: { node: JsonNode; depth: number }[] = [{ node: root, depth: 0 }];
  let visited = 0;
  for (let index = 0; index < queue.length; index += 1) {
    context.check();
    const entry = queue[index];
    if (entry === undefined) {
      continue;
    }
    visited += 1;
    if (visited > MAX_JSON_NODES || entry.depth > MAX_DEPTH) {
      context.truncated = true;
      context.issue({
        code: "DEPENDENCY_LIMIT",
        message: "bun.lock JSON structure exceeds its complexity limit",
      });
      return false;
    }
    if (entry.node.type === "object") {
      const keys = new Set<string>();
      for (const property of entry.node.children ?? []) {
        const keyNode = property.children?.[0];
        const key = keyNode?.value;
        if (typeof key !== "string" || keys.has(key)) {
          context.issue({
            code: "INVALID_LOCKFILE",
            message: "bun.lock contains a duplicate or invalid object key",
          });
          return false;
        }
        keys.add(key);
      }
    }
    for (const child of entry.node.children ?? []) {
      queue.push({ node: child, depth: entry.depth + 1 });
    }
  }
  return true;
}

function parseResolution(value: string): { name: string; reference: string } | undefined {
  const separator = value.startsWith("@")
    ? value.indexOf("@", value.indexOf("/") + 1)
    : value.indexOf("@");
  if (separator <= 0) {
    return undefined;
  }
  const name = value.slice(0, separator);
  const reference = value.slice(separator + 1);
  return PACKAGE_NAME.test(name) && reference.length > 0
    ? { name, reference }
    : undefined;
}

function aliasTarget(range: string): string | undefined {
  if (!range.startsWith("npm:")) {
    return undefined;
  }
  const parsed = parseResolution(range.slice(4));
  return parsed?.name;
}

function stringMap(value: unknown, context: ParserContext): Record<string, string> {
  const result: Record<string, string> = Object.create(null) as Record<string, string>;
  if (value === undefined) {
    return result;
  }
  if (!isRecord(value)) {
    context.issue({
      code: "INVALID_LOCKFILE",
      message: "Ignored a malformed Bun dependency map",
    });
    return result;
  }
  for (const [name, rawRange] of Object.entries(value)) {
    const range = safeString(rawRange);
    if (PACKAGE_NAME.test(name) && range !== undefined) {
      result[name] = range;
    } else {
      context.issue({
        code: "INVALID_LOCKFILE",
        message: "Ignored a malformed Bun dependency edge",
      });
    }
  }
  return result;
}

function packageMetadata(entry: readonly unknown[]): Record<string, unknown> {
  for (const value of entry.slice(1, 4)) {
    if (isRecord(value)) {
      return value;
    }
  }
  return Object.create(null) as Record<string, unknown>;
}

function packageSource(entry: readonly unknown[], reference: string): string {
  const second = entry[1];
  if (typeof second === "string" && second.length > 0) {
    return second;
  }
  return reference;
}

function supportedSource(source: string, version: string): boolean {
  if (version.length === 0) {
    return false;
  }
  if (/^\d+\.\d+\.\d+/u.test(source)) {
    return true;
  }
  if (source.length === 0) {
    return true;
  }
  return /^https?:\/\/(?:registry\.npmjs\.org|registry\.yarnpkg\.com)\//iu.test(source);
}

function buildNodes(
  document: Record<string, unknown>,
  context: ParserContext,
): { nodes: readonly BunNode[]; byKey: ReadonlyMap<string, BunNode> } {
  if (!isRecord(document.packages)) {
    context.issue({
      code: "INVALID_LOCKFILE",
      message: "bun.lock does not contain a packages object",
    });
    return { nodes: [], byKey: new Map() };
  }
  const nodes: BunNode[] = [];
  const byKey = new Map<string, BunNode>();
  for (const [key, rawEntry] of Object.entries(document.packages)) {
    context.check();
    if (nodes.length >= MAX_PACKAGES) {
      context.truncated = true;
      context.issue({
        code: "DEPENDENCY_LIMIT",
        message: `bun.lock exceeds the ${MAX_PACKAGES.toString()}-package limit`,
      });
      break;
    }
    if (
      key.length === 0 ||
      key.length > 8_192 ||
      key.startsWith("/") ||
      key.includes("\\") ||
      key.split("/").includes("..") ||
      !Array.isArray(rawEntry) ||
      rawEntry.length === 0 ||
      rawEntry.length > 5
    ) {
      context.issue({
        code: "INVALID_LOCKFILE",
        message: "Ignored a malformed Bun package entry",
      });
      continue;
    }
    const resolution = safeString(rawEntry[0]);
    const parsed = resolution === undefined ? undefined : parseResolution(resolution);
    if (parsed === undefined) {
      context.issue({
        code: "INVALID_LOCKFILE",
        message: "Ignored a Bun package entry with an invalid identity",
      });
      continue;
    }
    const normalizedVersion = semver.valid(parsed.reference) ?? "";
    const metadata = packageMetadata(rawEntry);
    const dependencies = stringMap(metadata.dependencies, context);
    const optionalDependencies = stringMap(metadata.optionalDependencies, context);
    const edges: BunEdge[] = Object.entries(dependencies).map(([name, range]) => ({
      name,
      range,
      optional: false,
    }));
    for (const [name, range] of Object.entries(optionalDependencies)) {
      if (!edges.some((edge) => edge.name === name)) {
        edges.push({ name, range, optional: true });
      }
    }
    const source = packageSource(rawEntry, parsed.reference);
    const node: BunNode = {
      key,
      name: parsed.name,
      version: normalizedVersion,
      supported: supportedSource(source, normalizedVersion),
      source,
      edges,
    };
    nodes.push(node);
    byKey.set(key, node);
  }
  return { nodes, byKey };
}

function environmentRank(environment: DependencyEnvironment): number {
  switch (environment) {
    case "production":
      return 4;
    case "optional":
      return 3;
    case "peer":
      return 2;
    case "development":
      return 1;
  }
}

function directEdges(
  workspace: Record<string, unknown>,
  includeDev: boolean,
  context: ParserContext,
): readonly DirectEdge[] {
  const result = new Map<string, DirectEdge>();
  const add = (field: string, environment: DependencyEnvironment): void => {
    const values = stringMap(workspace[field], context);
    for (const [name, range] of Object.entries(values)) {
      const existing = result.get(name);
      if (existing === undefined || environmentRank(environment) >= environmentRank(existing.environment)) {
        result.set(name, { name, range, environment });
      }
    }
  };
  add("dependencies", "production");
  add("peerDependencies", "peer");
  add("optionalDependencies", "optional");
  if (includeDev) {
    add("devDependencies", "development");
  }
  return [...result.values()];
}

function unsupportedRange(range: string): boolean {
  return /^(?:workspace:|file:|link:|portal:|git(?:\+|:)|https?:)/iu.test(range);
}

function ancestorKeys(key: string, byKey: ReadonlyMap<string, BunNode>): readonly string[] {
  const result: string[] = [];
  let prefix = key;
  while (prefix.includes("/")) {
    prefix = prefix.slice(0, prefix.lastIndexOf("/"));
    if (byKey.has(prefix)) {
      result.push(prefix);
    }
  }
  return result;
}

function lookupNode(
  graph: { nodes: readonly BunNode[]; byKey: ReadonlyMap<string, BunNode> },
  name: string,
  range: string,
  parentKey?: string,
): BunNode | undefined {
  if (unsupportedRange(range)) {
    return undefined;
  }
  const targetName = aliasTarget(range) ?? name;
  const rangeOnly = range.startsWith("npm:")
    ? range.slice(4 + targetName.length + 1)
    : range;
  const validRange = semver.validRange(rangeOnly);
  if (validRange === null && !REGISTRY_TAG.test(rangeOnly)) {
    return undefined;
  }
  const candidates: string[] = [];
  if (parentKey !== undefined) {
    candidates.push(`${parentKey}/${name}`);
    for (const ancestor of ancestorKeys(parentKey, graph.byKey)) {
      candidates.push(`${ancestor}/${name}`);
    }
  }
  candidates.push(name);
  for (const candidate of candidates) {
    const node = graph.byKey.get(candidate);
    if (
      node !== undefined &&
      node.name === targetName &&
      node.version.length > 0 &&
      (validRange === null || semver.satisfies(node.version, validRange))
    ) {
      return node;
    }
  }
  if (validRange === null) {
    return undefined;
  }
  const matches = graph.nodes.filter(
    (node) =>
      node.name === targetName &&
      node.version.length > 0 &&
      semver.satisfies(node.version, validRange),
  );
  return matches.length === 1 ? matches[0] : undefined;
}

function dependencyFromEntry(
  entry: QueueEntry,
  input: BunDependencyParserInput,
): Dependency {
  return {
    name: entry.node.name,
    ecosystem: "npm",
    requestedVersion: entry.requestedVersion,
    ...(entry.manifestName === undefined ? {} : { manifestName: entry.manifestName }),
    installedVersion: entry.node.version,
    resolutionStatus: entry.node.supported ? "resolved" : "unsupported",
    dependencyType: entry.direct ? "direct" : "transitive",
    environment: entry.environment,
    ...(entry.declaredEnvironment === undefined
      ? {}
      : { declaredEnvironment: entry.declaredEnvironment }),
    ...(entry.parent === undefined ? {} : { parent: entry.parent }),
    dependencyPath: [...entry.path],
    manifestPath: entry.manifestPath,
    packageJsonPath: entry.manifestPath,
    lockfilePath: input.lockfilePath,
    packageManager: "bun",
    projectPath: input.projectPath,
    workspacePath: input.workspacePath,
    metadata: { source: entry.node.source, workspace: entry.workspace || "." },
  };
}

function missingDependency(
  edge: DirectEdge,
  workspace: string,
  input: BunDependencyParserInput,
  manifestPath: string,
  direct: boolean,
  parent?: string,
  path?: readonly string[],
): Dependency {
  return {
    name: aliasTarget(edge.range) ?? edge.name,
    ecosystem: "npm",
    requestedVersion: edge.range,
    ...(direct ? { manifestName: edge.name } : {}),
    installedVersion: "",
    resolutionStatus: unsupportedRange(edge.range) ? "unsupported" : "unresolved",
    dependencyType: direct ? "direct" : "transitive",
    environment: edge.environment,
    ...(direct ? { declaredEnvironment: edge.environment } : {}),
    ...(parent === undefined ? {} : { parent }),
    ...(path === undefined ? {} : { dependencyPath: [...path] }),
    manifestPath,
    packageJsonPath: manifestPath,
    lockfilePath: input.lockfilePath,
    packageManager: "bun",
    projectPath: input.projectPath,
    workspacePath: input.workspacePath,
    metadata: { source: edge.range, workspace: workspace || "." },
  };
}

function mergeDependency(existing: Dependency, incoming: Dependency): Dependency {
  const preferred = incoming.dependencyType === "direct" && existing.dependencyType !== "direct"
    ? incoming
    : existing;
  return {
    ...preferred,
    dependencyType:
      incoming.dependencyType === "direct" || existing.dependencyType === "direct"
        ? "direct"
        : "transitive",
    environment:
      environmentRank(incoming.environment) > environmentRank(existing.environment)
        ? incoming.environment
        : existing.environment,
    ...(incoming.dependencyType === "direct"
      ? { declaredEnvironment: incoming.declaredEnvironment ?? incoming.environment }
      : existing.declaredEnvironment === undefined
        ? {}
        : { declaredEnvironment: existing.declaredEnvironment }),
  };
}

export function parseBunDependencies(
  input: BunDependencyParserInput,
): JavaScriptParseResult {
  const context = new ParserContext(input.signal);
  const dependencies = new Map<string, Dependency>();
  try {
    const parseErrors: ParseError[] = [];
    const tree = parseTree(input.lockfile, parseErrors, {
      allowTrailingComma: true,
      disallowComments: false,
      allowEmptyContent: false,
    });
    if (tree === undefined || parseErrors.length > 0 || !validateJsonTree(tree, context)) {
      context.issue({
        code: "INVALID_LOCKFILE",
        message: "Could not parse bun.lock as bounded JSONC",
      });
      return finish(dependencies, context, false);
    }
    const rawDocument: unknown = getNodeValue(tree);
    if (!isRecord(rawDocument)) {
      context.issue({
        code: "INVALID_LOCKFILE",
        message: "bun.lock must contain an object",
      });
      return finish(dependencies, context, false);
    }
    const version = rawDocument.lockfileVersion;
    if (
      typeof version !== "number" ||
      !Number.isSafeInteger(version) ||
      version < 0 ||
      version > 2
    ) {
      context.issue({
        code: "UNSUPPORTED_LOCKFILE",
        message: "Bun text lockfile version is not supported for static extraction",
      });
      return finish(dependencies, context, false);
    }
    if (!isRecord(rawDocument.workspaces)) {
      context.issue({
        code: "INVALID_LOCKFILE",
        message: "bun.lock does not contain a workspaces object",
      });
      return finish(dependencies, context, false);
    }
    const graph = buildNodes(rawDocument, context);
    const queue: QueueEntry[] = [];
    let seedLimitReached = false;
    const manifestsByWorkspace = new Map(
      input.manifests.map((manifest) => [manifest.relativeDirectory, manifest]),
    );
    const processedWorkspaces = new Set<string>();
    for (const [workspace, rawWorkspace] of Object.entries(rawDocument.workspaces)) {
      context.check();
      if (
        !isRecord(rawWorkspace) ||
        (workspace.length > 0 && !isSafeRelativePath(workspace))
      ) {
        context.issue({
          code: "INVALID_LOCKFILE",
          message: "Ignored an unsafe or malformed Bun workspace",
        });
        continue;
      }
      const rootLabel = safeString(rawWorkspace.name, 214) ??
        (workspace.length === 0 ? "workspace" : workspace);
      const lockEdges = directEdges(
        rawWorkspace,
        input.options.includeDevDependencies,
        context,
      );
      const workspaceKey = workspace.length === 0 ? "." : workspace;
      const manifest = manifestsByWorkspace.get(workspaceKey);
      if (manifest === undefined) {
        context.issue({
          code: "INVALID_MANIFEST",
          message: `Ignored Bun workspace ${workspaceKey} because no discovered package.json exists`,
        });
        continue;
      }
      const manifestResult = parseManifestDependencyEdges(
        manifest,
        input.options.includeDevDependencies,
      );
      for (const issue of manifestResult.issues) {
        context.issue(issue);
      }
      const lockEdgesByName = new Map(lockEdges.map((edge) => [edge.name, edge]));
      const manifestNames = new Set(
        manifestResult.edges.map((edge) => edge.name),
      );
      if (lockEdges.some((edge) => !manifestNames.has(edge.name))) {
        context.issue({
          code: "INVALID_LOCKFILE",
          message: `Bun workspace ${workspaceKey} contains dependencies absent from package.json`,
        });
      }
      const workspaceManifest = manifest.path;
      processedWorkspaces.add(workspaceKey);
      for (const manifestEdge of manifestResult.edges) {
        const lockedEdge = lockEdgesByName.get(manifestEdge.name);
        const edge: DirectEdge =
          lockedEdge !== undefined &&
          lockedEdge.range === manifestEdge.requestedVersion
            ? { ...lockedEdge, environment: manifestEdge.environment }
            : {
                name: manifestEdge.name,
                range: manifestEdge.requestedVersion,
                environment: manifestEdge.environment,
              };
        if (queue.length + dependencies.size >= MAX_PACKAGES) {
          reportDependencyLimit(context);
          seedLimitReached = true;
          break;
        }
        const node =
          lockedEdge !== undefined &&
          lockedEdge.range === manifestEdge.requestedVersion
            ? lookupNode(graph, edge.name, edge.range)
            : undefined;
        if (node === undefined) {
          const missing = missingDependency(
            edge,
            workspace,
            input,
            workspaceManifest,
            true,
            undefined,
            [rootLabel, edge.name],
          );
          storeDependency(
            dependencies,
            `${workspace}\u0000missing\u0000${edge.name}`,
            missing,
            context,
          );
          context.issue({
            code: missing.resolutionStatus === "unsupported"
              ? "UNSUPPORTED_PACKAGE_SOURCE"
              : "DEPENDENCY_UNRESOLVED",
            message: missing.resolutionStatus === "unsupported"
              ? `Bun dependency ${edge.name} is a local/workspace or non-registry reference`
              : lockedEdge === undefined
                ? `Bun dependency ${edge.name} is absent from the lock workspace`
                : lockedEdge.range !== manifestEdge.requestedVersion
                  ? `Bun dependency ${edge.name} does not match the current package.json declaration`
                  : `Bun dependency ${edge.name} has no unambiguous resolved package entry`,
            packageName: edge.name,
          });
          continue;
        }
        queue.push({
          workspace,
          manifestPath: workspaceManifest,
          rootLabel,
          node,
          requestedVersion: edge.range,
          manifestName: edge.name,
          environment: edge.environment,
          declaredEnvironment: edge.environment,
          direct: true,
          path: [rootLabel, `${node.name}@${node.version}`],
          depth: 1,
        });
      }
      if (seedLimitReached) {
        break;
      }
    }
    if (!seedLimitReached) {
      for (const manifest of input.manifests) {
        context.check();
        const workspaceKey = manifest.relativeDirectory;
        if (processedWorkspaces.has(workspaceKey)) {
          continue;
        }
        const manifestResult = parseManifestDependencyEdges(
          manifest,
          input.options.includeDevDependencies,
        );
        for (const issue of manifestResult.issues) {
          context.issue(issue);
        }
        const workspace = workspaceKey === "." ? "" : workspaceKey;
        const rootLabel = workspace.length === 0 ? "workspace" : workspace;
        for (const manifestEdge of manifestResult.edges) {
          const edge: DirectEdge = {
            name: manifestEdge.name,
            range: manifestEdge.requestedVersion,
            environment: manifestEdge.environment,
          };
          const missing = missingDependency(
            edge,
            workspace,
            input,
            manifest.path,
            true,
            undefined,
            [rootLabel, edge.name],
          );
          if (
            !storeDependency(
              dependencies,
              `${workspace}\u0000missing\u0000${edge.name}`,
              missing,
              context,
            )
          ) {
            seedLimitReached = true;
            break;
          }
          context.issue({
            code:
              missing.resolutionStatus === "unsupported"
                ? "UNSUPPORTED_PACKAGE_SOURCE"
                : "DEPENDENCY_UNRESOLVED",
            message: `Bun dependency ${edge.name} has no matching lock workspace`,
            packageName: edge.name,
          });
        }
        if (seedLimitReached) {
          break;
        }
      }
    }

    const visited = new Set<string>();
    let next = 0;
    while (next < queue.length) {
      context.check();
      const entry = queue[next];
      next += 1;
      if (entry === undefined) {
        continue;
      }
      const state = `${entry.workspace}\u0000${entry.node.key}\u0000${entry.environment}`;
      if (visited.has(state)) {
        continue;
      }
      visited.add(state);
      const key = `${entry.workspace}\u0000${entry.node.key}`;
      const incoming = dependencyFromEntry(entry, input);
      const existing = dependencies.get(key);
      if (
        !storeDependency(
          dependencies,
          key,
          existing === undefined ? incoming : mergeDependency(existing, incoming),
          context,
        )
      ) {
        break;
      }
      if (!entry.node.supported) {
        context.issue({
          code: "UNSUPPORTED_PACKAGE_SOURCE",
          message: `Bun dependency ${entry.node.name} has unsupported resolution provenance`,
          packageName: entry.node.name,
        });
      }
      if (!input.options.includeTransitiveDependencies || entry.depth >= MAX_DEPTH) {
        if (entry.depth >= MAX_DEPTH && entry.node.edges.length > 0) {
          context.truncated = true;
          context.issue({
            code: "DEPENDENCY_LIMIT",
            message: `Bun dependency traversal reached the depth limit of ${MAX_DEPTH.toString()}`,
          });
        }
        continue;
      }
      for (const edge of entry.node.edges) {
        context.edges += 1;
        if (context.edges > MAX_EDGES) {
          context.truncated = true;
          context.issue({
            code: "DEPENDENCY_LIMIT",
            message: `Bun dependency graph exceeds the ${MAX_EDGES.toString()}-edge limit`,
          });
          break;
        }
        const environment = edge.optional ? "optional" : entry.environment;
        const child = lookupNode(graph, edge.name, edge.range, entry.node.key);
        if (child === undefined) {
          const directLike: DirectEdge = { name: edge.name, range: edge.range, environment };
          const missing = missingDependency(
            directLike,
            entry.workspace,
            input,
            entry.manifestPath,
            false,
            `${entry.node.name}@${entry.node.version}`,
            [...entry.path, edge.name],
          );
          if (
            !storeDependency(
              dependencies,
              `${entry.workspace}\u0000missing\u0000${entry.node.key}\u0000${edge.name}\u0000${edge.range}`,
              missing,
              context,
            )
          ) {
            break;
          }
          context.issue({
            code: missing.resolutionStatus === "unsupported"
              ? "UNSUPPORTED_PACKAGE_SOURCE"
              : "DEPENDENCY_UNRESOLVED",
            message: `Bun transitive dependency ${edge.name} could not be resolved safely`,
            packageName: edge.name,
          });
          continue;
        }
        if (queue.length >= MAX_PACKAGES * 2) {
          reportDependencyLimit(context);
          break;
        }
        queue.push({
          workspace: entry.workspace,
          manifestPath: entry.manifestPath,
          rootLabel: entry.rootLabel,
          node: child,
          requestedVersion: edge.range,
          environment,
          direct: false,
          parent: `${entry.node.name}@${entry.node.version}`,
          path: [...entry.path, `${child.name}@${child.version}`].slice(-MAX_DEPTH - 1),
          depth: entry.depth + 1,
        });
      }
      if (context.edges > MAX_EDGES) {
        break;
      }
      if (context.truncated && dependencies.size >= MAX_PACKAGES) {
        break;
      }
    }
    return finish(dependencies, context, false);
  } catch (error: unknown) {
    if (error instanceof DOMException && error.name === "AbortError") {
      return finish(new Map(), context, true);
    }
    throw error;
  }
}

function finish(
  dependencies: ReadonlyMap<string, Dependency>,
  context: ParserContext,
  cancelled: boolean,
): JavaScriptParseResult {
  const values = [...dependencies.values()];
  return {
    dependencies: values,
    issues: context.issues,
    discovered: values.length,
    resolved: values.filter((dependency) => dependency.resolutionStatus === "resolved").length,
    unresolved: values.filter((dependency) => dependency.resolutionStatus === "unresolved").length,
    unsupported: values.filter((dependency) => dependency.resolutionStatus === "unsupported").length,
    truncated: context.truncated,
    cancelled,
  };
}
