import semver from "semver";
import { parse as parseYaml } from "yaml";

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
const SUPPORTED_LOCK_MAJORS = new Set([5, 6, 9]);

export interface PnpmDependencyParserInput {
  readonly lockfile: string;
  readonly lockfilePath: string;
  readonly projectPath: string;
  readonly workspacePath: string;
  readonly manifests: readonly ManifestInput[];
  readonly options: ScanOptions;
  readonly signal?: AbortSignal;
}

interface DirectEdge {
  readonly name: string;
  readonly specifier: string;
  readonly reference: string;
  readonly environment: DependencyEnvironment;
}

interface PnpmEdge {
  readonly name: string;
  readonly reference: string;
  readonly optional: boolean;
}

interface PnpmNode {
  readonly key: string;
  readonly name: string;
  readonly version: string;
  readonly rawReference: string;
  readonly supported: boolean;
  readonly source: string;
  readonly edges: readonly PnpmEdge[];
}

interface QueueEntry {
  readonly origin: string;
  readonly manifestPath: string;
  readonly rootLabel: string;
  readonly node: PnpmNode;
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
      throw new DOMException("pnpm dependency parsing cancelled", "AbortError");
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
      issue.message.includes("pnpm dependency output exceeds"),
    )
  ) {
    context.issue({
      code: "DEPENDENCY_LIMIT",
      message: `pnpm dependency output exceeds the ${MAX_PACKAGES.toString()}-dependency limit`,
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

function mainYamlDocument(source: string): string {
  const normalized = source.replace(/\r\n/gu, "\n");
  if (!normalized.startsWith("---\n")) {
    return normalized;
  }
  const separator = normalized.indexOf("\n---\n", 4);
  return separator === -1 ? "" : normalized.slice(separator + 5);
}

function lockMajor(value: unknown): number | undefined {
  const raw = typeof value === "number" || typeof value === "string"
    ? String(value)
    : "";
  const match = /^(\d+)(?:\.\d+)?$/u.exec(raw);
  const major = match?.[1] === undefined ? Number.NaN : Number(match[1]);
  return Number.isSafeInteger(major) ? major : undefined;
}

function packageVersion(raw: string): string | undefined {
  const direct = semver.valid(raw);
  if (direct !== null) {
    return direct;
  }
  const match = /^(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)(?:[_\(].*)$/u.exec(raw);
  return match?.[1] === undefined ? undefined : semver.valid(match[1]) ?? undefined;
}

function parseAtKey(value: string): { name: string; rawReference: string } | undefined {
  const separator = value.startsWith("@")
    ? value.indexOf("@", value.indexOf("/") + 1)
    : value.indexOf("@");
  if (separator <= 0) {
    return undefined;
  }
  const name = value.slice(0, separator);
  const rawReference = value.slice(separator + 1);
  return PACKAGE_NAME.test(name) && rawReference.length > 0
    ? { name, rawReference }
    : undefined;
}

function parseSlashKey(value: string): { name: string; rawReference: string } | undefined {
  const segments = value.replace(/^\//u, "").split("/");
  if (segments.length < 2) {
    return undefined;
  }
  let name: string;
  let rawReference: string;
  if (segments.at(-3)?.startsWith("@") === true) {
    name = `${segments.at(-3) ?? ""}/${segments.at(-2) ?? ""}`;
    rawReference = segments.at(-1) ?? "";
  } else {
    name = segments.at(-2) ?? "";
    rawReference = segments.at(-1) ?? "";
  }
  return PACKAGE_NAME.test(name) && rawReference.length > 0
    ? { name, rawReference }
    : undefined;
}

function parsePackageKey(
  key: string,
  major: number,
): { name: string; rawReference: string; version: string } | undefined {
  if (
    key.length === 0 ||
    key.length > 8_192 ||
    /^(?:file:|link:|workspace:|https?:|git)/iu.test(key)
  ) {
    return undefined;
  }
  const normalized = key.replace(/^\//u, "");
  const parsed = major === 5
    ? parseSlashKey(key) ?? parseAtKey(normalized)
    : parseAtKey(normalized) ?? parseSlashKey(key);
  if (parsed === undefined) {
    return undefined;
  }
  const version = packageVersion(parsed.rawReference);
  return version === undefined ? undefined : { ...parsed, version };
}

function stringMap(value: unknown, context: ParserContext): Record<string, string> {
  const result: Record<string, string> = Object.create(null) as Record<string, string>;
  if (value === undefined) {
    return result;
  }
  if (!isRecord(value)) {
    context.issue({
      code: "INVALID_LOCKFILE",
      message: "Ignored a malformed pnpm dependency map",
    });
    return result;
  }
  for (const [name, rawReference] of Object.entries(value)) {
    const reference = safeString(rawReference);
    if (PACKAGE_NAME.test(name) && reference !== undefined) {
      result[name] = reference;
    } else {
      context.issue({
        code: "INVALID_LOCKFILE",
        message: "Ignored a malformed pnpm dependency edge",
      });
    }
  }
  return result;
}

function sourceSupport(
  packageRecord: Record<string, unknown> | undefined,
): { supported: boolean; source: string } {
  const resolution = packageRecord?.resolution;
  if (!isRecord(resolution)) {
    return { supported: false, source: "missing-resolution" };
  }
  const type = safeString(resolution.type, 64);
  if (type !== undefined) {
    return { supported: false, source: type };
  }
  const tarball = safeString(resolution.tarball);
  if (tarball !== undefined) {
    return {
      supported: /^https?:\/\/(?:registry\.npmjs\.org|registry\.yarnpkg\.com)\//iu.test(tarball),
      source: tarball,
    };
  }
  return {
    supported: safeString(resolution.integrity) !== undefined,
    source: safeString(resolution.integrity) === undefined
      ? "unknown-resolution"
      : "integrity",
  };
}

function buildNodes(
  document: Record<string, unknown>,
  major: number,
  context: ParserContext,
): { nodes: readonly PnpmNode[]; index: ReadonlyMap<string, PnpmNode> } {
  const packageRecords = isRecord(document.packages)
    ? document.packages
    : Object.create(null) as Record<string, unknown>;
  const snapshots = major === 9 && isRecord(document.snapshots)
    ? document.snapshots
    : packageRecords;
  const nodes: PnpmNode[] = [];
  const index = new Map<string, PnpmNode>();
  for (const [key, rawSnapshot] of Object.entries(snapshots)) {
    context.check();
    if (nodes.length >= MAX_PACKAGES) {
      context.truncated = true;
      context.issue({
        code: "DEPENDENCY_LIMIT",
        message: `pnpm lockfile exceeds the ${MAX_PACKAGES.toString()}-package limit`,
      });
      break;
    }
    const parsed = parsePackageKey(key, major);
    if (parsed === undefined || !isRecord(rawSnapshot)) {
      context.issue({
        code: "UNSUPPORTED_PACKAGE_SOURCE",
        message: "Ignored a pnpm package entry with a non-registry or invalid identity",
      });
      continue;
    }
    const baseKey = key.replace(/\(.*/u, "");
    const packageRecord = major === 9
      ? (isRecord(packageRecords[baseKey]) ? packageRecords[baseKey] : undefined)
      : rawSnapshot;
    const source = sourceSupport(packageRecord);
    const dependencies = stringMap(rawSnapshot.dependencies, context);
    const optionalDependencies = stringMap(rawSnapshot.optionalDependencies, context);
    const edges: PnpmEdge[] = Object.entries(dependencies).map(([name, reference]) => ({
      name,
      reference,
      optional: false,
    }));
    for (const [name, reference] of Object.entries(optionalDependencies)) {
      if (!edges.some((edge) => edge.name === name)) {
        edges.push({ name, reference, optional: true });
      }
    }
    const node: PnpmNode = {
      key,
      name: parsed.name,
      version: parsed.version,
      rawReference: parsed.rawReference,
      supported: source.supported,
      source: source.source,
      edges,
    };
    nodes.push(node);
    const normalized = key.replace(/^\//u, "");
    const references = new Set([
      key,
      normalized,
      `${parsed.name}@${parsed.rawReference}`,
      `/${parsed.name}@${parsed.rawReference}`,
      `/${parsed.name}/${parsed.rawReference}`,
    ]);
    for (const reference of references) {
      if (!index.has(reference)) {
        index.set(reference, node);
      }
    }
  }
  return { nodes, index };
}

function importerRecords(
  document: Record<string, unknown>,
): Readonly<Record<string, unknown>> {
  if (isRecord(document.importers)) {
    return document.importers;
  }
  return { ".": document };
}

function directBlock(
  importer: Record<string, unknown>,
  field: string,
  environment: DependencyEnvironment,
  context: ParserContext,
): readonly DirectEdge[] {
  const rawBlock = importer[field];
  if (rawBlock === undefined) {
    return [];
  }
  if (!isRecord(rawBlock)) {
    context.issue({
      code: "INVALID_LOCKFILE",
      message: `Ignored malformed pnpm ${field}`,
    });
    return [];
  }
  const specifiers = isRecord(importer.specifiers)
    ? importer.specifiers
    : Object.create(null) as Record<string, unknown>;
  const result: DirectEdge[] = [];
  for (const [name, rawValue] of Object.entries(rawBlock)) {
    if (!PACKAGE_NAME.test(name)) {
      continue;
    }
    const objectValue = isRecord(rawValue) ? rawValue : undefined;
    const reference = safeString(objectValue?.version ?? rawValue);
    const specifier = safeString(objectValue?.specifier ?? specifiers[name]) ?? "";
    if (reference === undefined) {
      context.issue({
        code: "DEPENDENCY_UNRESOLVED",
        message: `pnpm dependency ${name} has no resolved reference`,
        packageName: name,
      });
      result.push({ name, specifier, reference: "", environment });
      continue;
    }
    result.push({ name, specifier, reference, environment });
  }
  return result;
}

function directEdges(
  importer: Record<string, unknown>,
  includeDev: boolean,
  context: ParserContext,
): readonly DirectEdge[] {
  const result = new Map<string, DirectEdge>();
  const add = (edge: DirectEdge): void => {
    const existing = result.get(edge.name);
    if (existing === undefined || environmentRank(edge.environment) >= environmentRank(existing.environment)) {
      result.set(edge.name, edge);
    }
  };
  for (const edge of directBlock(importer, "dependencies", "production", context)) {
    add(edge);
  }
  for (const edge of directBlock(importer, "optionalDependencies", "optional", context)) {
    add(edge);
  }
  if (includeDev) {
    for (const edge of directBlock(importer, "devDependencies", "development", context)) {
      add(edge);
    }
  }
  return [...result.values()];
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

function unsupportedReference(reference: string): boolean {
  return /^(?:workspace:|link:|file:|portal:|git(?:\+|:)|https?:)/iu.test(reference);
}

function lookupNode(
  index: ReadonlyMap<string, PnpmNode>,
  name: string,
  reference: string,
): PnpmNode | undefined {
  if (reference.length === 0 || unsupportedReference(reference)) {
    return undefined;
  }
  const candidates = [
    reference,
    reference.replace(/^\//u, ""),
    `${name}@${reference}`,
    `/${name}@${reference}`,
    `/${name}/${reference}`,
  ];
  for (const candidate of candidates) {
    const node = index.get(candidate);
    if (node !== undefined) {
      return node;
    }
  }
  return undefined;
}

function directEdgeMatchesResolvedNode(
  edge: DirectEdge,
  node: PnpmNode,
): boolean {
  if (!node.supported) {
    return true;
  }
  let expectedName = edge.name;
  let requestedVersion = edge.specifier || edge.reference;
  if (requestedVersion.startsWith("npm:")) {
    const alias = /^npm:((?:@[A-Za-z0-9._~-]+\/)?[A-Za-z0-9._~-]+)@(.+)$/u.exec(
      requestedVersion,
    );
    if (alias?.[1] === undefined || alias[2] === undefined) {
      return false;
    }
    expectedName = alias[1];
    requestedVersion = alias[2];
  }
  if (node.name !== expectedName) {
    return false;
  }
  const validRange = semver.validRange(requestedVersion);
  if (validRange !== null) {
    return semver.satisfies(node.version, validRange);
  }
  // Registry tags are exact lock snapshots; other non-semver declarations
  // cannot prove that the selected package identity/version is current.
  return /^[A-Za-z][A-Za-z0-9._-]{0,127}$/u.test(requestedVersion);
}

function dependencyFromEntry(
  entry: QueueEntry,
  input: PnpmDependencyParserInput,
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
    packageManager: "pnpm",
    projectPath: input.projectPath,
    workspacePath: input.workspacePath,
    metadata: { source: entry.node.source, importer: entry.origin },
  };
}

function missingDependency(
  edge: { name: string; specifier: string; reference: string; environment: DependencyEnvironment },
  input: PnpmDependencyParserInput,
  importer: string,
  manifestPath: string,
  direct: boolean,
  parent?: string,
  path?: readonly string[],
): Dependency {
  const unsupported = unsupportedReference(edge.specifier) || unsupportedReference(edge.reference);
  return {
    name: edge.name,
    ecosystem: "npm",
    requestedVersion: edge.specifier || edge.reference,
    ...(direct ? { manifestName: edge.name } : {}),
    installedVersion: "",
    resolutionStatus: unsupported ? "unsupported" : "unresolved",
    dependencyType: direct ? "direct" : "transitive",
    environment: edge.environment,
    ...(direct ? { declaredEnvironment: edge.environment } : {}),
    ...(parent === undefined ? {} : { parent }),
    ...(path === undefined ? {} : { dependencyPath: [...path] }),
    manifestPath,
    packageJsonPath: manifestPath,
    lockfilePath: input.lockfilePath,
    packageManager: "pnpm",
    projectPath: input.projectPath,
    workspacePath: input.workspacePath,
    metadata: { source: edge.reference, importer },
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

export function parsePnpmDependencies(
  input: PnpmDependencyParserInput,
): JavaScriptParseResult {
  const context = new ParserContext(input.signal);
  const dependencies = new Map<string, Dependency>();
  try {
    context.check();
    let document: Record<string, unknown>;
    try {
      const value: unknown = parseYaml(mainYamlDocument(input.lockfile), {
        schema: "core",
        uniqueKeys: true,
        maxAliasCount: 0,
      });
      if (!isRecord(value)) {
        throw new TypeError("pnpm lockfile must contain an object");
      }
      document = value;
    } catch (error: unknown) {
      context.issue({
        code: "INVALID_LOCKFILE",
        message: `Could not parse pnpm-lock.yaml: ${error instanceof Error ? error.message : "invalid YAML"}`,
      });
      return finish(dependencies, context, false);
    }
    const major = lockMajor(document.lockfileVersion);
    if (major === undefined || !SUPPORTED_LOCK_MAJORS.has(major)) {
      context.issue({
        code: "UNSUPPORTED_LOCKFILE",
        message: "pnpm lockfile version is not supported for static extraction",
      });
      return finish(dependencies, context, false);
    }
    const graph = buildNodes(document, major, context);
    const queue: QueueEntry[] = [];
    let seedLimitReached = false;
    const manifestsByImporter = new Map(
      input.manifests.map((manifest) => [manifest.relativeDirectory, manifest]),
    );
    const processedImporters = new Set<string>();
    for (const [importer, rawImporter] of Object.entries(importerRecords(document))) {
      context.check();
      if (
        !isRecord(rawImporter) ||
        (importer !== "." && !isSafeRelativePath(importer))
      ) {
        context.issue({
          code: "INVALID_LOCKFILE",
          message: "Ignored an unsafe or malformed pnpm importer",
        });
        continue;
      }
      const lockEdges = directEdges(
        rawImporter,
        input.options.includeDevDependencies,
        context,
      );
      const manifest = manifestsByImporter.get(importer);
      if (manifest === undefined) {
        context.issue({
          code: "INVALID_MANIFEST",
          message: `Ignored pnpm importer ${importer} because no discovered package.json exists`,
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
          message: `pnpm importer ${importer} contains dependencies absent from package.json`,
        });
      }
      const importerManifest = manifest.path;
      processedImporters.add(importer);
      const rootLabel = importer === "." ? "workspace" : importer;
      for (const manifestEdge of manifestResult.edges) {
        const lockedEdge = lockEdgesByName.get(manifestEdge.name);
        const edge: DirectEdge =
          lockedEdge !== undefined &&
          lockedEdge.specifier === manifestEdge.requestedVersion
            ? { ...lockedEdge, environment: manifestEdge.environment }
            : {
                name: manifestEdge.name,
                specifier: manifestEdge.requestedVersion,
                reference: manifestEdge.requestedVersion,
                environment: manifestEdge.environment,
              };
        if (queue.length + dependencies.size >= MAX_PACKAGES) {
          reportDependencyLimit(context);
          seedLimitReached = true;
          break;
        }
        const selectedNode =
          lockedEdge !== undefined &&
          lockedEdge.specifier === manifestEdge.requestedVersion
            ? lookupNode(graph.index, edge.name, edge.reference)
            : undefined;
        const node =
          selectedNode !== undefined &&
          directEdgeMatchesResolvedNode(edge, selectedNode)
            ? selectedNode
            : undefined;
        if (node === undefined) {
          const missing = missingDependency(
            edge,
            input,
            importer,
            importerManifest,
            true,
            undefined,
            [rootLabel, edge.name],
          );
          storeDependency(
            dependencies,
            `${importer}\u0000missing\u0000${edge.name}`,
            missing,
            context,
          );
          const unsupported = missing.resolutionStatus === "unsupported";
          context.issue({
            code: unsupported ? "UNSUPPORTED_PACKAGE_SOURCE" : "DEPENDENCY_UNRESOLVED",
            message: unsupported
              ? `pnpm dependency ${edge.name} is a local/workspace or non-registry reference`
              : lockedEdge === undefined
                ? `pnpm dependency ${edge.name} is absent from the lock importer`
                : lockedEdge.specifier !== manifestEdge.requestedVersion
                  ? `pnpm dependency ${edge.name} does not match the current package.json declaration`
                  : selectedNode !== undefined
                    ? `pnpm dependency ${edge.name} resolved to a package snapshot that does not satisfy the current package.json declaration`
                  : `pnpm dependency ${edge.name} has no resolved package snapshot`,
            packageName: edge.name,
          });
          continue;
        }
        queue.push({
          origin: importer,
          manifestPath: importerManifest,
          rootLabel,
          node,
          requestedVersion: edge.specifier || edge.reference,
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
        const importer = manifest.relativeDirectory;
        if (processedImporters.has(importer)) {
          continue;
        }
        const manifestResult = parseManifestDependencyEdges(
          manifest,
          input.options.includeDevDependencies,
        );
        for (const issue of manifestResult.issues) {
          context.issue(issue);
        }
        const rootLabel = importer === "." ? "workspace" : importer;
        for (const manifestEdge of manifestResult.edges) {
          const edge: DirectEdge = {
            name: manifestEdge.name,
            specifier: manifestEdge.requestedVersion,
            reference: manifestEdge.requestedVersion,
            environment: manifestEdge.environment,
          };
          const missing = missingDependency(
            edge,
            input,
            importer,
            manifest.path,
            true,
            undefined,
            [rootLabel, edge.name],
          );
          if (
            !storeDependency(
              dependencies,
              `${importer}\u0000missing\u0000${edge.name}`,
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
            message: `pnpm dependency ${edge.name} has no matching lock importer`,
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
      const state = `${entry.origin}\u0000${entry.node.key}\u0000${entry.environment}`;
      if (visited.has(state)) {
        continue;
      }
      visited.add(state);
      const key = `${entry.origin}\u0000${entry.node.key}`;
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
          message: `pnpm dependency ${entry.node.name} has unsupported resolution provenance`,
          packageName: entry.node.name,
        });
      }
      if (!input.options.includeTransitiveDependencies || entry.depth >= MAX_DEPTH) {
        if (entry.depth >= MAX_DEPTH && entry.node.edges.length > 0) {
          context.truncated = true;
          context.issue({
            code: "DEPENDENCY_LIMIT",
            message: `pnpm dependency traversal reached the depth limit of ${MAX_DEPTH.toString()}`,
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
            message: `pnpm dependency graph exceeds the ${MAX_EDGES.toString()}-edge limit`,
          });
          break;
        }
        const environment = edge.optional ? "optional" : entry.environment;
        const child = lookupNode(graph.index, edge.name, edge.reference);
        if (child === undefined) {
          const directLike = {
            name: edge.name,
            specifier: edge.reference,
            reference: edge.reference,
            environment,
          };
          const missing = missingDependency(
            directLike,
            input,
            entry.origin,
            entry.manifestPath,
            false,
            `${entry.node.name}@${entry.node.version}`,
            [...entry.path, edge.name],
          );
          if (
            !storeDependency(
              dependencies,
              `${entry.origin}\u0000missing\u0000${entry.node.key}\u0000${edge.name}\u0000${edge.reference}`,
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
            message: `pnpm transitive dependency ${edge.name} could not be resolved safely`,
            packageName: edge.name,
          });
          continue;
        }
        if (queue.length >= MAX_PACKAGES * 2) {
          reportDependencyLimit(context);
          break;
        }
        queue.push({
          origin: entry.origin,
          manifestPath: entry.manifestPath,
          rootLabel: entry.rootLabel,
          node: child,
          requestedVersion: edge.reference,
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
