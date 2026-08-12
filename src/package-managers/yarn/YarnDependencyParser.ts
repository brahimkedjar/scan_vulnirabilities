import { braceExpand, Minimatch } from "minimatch";
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
  safeString,
  type JavaScriptParseIssue,
  type JavaScriptParseResult,
  type ManifestInput,
} from "./JavaScriptParserTypes";

const LEGACY_HEADER = /^(?:#.*\r?\n)*#\s*yarn\s+lockfile\s+v1\r?\n/iu;
const MAX_LINE_LENGTH = 16_384;
const MAX_WORKSPACE_PATTERNS = 100;
const MAX_WORKSPACE_COMPARISONS = 100_000;
const MAX_WORKSPACE_EXPANSIONS = 1_024;
const SUPPORTED_BERRY_LOCK_VERSIONS = new Set([4, 5, 6, 7, 8]);
const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/[a-z0-9][a-z0-9._~-]*|[a-z0-9][a-z0-9._~-]*)$/iu;
const NPM_RESOLUTION = /^(.+)@npm:([^@#:]+)$/u;
const VIRTUAL_NPM_RESOLUTION =
  /^(.+)@virtual:([a-f0-9]{6,128})#npm:([^@#:]+)$/iu;

interface YarnDependencyParserInput {
  readonly manifests: readonly ManifestInput[];
  readonly lockfile: string;
  readonly lockfilePath: string;
  readonly projectPath: string;
  readonly workspacePath: string;
  readonly options: ScanOptions;
  readonly signal?: AbortSignal;
}

interface YarnEdge {
  readonly name: string;
  readonly range: string;
  readonly optional: boolean;
}

interface YarnNode {
  readonly key: string;
  readonly descriptors: readonly string[];
  readonly name: string;
  readonly version: string;
  readonly supported: boolean;
  readonly source: string;
  readonly edges: readonly YarnEdge[];
}

interface ParsedManifest {
  readonly input: ManifestInput;
  readonly document: Record<string, unknown>;
  readonly name: string;
}

interface WorkspacePattern {
  readonly excluded: boolean;
  readonly matcher: Minimatch;
}

interface QueueEntry {
  readonly origin: string;
  readonly node: YarnNode;
  readonly manifest: ParsedManifest;
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
  public edgeCount = 0;

  public constructor(public readonly signal?: AbortSignal) {}

  public check(): void {
    if (this.signal?.aborted === true) {
      throw new DOMException("Yarn dependency parsing cancelled", "AbortError");
    }
  }

  public issue(issue: JavaScriptParseIssue): void {
    if (this.issues.length < MAX_ISSUES) {
      this.issues.push(issue);
      return;
    }
    this.truncated = true;
  }
}

function reportDependencyLimit(context: ParserContext): void {
  if (
    !context.issues.some((issue) =>
      issue.message.includes("Yarn dependency output exceeds"),
    )
  ) {
    context.issue({
      code: "DEPENDENCY_LIMIT",
      message: `Yarn dependency output exceeds the ${MAX_PACKAGES.toString()}-dependency limit`,
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

function parseJsonManifest(
  input: ManifestInput,
  context: ParserContext,
): ParsedManifest | undefined {
  try {
    const value: unknown = JSON.parse(input.content);
    if (!isRecord(value)) {
      throw new TypeError("package.json must contain an object");
    }
    const name = safeString(value.name, 214) ??
      (input.relativeDirectory === "." ? "workspace" : input.relativeDirectory);
    return { input, document: value, name };
  } catch {
    context.issue({
      code: "INVALID_MANIFEST",
      message: `Could not parse Yarn package.json at ${input.path}`,
    });
    return undefined;
  }
}

function workspacePatterns(
  root: ParsedManifest,
  context: ParserContext,
): readonly WorkspacePattern[] {
  const raw = Array.isArray(root.document.workspaces)
    ? root.document.workspaces
    : isRecord(root.document.workspaces) && Array.isArray(root.document.workspaces.packages)
      ? root.document.workspaces.packages
      : [];
  if (raw.length > MAX_WORKSPACE_PATTERNS) {
    context.truncated = true;
    context.issue({
      code: "DEPENDENCY_LIMIT",
      message: `Yarn workspace pattern count exceeds ${MAX_WORKSPACE_PATTERNS.toString()}`,
    });
  }
  const patterns: WorkspacePattern[] = [];
  let totalExpansions = 0;
  for (const value of raw.slice(0, MAX_WORKSPACE_PATTERNS)) {
    const pattern = safeString(value, 512);
    if (
      pattern === undefined ||
      pattern.startsWith("/") ||
      pattern.includes("\\") ||
      pattern.split("/").includes("..")
    ) {
      context.issue({
        code: "INVALID_MANIFEST",
        message: "Ignored an unsafe Yarn workspace pattern",
      });
      continue;
    }
    const excluded = pattern.startsWith("!");
    const normalized = (excluded ? pattern.slice(1) : pattern)
      .replace(/^\.\//u, "")
      .replace(/\/$/u, "");
    if (
      normalized.length === 0 ||
      normalized.startsWith("/") ||
      normalized.split("/").includes("..")
    ) {
      context.issue({
        code: "INVALID_MANIFEST",
        message: "Ignored an unsafe Yarn workspace pattern",
      });
      continue;
    }
    try {
      const expansions = braceExpand(normalized, {
        braceExpandMax: MAX_WORKSPACE_EXPANSIONS + 1,
      });
      totalExpansions += expansions.length;
      if (
        expansions.length > MAX_WORKSPACE_EXPANSIONS ||
        totalExpansions > MAX_WORKSPACE_EXPANSIONS
      ) {
        context.truncated = true;
        context.issue({
          code: "DEPENDENCY_LIMIT",
          message: "Yarn workspace patterns exceed the expansion complexity limit",
        });
        break;
      }
      patterns.push({
        excluded,
        matcher: new Minimatch(normalized, {
          braceExpandMax: MAX_WORKSPACE_EXPANSIONS,
          dot: false,
          maxGlobstarRecursion: 16,
          nocase: false,
          nocomment: true,
          nonegate: true,
          platform: "linux",
        }),
      });
    } catch {
      context.issue({
        code: "INVALID_MANIFEST",
        message: "Ignored a Yarn workspace pattern that could not be evaluated",
      });
    }
  }
  return patterns;
}

function selectManifests(
  manifests: readonly ParsedManifest[],
  context: ParserContext,
): readonly ParsedManifest[] {
  const root = manifests.find((manifest) => manifest.input.relativeDirectory === ".");
  if (root === undefined) {
    context.issue({
      code: "INVALID_MANIFEST",
      message: "A package.json beside yarn.lock is required",
    });
    return [];
  }
  const patterns = workspacePatterns(root, context);
  let comparisons = 0;
  const nested = manifests.filter((manifest) => {
    const directory = manifest.input.relativeDirectory;
    if (directory === "." || !isSafeRelativePath(directory)) {
      return false;
    }
    let included = false;
    for (const pattern of patterns) {
      comparisons += 1;
      if (comparisons > MAX_WORKSPACE_COMPARISONS) {
        context.truncated = true;
        context.issue({
          code: "DEPENDENCY_LIMIT",
          message: "Yarn workspace matching exceeded its comparison limit",
        });
        return false;
      }
      if (pattern.matcher.match(directory)) {
        included = !pattern.excluded;
      }
    }
    return included;
  });
  return [root, ...nested];
}

function parseTokenPair(line: string): readonly [string, string] | undefined {
  const values: string[] = [];
  let index = 0;
  while (index < line.length && values.length < 2) {
    while (line[index] === " ") {
      index += 1;
    }
    if (index >= line.length) {
      break;
    }
    if (line[index] === '"') {
      let end = index + 1;
      let escaped = false;
      while (end < line.length) {
        const character = line[end];
        if (!escaped && character === '"') {
          break;
        }
        escaped = !escaped && character === "\\";
        if (character !== "\\") {
          escaped = false;
        }
        end += 1;
      }
      if (end >= line.length) {
        return undefined;
      }
      try {
        const parsed: unknown = JSON.parse(line.slice(index, end + 1));
        if (typeof parsed !== "string") {
          return undefined;
        }
        values.push(parsed);
      } catch {
        return undefined;
      }
      index = end + 1;
    } else {
      const end = line.indexOf(" ", index);
      values.push(end === -1 ? line.slice(index) : line.slice(index, end));
      index = end === -1 ? line.length : end;
    }
  }
  return values.length === 2 ? [values[0] ?? "", values[1] ?? ""] : undefined;
}

function parseLegacyLockfile(
  source: string,
  context: ParserContext,
): Record<string, unknown> | undefined {
  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  let currentKey: string | undefined;
  let current: Record<string, unknown> | undefined;
  let childBlock: "dependencies" | "optionalDependencies" | undefined;
  const lines = source.replace(/\r\n/gu, "\n").split("\n");
  for (const line of lines) {
    context.check();
    if (line.length > MAX_LINE_LENGTH || line.includes("\t")) {
      context.issue({
        code: "INVALID_LOCKFILE",
        message: "Yarn v1 lockfile contains an overlong or tab-indented line",
      });
      return undefined;
    }
    if (line.length === 0 || line.startsWith("#")) {
      continue;
    }
    if (!line.startsWith(" ")) {
      if (!line.endsWith(":")) {
        return undefined;
      }
      const rawKey = line.slice(0, -1);
      try {
        const parsed: unknown = rawKey.startsWith('"') ? JSON.parse(rawKey) : rawKey;
        currentKey = safeString(parsed);
      } catch {
        currentKey = undefined;
      }
      if (currentKey === undefined || Object.hasOwn(result, currentKey)) {
        return undefined;
      }
      current = Object.create(null) as Record<string, unknown>;
      result[currentKey] = current;
      childBlock = undefined;
      continue;
    }
    if (current === undefined || currentKey === undefined) {
      return undefined;
    }
    if (line.startsWith("    ")) {
      if (childBlock === undefined || line.startsWith("      ")) {
        return undefined;
      }
      const pair = parseTokenPair(line.slice(4));
      const block = current[childBlock];
      if (pair === undefined || !isRecord(block) || Object.hasOwn(block, pair[0])) {
        return undefined;
      }
      block[pair[0]] = pair[1];
      continue;
    }
    if (!line.startsWith("  ") || line.startsWith("   ")) {
      return undefined;
    }
    const field = line.slice(2);
    if (field === "dependencies:" || field === "optionalDependencies:") {
      childBlock = field.slice(0, -1) as "dependencies" | "optionalDependencies";
      current[childBlock] = Object.create(null) as Record<string, unknown>;
      continue;
    }
    childBlock = undefined;
    const pair = parseTokenPair(field);
    if (pair === undefined || Object.hasOwn(current, pair[0])) {
      return undefined;
    }
    current[pair[0]] = pair[1];
  }
  return result;
}

function splitDescriptors(key: string): readonly string[] {
  return key
    .split(/,\s+(?=(?:@[^/\s,]+\/)?[^@\s,]+@)/u)
    .map((descriptor) => descriptor.trim())
    .filter((descriptor) => descriptor.length > 0);
}

function parseDescriptor(descriptor: string): { name: string; range: string } | undefined {
  const separator = descriptor.startsWith("@")
    ? descriptor.indexOf("@", descriptor.indexOf("/") + 1)
    : descriptor.indexOf("@");
  if (separator <= 0) {
    return undefined;
  }
  const name = descriptor.slice(0, separator);
  const range = descriptor.slice(separator + 1);
  return PACKAGE_NAME.test(name) && range.length > 0 && range.length <= 8_192
    ? { name, range }
    : undefined;
}

function npmAliasName(range: string): string | undefined {
  if (!range.startsWith("npm:")) {
    return undefined;
  }
  const target = range.slice(4);
  const separator = target.startsWith("@")
    ? target.indexOf("@", target.indexOf("/") + 1)
    : target.indexOf("@");
  const name = separator === -1 ? target : target.slice(0, separator);
  return PACKAGE_NAME.test(name) ? name : undefined;
}

function stringMap(value: unknown, context: ParserContext): Record<string, string> {
  const result: Record<string, string> = Object.create(null) as Record<string, string>;
  if (value === undefined) {
    return result;
  }
  if (!isRecord(value)) {
    context.issue({
      code: "INVALID_LOCKFILE",
      message: "Ignored a malformed Yarn dependency map",
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
        message: "Ignored a malformed Yarn dependency edge",
      });
    }
  }
  return result;
}

function yarnSource(
  record: Record<string, unknown>,
  modern: boolean,
  descriptor: { name: string; range: string },
): { source: string; name: string; supported: boolean } {
  const aliasName = npmAliasName(descriptor.range);
  if (!modern) {
    const resolved = safeString(record.resolved) ?? "npm-registry";
    const exotic = /^(?:file:|link:|portal:|workspace:|git(?:\+|:)|https?:)/iu.test(
      descriptor.range,
    );
    const registryResolution =
      resolved === "npm-registry" ||
      /^(?:https?:\/\/)?(?:registry\.(?:npmjs\.org|yarnpkg\.com)|registry\.npmjs\.org)\//iu.test(
        resolved,
      );
    return {
      source: exotic ? descriptor.range : resolved,
      name: aliasName ?? descriptor.name,
      supported: !exotic && registryResolution,
    };
  }

  const resolution = safeString(record.resolution, 1_024) ?? "";
  const parsedResolution = exactNpmResolution(resolution);
  return {
    source: resolution,
    name: parsedResolution?.name ?? aliasName ?? descriptor.name,
    supported: parsedResolution !== undefined,
  };
}

function exactNpmResolution(
  resolution: string,
): { readonly name: string; readonly version: string } | undefined {
  const virtual = VIRTUAL_NPM_RESOLUTION.exec(resolution);
  const plain = virtual === null ? NPM_RESOLUTION.exec(resolution) : null;
  const name = virtual?.[1] ?? plain?.[1];
  const version = virtual?.[3] ?? plain?.[2];
  if (
    name === undefined ||
    version === undefined ||
    !PACKAGE_NAME.test(name) ||
    semver.valid(version) !== version
  ) {
    return undefined;
  }
  return { name, version };
}

function buildNodes(
  lock: Record<string, unknown>,
  modern: boolean,
  context: ParserContext,
): { nodes: readonly YarnNode[]; descriptors: ReadonlyMap<string, YarnNode | null> } {
  const nodes: YarnNode[] = [];
  const descriptorIndex = new Map<string, YarnNode | null>();
  for (const [key, rawValue] of Object.entries(lock)) {
    context.check();
    if (key === "__metadata") {
      continue;
    }
    if (nodes.length >= MAX_PACKAGES) {
      context.truncated = true;
      context.issue({
        code: "DEPENDENCY_LIMIT",
        message: `Yarn lockfile exceeds the ${MAX_PACKAGES.toString()}-package limit`,
      });
      break;
    }
    if (!isRecord(rawValue)) {
      context.issue({
        code: "INVALID_LOCKFILE",
        message: "Ignored a malformed Yarn lock entry",
      });
      continue;
    }
    const descriptors = splitDescriptors(key);
    const parsed = descriptors.map(parseDescriptor);
    const first = parsed[0];
    const rawVersion = safeString(rawValue.version, 256);
    if (first === undefined || parsed.some((value) => value === undefined) || rawVersion === undefined) {
      context.issue({
        code: "INVALID_LOCKFILE",
        message: "Ignored a Yarn lock entry with an invalid descriptor or version",
      });
      continue;
    }
    const source = yarnSource(rawValue, modern, first);
    const normalizedVersion = semver.valid(rawVersion);
    const dependencies = stringMap(rawValue.dependencies, context);
    const optionalDependencies = stringMap(rawValue.optionalDependencies, context);
    const metadata = isRecord(rawValue.dependenciesMeta)
      ? rawValue.dependenciesMeta
      : Object.create(null) as Record<string, unknown>;
    const edges: YarnEdge[] = [];
    for (const [name, range] of Object.entries(dependencies)) {
      const meta = metadata[name];
      edges.push({
        name,
        range,
        optional: isRecord(meta) && meta.optional === true,
      });
    }
    for (const [name, range] of Object.entries(optionalDependencies)) {
      if (!edges.some((edge) => edge.name === name)) {
        edges.push({ name, range, optional: true });
      }
    }
    const node: YarnNode = {
      key,
      descriptors,
      name: source.name,
      version: normalizedVersion ?? rawVersion,
      supported: source.supported && normalizedVersion !== null,
      source: source.source,
      edges,
    };
    nodes.push(node);
    for (const descriptor of descriptors) {
      descriptorIndex.set(
        descriptor,
        descriptorIndex.has(descriptor) ? null : node,
      );
    }
  }
  return { nodes, descriptors: descriptorIndex };
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
  manifest: ParsedManifest,
  includeDev: boolean,
): readonly { name: string; range: string; environment: DependencyEnvironment }[] {
  const result = new Map<string, { name: string; range: string; environment: DependencyEnvironment }>();
  const add = (field: string, environment: DependencyEnvironment): void => {
    const values = manifest.document[field];
    if (!isRecord(values)) {
      return;
    }
    for (const [name, rawRange] of Object.entries(values)) {
      const range = safeString(rawRange);
      if (!PACKAGE_NAME.test(name) || range === undefined) {
        continue;
      }
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

function lookupNode(
  index: ReadonlyMap<string, YarnNode | null>,
  name: string,
  range: string,
  modern: boolean,
): YarnNode | undefined {
  const candidates = range.includes(":")
    ? [`${name}@${range}`]
    : modern
      ? [`${name}@npm:${range}`, `${name}@${range}`]
      : [`${name}@${range}`];
  for (const candidate of candidates) {
    const node = index.get(candidate);
    if (node !== undefined && node !== null) {
      return node;
    }
  }
  return undefined;
}

function unsupportedRange(range: string): boolean {
  return /^(?:workspace:|file:|link:|portal:|patch:|exec:|git(?:\+|:)|https?:)/iu.test(range);
}

function edgeMatchesResolvedNode(
  name: string,
  range: string,
  node: YarnNode,
): boolean {
  if (!node.supported) {
    return true;
  }
  let expectedName = name;
  let requestedVersion = range;
  if (requestedVersion.startsWith("npm:")) {
    const payload = requestedVersion.slice(4);
    const alias = /^((?:@[A-Za-z0-9._~-]+\/)?[A-Za-z0-9._~-]+)@(.+)$/u.exec(
      payload,
    );
    if (alias?.[1] !== undefined && alias[2] !== undefined) {
      expectedName = alias[1];
      requestedVersion = alias[2];
    } else {
      requestedVersion = payload;
    }
  }
  if (node.name !== expectedName) {
    return false;
  }
  const validRange = semver.validRange(requestedVersion);
  if (validRange !== null) {
    return semver.satisfies(node.version, validRange);
  }
  // Registry tags are immutable lock snapshots, but protocols, paths, URLs,
  // malformed aliases, and other ambiguous specifications are not.
  return /^[A-Za-z][A-Za-z0-9._-]{0,127}$/u.test(requestedVersion);
}

function dependencyFromEntry(
  entry: QueueEntry,
  input: YarnDependencyParserInput,
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
    manifestPath: entry.manifest.input.path,
    packageJsonPath: entry.manifest.input.path,
    lockfilePath: input.lockfilePath,
    packageManager: "yarn",
    projectPath: input.projectPath,
    workspacePath: input.workspacePath,
    metadata: { source: entry.node.source },
  };
}

function missingDependency(
  name: string,
  range: string,
  environment: DependencyEnvironment,
  direct: boolean,
  parent: string | undefined,
  path: readonly string[],
  manifest: ParsedManifest,
  input: YarnDependencyParserInput,
  unsupported: boolean,
): Dependency {
  return {
    name: npmAliasName(range) ?? name,
    ecosystem: "npm",
    requestedVersion: range,
    ...(direct ? { manifestName: name } : {}),
    installedVersion: "",
    resolutionStatus: unsupported ? "unsupported" : "unresolved",
    dependencyType: direct ? "direct" : "transitive",
    environment,
    ...(direct ? { declaredEnvironment: environment } : {}),
    ...(parent === undefined ? {} : { parent }),
    dependencyPath: [...path],
    manifestPath: manifest.input.path,
    packageJsonPath: manifest.input.path,
    lockfilePath: input.lockfilePath,
    packageManager: "yarn",
    projectPath: input.projectPath,
    workspacePath: input.workspacePath,
    metadata: { source: range },
  };
}

function mergeDependency(existing: Dependency, incoming: Dependency): Dependency {
  const incomingDirect = incoming.dependencyType === "direct";
  const existingDirect = existing.dependencyType === "direct";
  const strongerEnvironment =
    environmentRank(incoming.environment) > environmentRank(existing.environment)
      ? incoming.environment
      : existing.environment;
  const preferred = incomingDirect && !existingDirect ? incoming : existing;
  return {
    ...preferred,
    dependencyType: incomingDirect || existingDirect ? "direct" : "transitive",
    environment: strongerEnvironment,
    ...(incomingDirect
      ? { declaredEnvironment: incoming.declaredEnvironment ?? incoming.environment }
      : existing.declaredEnvironment === undefined
        ? {}
        : { declaredEnvironment: existing.declaredEnvironment }),
  };
}

export function parseYarnDependencies(
  input: YarnDependencyParserInput,
): JavaScriptParseResult {
  const context = new ParserContext(input.signal);
  const dependencies = new Map<string, Dependency>();
  try {
    context.check();
    const parsedManifests = input.manifests.flatMap((manifest) => {
      const parsed = parseJsonManifest(manifest, context);
      return parsed === undefined ? [] : [parsed];
    });
    const manifests = selectManifests(parsedManifests, context);
    const modern = !LEGACY_HEADER.test(input.lockfile);
    let lock: Record<string, unknown> | undefined;
    if (modern) {
      try {
        const value: unknown = parseYaml(input.lockfile, {
          schema: "core",
          uniqueKeys: true,
          maxAliasCount: 0,
        });
        if (!isRecord(value) || !isRecord(value.__metadata)) {
          throw new TypeError("Yarn Berry metadata is missing");
        }
        const rawVersion = value.__metadata.version;
        const version = typeof rawVersion === "number"
          ? rawVersion
          : typeof rawVersion === "string"
            ? Number(rawVersion)
            : Number.NaN;
        if (!Number.isSafeInteger(version) || !SUPPORTED_BERRY_LOCK_VERSIONS.has(version)) {
          context.issue({
            code: "UNSUPPORTED_LOCKFILE",
            message: "Yarn lockfile version is not supported for static extraction",
          });
          return finishResult(dependencies, context, false);
        }
        lock = value;
      } catch (error: unknown) {
        context.issue({
          code: "INVALID_LOCKFILE",
          message: `Could not parse yarn.lock: ${error instanceof Error ? error.message : "invalid YAML"}`,
        });
      }
    } else {
      lock = parseLegacyLockfile(input.lockfile, context);
      if (lock === undefined) {
        context.issue({
          code: "INVALID_LOCKFILE",
          message: "Could not parse Yarn v1 lockfile",
        });
      }
    }
    if (lock === undefined) {
      let limitReached = false;
      for (const manifest of manifests) {
        for (const edge of directEdges(manifest, input.options.includeDevDependencies)) {
          if (dependencies.size >= MAX_PACKAGES) {
            reportDependencyLimit(context);
            limitReached = true;
            break;
          }
          const missing = missingDependency(
            edge.name,
            edge.range,
            edge.environment,
            true,
            undefined,
            [manifest.name, edge.name],
            manifest,
            input,
            unsupportedRange(edge.range),
          );
          storeDependency(
            dependencies,
            `${manifest.input.path}\u0000${edge.name}`,
            missing,
            context,
          );
        }
        if (limitReached) {
          break;
        }
      }
      return finishResult(dependencies, context, false);
    }

    const graph = buildNodes(lock, modern, context);
    const queue: QueueEntry[] = [];
    let seedLimitReached = false;
    for (const manifest of manifests) {
      for (const edge of directEdges(manifest, input.options.includeDevDependencies)) {
        if (queue.length + dependencies.size >= MAX_PACKAGES) {
          reportDependencyLimit(context);
          seedLimitReached = true;
          break;
        }
        const selected = lookupNode(
          graph.descriptors,
          edge.name,
          edge.range,
          modern,
        );
        const node =
          selected !== undefined &&
          edgeMatchesResolvedNode(edge.name, edge.range, selected)
            ? selected
            : undefined;
        if (node === undefined) {
          const unsupported = unsupportedRange(edge.range);
          const missing = missingDependency(
            edge.name,
            edge.range,
            edge.environment,
            true,
            undefined,
            [manifest.name, edge.name],
            manifest,
            input,
            unsupported,
          );
          storeDependency(
            dependencies,
            `${manifest.input.path}\u0000missing\u0000${edge.name}`,
            missing,
            context,
          );
          context.issue({
            code: unsupported ? "UNSUPPORTED_PACKAGE_SOURCE" : "DEPENDENCY_UNRESOLVED",
            message: unsupported
              ? `Yarn dependency ${edge.name} uses a local or non-registry source`
              : `Yarn dependency ${edge.name} has no unambiguous resolved lock entry`,
            packageName: edge.name,
          });
          continue;
        }
        queue.push({
          origin: manifest.input.path,
          node,
          manifest,
          requestedVersion: edge.range,
          manifestName: edge.name,
          environment: edge.environment,
          declaredEnvironment: edge.environment,
          direct: true,
          path: [manifest.name, `${node.name}@${node.version}`],
          depth: 1,
        });
      }
      if (seedLimitReached) {
        break;
      }
    }

    const visitedStates = new Set<string>();
    let nextIndex = 0;
    while (nextIndex < queue.length) {
      context.check();
      const entry = queue[nextIndex];
      nextIndex += 1;
      if (entry === undefined) {
        continue;
      }
      const stateKey = `${entry.origin}\u0000${entry.node.key}\u0000${entry.environment}`;
      if (visitedStates.has(stateKey)) {
        continue;
      }
      visitedStates.add(stateKey);
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
          message: `Yarn dependency ${entry.node.name} is not backed by an npm registry resolution`,
          packageName: entry.node.name,
        });
      }
      if (!input.options.includeTransitiveDependencies || entry.depth >= MAX_DEPTH) {
        if (entry.depth >= MAX_DEPTH && entry.node.edges.length > 0) {
          context.truncated = true;
          context.issue({
            code: "DEPENDENCY_LIMIT",
            message: `Yarn dependency traversal reached the depth limit of ${MAX_DEPTH.toString()}`,
          });
        }
        continue;
      }
      for (const edge of entry.node.edges) {
        context.edgeCount += 1;
        if (context.edgeCount > MAX_EDGES) {
          context.truncated = true;
          context.issue({
            code: "DEPENDENCY_LIMIT",
            message: `Yarn dependency graph exceeds the ${MAX_EDGES.toString()}-edge limit`,
          });
          break;
        }
        const environment = edge.optional ? "optional" : entry.environment;
        const selectedChild = lookupNode(
          graph.descriptors,
          edge.name,
          edge.range,
          modern,
        );
        const child =
          selectedChild !== undefined &&
          edgeMatchesResolvedNode(edge.name, edge.range, selectedChild)
            ? selectedChild
            : undefined;
        if (child === undefined) {
          const missing = missingDependency(
            edge.name,
            edge.range,
            environment,
            false,
            `${entry.node.name}@${entry.node.version}`,
            [...entry.path, edge.name],
            entry.manifest,
            input,
            unsupportedRange(edge.range),
          );
          const missingKey = `${entry.origin}\u0000missing\u0000${entry.node.key}\u0000${edge.name}\u0000${edge.range}`;
          if (!storeDependency(dependencies, missingKey, missing, context)) {
            break;
          }
          context.issue({
            code: unsupportedRange(edge.range)
              ? "UNSUPPORTED_PACKAGE_SOURCE"
              : "DEPENDENCY_UNRESOLVED",
            message: `Yarn transitive dependency ${edge.name} could not be resolved safely`,
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
          node: child,
          manifest: entry.manifest,
          requestedVersion: edge.range,
          environment,
          direct: false,
          parent: `${entry.node.name}@${entry.node.version}`,
          path: [...entry.path, `${child.name}@${child.version}`].slice(-MAX_DEPTH - 1),
          depth: entry.depth + 1,
        });
      }
      if (context.edgeCount > MAX_EDGES) {
        break;
      }
      if (context.truncated && dependencies.size >= MAX_PACKAGES) {
        break;
      }
    }
    return finishResult(dependencies, context, false);
  } catch (error: unknown) {
    if (error instanceof DOMException && error.name === "AbortError") {
      return finishResult(new Map(), context, true);
    }
    throw error;
  }
}

function finishResult(
  dependencies: ReadonlyMap<string, Dependency>,
  context: ParserContext,
  cancelled: boolean,
): JavaScriptParseResult {
  const values = [...dependencies.values()];
  const resolved = values.filter(
    (dependency) => dependency.resolutionStatus === "resolved",
  ).length;
  const unresolved = values.filter(
    (dependency) => dependency.resolutionStatus === "unresolved",
  ).length;
  const unsupported = values.filter(
    (dependency) => dependency.resolutionStatus === "unsupported",
  ).length;
  return {
    dependencies: values,
    issues: context.issues,
    discovered: values.length,
    resolved,
    unresolved,
    unsupported,
    truncated: context.truncated,
    cancelled,
  };
}
