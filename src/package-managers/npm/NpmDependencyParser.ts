import { braceExpand, Minimatch } from "minimatch";
import { satisfies, validRange } from "semver";

import type {
  Dependency,
  DependencyEnvironment,
} from "../../models/Dependency";

type JsonRecord = Record<string, unknown>;

type EdgeKind = "production" | "development" | "optional" | "peer";

export type NpmDependencyParseIssueLevel = "warning" | "error";

export interface NpmDependencyParseIssue {
  readonly level: NpmDependencyParseIssueLevel;
  readonly code: string;
  readonly message: string;
}

export interface NpmDependencyParserLimits {
  readonly maxPackages: number;
  readonly maxEdges: number;
  readonly maxDepth: number;
  readonly maxLinkHops: number;
  readonly maxLocationLength: number;
  readonly maxIssues: number;
  readonly maxWorkspacePatternComparisons: number;
  readonly maxWorkspacePatternExpansions: number;
}

export interface NpmDependencyParserInput {
  readonly packageJson: unknown;
  readonly packageJsonPath: string;
  readonly workspaceManifests?: readonly NpmWorkspaceManifestInput[];
  readonly lockfile?: unknown;
  readonly lockfilePath?: string;
  readonly signal?: AbortSignal;
  readonly limits?: Partial<NpmDependencyParserLimits>;
}

export interface NpmWorkspaceManifestInput {
  /** Forward-slash lockfile `packages` location, for example `packages/web`. */
  readonly location: string;
  readonly packageJson: unknown;
  readonly packageJsonPath: string;
}

export interface NpmDependencyParseResult {
  readonly dependencies: readonly Dependency[];
  readonly issues: readonly NpmDependencyParseIssue[];
  readonly unresolvedDependencies: number;
  readonly truncated: boolean;
  readonly cancelled: boolean;
}

export const DEFAULT_NPM_DEPENDENCY_PARSER_LIMITS: NpmDependencyParserLimits = {
  maxPackages: 10_000,
  maxEdges: 250_000,
  maxDepth: 512,
  maxLinkHops: 16,
  maxLocationLength: 4_096,
  maxIssues: 1_000,
  maxWorkspacePatternComparisons: 100_000,
  maxWorkspacePatternExpansions: 2_048,
};

const MAX_EXPANSIONS_PER_WORKSPACE_PATTERN = 128;

interface EdgeDeclaration {
  readonly installName: string;
  readonly requestedVersion: string;
  readonly kind: EdgeKind;
  readonly optionalPeer: boolean;
}

interface LockNode {
  readonly location: string;
  readonly descriptor: JsonRecord;
  readonly installName?: string;
  readonly actualName?: string;
  readonly version?: string;
  readonly linkTarget?: string;
  readonly isLink: boolean;
  readonly dev: boolean;
  readonly optional: boolean;
  readonly devOptional: boolean;
  readonly source: "registry" | "git" | "local" | "remote";
}

interface QueueEntry {
  readonly node: LockNode;
  readonly incomingEdge: EdgeDeclaration;
  readonly dependencyPath: readonly string[];
  readonly parentLabel?: string;
  readonly environment: DependencyEnvironment;
  readonly packageJsonPath: string;
  readonly originKey: string;
  readonly direct: boolean;
  readonly depth: number;
}

class ParserCancelledError extends Error {}

class ParseContext {
  public readonly issues: NpmDependencyParseIssue[] = [];
  public unresolvedDependencies = 0;
  public truncated = false;
  public edgeCount = 0;
  private workspacePatternComparisons = 0;
  private workspacePatternLimitReported = false;
  private workspacePatternExpansions = 0;
  private workspacePatternExpansionLimitReported = false;
  private readonly reportedUnsupportedSources = new Set<string>();
  private readonly reportedInvalidResolvedPackages = new Set<string>();

  public constructor(
    public readonly limits: NpmDependencyParserLimits,
    private readonly signal: AbortSignal | undefined,
  ) {}

  public checkCancellation(): void {
    if (this.signal?.aborted === true) {
      throw new ParserCancelledError("npm dependency parsing cancelled");
    }
  }

  public addIssue(
    level: NpmDependencyParseIssueLevel,
    code: string,
    message: string,
  ): void {
    if (this.issues.length < this.limits.maxIssues) {
      this.issues.push({ level, code, message });
      return;
    }
    this.truncated = true;
  }

  public consumeEdge(): boolean {
    if (this.edgeCount >= this.limits.maxEdges) {
      this.truncated = true;
      return false;
    }
    this.edgeCount += 1;
    return true;
  }

  public consumeWorkspacePatternComparison(): boolean {
    this.checkCancellation();
    if (
      this.workspacePatternComparisons >=
      this.limits.maxWorkspacePatternComparisons
    ) {
      if (!this.workspacePatternLimitReported) {
        this.workspacePatternLimitReported = true;
        this.truncated = true;
        this.addIssue(
          "error",
          "WORKSPACE_MATCH_LIMIT_EXCEEDED",
          "Workspace matching exceeded its comparison safety limit",
        );
      }
      return false;
    }
    this.workspacePatternComparisons += 1;
    return true;
  }

  public consumeWorkspacePatternExpansions(count: number): boolean {
    this.checkCancellation();
    if (
      !Number.isSafeInteger(count) ||
      count < 1 ||
      count >
        this.limits.maxWorkspacePatternExpansions -
          this.workspacePatternExpansions
    ) {
      this.reportWorkspacePatternComplexityLimit();
      return false;
    }
    this.workspacePatternExpansions += count;
    return true;
  }

  public reportWorkspacePatternComplexityLimit(): void {
    if (this.workspacePatternExpansionLimitReported) {
      return;
    }
    this.workspacePatternExpansionLimitReported = true;
    this.truncated = true;
    this.addIssue(
      "error",
      "WORKSPACE_PATTERN_COMPLEXITY_LIMIT_EXCEEDED",
      "Workspace glob expansion exceeded its compilation safety limit",
    );
  }

  public reportUnsupportedSource(
    location: string,
    source: LockNode["source"],
  ): void {
    const key = `${source}\u0000${location}`;
    if (this.reportedUnsupportedSources.has(key)) {
      return;
    }
    this.reportedUnsupportedSources.add(key);
    this.addIssue(
      "warning",
      "UNSUPPORTED_PACKAGE_SOURCE",
      `Skipped a ${source} package at ${sanitizeIssueValue(location)}`,
    );
  }

  public reportInvalidResolvedPackage(location: string): void {
    if (this.reportedInvalidResolvedPackages.has(location)) {
      return;
    }
    this.reportedInvalidResolvedPackages.add(location);
    this.unresolvedDependencies += 1;
    this.addIssue(
      "warning",
      "INVALID_RESOLVED_PACKAGE",
      `Resolved lockfile package lacks a valid identity or exact version at ${sanitizeIssueValue(location)}`,
    );
  }
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sanitizeIssueValue(value: string): string {
  const sanitized = value.replace(/[\u0000-\u001F\u007F]/gu, " ");
  return sanitized.length <= 200 ? sanitized : `${sanitized.slice(0, 197)}...`;
}

function normalizePositiveLimit(value: unknown, fallback: number): number {
  return Number.isSafeInteger(value) && Number(value) > 0
    ? Number(value)
    : fallback;
}

function normalizeLimits(
  supplied: Partial<NpmDependencyParserLimits> | undefined,
): NpmDependencyParserLimits {
  return {
    maxPackages: normalizePositiveLimit(
      supplied?.maxPackages,
      DEFAULT_NPM_DEPENDENCY_PARSER_LIMITS.maxPackages,
    ),
    maxEdges: normalizePositiveLimit(
      supplied?.maxEdges,
      DEFAULT_NPM_DEPENDENCY_PARSER_LIMITS.maxEdges,
    ),
    maxDepth: normalizePositiveLimit(
      supplied?.maxDepth,
      DEFAULT_NPM_DEPENDENCY_PARSER_LIMITS.maxDepth,
    ),
    maxLinkHops: normalizePositiveLimit(
      supplied?.maxLinkHops,
      DEFAULT_NPM_DEPENDENCY_PARSER_LIMITS.maxLinkHops,
    ),
    maxLocationLength: normalizePositiveLimit(
      supplied?.maxLocationLength,
      DEFAULT_NPM_DEPENDENCY_PARSER_LIMITS.maxLocationLength,
    ),
    maxIssues: normalizePositiveLimit(
      supplied?.maxIssues,
      DEFAULT_NPM_DEPENDENCY_PARSER_LIMITS.maxIssues,
    ),
    maxWorkspacePatternComparisons: normalizePositiveLimit(
      supplied?.maxWorkspacePatternComparisons,
      DEFAULT_NPM_DEPENDENCY_PARSER_LIMITS.maxWorkspacePatternComparisons,
    ),
    maxWorkspacePatternExpansions: normalizePositiveLimit(
      supplied?.maxWorkspacePatternExpansions,
      DEFAULT_NPM_DEPENDENCY_PARSER_LIMITS.maxWorkspacePatternExpansions,
    ),
  };
}

function parseDocument(
  value: unknown,
  label: string,
  issueCode: string,
  context: ParseContext,
): JsonRecord | undefined {
  let parsed = value;
  if (typeof value === "string") {
    try {
      parsed = JSON.parse(value) as unknown;
    } catch (_error: unknown) {
      context.addIssue("error", issueCode, `${label} is not valid JSON`);
      return undefined;
    }
  }

  if (!isRecord(parsed)) {
    context.addIssue("error", issueCode, `${label} must contain a JSON object`);
    return undefined;
  }
  return parsed;
}

function isValidPackageName(value: string): boolean {
  if (
    value.length === 0 ||
    value.length > 214 ||
    /[\u0000-\u0020\u007F\\]/u.test(value)
  ) {
    return false;
  }

  const segmentPattern = /^[A-Za-z0-9_.~-]+$/u;
  if (value.startsWith("@")) {
    const parts = value.split("/");
    return (
      parts.length === 2 &&
      parts[0] !== undefined &&
      parts[0].length > 1 &&
      segmentPattern.test(parts[0].slice(1)) &&
      parts[1] !== undefined &&
      parts[1] !== "." &&
      parts[1] !== ".." &&
      segmentPattern.test(parts[1])
    );
  }

  return (
    value !== "." &&
    value !== ".." &&
    !value.includes("/") &&
    segmentPattern.test(value)
  );
}

function isSafeVersion(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 256 &&
    !/[\u0000-\u001F\u007F]/u.test(value)
  );
}

function isSafeLockLocation(
  value: string,
  maximumLength: number,
  allowRoot: boolean,
): boolean {
  if (value === "") {
    return allowRoot;
  }
  if (
    value.length > maximumLength ||
    value.startsWith("/") ||
    /^[A-Za-z]:/u.test(value) ||
    /[\u0000-\u001F\u007F\\]/u.test(value)
  ) {
    return false;
  }

  const segments = value.split("/");
  return segments.every(
    (segment) => segment.length > 0 && segment !== "." && segment !== "..",
  );
}

function isNodeModulesLocation(location: string): boolean {
  return (
    location.startsWith("node_modules/") ||
    location.includes("/node_modules/")
  );
}

function packageSource(
  location: string,
  descriptor: JsonRecord,
  isLink: boolean,
): LockNode["source"] {
  if (isLink || (location.length > 0 && !isNodeModulesLocation(location))) {
    return "local";
  }
  const resolved = descriptor.resolved;
  if (typeof resolved !== "string" || resolved.length === 0) {
    // npm may omit registry tarball URLs from otherwise authoritative locks.
    return "registry";
  }
  if (
    resolved.trim() !== resolved ||
    /[\u0000-\u001F\u007F]/u.test(resolved)
  ) {
    return "remote";
  }
  const normalized = resolved.trim().toLowerCase();
  if (
    normalized.startsWith("git+") ||
    normalized.startsWith("git://") ||
    normalized.startsWith("github:") ||
    normalized.startsWith("gitlab:") ||
    normalized.startsWith("bitbucket:") ||
    normalized.startsWith("ssh:")
  ) {
    return "git";
  }
  if (
    normalized.startsWith("file:") ||
    normalized.startsWith("link:") ||
    normalized.startsWith("workspace:") ||
    normalized.startsWith("./") ||
    normalized.startsWith("../")
  ) {
    return "local";
  }
  try {
    const url = new URL(resolved);
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      return "remote";
    }
    if (
      url.username.length > 0 ||
      url.password.length > 0 ||
      (url.port.length > 0 && url.port !== "443" && url.port !== "80")
    ) {
      return "remote";
    }
    const hostname = url.hostname.toLowerCase();
    return hostname === "registry.npmjs.org" || hostname === "registry.npmjs.com"
      ? "registry"
      : "remote";
  } catch {
    return "remote";
  }
}

function installedNameFromLocation(location: string): string | undefined {
  let markerIndex: number;
  const nestedMarkerIndex = location.lastIndexOf("/node_modules/");
  if (nestedMarkerIndex !== -1) {
    markerIndex = nestedMarkerIndex + 1;
  } else if (location.startsWith("node_modules/")) {
    markerIndex = 0;
  } else {
    return undefined;
  }

  const remainder = location.slice(markerIndex + "node_modules/".length);
  const segments = remainder.split("/");
  const candidate = segments[0]?.startsWith("@")
    ? segments.length === 2
      ? `${segments[0]}/${segments[1] ?? ""}`
      : undefined
    : segments.length === 1
      ? segments[0]
      : undefined;

  return candidate !== undefined && isValidPackageName(candidate)
    ? candidate
    : undefined;
}

function safeDeclaredName(
  descriptor: JsonRecord,
  location: string,
  context: ParseContext,
): string | undefined {
  const declaredName = descriptor.name;
  if (declaredName === undefined) {
    return undefined;
  }
  if (typeof declaredName === "string" && isValidPackageName(declaredName)) {
    return declaredName;
  }

  context.addIssue(
    "warning",
    "INVALID_PACKAGE_NAME",
    `Ignored an invalid package name at ${sanitizeIssueValue(location || "<root>")}`,
  );
  return undefined;
}

function buildLockNodes(
  packages: JsonRecord,
  context: ParseContext,
): ReadonlyMap<string, LockNode> {
  const nodes = new Map<string, LockNode>();
  const locations = Object.keys(packages).sort((left, right) =>
    left.localeCompare(right),
  );

  if (locations.length > context.limits.maxPackages) {
    context.truncated = true;
    context.addIssue(
      "error",
      "PACKAGE_LIMIT_EXCEEDED",
      `Lockfile contains more than ${context.limits.maxPackages.toString()} package entries`,
    );
  }

  for (const location of locations.slice(0, context.limits.maxPackages)) {
    context.checkCancellation();
    if (
      !isSafeLockLocation(
        location,
        context.limits.maxLocationLength,
        true,
      )
    ) {
      context.addIssue(
        "warning",
        "INVALID_LOCKFILE_LOCATION",
        `Ignored unsafe lockfile location ${sanitizeIssueValue(location)}`,
      );
      continue;
    }

    const descriptor = packages[location];
    if (!isRecord(descriptor)) {
      context.addIssue(
        "warning",
        "INVALID_PACKAGE_ENTRY",
        `Ignored malformed package entry at ${sanitizeIssueValue(location || "<root>")}`,
      );
      continue;
    }

    const installName = installedNameFromLocation(location);
    const declaredName = safeDeclaredName(descriptor, location, context);
    const actualName =
      descriptor.name === undefined ? installName : declaredName;
    const isLink = descriptor.link === true;
    const source = packageSource(location, descriptor, isLink);
    let version: string | undefined;
    let linkTarget: string | undefined;

    if (isLink) {
      if (
        typeof descriptor.resolved === "string" &&
        isSafeLockLocation(
          descriptor.resolved,
          context.limits.maxLocationLength,
          true,
        )
      ) {
        linkTarget = descriptor.resolved;
      } else {
        context.addIssue(
          "warning",
          "INVALID_LINK_TARGET",
          `Ignored an invalid link target at ${sanitizeIssueValue(location)}`,
        );
      }
    } else if (descriptor.version !== undefined) {
      if (
        typeof descriptor.version === "string" &&
        isSafeVersion(descriptor.version)
      ) {
        version = descriptor.version;
      } else {
        context.addIssue(
          "warning",
          "INVALID_PACKAGE_VERSION",
          `Ignored an invalid package version at ${sanitizeIssueValue(location || "<root>")}`,
        );
      }
    }

    nodes.set(location, {
      location,
      descriptor,
      ...(installName === undefined ? {} : { installName }),
      ...(actualName === undefined ? {} : { actualName }),
      ...(version === undefined ? {} : { version }),
      ...(linkTarget === undefined ? {} : { linkTarget }),
      isLink,
      dev: descriptor.dev === true,
      optional: descriptor.optional === true,
      devOptional: descriptor.devOptional === true,
      source,
    });
  }

  return nodes;
}

function peerIsOptional(descriptor: JsonRecord, packageName: string): boolean {
  const metadata = descriptor.peerDependenciesMeta;
  if (!isRecord(metadata)) {
    return false;
  }
  const entry = metadata[packageName];
  return isRecord(entry) && entry.optional === true;
}

function applyDependencyMap(
  owner: JsonRecord,
  field: string,
  edges: Map<string, EdgeDeclaration>,
  kind: EdgeKind,
  overwrite: boolean,
  context: ParseContext,
): void {
  const rawMap = owner[field];
  if (rawMap === undefined) {
    return;
  }
  if (!isRecord(rawMap)) {
    context.addIssue(
      "warning",
      "INVALID_DEPENDENCY_MAP",
      `Ignored malformed ${field}`,
    );
    return;
  }

  for (const [installName, rawVersion] of Object.entries(rawMap).sort(
    ([left], [right]) => left.localeCompare(right),
  )) {
    context.checkCancellation();
    if (!context.consumeEdge()) {
      return;
    }
    if (!isValidPackageName(installName)) {
      context.addIssue(
        "warning",
        "INVALID_DEPENDENCY_NAME",
        `Ignored invalid dependency name ${sanitizeIssueValue(installName)}`,
      );
      continue;
    }
    if (
      typeof rawVersion !== "string" ||
      rawVersion.length === 0 ||
      rawVersion.length > 2_048 ||
      /[\u0000-\u001F\u007F]/u.test(rawVersion)
    ) {
      context.addIssue(
        "warning",
        "INVALID_DEPENDENCY_SPEC",
        `Ignored invalid dependency specification for ${sanitizeIssueValue(installName)}`,
      );
      continue;
    }
    if (!overwrite && edges.has(installName)) {
      continue;
    }

    edges.set(installName, {
      installName,
      requestedVersion: rawVersion,
      kind,
      optionalPeer:
        kind === "peer" && peerIsOptional(owner, installName),
    });
  }
}

function rootEdges(
  packageJson: JsonRecord,
  context: ParseContext,
): readonly EdgeDeclaration[] {
  const edges = new Map<string, EdgeDeclaration>();

  applyDependencyMap(
    packageJson,
    "peerDependencies",
    edges,
    "peer",
    true,
    context,
  );
  applyDependencyMap(
    packageJson,
    "devDependencies",
    edges,
    "development",
    true,
    context,
  );
  applyDependencyMap(
    packageJson,
    "dependencies",
    edges,
    "production",
    true,
    context,
  );
  applyDependencyMap(
    packageJson,
    "optionalDependencies",
    edges,
    "optional",
    true,
    context,
  );

  return [...edges.values()].sort((left, right) =>
    left.installName.localeCompare(right.installName),
  );
}

function childEdges(
  node: LockNode,
  context: ParseContext,
): readonly EdgeDeclaration[] {
  const edges = new Map<string, EdgeDeclaration>();
  applyDependencyMap(
    node.descriptor,
    "dependencies",
    edges,
    "production",
    true,
    context,
  );
  applyDependencyMap(
    node.descriptor,
    "optionalDependencies",
    edges,
    "optional",
    true,
    context,
  );
  applyDependencyMap(
    node.descriptor,
    "peerDependencies",
    edges,
    "peer",
    false,
    context,
  );

  return [...edges.values()].sort((left, right) =>
    left.installName.localeCompare(right.installName),
  );
}

function directoryName(location: string): string {
  const separatorIndex = location.lastIndexOf("/");
  return separatorIndex === -1 ? "" : location.slice(0, separatorIndex);
}

function baseName(location: string): string {
  const separatorIndex = location.lastIndexOf("/");
  return separatorIndex === -1
    ? location
    : location.slice(separatorIndex + 1);
}

function resolutionCandidates(
  parentLocation: string,
  installName: string,
  maximumLength: number,
): readonly string[] {
  const candidates: string[] = [];
  let currentLocation = parentLocation;

  while (true) {
    if (baseName(currentLocation) !== "node_modules") {
      const candidate =
        currentLocation.length === 0
          ? `node_modules/${installName}`
          : `${currentLocation}/node_modules/${installName}`;
      if (candidate.length <= maximumLength) {
        candidates.push(candidate);
      }
    }
    if (currentLocation.length === 0) {
      return candidates;
    }
    currentLocation = directoryName(currentLocation);
  }
}

function resolveLinks(
  initialNode: LockNode,
  nodes: ReadonlyMap<string, LockNode>,
  context: ParseContext,
): LockNode | undefined {
  let node = initialNode;
  const visited = new Set<string>();

  for (let hop = 0; hop < context.limits.maxLinkHops; hop += 1) {
    context.checkCancellation();
    if (!node.isLink) {
      return node;
    }
    if (visited.has(node.location)) {
      context.addIssue(
        "warning",
        "LINK_CYCLE",
        `Ignored cyclic lockfile link at ${sanitizeIssueValue(node.location)}`,
      );
      return undefined;
    }
    visited.add(node.location);

    if (node.linkTarget === undefined) {
      return undefined;
    }
    const target = nodes.get(node.linkTarget);
    if (target === undefined) {
      context.addIssue(
        "warning",
        "MISSING_LINK_TARGET",
        `Lockfile link target is missing for ${sanitizeIssueValue(node.location)}`,
      );
      return undefined;
    }
    node = target;
  }

  if (!node.isLink) {
    return node;
  }

  context.addIssue(
    "warning",
    "LINK_HOP_LIMIT_EXCEEDED",
    `Ignored lockfile link exceeding ${context.limits.maxLinkHops.toString()} hops`,
  );
  context.truncated = true;
  return undefined;
}

function resolveEdge(
  parentLocation: string,
  edge: EdgeDeclaration,
  nodes: ReadonlyMap<string, LockNode>,
  context: ParseContext,
): LockNode | undefined {
  for (const candidate of resolutionCandidates(
    parentLocation,
    edge.installName,
    context.limits.maxLocationLength,
  )) {
    const initialNode = nodes.get(candidate);
    if (initialNode === undefined) {
      continue;
    }
    const resolvedNode = resolveLinks(initialNode, nodes, context);
    if (resolvedNode === undefined) {
      return undefined;
    }
    if (
      resolvedNode.source === "registry" &&
      (resolvedNode.actualName === undefined || resolvedNode.version === undefined)
    ) {
      context.reportInvalidResolvedPackage(resolvedNode.location);
      return undefined;
    }
    if (!edgeMatchesResolvedNode(edge, resolvedNode)) {
      if (edge.kind !== "optional" && !edge.optionalPeer) {
        context.unresolvedDependencies += 1;
        context.addIssue(
          "warning",
          "STALE_LOCKFILE_DEPENDENCY",
          `Resolved lockfile package does not match the declared edge for ${sanitizeIssueValue(edge.installName)}`,
        );
      }
      return undefined;
    }
    return resolvedNode;
  }

  if (edge.kind !== "optional" && !edge.optionalPeer) {
    context.unresolvedDependencies += 1;
    context.addIssue(
      "warning",
      "UNRESOLVED_DEPENDENCY",
      `No resolved lockfile package was found for ${sanitizeIssueValue(edge.installName)}`,
    );
  }
  return undefined;
}

function rootLabel(packageJson: JsonRecord): string {
  const name = packageJson.name;
  if (
    typeof name === "string" &&
    name.length > 0 &&
    name.length <= 214 &&
    !/[\u0000-\u001F\u007F]/u.test(name)
  ) {
    return name;
  }
  return "application";
}

function classifyDirectEnvironment(
  node: LockNode,
): DependencyEnvironment {
  return classifyTransitiveEnvironment(node);
}

function declaredEnvironment(
  edge: EdgeDeclaration,
): DependencyEnvironment {
  if (edge.kind === "optional" || edge.optionalPeer) {
    return "optional";
  }
  if (edge.kind === "development") {
    return "development";
  }
  return "production";
}

function classifyTransitiveEnvironment(
  node: LockNode,
): DependencyEnvironment {
  if (node.optional || node.devOptional) {
    return "optional";
  }
  if (node.dev) {
    return "development";
  }
  // npm marks packages that are exclusively development/optional in the
  // lockfile. An unmarked package participates in the production graph, even
  // if the first shortest path encountered happens to start at a dev tool.
  return "production";
}

function nodeLabel(node: LockNode): string {
  const name = node.actualName ?? node.installName ?? "unknown-package";
  return `${name}@${node.version ?? "unknown"}`;
}

function dependencyFromQueueEntry(
  entry: QueueEntry,
  input: NpmDependencyParserInput,
  context: ParseContext,
  workspaceLocations: ReadonlySet<string>,
): Dependency | undefined {
  if (workspaceLocations.has(entry.node.location)) {
    return undefined;
  }
  if (entry.node.source !== "registry") {
    context.reportUnsupportedSource(entry.node.location, entry.node.source);
    return undefined;
  }
  const name = entry.node.actualName;
  const installedVersion = entry.node.version;
  if (name === undefined || installedVersion === undefined) {
    context.reportInvalidResolvedPackage(entry.node.location);
    return undefined;
  }

  return {
    name,
    ecosystem: "npm",
    requestedVersion: entry.incomingEdge.requestedVersion,
    manifestName: entry.incomingEdge.installName,
    installedVersion,
    dependencyType: entry.direct ? "direct" : "transitive",
    environment: entry.environment,
    ...(entry.direct
      ? { declaredEnvironment: declaredEnvironment(entry.incomingEdge) }
      : {}),
    ...(entry.parentLabel === undefined ? {} : { parent: entry.parentLabel }),
    dependencyPath: [...entry.dependencyPath],
    packageJsonPath: entry.packageJsonPath,
    ...(input.lockfilePath === undefined
      ? {}
      : { lockfilePath: input.lockfilePath }),
  };
}

interface ParsedWorkspaceManifest {
  readonly location: string;
  readonly packageJson: JsonRecord;
  readonly packageJsonPath: string;
}

interface WorkspacePattern {
  readonly excluded: boolean;
  readonly matcher: Minimatch;
}

function workspacePatterns(
  packageJson: JsonRecord,
  context: ParseContext,
): readonly WorkspacePattern[] {
  const rawWorkspaces = packageJson.workspaces;
  const rawPatterns = Array.isArray(rawWorkspaces)
    ? rawWorkspaces
    : isRecord(rawWorkspaces) && Array.isArray(rawWorkspaces.packages)
      ? rawWorkspaces.packages
      : undefined;
  if (rawWorkspaces === undefined) {
    return [];
  }
  if (rawPatterns === undefined) {
    context.addIssue(
      "warning",
      "INVALID_WORKSPACES_CONFIG",
      "Ignored a malformed package.json workspaces declaration",
    );
    return [];
  }
  if (rawPatterns.length > 1_000) {
    context.addIssue(
      "error",
      "WORKSPACE_PATTERN_LIMIT_EXCEEDED",
      "package.json contains too many workspace patterns",
    );
    context.truncated = true;
  }

  const patterns: WorkspacePattern[] = [];
  for (const rawPattern of rawPatterns.slice(0, 1_000)) {
    context.checkCancellation();
    if (
      typeof rawPattern !== "string" ||
      rawPattern.length === 0 ||
      rawPattern.length > 2_048 ||
      /[\u0000-\u001F\u007F\\]/u.test(rawPattern)
    ) {
      context.addIssue(
        "warning",
        "INVALID_WORKSPACE_PATTERN",
        "Ignored an unsafe package.json workspace pattern",
      );
      continue;
    }
    const excluded = rawPattern.startsWith("!");
    let pattern = excluded ? rawPattern.slice(1) : rawPattern;
    pattern = pattern.replace(/^\.\//u, "").replace(/\/$/u, "");
    if (
      pattern.length === 0 ||
      pattern.startsWith("/") ||
      pattern.split("/").includes("..")
    ) {
      context.addIssue(
        "warning",
        "INVALID_WORKSPACE_PATTERN",
        "Ignored an unsafe package.json workspace pattern",
      );
      continue;
    }
    try {
      const expansions = braceExpand(pattern, {
        braceExpandMax: MAX_EXPANSIONS_PER_WORKSPACE_PATTERN + 1,
      });
      if (expansions.length > MAX_EXPANSIONS_PER_WORKSPACE_PATTERN) {
        context.reportWorkspacePatternComplexityLimit();
        break;
      }
      if (!context.consumeWorkspacePatternExpansions(expansions.length)) {
        break;
      }
      patterns.push({
        excluded,
        matcher: new Minimatch(pattern, {
          braceExpandMax: MAX_EXPANSIONS_PER_WORKSPACE_PATTERN,
          dot: false,
          maxGlobstarRecursion: 16,
          nocase: false,
          nocomment: true,
          nonegate: true,
          platform: "linux",
        }),
      });
    } catch {
      context.addIssue(
        "warning",
        "INVALID_WORKSPACE_PATTERN",
        "Ignored a package.json workspace pattern that could not be evaluated",
      );
    }
  }
  return patterns;
}

interface WorkspaceMatchResult {
  readonly configured: boolean;
  readonly complete: boolean;
}

function isConfiguredWorkspace(
  location: string,
  patterns: readonly WorkspacePattern[],
  context: ParseContext,
): WorkspaceMatchResult {
  let configured = false;
  for (const workspacePattern of patterns) {
    if (!context.consumeWorkspacePatternComparison()) {
      return { configured, complete: false };
    }
    if (workspacePattern.matcher.match(location)) {
      configured = !workspacePattern.excluded;
    }
  }
  return { configured, complete: true };
}

function configuredWorkspaceLocations(
  nodes: ReadonlyMap<string, LockNode>,
  packageJson: JsonRecord,
  context: ParseContext,
): ReadonlySet<string> {
  const patterns = workspacePatterns(packageJson, context);
  const locations = new Set<string>();
  for (const node of nodes.values()) {
    context.checkCancellation();
    if (node.location.length === 0 || isNodeModulesLocation(node.location)) {
      continue;
    }
    const match = isConfiguredWorkspace(node.location, patterns, context);
    if (!match.complete) {
      break;
    }
    if (match.configured) {
      locations.add(node.location);
    }
  }
  return locations;
}

function parseWorkspaceManifests(
  supplied: readonly NpmWorkspaceManifestInput[] | undefined,
  nodes: ReadonlyMap<string, LockNode>,
  workspaceLocations: ReadonlySet<string>,
  context: ParseContext,
): ReadonlyMap<string, ParsedWorkspaceManifest> {
  const manifests = new Map<string, ParsedWorkspaceManifest>();
  const retained = (supplied ?? []).slice(0, context.limits.maxPackages);
  if ((supplied?.length ?? 0) > retained.length) {
    context.truncated = true;
    context.addIssue(
      "error",
      "WORKSPACE_MANIFEST_LIMIT_EXCEEDED",
      "Workspace manifest input exceeds the package safety limit",
    );
  }

  for (const manifest of retained) {
    context.checkCancellation();
    if (
      !isSafeLockLocation(
        manifest.location,
        context.limits.maxLocationLength,
        false,
      ) ||
      isNodeModulesLocation(manifest.location)
    ) {
      context.addIssue(
        "warning",
        "INVALID_WORKSPACE_LOCATION",
        "Ignored a workspace manifest with an unsafe lockfile location",
      );
      continue;
    }
    if (
      manifest.packageJsonPath.length === 0 ||
      manifest.packageJsonPath.length > 8_192 ||
      /[\u0000-\u001F\u007F]/u.test(manifest.packageJsonPath)
    ) {
      context.addIssue(
        "warning",
        "INVALID_WORKSPACE_MANIFEST_PATH",
        `Ignored an invalid workspace manifest path at ${sanitizeIssueValue(manifest.location)}`,
      );
      continue;
    }
    const node = nodes.get(manifest.location);
    if (node === undefined || !workspaceLocations.has(manifest.location)) {
      context.addIssue(
        "warning",
        "WORKSPACE_NOT_LOCKED",
        `Manifest is not a configured locked workspace at ${sanitizeIssueValue(manifest.location)}`,
      );
      continue;
    }
    if (manifests.has(manifest.location)) {
      context.addIssue(
        "warning",
        "DUPLICATE_WORKSPACE_MANIFEST",
        `Ignored a duplicate workspace manifest at ${sanitizeIssueValue(manifest.location)}`,
      );
      continue;
    }
    const parsed = parseDocument(
      manifest.packageJson,
      `workspace package.json at ${sanitizeIssueValue(manifest.location)}`,
      "INVALID_WORKSPACE_PACKAGE_JSON",
      context,
    );
    if (parsed !== undefined) {
      manifests.set(manifest.location, {
        location: manifest.location,
        packageJson: parsed,
        packageJsonPath: manifest.packageJsonPath,
      });
    }
  }
  return manifests;
}

function enqueueDirectDependencies(
  owner: JsonRecord,
  parentLocation: string,
  packageJsonPath: string,
  originKey: string,
  nodes: ReadonlyMap<string, LockNode>,
  context: ParseContext,
  queue: QueueEntry[],
): void {
  const applicationLabel = rootLabel(owner);
  for (const edge of rootEdges(owner, context)) {
    const node = resolveEdge(parentLocation, edge, nodes, context);
    if (node === undefined) {
      continue;
    }
    queue.push({
      node,
      incomingEdge: edge,
      dependencyPath: [applicationLabel, nodeLabel(node)],
      environment: classifyDirectEnvironment(node),
      packageJsonPath,
      originKey,
      direct: true,
      depth: 1,
    });
  }
}

function edgeMatchesResolvedNode(
  edge: EdgeDeclaration,
  node: LockNode,
): boolean {
  if (node.source !== "registry") {
    return true;
  }
  if (node.version === undefined) {
    return false;
  }
  let requestedVersion = edge.requestedVersion;
  if (requestedVersion.startsWith("npm:")) {
    const alias = /^npm:((?:@[A-Za-z0-9._~-]+\/)?[A-Za-z0-9._~-]+)@(.+)$/u.exec(
      requestedVersion,
    );
    const expectedName = alias?.[1];
    const aliasRange = alias?.[2];
    if (
      expectedName === undefined ||
      aliasRange === undefined ||
      node.actualName !== expectedName
    ) {
      return false;
    }
    requestedVersion = aliasRange;
  } else if (node.actualName !== edge.installName) {
    return false;
  }
  const range = validRange(requestedVersion);
  if (range !== null) {
    return satisfies(node.version, range);
  }
  // Registry tags are snapshots whose exact installed version is authoritative
  // in the lock. Protocols, URLs, paths, and malformed specifications are not.
  return /^[A-Za-z][A-Za-z0-9._-]{0,127}$/u.test(requestedVersion);
}

function parseModernLockfile(
  packageJson: JsonRecord,
  lockfile: JsonRecord,
  input: NpmDependencyParserInput,
  context: ParseContext,
): NpmDependencyParseResult {
  if (
    lockfile.lockfileVersion !== 2 &&
    lockfile.lockfileVersion !== 3
  ) {
    context.addIssue(
      "error",
      "UNSUPPORTED_LOCKFILE_VERSION",
      "Only npm package-lock versions 2 and 3 are supported",
    );
    return {
      dependencies: [],
      issues: context.issues,
      unresolvedDependencies: context.unresolvedDependencies,
      truncated: context.truncated,
      cancelled: false,
    };
  }

  if (!isRecord(lockfile.packages)) {
    context.addIssue(
      "error",
      "INVALID_PACKAGES_MAP",
      "The npm lockfile does not contain a valid packages map",
    );
    return {
      dependencies: [],
      issues: context.issues,
      unresolvedDependencies: context.unresolvedDependencies,
      truncated: context.truncated,
      cancelled: false,
    };
  }

  const nodes = buildLockNodes(lockfile.packages, context);
  if (!nodes.has("")) {
    context.addIssue(
      "warning",
      "MISSING_ROOT_PACKAGE",
      "The npm lockfile packages map does not contain a root entry",
    );
  }

  const queue: QueueEntry[] = [];
  enqueueDirectDependencies(
    packageJson,
    "",
    input.packageJsonPath,
    "<root>",
    nodes,
    context,
    queue,
  );

  const workspaceLocations = configuredWorkspaceLocations(
    nodes,
    packageJson,
    context,
  );
  const workspaceManifests = parseWorkspaceManifests(
    input.workspaceManifests,
    nodes,
    workspaceLocations,
    context,
  );
  for (const location of workspaceLocations) {
    const node = nodes.get(location);
    if (node === undefined) {
      continue;
    }
    const manifest = workspaceManifests.get(node.location);
    if (manifest === undefined) {
      context.addIssue(
        "warning",
        "WORKSPACE_MANIFEST_MISSING",
        `Workspace lock entry has no readable package.json at ${sanitizeIssueValue(node.location)}`,
      );
    }
    enqueueDirectDependencies(
      manifest?.packageJson ?? node.descriptor,
      node.location,
      manifest?.packageJsonPath ?? input.packageJsonPath,
      `workspace:${node.location}`,
      nodes,
      context,
      queue,
    );
  }

  const dependencies: Dependency[] = [];
  const visited = new Set<string>();
  let nextIndex = 0;

  while (nextIndex < queue.length) {
    context.checkCancellation();
    const entry = queue[nextIndex];
    nextIndex += 1;
    const visitKey =
      entry === undefined
        ? undefined
        : `${entry.originKey}\u0000${entry.node.location}`;
    if (entry === undefined || visitKey === undefined || visited.has(visitKey)) {
      continue;
    }
    visited.add(visitKey);

    const dependency = dependencyFromQueueEntry(
      entry,
      input,
      context,
      workspaceLocations,
    );
    if (dependency !== undefined) {
      dependencies.push(dependency);
    }

    if (entry.depth >= context.limits.maxDepth) {
      context.truncated = true;
      context.addIssue(
        "warning",
        "DEPENDENCY_DEPTH_LIMIT_EXCEEDED",
        `Stopped traversing dependencies at depth ${context.limits.maxDepth.toString()}`,
      );
      continue;
    }

    const parentLabel = nodeLabel(entry.node);
    for (const edge of childEdges(entry.node, context)) {
      const child = resolveEdge(entry.node.location, edge, nodes, context);
      if (
        child === undefined ||
        visited.has(`${entry.originKey}\u0000${child.location}`)
      ) {
        continue;
      }
      queue.push({
        node: child,
        incomingEdge: edge,
        dependencyPath: [...entry.dependencyPath, nodeLabel(child)],
        parentLabel,
        environment: classifyTransitiveEnvironment(child),
        packageJsonPath: entry.packageJsonPath,
        originKey: entry.originKey,
        direct: false,
        depth: entry.depth + 1,
      });
    }
  }

  return {
    dependencies,
    issues: context.issues,
    unresolvedDependencies: context.unresolvedDependencies,
    truncated: context.truncated,
    cancelled: false,
  };
}

export function parseNpmDependencies(
  input: NpmDependencyParserInput,
): NpmDependencyParseResult {
  const context = new ParseContext(normalizeLimits(input.limits), input.signal);

  try {
    context.checkCancellation();
    const packageJson = parseDocument(
      input.packageJson,
      "package.json",
      "INVALID_PACKAGE_JSON",
      context,
    );
    if (packageJson === undefined) {
      return {
        dependencies: [],
        issues: context.issues,
        unresolvedDependencies: 0,
        truncated: context.truncated,
        cancelled: false,
      };
    }

    if (input.lockfile === undefined) {
      context.addIssue(
        "error",
        "LOCKFILE_MISSING",
        "A package-lock.json is required to determine resolved npm versions",
      );
      return {
        dependencies: [],
        issues: context.issues,
        unresolvedDependencies: 0,
        truncated: context.truncated,
        cancelled: false,
      };
    }

    const lockfile = parseDocument(
      input.lockfile,
      "package-lock.json",
      "INVALID_LOCKFILE_JSON",
      context,
    );
    if (lockfile === undefined) {
      return {
        dependencies: [],
        issues: context.issues,
        unresolvedDependencies: 0,
        truncated: context.truncated,
        cancelled: false,
      };
    }

    return parseModernLockfile(packageJson, lockfile, input, context);
  } catch (error: unknown) {
    if (error instanceof ParserCancelledError) {
      return {
        dependencies: [],
        issues: [
          ...context.issues,
          {
            level: "warning",
            code: "CANCELLED",
            message: "npm dependency parsing was cancelled",
          },
        ],
        unresolvedDependencies: context.unresolvedDependencies,
        truncated: context.truncated,
        cancelled: true,
      };
    }
    throw error;
  }
}
