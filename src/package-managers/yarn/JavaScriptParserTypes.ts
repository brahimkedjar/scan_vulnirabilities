import {
  parseTree,
  type Node as JsonNode,
  type ParseError,
} from "jsonc-parser";

import type { Dependency } from "../../models/Dependency";

export const MAX_PACKAGES = 10_000;
export const MAX_EDGES = 50_000;
export const MAX_DEPTH = 256;
export const MAX_ISSUES = 1_000;

export interface JavaScriptParseIssue {
  readonly code:
    | "INVALID_MANIFEST"
    | "INVALID_LOCKFILE"
    | "UNSUPPORTED_LOCKFILE"
    | "UNSUPPORTED_PACKAGE_SOURCE"
    | "DEPENDENCY_UNRESOLVED"
    | "DEPENDENCY_LIMIT";
  readonly message: string;
  readonly packageName?: string;
}

export interface JavaScriptParseResult {
  readonly dependencies: readonly Dependency[];
  readonly issues: readonly JavaScriptParseIssue[];
  readonly discovered: number;
  readonly resolved: number;
  readonly unresolved: number;
  readonly unsupported: number;
  readonly truncated: boolean;
  readonly cancelled: boolean;
}

export interface ManifestInput {
  readonly path: string;
  readonly relativeDirectory: string;
  readonly content: string;
}

export interface ManifestDependencyEdge {
  readonly name: string;
  readonly requestedVersion: string;
  readonly environment: Dependency["environment"];
}

export interface ManifestDependencyParseResult {
  readonly edges: readonly ManifestDependencyEdge[];
  readonly issues: readonly JavaScriptParseIssue[];
}

const NPM_PACKAGE_NAME =
  /^(?:@[a-z0-9][a-z0-9._~-]*\/[a-z0-9][a-z0-9._~-]*|[a-z0-9][a-z0-9._~-]*)$/iu;
const MANIFEST_SECTIONS = [
  ["dependencies", "production"],
  ["peerDependencies", "peer"],
  ["optionalDependencies", "optional"],
  ["devDependencies", "development"],
] as const;
const MAX_MANIFEST_JSON_NODES = 250_000;
const MAX_MANIFEST_JSON_DEPTH = 128;

function environmentRank(environment: Dependency["environment"]): number {
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

function propertyEntries(
  node: JsonNode,
): readonly { readonly key: string; readonly value: JsonNode }[] | undefined {
  if (node.type !== "object") {
    return undefined;
  }
  const output: Array<{ readonly key: string; readonly value: JsonNode }> = [];
  const keys = new Set<string>();
  for (const property of node.children ?? []) {
    const key = property.children?.[0]?.value;
    const value = property.children?.[1];
    if (typeof key !== "string" || value === undefined || keys.has(key)) {
      return undefined;
    }
    keys.add(key);
    output.push({ key, value });
  }
  return output;
}

function manifestTreeIsBounded(root: JsonNode): boolean {
  const queue: Array<{ readonly node: JsonNode; readonly depth: number }> = [
    { node: root, depth: 0 },
  ];
  for (let index = 0; index < queue.length; index += 1) {
    const entry = queue[index];
    if (
      entry === undefined ||
      index >= MAX_MANIFEST_JSON_NODES ||
      entry.depth > MAX_MANIFEST_JSON_DEPTH
    ) {
      return false;
    }
    for (const child of entry.node.children ?? []) {
      queue.push({ node: child, depth: entry.depth + 1 });
    }
  }
  return true;
}

/**
 * Parses only direct package.json declarations. Lock parsers use this to prove
 * that a lock importer/workspace still represents the current manifest rather
 * than silently trusting stale lock state.
 */
export function parseManifestDependencyEdges(
  manifest: ManifestInput,
  includeDevDependencies: boolean,
): ManifestDependencyParseResult {
  const parseErrors: ParseError[] = [];
  const root = parseTree(manifest.content, parseErrors, {
    allowEmptyContent: false,
    allowTrailingComma: false,
    disallowComments: true,
  });
  const invalid = (message: string): ManifestDependencyParseResult => ({
    edges: [],
    issues: [
      {
        code: "INVALID_MANIFEST",
        message: `${message} at ${manifest.path}`,
      },
    ],
  });
  if (
    root === undefined ||
    root.type !== "object" ||
    parseErrors.length > 0
  ) {
    return invalid("Could not parse package.json");
  }
  if (!manifestTreeIsBounded(root)) {
    return {
      edges: [],
      issues: [
        {
          code: "DEPENDENCY_LIMIT",
          message: `package.json structure exceeds its complexity limit at ${manifest.path}`,
        },
      ],
    };
  }
  const rootEntries = propertyEntries(root);
  if (rootEntries === undefined) {
    return invalid("package.json contains a duplicate or invalid property");
  }
  const rootByName = new Map(rootEntries.map((entry) => [entry.key, entry.value]));
  const edges = new Map<string, ManifestDependencyEdge>();
  const issues: JavaScriptParseIssue[] = [];
  for (const [section, environment] of MANIFEST_SECTIONS) {
    if (environment === "development" && !includeDevDependencies) {
      continue;
    }
    const sectionNode = rootByName.get(section);
    if (sectionNode === undefined) {
      continue;
    }
    const entries = propertyEntries(sectionNode);
    if (entries === undefined) {
      issues.push({
        code: "INVALID_MANIFEST",
        message: `package.json ${section} must be an object with unique keys at ${manifest.path}`,
      });
      continue;
    }
    for (const entry of entries) {
      const requestedVersion = entry.value.value;
      if (
        !NPM_PACKAGE_NAME.test(entry.key) ||
        typeof requestedVersion !== "string" ||
        safeString(requestedVersion, 8_192) === undefined
      ) {
        issues.push({
          code: "INVALID_MANIFEST",
          message: `Ignored an invalid ${section} declaration at ${manifest.path}`,
          ...(NPM_PACKAGE_NAME.test(entry.key)
            ? { packageName: entry.key }
            : {}),
        });
        continue;
      }
      const previous = edges.get(entry.key);
      if (
        previous === undefined ||
        environmentRank(environment) >= environmentRank(previous.environment)
      ) {
        edges.set(entry.key, {
          name: entry.key,
          requestedVersion,
          environment,
        });
      }
    }
  }
  return { edges: [...edges.values()], issues };
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function safeString(
  value: unknown,
  maximumLength = 8_192,
): string | undefined {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximumLength &&
    !/[\u0000-\u001F\u007F]/u.test(value)
    ? value
    : undefined;
}

export function isSafeRelativePath(value: string): boolean {
  if (
    value.length === 0 ||
    value.length > 4_096 ||
    value.startsWith("/") ||
    value.includes("\\") ||
    /[\u0000-\u001F\u007F]/u.test(value)
  ) {
    return false;
  }
  const segments = value.split("/");
  return segments.every(
    (segment) => segment.length > 0 && segment !== ".." && segment !== ".",
  );
}
