import { parse as parseYaml } from "yaml";

import {
  dependencyIsResolved,
  type Dependency,
} from "../../models/Dependency";
import type { ScanError } from "../../models/ScanResult";
import type { JavaScriptParseResult } from "../yarn/JavaScriptParserTypes";

export type WorkspaceRegistryConfigKind =
  | "npmrc"
  | "yarnrc"
  | "yarnrc-yaml"
  | "bunfig-toml";

export interface WorkspaceRegistryConfigAssessment {
  readonly path: string;
  readonly directoryPath: string;
  readonly blockAll: boolean;
  readonly blockedScopes: readonly string[];
  readonly packageManagers?: readonly string[];
}

export interface WorkspaceRegistrySnapshot {
  readonly configs: readonly WorkspaceRegistryConfigAssessment[];
  /** Discovery or bounded reading was incomplete, so no registry can be proven. */
  readonly incomplete: boolean;
}

export interface WorkspaceRegistryGateResult {
  readonly dependencies: readonly Dependency[];
  readonly affectedCount: number;
  readonly affectedByProject: readonly {
    readonly projectPath: string;
    readonly count: number;
  }[];
  readonly resolvedToUnsupported: number;
  readonly unresolvedToUnsupported: number;
}

export interface JavaScriptRegistryGateResult {
  readonly result: JavaScriptParseResult;
  readonly affectedCount: number;
}

const MAX_CONFIG_CHARACTERS = 64 * 1024;
const MAX_CONFIG_LINES = 4_096;
const MAX_CONFIG_LINE_CHARACTERS = 8_192;
const MAX_SCOPES = 256;
const SCOPE = /^@[a-z0-9][a-z0-9._~-]{0,213}$/iu;
const SCOPED_PACKAGE = /^(@[a-z0-9][a-z0-9._~-]{0,213})\//iu;
const CANONICAL_REGISTRY =
  /^https:\/\/(?:registry\.npmjs\.(?:org|com)|registry\.yarnpkg\.com)(?::443)?\/?$/iu;

interface MutableAssessment {
  blockAll: boolean;
  readonly blockedScopes: Set<string>;
  readonly seenDirectives: Map<string, string>;
}

function unquote(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.length < 2) {
    return trimmed;
  }
  const first = trimmed[0];
  const last = trimmed.at(-1);
  if (first === '"' || first === "'") {
    return last === first ? trimmed.slice(1, -1) : undefined;
  }
  return last === '"' || last === "'" ? undefined : trimmed;
}

function canonicalRegistry(value: string): string | undefined {
  const unquoted = unquote(value);
  if (unquoted === undefined || !CANONICAL_REGISTRY.test(unquoted)) {
    return undefined;
  }
  return unquoted.toLowerCase().replace(/\/$/u, "");
}

function normalizeScope(value: string): string | undefined {
  const trimmed = value.trim();
  const scope = trimmed.startsWith("@") ? trimmed : `@${trimmed}`;
  return SCOPE.test(scope) ? scope.toLowerCase() : undefined;
}

function registerDirective(
  assessment: MutableAssessment,
  scope: string | undefined,
  rawValue: string | undefined,
): void {
  const normalizedScope = scope === undefined ? undefined : normalizeScope(scope);
  if (scope !== undefined && normalizedScope === undefined) {
    assessment.blockAll = true;
    return;
  }
  const selector = normalizedScope ?? "*";
  const registry = rawValue === undefined ? undefined : canonicalRegistry(rawValue);
  const previous = assessment.seenDirectives.get(selector);
  if (
    registry === undefined ||
    (previous !== undefined && previous !== registry)
  ) {
    if (normalizedScope === undefined) {
      assessment.blockAll = true;
    } else {
      assessment.blockedScopes.add(normalizedScope);
    }
    return;
  }
  assessment.seenDirectives.set(selector, registry);
}

function boundedLines(content: string): readonly string[] | undefined {
  if (content.length > MAX_CONFIG_CHARACTERS) {
    return undefined;
  }
  const lines = content.split(/\r?\n/u);
  if (
    lines.length > MAX_CONFIG_LINES ||
    lines.some((line) => line.length > MAX_CONFIG_LINE_CHARACTERS)
  ) {
    return undefined;
  }
  return lines;
}

function npmrcSelector(key: string):
  | { readonly relevant: false }
  | { readonly relevant: true; readonly scope?: string } {
  const normalized = key.trim().toLowerCase();
  if (normalized === "registry") {
    return { relevant: true };
  }
  const scopeMatch = /^(@[^\s/:]+):registry$/iu.exec(normalized);
  if (scopeMatch?.[1] !== undefined) {
    return { relevant: true, scope: scopeMatch[1] };
  }
  return { relevant: false };
}

function looksLikeMalformedRegistryDirective(line: string): {
  readonly relevant: boolean;
  readonly scope?: string;
} {
  const normalized = line.trim().replace(/^--/u, "");
  if (/^registry(?:\s|=|:|$)/iu.test(normalized)) {
    return { relevant: true };
  }
  const match = /^(@[^\s/:]+):registry(?:\s|=|:|$)/iu.exec(normalized);
  return match?.[1] === undefined
    ? { relevant: false }
    : { relevant: true, scope: match[1] };
}

function inspectNpmrc(
  lines: readonly string[],
  assessment: MutableAssessment,
): void {
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#") || line.startsWith(";")) {
      continue;
    }
    const separator = line.indexOf("=");
    if (separator === -1) {
      const malformed = looksLikeMalformedRegistryDirective(line);
      if (malformed.relevant) {
        registerDirective(assessment, malformed.scope, undefined);
      }
      continue;
    }
    const selector = npmrcSelector(line.slice(0, separator));
    if (selector.relevant) {
      registerDirective(assessment, selector.scope, line.slice(separator + 1));
      continue;
    }
    const malformed = looksLikeMalformedRegistryDirective(line.slice(0, separator));
    if (malformed.relevant) {
      registerDirective(assessment, malformed.scope, undefined);
    }
  }
}

function splitYarnrcDirective(line: string): {
  readonly key: string;
  readonly value?: string;
} {
  const equals = line.indexOf("=");
  if (equals !== -1) {
    return {
      key: line.slice(0, equals),
      value: line.slice(equals + 1),
    };
  }
  const whitespace = line.search(/\s/u);
  if (whitespace === -1) {
    return { key: line };
  }
  return {
    key: line.slice(0, whitespace),
    value: line.slice(whitespace).trim(),
  };
}

function inspectYarnrc(
  lines: readonly string[],
  assessment: MutableAssessment,
): void {
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#")) {
      continue;
    }
    const directive = splitYarnrcDirective(line);
    const unquotedKey = unquote(directive.key)?.replace(/^--/u, "");
    if (unquotedKey === undefined) {
      const malformed = looksLikeMalformedRegistryDirective(directive.key);
      if (malformed.relevant) {
        registerDirective(assessment, malformed.scope, undefined);
      }
      continue;
    }
    const selector = npmrcSelector(unquotedKey);
    if (selector.relevant) {
      registerDirective(assessment, selector.scope, directive.value);
      continue;
    }
    if (unquotedKey === "npmRegistryServer") {
      registerDirective(assessment, undefined, directive.value);
      continue;
    }
    const malformed = looksLikeMalformedRegistryDirective(unquotedKey);
    if (malformed.relevant) {
      registerDirective(assessment, malformed.scope, undefined);
    }
  }
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function inspectYarnrcYaml(
  content: string,
  assessment: MutableAssessment,
): void {
  let parsed: unknown;
  try {
    parsed = parseYaml(content, {
      maxAliasCount: 0,
      schema: "core",
      uniqueKeys: true,
    });
  } catch {
    assessment.blockAll = true;
    return;
  }
  if (parsed === null || parsed === undefined) {
    return;
  }
  if (!isRecord(parsed)) {
    assessment.blockAll = true;
    return;
  }
  if (Object.keys(parsed).length > MAX_SCOPES * 4) {
    assessment.blockAll = true;
    return;
  }
  if (Object.hasOwn(parsed, "npmRegistryServer")) {
    registerDirective(
      assessment,
      undefined,
      typeof parsed.npmRegistryServer === "string"
        ? parsed.npmRegistryServer
        : undefined,
    );
  }
  if (Object.hasOwn(parsed, "registry")) {
    registerDirective(
      assessment,
      undefined,
      typeof parsed.registry === "string" ? parsed.registry : undefined,
    );
  }
  if (!Object.hasOwn(parsed, "npmScopes")) {
    return;
  }
  if (!isRecord(parsed.npmScopes)) {
    assessment.blockAll = true;
    return;
  }
  const scopes = Object.entries(parsed.npmScopes);
  if (scopes.length > MAX_SCOPES) {
    assessment.blockAll = true;
    return;
  }
  for (const [rawScope, rawConfiguration] of scopes) {
    const scope = normalizeScope(rawScope);
    if (scope === undefined || !isRecord(rawConfiguration)) {
      assessment.blockAll = true;
      continue;
    }
    if (Object.hasOwn(rawConfiguration, "npmRegistryServer")) {
      registerDirective(
        assessment,
        scope,
        typeof rawConfiguration.npmRegistryServer === "string"
          ? rawConfiguration.npmRegistryServer
          : undefined,
      );
    }
    if (Object.hasOwn(rawConfiguration, "registry")) {
      registerDirective(
        assessment,
        scope,
        typeof rawConfiguration.registry === "string"
          ? rawConfiguration.registry
          : undefined,
      );
    }
  }
}

export function inspectWorkspaceRegistryConfig(input: {
  readonly path: string;
  readonly directoryPath: string;
  readonly kind: WorkspaceRegistryConfigKind;
  readonly content: string;
}): WorkspaceRegistryConfigAssessment {
  const assessment: MutableAssessment = {
    blockAll: false,
    blockedScopes: new Set<string>(),
    seenDirectives: new Map<string, string>(),
  };
  const lines = boundedLines(input.content);
  if (lines === undefined) {
    assessment.blockAll = true;
  } else if (input.kind === "npmrc") {
    inspectNpmrc(lines, assessment);
  } else if (input.kind === "yarnrc") {
    inspectYarnrc(lines, assessment);
  } else if (input.kind === "yarnrc-yaml") {
    inspectYarnrcYaml(input.content, assessment);
  } else {
    assessment.blockAll = true;
  }
  return {
    path: input.path,
    directoryPath: input.directoryPath,
    blockAll: assessment.blockAll,
    blockedScopes: [...assessment.blockedScopes].sort(),
  };
}

function registryValue(value: unknown): string | undefined {
  if (typeof value === "string") {
    return value;
  }
  return isRecord(value) && typeof value.url === "string"
    ? value.url
    : undefined;
}

export async function inspectWorkspaceBunfigConfig(input: {
  readonly path: string;
  readonly directoryPath: string;
  readonly content: string;
}): Promise<WorkspaceRegistryConfigAssessment> {
  const assessment: MutableAssessment = {
    blockAll: false,
    blockedScopes: new Set<string>(),
    seenDirectives: new Map<string, string>(),
  };
  if (boundedLines(input.content) === undefined) {
    assessment.blockAll = true;
  } else {
    try {
      const { parse: parseToml } = await import("smol-toml");
      const parsed: unknown = parseToml(input.content);
      if (!isRecord(parsed)) {
        assessment.blockAll = true;
      } else if (Object.hasOwn(parsed, "install")) {
        if (!isRecord(parsed.install)) {
          assessment.blockAll = true;
        } else {
          if (Object.hasOwn(parsed.install, "registry")) {
            registerDirective(
              assessment,
              undefined,
              registryValue(parsed.install.registry),
            );
          }
          if (Object.hasOwn(parsed.install, "scopes")) {
            if (!isRecord(parsed.install.scopes)) {
              assessment.blockAll = true;
            } else {
              const scopes = Object.entries(parsed.install.scopes);
              if (scopes.length > MAX_SCOPES) {
                assessment.blockAll = true;
              } else {
                for (const [scope, value] of scopes) {
                  registerDirective(
                    assessment,
                    scope,
                    registryValue(value),
                  );
                }
              }
            }
          }
        }
      }
    } catch {
      assessment.blockAll = true;
    }
  }
  return {
    path: input.path,
    directoryPath: input.directoryPath,
    blockAll: assessment.blockAll,
    blockedScopes: [...assessment.blockedScopes].sort(),
    packageManagers: ["bun"],
  };
}

export function unreadableWorkspaceRegistryConfig(
  path: string,
  directoryPath: string,
  packageManagers?: readonly string[],
): WorkspaceRegistryConfigAssessment {
  return {
    path,
    directoryPath,
    blockAll: true,
    blockedScopes: [],
    ...(packageManagers === undefined ? {} : { packageManagers }),
  };
}

function normalizeLocation(value: string): string {
  const normalized = value.replaceAll("\\", "/").replace(/\/{2,}/gu, "/");
  const withoutTrailingSlash = normalized.replace(/\/+$/u, "");
  return withoutTrailingSlash.length === 0 ? "/" : withoutTrailingSlash;
}

function directoryName(value: string): string {
  const normalized = normalizeLocation(value);
  const separator = normalized.lastIndexOf("/");
  return separator <= 0 ? normalized : normalized.slice(0, separator);
}

function isSameOrAncestor(ancestor: string, target: string): boolean {
  const normalizedAncestor = normalizeLocation(ancestor);
  const normalizedTarget = normalizeLocation(target);
  return (
    normalizedAncestor === normalizedTarget ||
    normalizedTarget.startsWith(
      normalizedAncestor === "/"
        ? normalizedAncestor
        : `${normalizedAncestor}/`,
    )
  );
}

function dependencyScopes(dependency: Dependency): readonly string[] {
  const scopes = new Set<string>();
  for (const name of [dependency.name, dependency.manifestName]) {
    const match = name === undefined ? undefined : SCOPED_PACKAGE.exec(name);
    if (match?.[1] !== undefined) {
      scopes.add(match[1].toLowerCase());
    }
  }
  return [...scopes];
}

function registryPolicyBlocksDependency(
  snapshot: WorkspaceRegistrySnapshot,
  dependency: Dependency,
  fallbackProjectPath: string,
): boolean {
  if (snapshot.incomplete) {
    return true;
  }
  const manifestPath = dependency.manifestPath ?? dependency.packageJsonPath;
  const targetDirectory =
    manifestPath === undefined
      ? dependency.projectPath ?? fallbackProjectPath
      : directoryName(manifestPath);
  const scopes = dependencyScopes(dependency);
  for (const config of snapshot.configs) {
    if (
      config.packageManagers !== undefined &&
      (dependency.packageManager === undefined ||
        !config.packageManagers.includes(dependency.packageManager))
    ) {
      continue;
    }
    if (!isSameOrAncestor(config.directoryPath, targetDirectory)) {
      continue;
    }
    if (config.blockAll) {
      return true;
    }
    if (scopes.some((scope) => config.blockedScopes.includes(scope))) {
      return true;
    }
  }
  return false;
}

export function applyWorkspaceRegistryGate(
  dependencies: readonly Dependency[],
  snapshot: WorkspaceRegistrySnapshot,
  fallbackProjectPath: string,
): WorkspaceRegistryGateResult {
  let affectedCount = 0;
  let resolvedToUnsupported = 0;
  let unresolvedToUnsupported = 0;
  const affectedByProject = new Map<string, number>();
  const gated = dependencies.map((dependency) => {
    if (
      !registryPolicyBlocksDependency(
        snapshot,
        dependency,
        fallbackProjectPath,
      )
    ) {
      return dependency;
    }
    const alreadyUnsupported =
      dependency.resolutionStatus === "unsupported" &&
      dependency.installedVersion.length === 0;
    if (alreadyUnsupported) {
      return dependency;
    }
    affectedCount += 1;
    if (dependencyIsResolved(dependency)) {
      resolvedToUnsupported += 1;
    } else if (dependency.resolutionStatus === "unresolved") {
      unresolvedToUnsupported += 1;
    }
    const projectPath = dependency.projectPath ?? fallbackProjectPath;
    affectedByProject.set(
      projectPath,
      (affectedByProject.get(projectPath) ?? 0) + 1,
    );
    return {
      ...dependency,
      installedVersion: "",
      resolutionStatus: "unsupported" as const,
    };
  });
  return {
    dependencies: gated,
    affectedCount,
    affectedByProject: [...affectedByProject]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([projectPath, count]) => ({ projectPath, count })),
    resolvedToUnsupported,
    unresolvedToUnsupported,
  };
}

export function applyWorkspaceRegistryGateToParseResult(
  result: JavaScriptParseResult,
  snapshot: WorkspaceRegistrySnapshot,
  fallbackProjectPath: string,
): JavaScriptRegistryGateResult {
  const gated = applyWorkspaceRegistryGate(
    result.dependencies,
    snapshot,
    fallbackProjectPath,
  );
  return {
    result: {
      ...result,
      dependencies: gated.dependencies,
      resolved: Math.max(0, result.resolved - gated.resolvedToUnsupported),
      unresolved: Math.max(
        0,
        result.unresolved - gated.unresolvedToUnsupported,
      ),
      unsupported: result.unsupported + gated.affectedCount,
    },
    affectedCount: gated.affectedCount,
  };
}

export function workspaceRegistryCoverageError(
  affectedCount: number,
  projectPath: string,
): ScanError {
  return {
    code: "UNSUPPORTED_PACKAGE_SOURCE",
    message: `${affectedCount.toString()} dependency record(s) cannot be proven to use an approved public npm registry from bounded workspace configuration; user and global package-manager configuration is intentionally outside the scan boundary`,
    path: projectPath,
  };
}
