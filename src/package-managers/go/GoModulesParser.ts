import type { Dependency } from "../../models/Dependency";

export interface GoModulesParseIssue {
  readonly code: string;
  readonly message: string;
}

export interface GoModulesParserLimits {
  readonly maxLines: number;
  readonly maxDependencies: number;
  readonly maxIssues: number;
  readonly maxLineLength: number;
}

export interface GoModulesParserInput {
  readonly goMod: string;
  readonly manifestPath: string;
  readonly goSum?: string;
  readonly sumPath?: string;
  readonly projectPath?: string;
  readonly workspacePath?: string;
  readonly signal?: AbortSignal;
  readonly limits?: Partial<GoModulesParserLimits>;
}

export interface GoModulesParseResult {
  readonly dependencies: readonly Dependency[];
  readonly issues: readonly GoModulesParseIssue[];
  readonly truncated: boolean;
  readonly cancelled: boolean;
}

export const DEFAULT_GO_MODULES_PARSER_LIMITS: GoModulesParserLimits = {
  maxLines: 100_000,
  maxDependencies: 10_000,
  maxIssues: 1_000,
  maxLineLength: 16_384,
};

interface Requirement {
  readonly path: string;
  readonly version: string;
  readonly indirect: boolean;
}

interface Replacement {
  readonly oldPath: string;
  readonly oldVersion?: string;
  readonly newPath: string;
  readonly newVersion?: string;
  readonly local: boolean;
}

class GoParseContext {
  public readonly issues: GoModulesParseIssue[] = [];
  public truncated = false;

  public constructor(
    public readonly limits: GoModulesParserLimits,
    private readonly signal: AbortSignal | undefined,
  ) {}

  public checkCancellation(): void {
    if (this.signal?.aborted === true) {
      throw new DOMException("Go module parsing cancelled", "AbortError");
    }
  }

  public addIssue(code: string, message: string): void {
    if (this.issues.length < this.limits.maxIssues) {
      this.issues.push({ code, message });
    } else {
      this.truncated = true;
    }
  }
}

function positiveLimit(value: unknown, fallback: number): number {
  return Number.isSafeInteger(value) && Number(value) > 0
    ? Number(value)
    : fallback;
}

function parserLimits(
  supplied: Partial<GoModulesParserLimits> | undefined,
): GoModulesParserLimits {
  return {
    maxLines: positiveLimit(
      supplied?.maxLines,
      DEFAULT_GO_MODULES_PARSER_LIMITS.maxLines,
    ),
    maxDependencies: positiveLimit(
      supplied?.maxDependencies,
      DEFAULT_GO_MODULES_PARSER_LIMITS.maxDependencies,
    ),
    maxIssues: positiveLimit(
      supplied?.maxIssues,
      DEFAULT_GO_MODULES_PARSER_LIMITS.maxIssues,
    ),
    maxLineLength: positiveLimit(
      supplied?.maxLineLength,
      DEFAULT_GO_MODULES_PARSER_LIMITS.maxLineLength,
    ),
  };
}

function safeModulePath(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 2_048 &&
    !/[\u0000-\u0020\u007F\\]/u.test(value) &&
    !value.startsWith("-") &&
    !value.includes("..")
  );
}

function safeGoVersion(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 256 &&
    /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u.test(
      value,
    )
  );
}

function decodeQuotedToken(token: string): string | undefined {
  if (token.startsWith("`") && token.endsWith("`") && token.length >= 2) {
    const value = token.slice(1, -1);
    return value.includes("`") ? undefined : value;
  }
  if (!token.startsWith('"')) {
    return token;
  }
  if (!token.endsWith('"') || token.length < 2) {
    return undefined;
  }
  const body = token.slice(1, -1);
  let output = "";
  for (let index = 0; index < body.length; index += 1) {
    const character = body[index];
    if (character !== "\\") {
      output += character;
      continue;
    }
    const next = body[index + 1];
    if (next === undefined) {
      return undefined;
    }
    index += 1;
    switch (next) {
      case "\\":
      case '"':
        output += next;
        break;
      case "n":
        output += "\n";
        break;
      case "r":
        output += "\r";
        break;
      case "t":
        output += "\t";
        break;
      default:
        return undefined;
    }
  }
  return output;
}

function tokenizeLine(line: string): readonly string[] | undefined {
  const tokens: string[] = [];
  let current = "";
  let quote: '"' | "`" | undefined;
  let escaped = false;
  for (const character of line) {
    if (quote !== undefined) {
      current += character;
      if (quote === '"' && character === "\\" && !escaped) {
        escaped = true;
        continue;
      }
      if (character === quote && !escaped) {
        quote = undefined;
      }
      escaped = false;
      continue;
    }
    if (character === '"' || character === "`") {
      quote = character;
      current += character;
      continue;
    }
    if (/\s/u.test(character)) {
      if (current.length > 0) {
        const decoded = decodeQuotedToken(current);
        if (decoded === undefined) {
          return undefined;
        }
        tokens.push(decoded);
        current = "";
      }
      continue;
    }
    current += character;
  }
  if (quote !== undefined) {
    return undefined;
  }
  if (current.length > 0) {
    const decoded = decodeQuotedToken(current);
    if (decoded === undefined) {
      return undefined;
    }
    tokens.push(decoded);
  }
  return tokens;
}

function splitComment(line: string): {
  readonly code: string;
  readonly comment: string;
} {
  let quote: '"' | "`" | undefined;
  let escaped = false;
  for (let index = 0; index < line.length - 1; index += 1) {
    const character = line[index];
    if (quote !== undefined) {
      if (quote === '"' && character === "\\" && !escaped) {
        escaped = true;
        continue;
      }
      if (character === quote && !escaped) {
        quote = undefined;
      }
      escaped = false;
      continue;
    }
    if (character === '"' || character === "`") {
      quote = character;
      continue;
    }
    if (character === "/" && line[index + 1] === "/") {
      return {
        code: line.slice(0, index).trim(),
        comment: line.slice(index + 2).trim(),
      };
    }
  }
  return { code: line.trim(), comment: "" };
}

function replacementFromTokens(
  tokens: readonly string[],
): Replacement | undefined {
  const arrow = tokens.indexOf("=>");
  if (arrow < 1 || arrow > 2 || tokens.length - arrow < 2 || tokens.length - arrow > 3) {
    return undefined;
  }
  const oldPath = tokens[0];
  const oldVersion = arrow === 2 ? tokens[1] : undefined;
  const newPath = tokens[arrow + 1];
  const newVersion = tokens[arrow + 2];
  if (
    oldPath === undefined ||
    newPath === undefined ||
    !safeModulePath(oldPath)
  ) {
    return undefined;
  }
  const local = newVersion === undefined;
  if (!local && (!safeModulePath(newPath) || !safeGoVersion(newVersion))) {
    return undefined;
  }
  return {
    oldPath,
    ...(oldVersion === undefined ? {} : { oldVersion }),
    newPath,
    ...(newVersion === undefined ? {} : { newVersion }),
    local,
  };
}

function parseGoMod(
  text: string,
  context: GoParseContext,
): {
  readonly modulePath?: string;
  readonly goVersion?: string;
  readonly requirements: readonly Requirement[];
  readonly replacements: readonly Replacement[];
  readonly exclusions: ReadonlySet<string>;
} {
  const allLines = text.replace(/^\uFEFF/u, "").split(/\r?\n/u);
  if (allLines.length > context.limits.maxLines) {
    context.truncated = true;
    context.addIssue("DEPENDENCY_LIMIT", "go.mod exceeded its line safety limit");
  }
  const lines = allLines.slice(0, context.limits.maxLines);
  const requirements: Requirement[] = [];
  const replacements: Replacement[] = [];
  const exclusions = new Set<string>();
  let modulePath: string | undefined;
  let goVersion: string | undefined;
  let block: "require" | "replace" | "exclude" | undefined;

  for (const rawLine of lines) {
    context.checkCancellation();
    if (rawLine.length > context.limits.maxLineLength) {
      context.addIssue("DEPENDENCY_LIMIT", "go.mod contains an overlong line");
      context.truncated = true;
      continue;
    }
    const { code, comment } = splitComment(rawLine);
    if (code.length === 0) {
      continue;
    }
    if (code === ")") {
      if (block === undefined) {
        context.addIssue("INVALID_MANIFEST", "go.mod has an unmatched block terminator");
      }
      block = undefined;
      continue;
    }
    const tokens = tokenizeLine(code);
    if (tokens === undefined || tokens.length === 0) {
      context.addIssue("INVALID_MANIFEST", "go.mod contains an invalid quoted token");
      continue;
    }
    if (tokens.length === 2 && tokens[1] === "(" && block === undefined) {
      const keyword = tokens[0];
      if (keyword === "require" || keyword === "replace" || keyword === "exclude") {
        block = keyword;
      }
      continue;
    }

    const keyword = block ?? tokens[0];
    const values = block === undefined ? tokens.slice(1) : tokens;
    switch (keyword) {
      case "module": {
        const value = values[0];
        if (values.length === 1 && value !== undefined && safeModulePath(value)) {
          modulePath = value;
        } else {
          context.addIssue("INVALID_MANIFEST", "go.mod has an invalid module directive");
        }
        break;
      }
      case "go": {
        const value = values[0];
        if (
          values.length === 1 &&
          value !== undefined &&
          /^\d+\.\d+(?:\.\d+)?$/u.test(value)
        ) {
          goVersion = value;
        } else {
          context.addIssue("INVALID_MANIFEST", "go.mod has an invalid go directive");
        }
        break;
      }
      case "require": {
        const path = values[0];
        const version = values[1];
        if (
          values.length !== 2 ||
          path === undefined ||
          version === undefined ||
          !safeModulePath(path)
        ) {
          context.addIssue("DEPENDENCY_UNRESOLVED", "go.mod has an invalid require directive");
          break;
        }
        if (requirements.length >= context.limits.maxDependencies) {
          context.truncated = true;
          context.addIssue(
            "DEPENDENCY_LIMIT",
            "go.mod exceeded its dependency safety limit",
          );
          break;
        }
        requirements.push({
          path,
          version,
          indirect: /(?:^|\s)indirect(?:\s|$)/u.test(comment),
        });
        break;
      }
      case "replace": {
        const replacement = replacementFromTokens(values);
        if (replacement === undefined) {
          context.addIssue("DEPENDENCY_UNRESOLVED", "go.mod has an invalid replace directive");
        } else {
          replacements.push(replacement);
        }
        break;
      }
      case "exclude": {
        const path = values[0];
        const version = values[1];
        if (
          values.length === 2 &&
          path !== undefined &&
          version !== undefined &&
          safeModulePath(path) &&
          safeGoVersion(version)
        ) {
          exclusions.add(`${path}\u0000${version}`);
        } else {
          context.addIssue("INVALID_MANIFEST", "go.mod has an invalid exclude directive");
        }
        break;
      }
      default:
        break;
    }
  }
  if (block !== undefined) {
    context.addIssue("INVALID_MANIFEST", `go.mod has an unterminated ${block} block`);
  }
  return {
    ...(modulePath === undefined ? {} : { modulePath }),
    ...(goVersion === undefined ? {} : { goVersion }),
    requirements,
    replacements,
    exclusions,
  };
}

function hasCompleteGoModGraph(goVersion: string | undefined): boolean {
  if (goVersion === undefined) {
    return false;
  }
  const match = /^(\d+)\.(\d+)(?:\.\d+)?$/u.exec(goVersion);
  if (match === null) {
    return false;
  }
  const major = Number(match[1]);
  const minor = Number(match[2]);
  return major > 1 || (major === 1 && minor >= 17);
}

function goSumEntries(
  text: string | undefined,
  context: GoParseContext,
): ReadonlySet<string> {
  const entries = new Set<string>();
  if (text === undefined) {
    return entries;
  }
  const lines = text.split(/\r?\n/u);
  if (lines.length > context.limits.maxLines) {
    context.addIssue("DEPENDENCY_LIMIT", "go.sum exceeded its line safety limit");
    context.truncated = true;
  }
  for (const line of lines.slice(0, context.limits.maxLines)) {
    context.checkCancellation();
    if (line.trim().length === 0) {
      continue;
    }
    const fields = line.trim().split(/\s+/u);
    const path = fields[0];
    const rawVersion = fields[1];
    const hash = fields[2];
    if (
      fields.length !== 3 ||
      path === undefined ||
      rawVersion === undefined ||
      hash === undefined ||
      !safeModulePath(path) ||
      !/^h\d+:[A-Za-z0-9+/=]+$/u.test(hash)
    ) {
      context.addIssue("INVALID_LOCKFILE", "go.sum contains a malformed checksum line");
      continue;
    }
    const version = rawVersion.endsWith("/go.mod")
      ? rawVersion.slice(0, -"/go.mod".length)
      : rawVersion;
    if (safeGoVersion(version)) {
      entries.add(`${path}\u0000${version}`);
    }
  }
  return entries;
}

function dependencyForRequirement(
  input: GoModulesParserInput,
  requirement: Requirement,
  replacements: readonly Replacement[],
  exclusions: ReadonlySet<string>,
  sums: ReadonlySet<string>,
  modulePath: string,
  completeGoModGraph: boolean,
  context: GoParseContext,
): Dependency {
  const matchingReplacements = replacements.filter(
    (replacement) =>
      replacement.oldPath === requirement.path &&
      (replacement.oldVersion === undefined ||
        replacement.oldVersion === requirement.version),
  );
  const specific = matchingReplacements.filter(
    (replacement) => replacement.oldVersion === requirement.version,
  );
  const applicable = specific.length > 0 ? specific : matchingReplacements;
  const replacement = applicable.length === 1 ? applicable[0] : undefined;
  const excluded = exclusions.has(`${requirement.path}\u0000${requirement.version}`);
  let name = requirement.path;
  let version = requirement.version;
  let resolutionStatus: "resolved" | "unresolved" | "unsupported" = "resolved";
  let replacementKind = "none";
  if (applicable.length > 1) {
    resolutionStatus = "unresolved";
    context.addIssue(
      "DEPENDENCY_UNRESOLVED",
      `Go module ${requirement.path} has ambiguous replacements`,
    );
  } else if (replacement?.local === true) {
    resolutionStatus = "unsupported";
    version = "";
    replacementKind = "local";
    context.addIssue(
      "UNSUPPORTED_PACKAGE_SOURCE",
      `Go module ${requirement.path} is replaced by a local path`,
    );
  } else if (replacement !== undefined) {
    name = replacement.newPath;
    version = replacement.newVersion ?? "";
    replacementKind = "module";
  }
  if (
    excluded ||
    (resolutionStatus !== "unsupported" && !safeGoVersion(version))
  ) {
    resolutionStatus = "unresolved";
    version = "";
    context.addIssue(
      "DEPENDENCY_UNRESOLVED",
      `Go module ${requirement.path} does not have a usable canonical version`,
    );
  }
  const checksumPresent =
    version.length > 0 && sums.has(`${name}\u0000${version}`);
  if (
    resolutionStatus === "resolved" &&
    (!completeGoModGraph || !checksumPresent)
  ) {
    resolutionStatus = "unresolved";
    version = "";
    context.addIssue(
      "DEPENDENCY_UNRESOLVED",
      !completeGoModGraph
        ? `Go module ${requirement.path} lacks Go 1.17+ selected-graph evidence`
        : `Go module ${requirement.path} lacks a matching go.sum checksum`,
    );
  }
  return {
    name,
    ecosystem: "Go",
    requestedVersion: requirement.version,
    manifestName: requirement.path,
    installedVersion: version,
    resolutionStatus,
    dependencyType: requirement.indirect ? "transitive" : "direct",
    environment: "production",
    declaredEnvironment: "production",
    dependencyPath: [
      modulePath,
      `${name}${version.length === 0 ? "" : `@${version}`}`,
    ],
    manifestPath: input.manifestPath,
    ...(input.sumPath === undefined ? {} : { lockfilePath: input.sumPath }),
    packageManager: "go",
    ...(input.projectPath === undefined
      ? {}
      : { projectPath: input.projectPath }),
    ...(input.workspacePath === undefined
      ? {}
      : { workspacePath: input.workspacePath }),
    metadata: {
      manifestSection: "require",
      indirect: requirement.indirect,
      checksumPresent,
      completeGoModGraph,
      replacementKind,
      relationshipDetail: requirement.indirect
        ? "parent-unavailable-from-go.mod"
        : "direct-requirement",
    },
  };
}

export function parseGoModules(
  input: GoModulesParserInput,
): GoModulesParseResult {
  const context = new GoParseContext(parserLimits(input.limits), input.signal);
  try {
    context.checkCancellation();
    const parsed = parseGoMod(input.goMod, context);
    const sums = goSumEntries(input.goSum, context);
    const modulePath = parsed.modulePath ?? "<main-module>";
    const completeGoModGraph = hasCompleteGoModGraph(parsed.goVersion);
    if (parsed.modulePath === undefined) {
      context.addIssue("INVALID_MANIFEST", "go.mod has no valid module directive");
    }
    const dependencyMap = new Map<string, Dependency>();
    for (const requirement of parsed.requirements) {
      context.checkCancellation();
      const dependency = dependencyForRequirement(
        input,
        requirement,
        parsed.replacements,
        parsed.exclusions,
        sums,
        modulePath,
        completeGoModGraph,
        context,
      );
      const key = requirement.path.toLowerCase();
      const previous = dependencyMap.get(key);
      if (
        previous !== undefined &&
        (previous.requestedVersion !== dependency.requestedVersion ||
          previous.name !== dependency.name)
      ) {
        context.addIssue(
          "DEPENDENCY_UNRESOLVED",
          `Go module ${requirement.path} is required more than once with conflicting versions`,
        );
        dependencyMap.set(key, {
          ...dependency,
          installedVersion: "",
          resolutionStatus: "unresolved",
        });
      } else if (previous === undefined) {
        dependencyMap.set(key, dependency);
      }
    }
    return {
      dependencies: [...dependencyMap.values()].sort((left, right) =>
        left.name.localeCompare(right.name),
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
    context.addIssue("INVALID_MANIFEST", "Go module dependency parsing failed");
    return {
      dependencies: [],
      issues: context.issues,
      truncated: context.truncated,
      cancelled: false,
    };
  }
}
