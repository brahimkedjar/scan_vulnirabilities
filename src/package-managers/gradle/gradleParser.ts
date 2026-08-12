import type { Dependency, DependencyEnvironment } from "../../models/Dependency";
import type { ScanError } from "../../models/ScanResult";
import { MAX_PARSED_DEPENDENCIES as MAX_DEPENDENCIES } from "../python/parserLimits";

const COORDINATE_PART = /^[A-Za-z0-9_.-]+$/u;
const DECLARATION =
  /(^|[\n;])([ \t]*)([A-Za-z_][A-Za-z0-9_]*)[ \t]*(?:\([ \t]*)?(["'])([^"'\r\n]+)\4[ \t]*\)?/gmu;
const MAX_PLUGIN_BLOCKS = 256;

interface GradleDeclaration {
  readonly name: string;
  readonly requestedVersion: string;
  readonly configuration: string;
  readonly environment: DependencyEnvironment;
  readonly sourceLine: number;
}

interface LockedModule {
  readonly name: string;
  readonly version: string;
  readonly configurations: readonly string[];
}

function concreteMavenVersion(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 256 &&
    /[0-9]/u.test(value) &&
    /^[A-Za-z0-9][A-Za-z0-9._+-]*$/u.test(value) &&
    !/snapshot/iu.test(value) &&
    !/^latest(?:[._-].*)?$/iu.test(value) &&
    !/[?*]/u.test(value) &&
    !/(?:^|[^A-Za-z0-9])\+|\+(?:$|[^A-Za-z0-9])/u.test(value)
  );
}

export interface GradleParseInput {
  readonly scriptText: string;
  /** Sibling/ancestor settings.gradle(.kts) content used only for repository provenance. */
  readonly repositoryConfigurationTexts?: readonly string[];
  readonly manifestPath: string;
  readonly lockfileText?: string;
  readonly lockfilePath?: string;
  readonly projectPath: string;
  readonly workspacePath: string;
  readonly signal?: AbortSignal;
}

export interface GradleParseResult {
  readonly dependencies: readonly Dependency[];
  readonly errors: readonly ScanError[];
  readonly truncated: boolean;
}

function maskNonCode(text: string): string {
  const characters = [...text];
  let quote: "'" | '"' | undefined;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  for (let index = 0; index < characters.length; index += 1) {
    const current = characters[index] ?? "";
    const next = characters[index + 1] ?? "";
    if (lineComment) {
      if (current === "\n") {
        lineComment = false;
      } else {
        characters[index] = " ";
      }
      continue;
    }
    if (blockComment) {
      if (current === "*" && next === "/") {
        characters[index] = " ";
        characters[index + 1] = " ";
        index += 1;
        blockComment = false;
      } else if (current !== "\n") {
        characters[index] = " ";
      }
      continue;
    }
    if (quote !== undefined) {
      if (escaped) {
        escaped = false;
      } else if (current === "\\") {
        escaped = true;
      } else if (current === quote) {
        quote = undefined;
      }
      if (current !== "\n") {
        characters[index] = " ";
      }
      continue;
    }
    if (current === "/" && next === "/") {
      characters[index] = " ";
      characters[index + 1] = " ";
      index += 1;
      lineComment = true;
    } else if (current === "/" && next === "*") {
      characters[index] = " ";
      characters[index + 1] = " ";
      index += 1;
      blockComment = true;
    } else if (current === "'" || current === '"') {
      quote = current;
      characters[index] = " ";
    }
  }
  return characters.join("");
}

function dependencyBlocks(text: string): {
  readonly blocks: readonly { readonly start: number; readonly end: number }[];
  readonly malformed: boolean;
} {
  const mask = maskNonCode(text);
  const blocks: Array<{ start: number; end: number }> = [];
  const opener = /\bdependencies\s*\{/gu;
  let malformed = false;
  let match: RegExpExecArray | null;
  while ((match = opener.exec(mask)) !== null) {
    const open = mask.indexOf("{", match.index);
    let depth = 1;
    let closed = false;
    for (let index = open + 1; index < mask.length; index += 1) {
      const character = mask[index];
      if (character === "{") {
        depth += 1;
      } else if (character === "}") {
        depth -= 1;
        if (depth === 0) {
          blocks.push({ start: open + 1, end: index });
          opener.lastIndex = index + 1;
          closed = true;
          break;
        }
      }
    }
    if (!closed) {
      malformed = true;
      break;
    }
  }
  return { blocks, malformed };
}

function repositoryBlocks(text: string): {
  readonly blocks: readonly { readonly start: number; readonly end: number }[];
  readonly malformed: boolean;
} {
  const mask = maskNonCode(text);
  const blocks: Array<{ start: number; end: number }> = [];
  const opener = /\brepositories\s*\{/gu;
  let malformed = false;
  let match: RegExpExecArray | null;
  while ((match = opener.exec(mask)) !== null) {
    const open = mask.indexOf("{", match.index);
    let depth = 1;
    let closed = false;
    for (let index = open + 1; index < mask.length; index += 1) {
      const character = mask[index];
      if (character === "{") {
        depth += 1;
      } else if (character === "}") {
        depth -= 1;
        if (depth === 0) {
          blocks.push({ start: open + 1, end: index });
          opener.lastIndex = index + 1;
          closed = true;
          break;
        }
      }
    }
    if (!closed) {
      malformed = true;
      break;
    }
  }
  return { blocks, malformed };
}

function pluginBlocks(text: string): {
  readonly blocks: readonly { readonly start: number; readonly end: number }[];
  readonly malformed: boolean;
} {
  const mask = maskNonCode(text);
  const blocks: Array<{ start: number; end: number }> = [];
  const opener = /\bplugins\s*\{/gu;
  let malformed = false;
  let match: RegExpExecArray | null;
  while ((match = opener.exec(mask)) !== null) {
    if (blocks.length >= MAX_PLUGIN_BLOCKS) {
      malformed = true;
      break;
    }
    const open = mask.indexOf("{", match.index);
    let depth = 1;
    let closed = false;
    for (let index = open + 1; index < mask.length; index += 1) {
      const character = mask[index];
      if (character === "{") {
        depth += 1;
      } else if (character === "}") {
        depth -= 1;
        if (depth === 0) {
          blocks.push({ start: open + 1, end: index });
          opener.lastIndex = index + 1;
          closed = true;
          break;
        }
      }
    }
    if (!closed) {
      malformed = true;
      break;
    }
  }
  return { blocks, malformed };
}

function withoutGradleComments(text: string): string {
  const characters = [...text];
  let quote: "'" | '"' | undefined;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  for (let index = 0; index < characters.length; index += 1) {
    const current = characters[index] ?? "";
    const next = characters[index + 1] ?? "";
    if (lineComment) {
      if (current === "\n") {
        lineComment = false;
      } else {
        characters[index] = " ";
      }
      continue;
    }
    if (blockComment) {
      if (current === "*" && next === "/") {
        characters[index] = " ";
        characters[index + 1] = " ";
        index += 1;
        blockComment = false;
      } else if (current !== "\n") {
        characters[index] = " ";
      }
      continue;
    }
    if (quote !== undefined) {
      if (escaped) {
        escaped = false;
      } else if (current === "\\") {
        escaped = true;
      } else if (current === quote) {
        quote = undefined;
      }
      continue;
    }
    if (current === "/" && next === "/") {
      characters[index] = " ";
      characters[index + 1] = " ";
      index += 1;
      lineComment = true;
    } else if (current === "/" && next === "*") {
      characters[index] = " ";
      characters[index + 1] = " ";
      index += 1;
      blockComment = true;
    } else if (current === "'" || current === '"') {
      quote = current;
    }
  }
  return characters.join("");
}

function canonicalMavenCentralUrl(value: string): boolean {
  if (value.length === 0 || value.length > 2_048) {
    return false;
  }
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.username.length === 0 &&
      url.password.length === 0 &&
      url.port.length === 0 &&
      (url.hostname.toLowerCase() === "repo.maven.apache.org" ||
        url.hostname.toLowerCase() === "repo1.maven.org") &&
      (url.pathname === "/maven2" || url.pathname === "/maven2/") &&
      url.search.length === 0 &&
      url.hash.length === 0
    );
  } catch {
    return false;
  }
}

function canonicalMavenRepositoryBody(value: string): boolean {
  const body = withoutGradleComments(value);
  const patterns = [
    /^\s*url\s*=\s*uri\s*\(\s*(["'])([^"']+)\1\s*\)\s*;?\s*$/u,
    /^\s*url\s*(?:=\s*)?(["'])([^"']+)\1\s*;?\s*$/u,
    /^\s*setUrl\s*\(\s*(["'])([^"']+)\1\s*\)\s*;?\s*$/u,
  ];
  for (const pattern of patterns) {
    const url = pattern.exec(body)?.[2];
    if (url !== undefined && canonicalMavenCentralUrl(url)) {
      return true;
    }
  }
  return false;
}

function canonicalRepositoryBlock(value: string): boolean {
  const content = withoutGradleComments(value);
  const mask = maskNonCode(content);
  let cursor = 0;
  while (cursor < content.length) {
    while (
      cursor < content.length &&
      (/[\s;]/u.test(content[cursor] ?? "") ||
        /[\s;]/u.test(mask[cursor] ?? ""))
    ) {
      cursor += 1;
    }
    if (cursor >= content.length) {
      return true;
    }

    const central = /^mavenCentral\s*\(\s*\)/u.exec(mask.slice(cursor));
    if (central?.[0] !== undefined) {
      cursor += central[0].length;
      continue;
    }

    const maven = /^maven\s*\{/u.exec(mask.slice(cursor));
    if (maven?.[0] === undefined) {
      return false;
    }
    const open = cursor + maven[0].lastIndexOf("{");
    let depth = 1;
    let close = -1;
    for (let index = open + 1; index < mask.length; index += 1) {
      if (mask[index] === "{") {
        depth += 1;
      } else if (mask[index] === "}") {
        depth -= 1;
        if (depth === 0) {
          close = index;
          break;
        }
      }
    }
    if (
      close === -1 ||
      !canonicalMavenRepositoryBody(content.slice(open + 1, close))
    ) {
      return false;
    }
    cursor = close + 1;
  }
  return true;
}

function customRepositoryConfiguration(text: string): boolean {
  const repositories = repositoryBlocks(text);
  const plugins = pluginBlocks(text);
  const mask = maskNonCode(text);
  // Gradle plugins execute arbitrary build logic and can add repositories
  // without a repositories{} declaration. Only an empty block or the exact
  // built-in `java` shorthand is statically proven safe here; custom,
  // versioned, aliased, and otherwise nontrivial declarations fail closed.
  if (
    plugins.malformed ||
    plugins.blocks.some((block) =>
      !/^\s*(?:java\s*;?)?\s*$/u.test(
        mask.slice(block.start, block.end),
      ),
    )
  ) {
    return true;
  }
  if (
    /\b(?:project\s*\.\s*)?apply(?=\s*(?:\(|\{|[A-Za-z_]))/u.test(mask)
  ) {
    return true;
  }
  const handlerAccess = /\brepositories\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)/gu;
  let handlerMatch: RegExpExecArray | null;
  while ((handlerMatch = handlerAccess.exec(mask)) !== null) {
    if (
      handlerMatch[1] !== "mavenCentral" ||
      !/^\s*\(\s*\)/u.test(mask.slice(handlerAccess.lastIndex))
    ) {
      return true;
    }
  }
  return (
    repositories.malformed ||
    repositories.blocks.some(
      (block) => !canonicalRepositoryBlock(text.slice(block.start, block.end)),
    )
  );
}

function configurationEnvironment(
  configuration: string,
): DependencyEnvironment | undefined {
  const lower = configuration.toLowerCase();
  if (
    ![
      "implementation",
      "api",
      "runtimeonly",
      "compileonly",
      "annotationprocessor",
    ].some((suffix) => lower.endsWith(suffix))
  ) {
    return undefined;
  }
  if (lower.includes("test") || lower.includes("androidtest")) {
    return "development";
  }
  return lower.endsWith("compileonly") || lower.endsWith("annotationprocessor")
    ? "optional"
    : "production";
}

function declarations(text: string): {
  readonly declarations: readonly GradleDeclaration[];
  readonly unsupportedCount: number;
  readonly malformed: boolean;
} {
  const mask = maskNonCode(text);
  const output: GradleDeclaration[] = [];
  let unsupportedCount = 0;
  const dependencyBlockResult = dependencyBlocks(text);
  for (const block of dependencyBlockResult.blocks) {
    const raw = text.slice(block.start, block.end);
    const recognizedStarts = new Set<number>();
    DECLARATION.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = DECLARATION.exec(raw)) !== null) {
      const configuration = match[3];
      const coordinate = match[5];
      if (configuration === undefined || coordinate === undefined) {
        continue;
      }
      const environment = configurationEnvironment(configuration);
      if (environment === undefined) {
        continue;
      }
      const absoluteConfigurationIndex =
        block.start + match.index + (match[1]?.length ?? 0) + (match[2]?.length ?? 0);
      if (
        mask
          .slice(
            absoluteConfigurationIndex,
            absoluteConfigurationIndex + configuration.length,
          )
          .trim() !== configuration
      ) {
        continue;
      }
      let structuralDepth = 0;
      for (const character of mask.slice(block.start, absoluteConfigurationIndex)) {
        if (character === "{") {
          structuralDepth += 1;
        } else if (character === "}") {
          structuralDepth -= 1;
        }
      }
      // A declaration nested in constraints/build logic is not an installed
      // dependency declaration and must not be guessed as one.
      if (structuralDepth !== 0) {
        recognizedStarts.add(absoluteConfigurationIndex);
        unsupportedCount += 1;
        continue;
      }
      recognizedStarts.add(absoluteConfigurationIndex);
      const parts = coordinate.split(":");
      if (
        parts.length !== 3 ||
        parts[0] === undefined ||
        parts[1] === undefined ||
        parts[2] === undefined ||
        !COORDINATE_PART.test(parts[0]) ||
        !COORDINATE_PART.test(parts[1])
      ) {
        unsupportedCount += 1;
        continue;
      }
      const prefix = text.slice(0, absoluteConfigurationIndex);
      output.push({
        name: `${parts[0]}:${parts[1]}`,
        requestedVersion: parts[2],
        configuration,
        environment,
        sourceLine: prefix.split(/\r?\n/u).length,
      });
    }

    const candidate =
      /\b([A-Za-z_][A-Za-z0-9_]*)(?=\s*(?:\(|[A-Za-z_]))/gu;
    let candidateMatch: RegExpExecArray | null;
    while ((candidateMatch = candidate.exec(mask.slice(block.start, block.end))) !== null) {
      const configuration = candidateMatch[1];
      if (configuration === undefined) {
        continue;
      }
      const absoluteConfigurationIndex =
        block.start + candidateMatch.index;
      if (!recognizedStarts.has(absoluteConfigurationIndex)) {
        unsupportedCount += 1;
      }
    }

    // Kotlin DSL permits string-invoked configurations such as
    // `"implementation"("group:name:version")`. They are not safely parsed
    // by the literal grammar above, but they must still make coverage partial.
    const rawStringInvocations =
      /["'][^"'\\\r\n]{1,128}["']\s*\(/gu;
    while (rawStringInvocations.exec(raw) !== null) {
      unsupportedCount += 1;
    }
  }

  // Handler-style declarations can occur outside a `dependencies {}` block,
  // for example dependencies.add(...). Treat every such call as a visible gap
  // unless a future bounded grammar represents it explicitly.
  const handlerCall = /\bdependencies\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\s*\(/gu;
  while (handlerCall.exec(mask) !== null) {
    unsupportedCount += 1;
  }
  return {
    declarations: output,
    unsupportedCount,
    malformed: dependencyBlockResult.malformed,
  };
}

function parseLockfile(text: string): {
  readonly modules: readonly LockedModule[];
  readonly errors: readonly string[];
  readonly truncated: boolean;
} {
  const modules: LockedModule[] = [];
  const errors: string[] = [];
  const lines = text.split(/\r?\n/u);
  for (const raw of lines.slice(0, MAX_DEPENDENCIES + 1)) {
    const line = raw.trim();
    if (line.length === 0 || line.startsWith("#") || line.startsWith("empty=")) {
      continue;
    }
    const equals = line.indexOf("=");
    if (equals <= 0 || line.indexOf("=", equals + 1) !== -1) {
      errors.push("malformed Gradle lock line");
      continue;
    }
    const coordinate = line.slice(0, equals);
    const parts = coordinate.split(":");
    if (
      parts.length !== 3 ||
      parts[0] === undefined ||
      parts[1] === undefined ||
      parts[2] === undefined ||
      !COORDINATE_PART.test(parts[0]) ||
      !COORDINATE_PART.test(parts[1]) ||
      !concreteMavenVersion(parts[2])
    ) {
      errors.push("invalid Gradle lock coordinate");
      continue;
    }
    modules.push({
      name: `${parts[0]}:${parts[1]}`,
      version: parts[2],
      configurations: line
        .slice(equals + 1)
        .split(",")
        .map((value) => value.trim())
        .filter((value) => value.length > 0),
    });
  }
  return {
    modules: modules.slice(0, MAX_DEPENDENCIES),
    errors,
    truncated: lines.length > MAX_DEPENDENCIES + 1,
  };
}

function dynamicVersion(version: string): boolean {
  return (
    version.length === 0 ||
    version.length > 256 ||
    /[+$\[\](){}]/u.test(version) ||
    /(?:latest|release)\./iu.test(version)
  );
}

function numericVersionParts(value: string): readonly number[] | undefined {
  if (!/^\d+(?:\.\d+)*$/u.test(value)) {
    return undefined;
  }
  return value.split(".").map(Number);
}

function compareNumericVersions(left: string, right: string): number | undefined {
  const leftParts = numericVersionParts(left);
  const rightParts = numericVersionParts(right);
  if (leftParts === undefined || rightParts === undefined) {
    return undefined;
  }
  const length = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
    if (difference !== 0) {
      return difference < 0 ? -1 : 1;
    }
  }
  return 0;
}

/**
 * Proves only selectors whose semantics can be checked without executing
 * Gradle. Unknown rich/dynamic selectors fail closed instead of trusting a
 * potentially stale lockfile.
 */
function selectedVersionMatches(requested: string, selected: string): boolean {
  const selector = requested.trim();
  if (selector.length === 0 || selector.length > 256 || selected.length > 256) {
    return false;
  }
  if (selector === selected) {
    return true;
  }
  const singleton = /^\[([^,[\]()]+)\]$/u.exec(selector)?.[1];
  if (singleton !== undefined) {
    return singleton === selected;
  }
  const prefix = /^(\d+(?:\.\d+)*)\.\+$/u.exec(selector)?.[1];
  if (prefix !== undefined) {
    return selected.startsWith(`${prefix}.`);
  }
  const interval = /^([[(])\s*(\d+(?:\.\d+)*)?\s*,\s*(\d+(?:\.\d+)*)?\s*([\])])$/u.exec(
    selector,
  );
  if (interval === null) {
    return false;
  }
  const lower = interval[2];
  const upper = interval[3];
  if (lower !== undefined) {
    const comparison = compareNumericVersions(selected, lower);
    if (
      comparison === undefined ||
      comparison < 0 ||
      (comparison === 0 && interval[1] === "(")
    ) {
      return false;
    }
  }
  if (upper !== undefined) {
    const comparison = compareNumericVersions(selected, upper);
    if (
      comparison === undefined ||
      comparison > 0 ||
      (comparison === 0 && interval[4] === ")")
    ) {
      return false;
    }
  }
  return true;
}

function environmentFromConfigurations(
  configurations: readonly string[],
): DependencyEnvironment {
  if (configurations.some((value) => !value.toLowerCase().includes("test"))) {
    return "production";
  }
  return "development";
}

export function parseGradleProject(input: GradleParseInput): GradleParseResult {
  const declared = declarations(input.scriptText);
  const errors: ScanError[] = [];
  const dependencies: Dependency[] = [];
  const repositoryConfigurationTexts = input.repositoryConfigurationTexts ?? [];
  const customRepository =
    repositoryConfigurationTexts.length > 16 ||
    [input.scriptText, ...repositoryConfigurationTexts.slice(0, 16)].some(
      customRepositoryConfiguration,
    );
  if (customRepository) {
    errors.push({
      code: "UNSUPPORTED_PACKAGE_SOURCE",
      message:
        "Gradle configures a custom or unresolvable dependency repository; Maven Central identity cannot be assumed",
      path: input.manifestPath,
    });
  }
  if (declared.unsupportedCount > 0) {
    errors.push({
      code: "DEPENDENCY_UNRESOLVED",
      message: `${declared.unsupportedCount.toString()} Gradle declaration(s) used unsupported non-literal notation`,
      path: input.manifestPath,
    });
  }
  if (declared.malformed) {
    errors.push({
      code: "INVALID_MANIFEST",
      message:
        "Gradle dependency declarations are structurally incomplete; lock selections cannot be attributed safely",
      path: input.manifestPath,
    });
  }
  const directByName = new Map<string, GradleDeclaration[]>();
  for (const declaration of declared.declarations) {
    const current = directByName.get(declaration.name) ?? [];
    current.push(declaration);
    directByName.set(declaration.name, current);
  }
  const lock =
    input.lockfileText === undefined ? undefined : parseLockfile(input.lockfileText);
  const declarationParsingIncomplete =
    declared.malformed || declared.unsupportedCount > 0;
  if (lock !== undefined) {
    for (const message of lock.errors) {
      errors.push({
        code: "INVALID_LOCKFILE",
        message,
        ...(input.lockfilePath === undefined
          ? {}
          : { path: input.lockfilePath }),
      });
    }
    const lockedNames = new Set<string>();
    let unattributedLockEntries = 0;
    for (const module of lock.modules) {
      if (input.signal?.aborted === true) {
        return { dependencies: [], errors, truncated: lock.truncated };
      }
      lockedNames.add(module.name);
      const matchingDeclarations = directByName.get(module.name);
      const declaration = matchingDeclarations?.[0];
      const declarationMatches =
        matchingDeclarations !== undefined &&
        matchingDeclarations.every((candidate) =>
          selectedVersionMatches(candidate.requestedVersion, module.version),
        );
      if (declaration === undefined) {
        unattributedLockEntries += 1;
      }
      const environment =
        declaration?.environment ??
        environmentFromConfigurations(module.configurations);
      dependencies.push({
        name: module.name,
        ecosystem: "Maven",
        ...(declaration === undefined
          ? {}
          : { requestedVersion: declaration.requestedVersion }),
        installedVersion:
          customRepository ||
          declaration === undefined ||
          declarationParsingIncomplete ||
          !declarationMatches
            ? ""
            : module.version,
        resolutionStatus: customRepository
          ? "unsupported"
          : declaration !== undefined &&
              declarationMatches &&
              !declarationParsingIncomplete
            ? "resolved"
            : "unresolved",
        dependencyType: declaration === undefined ? "transitive" : "direct",
        environment,
        ...(declaration === undefined || customRepository || !declarationMatches
          ? {}
          : { declaredEnvironment: declaration.environment }),
        ...(declaration === undefined ||
        declarationParsingIncomplete ||
        !declarationMatches
          ? {}
          : {
              dependencyPath: [
                input.projectPath,
                `${module.name}@${module.version}`,
              ],
            }),
        manifestPath: input.manifestPath,
        ...(input.lockfilePath === undefined
          ? {}
          : { lockfilePath: input.lockfilePath }),
        packageManager: "gradle",
        projectPath: input.projectPath,
        workspacePath: input.workspacePath,
        metadata: {
          configurations: module.configurations,
          ...(customRepository
            ? { repositorySource: "custom-or-unresolved" }
            : {}),
          ...(declaration === undefined
            ? {
                resolutionBasis:
                  "lock entry has no statically attributable manifest edge",
              }
            : { sourceLine: declaration.sourceLine }),
        },
      });
      if (
        !customRepository &&
        !declarationParsingIncomplete &&
        !declarationMatches
      ) {
        errors.push({
          code: "DEPENDENCY_UNRESOLVED",
          message:
            "Gradle lock selection does not satisfy the manifest dependency selector",
          packageName: module.name,
          path: input.manifestPath,
        });
      }
    }
    if (
      unattributedLockEntries > 0 &&
      !customRepository &&
      !declarationParsingIncomplete
    ) {
      errors.push({
        code: "DEPENDENCY_UNRESOLVED",
        message: `${unattributedLockEntries.toString()} Gradle lock entr${
          unattributedLockEntries === 1 ? "y has" : "ies have"
        } no statically attributable manifest edge; graphless transitive coordinates were not submitted`,
        ...(input.lockfilePath === undefined
          ? {}
          : { path: input.lockfilePath }),
      });
    }
    for (const declaration of declared.declarations) {
      if (!lockedNames.has(declaration.name)) {
        dependencies.push({
          name: declaration.name,
          ecosystem: "Maven",
          requestedVersion: declaration.requestedVersion,
          installedVersion: "",
          resolutionStatus: customRepository ? "unsupported" : "unresolved",
          dependencyType: "direct",
          environment: declaration.environment,
          declaredEnvironment: declaration.environment,
          manifestPath: input.manifestPath,
          ...(input.lockfilePath === undefined
            ? {}
            : { lockfilePath: input.lockfilePath }),
          packageManager: "gradle",
          projectPath: input.projectPath,
          workspacePath: input.workspacePath,
          metadata: {
            configuration: declaration.configuration,
            sourceLine: declaration.sourceLine,
            ...(customRepository
              ? { repositorySource: "custom-or-unresolved" }
              : {}),
          },
        });
        if (!customRepository) {
          errors.push({
            code: "DEPENDENCY_UNRESOLVED",
            message: "Gradle declaration is absent from the available lock state",
            packageName: declaration.name,
            path: input.manifestPath,
          });
        }
      }
    }
    if (lock.truncated) {
      errors.push({
        code: "DEPENDENCY_LIMIT",
        message: "Gradle lockfile exceeds its dependency limit",
        ...(input.lockfilePath === undefined
          ? {}
          : { path: input.lockfilePath }),
      });
    }
    return { dependencies, errors, truncated: lock.truncated };
  }

  for (const declaration of declared.declarations.slice(0, MAX_DEPENDENCIES)) {
    dependencies.push({
      name: declaration.name,
      ecosystem: "Maven",
      requestedVersion: declaration.requestedVersion,
      installedVersion: "",
      resolutionStatus: customRepository ? "unsupported" : "unresolved",
      dependencyType: "direct",
      environment: declaration.environment,
      declaredEnvironment: declaration.environment,
      manifestPath: input.manifestPath,
      packageManager: "gradle",
      projectPath: input.projectPath,
      workspacePath: input.workspacePath,
      metadata: {
        configuration: declaration.configuration,
        sourceLine: declaration.sourceLine,
        resolutionBasis: "declaration only; selected version unavailable",
        ...(customRepository
          ? { repositorySource: "custom-or-unresolved" }
          : {}),
      },
    });
    if (!customRepository) {
      errors.push({
        code: "DEPENDENCY_UNRESOLVED",
        message: dynamicVersion(declaration.requestedVersion)
          ? "Gradle dependency uses a dynamic or interpolated version"
          : "No gradle.lockfile is available to prove the selected Gradle version",
        packageName: declaration.name,
        path: input.manifestPath,
      });
    }
  }
  if (declared.declarations.length > 0) {
    errors.push({
      code: "DEPENDENCY_UNRESOLVED",
      message: "No gradle.lockfile is available; transitive dependency resolution is unavailable",
      path: input.manifestPath,
    });
  }
  const truncated = declared.declarations.length > MAX_DEPENDENCIES;
  return { dependencies, errors, truncated };
}
