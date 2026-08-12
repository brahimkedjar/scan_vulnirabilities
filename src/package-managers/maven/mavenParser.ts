import { SaxesParser } from "saxes";

import type { Dependency, DependencyMetadataValue } from "../../models/Dependency";
import type { ScanError } from "../../models/ScanResult";
import { MAX_PARSED_DEPENDENCIES as MAX_DEPENDENCIES } from "../python/parserLimits";

const MAX_XML_DEPTH = 64;
const MAX_XML_ELEMENTS = 200_000;
const MAX_INTERPOLATION_DEPTH = 16;
const MAX_REPOSITORIES = 256;
const COORDINATE_PART = /^[A-Za-z0-9_.-]+$/u;

interface RawDependency {
  readonly values: Readonly<Record<string, string>>;
  readonly sourceLine: number;
}

export interface MavenParseInput {
  readonly text: string;
  /** Ancestor POM content available for bounded parent/repository provenance. */
  readonly repositoryConfigurationTexts?: readonly string[];
  /** Applicable workspace .mvn/maven.config content, used for source provenance. */
  readonly mavenConfigurationTexts?: readonly string[];
  /** Applicable workspace .mvn/extensions.xml content; presence is executable. */
  readonly mavenExtensionTexts?: readonly string[];
  readonly manifestPath: string;
  readonly projectPath: string;
  readonly workspacePath: string;
  readonly signal?: AbortSignal;
}

export interface MavenParseResult {
  readonly dependencies: readonly Dependency[];
  readonly errors: readonly ScanError[];
  readonly truncated: boolean;
}

function localName(name: string): string {
  return name.split(":").at(-1) ?? name;
}

function parseXml(input: MavenParseInput): {
  readonly direct: readonly RawDependency[];
  readonly managed: readonly RawDependency[];
  readonly properties: Readonly<Record<string, string>>;
  readonly projectValues: Readonly<Record<string, string>>;
  readonly conditionalDependencyCount: number;
  readonly repositoryDeclarationCount: number;
  readonly repositoryUrls: readonly string[];
  readonly buildExtensionDeclarationCount: number;
  readonly truncated: boolean;
} {
  if (/<!DOCTYPE|<!ENTITY/iu.test(input.text)) {
    throw new Error("DOCTYPE and entity declarations are not accepted in POM files");
  }
  const parser = new SaxesParser({ xmlns: false, position: true });
  const stack: string[] = [];
  const textStack: string[] = [];
  const direct: RawDependency[] = [];
  const managed: RawDependency[] = [];
  const properties: Record<string, string> = {};
  const projectValues: Record<string, string> = {};
  let currentDependency:
    | { values: Record<string, string>; sourceLine: number; managed: boolean }
    | undefined;
  let elements = 0;
  let conditionalDependencyCount = 0;
  let repositoryDeclarationCount = 0;
  let buildExtensionDeclarationCount = 0;
  const repositoryUrls: string[] = [];
  let truncated = false;
  parser.on("opentag", (tag) => {
    if (input.signal?.aborted === true) {
      throw new DOMException("Maven parse cancelled", "AbortError");
    }
    elements += 1;
    if (elements > MAX_XML_ELEMENTS || stack.length >= MAX_XML_DEPTH) {
      truncated = true;
      throw new RangeError("POM XML exceeds its structural limit");
    }
    const name = localName(tag.name);
    const parentPath = stack.join("/");
    stack.push(name);
    textStack.push("");
    if (
      name === "dependency" &&
      (parentPath === "project/dependencies" ||
        parentPath === "project/dependencyManagement/dependencies")
    ) {
      currentDependency = {
        values: {},
        sourceLine: parser.line,
        managed: parentPath.includes("dependencyManagement"),
      };
    } else if (
      name === "dependency" &&
      parentPath.startsWith("project/profiles/profile/") &&
      parentPath.endsWith("/dependencies")
    ) {
      conditionalDependencyCount += 1;
    } else if (
      name === "repository" &&
      (parentPath === "project/repositories" ||
        parentPath === "project/profiles/profile/repositories")
    ) {
      repositoryDeclarationCount += 1;
      if (repositoryDeclarationCount > MAX_REPOSITORIES) {
        truncated = true;
      }
    } else if (
      name === "extension" &&
      (parentPath === "project/build/extensions" ||
        parentPath === "project/profiles/profile/build/extensions")
    ) {
      buildExtensionDeclarationCount += 1;
    }
  });
  parser.on("text", (text) => {
    const index = textStack.length - 1;
    if (index >= 0) {
      textStack[index] = `${textStack[index] ?? ""}${text}`.slice(0, 65_537);
    }
  });
  parser.on("cdata", (text) => {
    const index = textStack.length - 1;
    if (index >= 0) {
      textStack[index] = `${textStack[index] ?? ""}${text}`.slice(0, 65_537);
    }
  });
  parser.on("closetag", (tag) => {
    const name = localName(tag.name);
    const value = (textStack.pop() ?? "").trim();
    const path = stack.join("/");
    if (
      currentDependency !== undefined &&
      path.endsWith(`/dependency/${name}`) &&
      stack.at(-2) === "dependency" &&
      value.length > 0
    ) {
      currentDependency.values[name] = value;
    }
    if (name === "dependency" && currentDependency !== undefined) {
      const completed = {
        values: currentDependency.values,
        sourceLine: currentDependency.sourceLine,
      };
      if (currentDependency.managed) {
        managed.push(completed);
      } else {
        direct.push(completed);
      }
      currentDependency = undefined;
    } else if (
      stack.length === 3 &&
      stack[0] === "project" &&
      stack[1] === "properties" &&
      value.length > 0
    ) {
      properties[name] = value;
    } else if (
      value.length > 0 &&
      [
        "project/groupId",
        "project/artifactId",
        "project/version",
        "project/parent/groupId",
        "project/parent/artifactId",
        "project/parent/version",
      ].includes(path)
    ) {
      projectValues[path] = value;
    } else if (
      name === "url" &&
      repositoryUrls.length < MAX_REPOSITORIES &&
      (path === "project/repositories/repository/url" ||
        path === "project/profiles/profile/repositories/repository/url")
    ) {
      repositoryUrls.push(value);
    }
    stack.pop();
  });
  parser.on("doctype", () => {
    throw new Error("DOCTYPE is not accepted in POM files");
  });
  parser.on("error", (error) => {
    throw error;
  });
  parser.write(input.text).close();
  return {
    direct,
    managed,
    properties,
    projectValues,
    conditionalDependencyCount,
    repositoryDeclarationCount,
    repositoryUrls,
    buildExtensionDeclarationCount,
    truncated,
  };
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

type ParsedPom = ReturnType<typeof parseXml>;

function hasCustomRepository(parsed: ParsedPom): boolean {
  return (
    parsed.buildExtensionDeclarationCount > 0 ||
    parsed.repositoryDeclarationCount !== parsed.repositoryUrls.length ||
    parsed.repositoryUrls.some((url) => !canonicalMavenCentralUrl(url))
  );
}

function mavenConfigurationTokenUnsupported(token: string): boolean {
  const normalized = token.toLowerCase();
  if (
    normalized === "-o" ||
    normalized === "--offline" ||
    normalized.startsWith("--offline=") ||
    normalized === "-f" ||
    normalized === "--file" ||
    normalized.startsWith("--file=") ||
    /^-dmaven\.repo\.local(?:=|$)/iu.test(token)
  ) {
    return true;
  }
  if (
    normalized.startsWith("-f") &&
    !["-fae", "-ff", "-fn"].includes(normalized)
  ) {
    return true;
  }
  return (
    normalized === "--settings" ||
    normalized === "--global-settings" ||
    normalized.startsWith("--settings=") ||
    normalized.startsWith("--global-settings=") ||
    normalized.startsWith("-s") ||
    normalized.startsWith("-gs")
  );
}

function hasUnsupportedMavenConfiguration(input: MavenParseInput): boolean {
  const configurations = input.mavenConfigurationTexts ?? [];
  const extensionFiles = input.mavenExtensionTexts ?? [];
  if (
    configurations.length > MAX_INTERPOLATION_DEPTH ||
    extensionFiles.length > MAX_INTERPOLATION_DEPTH ||
    extensionFiles.length > 0
  ) {
    return true;
  }
  return configurations.some((configuration) =>
    (configuration.match(/"[^"\r\n]*"|'[^'\r\n]*'|[^\s]+/gu) ?? []).some(
      (rawToken) => {
        const quoted =
          rawToken.length >= 2 &&
          ((rawToken.startsWith('"') && rawToken.endsWith('"')) ||
            (rawToken.startsWith("'") && rawToken.endsWith("'")));
        return mavenConfigurationTokenUnsupported(
          quoted ? rawToken.slice(1, -1) : rawToken,
        );
      },
    ),
  );
}

function parentCoordinate(
  parsed: ParsedPom,
): { readonly group: string; readonly artifact: string; readonly version: string } | undefined {
  const group = parsed.projectValues["project/parent/groupId"];
  const artifact = parsed.projectValues["project/parent/artifactId"];
  const version = parsed.projectValues["project/parent/version"];
  return group === undefined || artifact === undefined || version === undefined
    ? undefined
    : { group, artifact, version };
}

function projectCoordinate(
  parsed: ParsedPom,
): { readonly group: string; readonly artifact: string; readonly version: string } | undefined {
  const group =
    parsed.projectValues["project/groupId"] ??
    parsed.projectValues["project/parent/groupId"];
  const artifact = parsed.projectValues["project/artifactId"];
  const version =
    parsed.projectValues["project/version"] ??
    parsed.projectValues["project/parent/version"];
  return group === undefined || artifact === undefined || version === undefined
    ? undefined
    : { group, artifact, version };
}

function sameCoordinate(
  left: { readonly group: string; readonly artifact: string; readonly version: string },
  right: { readonly group: string; readonly artifact: string; readonly version: string },
): boolean {
  return (
    left.group === right.group &&
    left.artifact === right.artifact &&
    left.version === right.version
  );
}

function inheritedRepositoryUnsupported(
  parsed: ParsedPom,
  input: MavenParseInput,
): boolean {
  let expected = parentCoordinate(parsed);
  if (expected === undefined) {
    return false;
  }
  const texts = input.repositoryConfigurationTexts ?? [];
  if (texts.length === 0 || texts.length > MAX_INTERPOLATION_DEPTH) {
    return true;
  }
  const candidates: ParsedPom[] = [];
  try {
    for (const text of texts.slice(0, MAX_INTERPOLATION_DEPTH)) {
      candidates.push(parseXml({ ...input, text }));
    }
  } catch {
    return true;
  }

  const visited = new Set<string>();
  for (let depth = 0; depth < MAX_INTERPOLATION_DEPTH; depth += 1) {
    const expectedCoordinate = expected;
    const key = JSON.stringify([
      expectedCoordinate.group,
      expectedCoordinate.artifact,
      expectedCoordinate.version,
    ]);
    if (visited.has(key)) {
      return true;
    }
    visited.add(key);
    const matches = candidates.filter((candidate) => {
      const coordinate = projectCoordinate(candidate);
      return (
        coordinate !== undefined && sameCoordinate(coordinate, expectedCoordinate)
      );
    });
    if (matches.length !== 1) {
      return true;
    }
    const parent = matches[0];
    if (parent === undefined || hasCustomRepository(parent)) {
      return true;
    }
    const next = parentCoordinate(parent);
    if (next === undefined) {
      return false;
    }
    expected = next;
  }
  return true;
}

function resolver(
  properties: Readonly<Record<string, string>>,
  project: Readonly<Record<string, string>>,
): (value: string) => string | undefined {
  const known: Record<string, string> = { ...properties };
  const group = project["project/groupId"] ?? project["project/parent/groupId"];
  const version = project["project/version"] ?? project["project/parent/version"];
  if (group !== undefined) {
    known["project.groupId"] = group;
    known["pom.groupId"] = group;
  }
  if (version !== undefined) {
    known["project.version"] = version;
    known["pom.version"] = version;
  }
  const parentGroup = project["project/parent/groupId"];
  const parentVersion = project["project/parent/version"];
  if (parentGroup !== undefined) {
    known["project.parent.groupId"] = parentGroup;
    known["parent.groupId"] = parentGroup;
  }
  if (parentVersion !== undefined) {
    known["project.parent.version"] = parentVersion;
    known["parent.version"] = parentVersion;
  }
  return (raw: string): string | undefined => {
    let value = raw;
    for (let depth = 0; depth < MAX_INTERPOLATION_DEPTH; depth += 1) {
      let unresolved = false;
      const next = value.replace(/\$\{([^}]+)\}/gu, (_match, key: string) => {
        const replacement = known[key];
        if (replacement === undefined) {
          unresolved = true;
          return `\${${key}}`;
        }
        return replacement;
      });
      if (next.length > 8_192) {
        return undefined;
      }
      value = next;
      if (!value.includes("${")) {
        return value;
      }
      if (unresolved && next === value) {
        return undefined;
      }
    }
    return undefined;
  };
}

function exactMavenVersion(value: string): string | undefined {
  const trimmed = value.trim();
  const singleton = /^\[([^,[\]()]+)\]$/u.exec(trimmed)?.[1];
  if (singleton !== undefined) {
    return exactMavenVersion(singleton);
  }
  if (
    trimmed.length === 0 ||
    trimmed.length > 256 ||
    /^[[(]/u.test(trimmed) ||
    /^latest(?:[._-].*)?$/iu.test(trimmed) ||
    /[\s,?*]/u.test(trimmed) ||
    !/[0-9]/u.test(trimmed) ||
    !/^[A-Za-z0-9][A-Za-z0-9._+-]*$/u.test(trimmed) ||
    /(?:^|[^A-Za-z0-9])\+|\+(?:$|[^A-Za-z0-9])/u.test(trimmed)
  ) {
    return undefined;
  }
  return trimmed;
}

export function parseMavenPom(input: MavenParseInput): MavenParseResult {
  let parsed: ReturnType<typeof parseXml>;
  try {
    parsed = parseXml(input);
  } catch (error: unknown) {
    if (error instanceof DOMException && error.name === "AbortError") {
      return { dependencies: [], errors: [], truncated: false };
    }
    return {
      dependencies: [],
      errors: [
        {
          code: error instanceof RangeError ? "DEPENDENCY_LIMIT" : "INVALID_MANIFEST",
          message: error instanceof Error ? error.message : "invalid pom.xml",
          path: input.manifestPath,
        },
      ],
      truncated: error instanceof RangeError,
    };
  }
  const resolve = resolver(parsed.properties, parsed.projectValues);
  const managed = new Map<string, string>();
  for (const dependency of parsed.managed) {
    const group = resolve(dependency.values.groupId ?? "");
    const artifact = resolve(dependency.values.artifactId ?? "");
    const version = resolve(dependency.values.version ?? "");
    if (group !== undefined && artifact !== undefined && version !== undefined) {
      managed.set(`${group}:${artifact}`, version);
    }
  }
  const dependencies: Dependency[] = [];
  const errors: ScanError[] = [];
  const customRepository =
    hasCustomRepository(parsed) ||
    inheritedRepositoryUnsupported(parsed, input) ||
    hasUnsupportedMavenConfiguration(input);
  if (customRepository) {
    errors.push({
      code: "UNSUPPORTED_PACKAGE_SOURCE",
      message:
        "POM configures a custom or unresolvable dependency repository; Maven Central identity cannot be assumed",
      path: input.manifestPath,
    });
  }
  const retained = parsed.direct.slice(0, MAX_DEPENDENCIES);
  const truncated = parsed.truncated || parsed.direct.length > MAX_DEPENDENCIES;
  for (const raw of retained) {
    const group = resolve(raw.values.groupId ?? "");
    const artifact = resolve(raw.values.artifactId ?? "");
    if (
      group === undefined ||
      artifact === undefined ||
      !COORDINATE_PART.test(group) ||
      !COORDINATE_PART.test(artifact)
    ) {
      errors.push({
        code: "INVALID_MANIFEST",
        message: "Maven dependency has an unresolved or invalid groupId/artifactId",
        path: input.manifestPath,
      });
      continue;
    }
    const name = `${group}:${artifact}`;
    const requested = raw.values.version ?? managed.get(name);
    const resolvedRequested =
      requested === undefined ? undefined : resolve(requested);
    const version =
      resolvedRequested === undefined
        ? undefined
        : exactMavenVersion(resolvedRequested);
    const scope = (resolve(raw.values.scope ?? "compile") ?? "compile").toLowerCase();
    const systemSource =
      scope === "system" || raw.values.systemPath !== undefined;
    const unsupported = customRepository || systemSource;
    const environment =
      raw.values.optional?.toLowerCase() === "true"
        ? "optional"
        : scope === "test"
          ? "development"
          : "production";
    const status = unsupported
      ? "unsupported"
      : version === undefined
        ? "unresolved"
        : "resolved";
    const metadata: Record<string, DependencyMetadataValue> = {
      scope,
      sourceLine: raw.sourceLine,
      ...(raw.values.type === undefined ? {} : { type: raw.values.type }),
      ...(raw.values.classifier === undefined
        ? {}
        : { classifier: raw.values.classifier }),
      ...(customRepository
        ? { repositorySource: "custom-or-unresolved" }
        : {}),
    };
    dependencies.push({
      name,
      ecosystem: "Maven",
      manifestName: artifact,
      ...(requested === undefined ? {} : { requestedVersion: requested }),
      installedVersion: status === "resolved" ? (version ?? "") : "",
      resolutionStatus: status,
      dependencyType: "direct",
      environment,
      declaredEnvironment: environment,
      ...(status === "resolved"
        ? { dependencyPath: [input.projectPath, `${name}@${version ?? ""}`] }
        : {}),
      manifestPath: input.manifestPath,
      packageManager: "maven",
      projectPath: input.projectPath,
      workspacePath: input.workspacePath,
      metadata,
    });
    if (status !== "resolved" && !(customRepository && !systemSource)) {
      errors.push({
        code: unsupported
          ? "UNSUPPORTED_PACKAGE_SOURCE"
          : "DEPENDENCY_UNRESOLVED",
        message: systemSource
          ? "Maven system-scope dependency has no canonical repository release"
          : "Maven dependency version is missing, dynamic, ranged, or uses an unresolved property",
        packageName: name,
        path: input.manifestPath,
      });
    }
  }
  if (truncated) {
    errors.push({
      code: "DEPENDENCY_LIMIT",
      message: `POM exceeds the ${MAX_DEPENDENCIES.toString()}-dependency limit`,
      path: input.manifestPath,
    });
  }
  if (dependencies.length > 0) {
    errors.push({
      code: "DEPENDENCY_UNRESOLVED",
      message: "pom.xml does not contain Maven's resolved transitive dependency graph",
      path: input.manifestPath,
    });
  }
  if (parsed.conditionalDependencyCount > 0) {
    errors.push({
      code: "DEPENDENCY_UNRESOLVED",
      message: `${parsed.conditionalDependencyCount.toString()} profile-conditional Maven dependency declaration(s) were not activated statically`,
      path: input.manifestPath,
    });
  }
  return { dependencies, errors, truncated };
}
