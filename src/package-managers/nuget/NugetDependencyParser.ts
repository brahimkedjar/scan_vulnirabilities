import { SaxesParser, type SaxesTagPlain } from "saxes";

import type { Dependency, DependencyEnvironment } from "../../models/Dependency";

type UnknownRecord = Record<string, unknown>;

export interface NugetParseIssue {
  readonly code: string;
  readonly message: string;
}

export interface NugetParserLimits {
  readonly maxPackages: number;
  readonly maxTargets: number;
  readonly maxEdges: number;
  readonly maxIssues: number;
  readonly maxXmlDepth: number;
}

export interface NugetParserInput {
  readonly projectXml?: string;
  readonly manifestPath: string;
  /** Applicable workspace/sibling NuGet.config files, ordered outermost first. */
  readonly nugetConfigXmls?: readonly string[];
  /** Applicable Directory.Packages.props files, ordered outermost first. */
  readonly directoryPackagesPropsXmls?: readonly string[];
  /** Applicable ancestor Directory.Build.props files, ordered outermost first. */
  readonly restoreConfigurationXmls?: readonly string[];
  readonly lockfile?: string;
  readonly lockfilePath?: string;
  readonly packagesConfigXml?: string;
  readonly projectPath?: string;
  readonly workspacePath?: string;
  readonly signal?: AbortSignal;
  readonly limits?: Partial<NugetParserLimits>;
}

export interface NugetParseResult {
  readonly dependencies: readonly Dependency[];
  readonly issues: readonly NugetParseIssue[];
  readonly truncated: boolean;
  readonly cancelled: boolean;
}

export const DEFAULT_NUGET_PARSER_LIMITS: NugetParserLimits = {
  maxPackages: 10_000,
  maxTargets: 256,
  maxEdges: 250_000,
  maxIssues: 1_000,
  maxXmlDepth: 256,
};

interface ProjectReference {
  readonly name: string;
  readonly requestedVersion?: string;
  readonly environment: DependencyEnvironment;
  readonly conditioned: boolean;
}

interface ConfigPackage {
  readonly name: string;
  readonly version: string;
  readonly originalVersion?: string;
  readonly requestedVersion?: string;
  readonly environment: DependencyEnvironment;
}

interface LockPackage {
  readonly name: string;
  readonly type: "Direct" | "Transitive" | "CentralTransitive" | "Project";
  readonly requestedVersion?: string;
  readonly resolvedVersion?: string;
  readonly originalResolvedVersion?: string;
  readonly dependencies: readonly {
    readonly name: string;
    readonly constraint?: string;
  }[];
}

interface LockTarget {
  readonly name: string;
  readonly framework: string;
  readonly packages: readonly LockPackage[];
}

class NugetParseContext {
  public readonly issues: NugetParseIssue[] = [];
  public truncated = false;
  public edges = 0;

  public constructor(
    public readonly limits: NugetParserLimits,
    private readonly signal: AbortSignal | undefined,
  ) {}

  public checkCancellation(): void {
    if (this.signal?.aborted === true) {
      throw new DOMException("NuGet parsing cancelled", "AbortError");
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
        "NuGet dependency graph exceeded its edge safety limit",
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
  supplied: Partial<NugetParserLimits> | undefined,
): NugetParserLimits {
  return {
    maxPackages: positiveLimit(
      supplied?.maxPackages,
      DEFAULT_NUGET_PARSER_LIMITS.maxPackages,
    ),
    maxTargets: positiveLimit(
      supplied?.maxTargets,
      DEFAULT_NUGET_PARSER_LIMITS.maxTargets,
    ),
    maxEdges: positiveLimit(
      supplied?.maxEdges,
      DEFAULT_NUGET_PARSER_LIMITS.maxEdges,
    ),
    maxIssues: positiveLimit(
      supplied?.maxIssues,
      DEFAULT_NUGET_PARSER_LIMITS.maxIssues,
    ),
    maxXmlDepth: positiveLimit(
      supplied?.maxXmlDepth,
      DEFAULT_NUGET_PARSER_LIMITS.maxXmlDepth,
    ),
  };
}

function safePackageName(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 256 &&
    /^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(value)
  );
}

function safeValue(value: unknown, maximum = 2_048): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    !/[\u0000-\u001F\u007F]/u.test(value)
  );
}

function safeResolvedVersion(value: unknown): value is string {
  if (!safeValue(value, 256)) {
    return false;
  }
  const match = /^(\d+(?:\.\d+){1,3})(?:-([0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*))?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u.exec(
    value,
  );
  const numeric = [
    ...(match?.[1]?.split(".") ?? []),
    ...(match?.[2]?.split(/[.-]/u).filter((part) => /^\d+$/u.test(part)) ?? []),
  ];
  return (
    match !== null &&
    numeric.every((part) => part === "0" || !part.startsWith("0"))
  );
}

function normalizedResolvedVersion(value: unknown): string | undefined {
  if (!safeResolvedVersion(value)) {
    return undefined;
  }
  return value.split("+", 1)[0];
}

function attr(tag: SaxesTagPlain, name: string): string | undefined {
  const direct = tag.attributes[name];
  if (typeof direct === "string") {
    return direct;
  }
  const key = Object.keys(tag.attributes).find(
    (candidate) => candidate.toLowerCase() === name.toLowerCase(),
  );
  const value = key === undefined ? undefined : tag.attributes[key];
  return typeof value === "string" ? value : undefined;
}

const MAX_NUGET_CONFIGS = 32;
const MAX_NUGET_CONFIG_ELEMENTS = 20_000;
const MAX_NUGET_PACKAGE_SOURCES = 256;
const MAX_DIRECTORY_PACKAGES_PROPS = 32;
const MAX_RESTORE_CONFIGURATION_FILES = 32;

function localXmlName(name: string): string {
  return name.includes(":") ? name.slice(name.lastIndexOf(":") + 1) : name;
}

function canonicalNugetOrgSource(value: string): boolean {
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
      ((url.hostname.toLowerCase() === "api.nuget.org" &&
        (url.pathname === "/v3/index.json" ||
          url.pathname === "/v3/index.json/")) ||
        (url.hostname.toLowerCase() === "www.nuget.org" &&
          (url.pathname === "/api/v2" || url.pathname === "/api/v2/"))) &&
      url.search.length === 0 &&
      url.hash.length === 0
    );
  } catch {
    return false;
  }
}

function nugetConfigHasCustomSource(
  xml: string,
  context: NugetParseContext,
): boolean {
  if (/<!DOCTYPE|<!ENTITY/iu.test(xml)) {
    context.addIssue(
      "INVALID_MANIFEST",
      "NuGet.config must not contain a DOCTYPE or entity declaration",
    );
    return true;
  }
  const parser = new SaxesParser({ xmlns: false, position: true });
  const stack: string[] = [];
  let elements = 0;
  let sources = 0;
  let custom = false;
  let rejected = false;
  parser.on("doctype", () => {
    rejected = true;
  });
  parser.on("error", () => {
    rejected = true;
  });
  parser.on("opentag", (tag) => {
    context.checkCancellation();
    elements += 1;
    if (
      elements > MAX_NUGET_CONFIG_ELEMENTS ||
      stack.length >= context.limits.maxXmlDepth
    ) {
      rejected = true;
      return;
    }
    const local = localXmlName(tag.name);
    const parentPath = stack.join("/").toLowerCase();
    stack.push(local);
    if (parentPath !== "configuration/packagesources") {
      return;
    }
    if (local.toLowerCase() === "add") {
      sources += 1;
      const value = attr(tag, "value");
      if (
        sources > MAX_NUGET_PACKAGE_SOURCES ||
        !safeValue(value) ||
        !canonicalNugetOrgSource(value)
      ) {
        custom = true;
      }
    } else if (
      local.toLowerCase() !== "clear" &&
      local.toLowerCase() !== "remove"
    ) {
      custom = true;
    }
  });
  parser.on("closetag", () => {
    stack.pop();
  });
  try {
    parser.write(xml).close();
  } catch {
    rejected = true;
  }
  if (rejected) {
    context.addIssue("INVALID_MANIFEST", "NuGet.config is malformed or unsafe");
    return true;
  }
  return custom;
}

const RESTORE_SOURCE_PROPERTIES = new Set([
  "restoresources",
  "restoreadditionalprojectsources",
]);
const AMBIGUOUS_RESTORE_PROPERTIES = new Set([
  "restoreconfigfile",
  "restorefallbackfolders",
  "restoreadditionalprojectfallbackfolders",
]);
const BUILT_IN_DOTNET_SDKS = new Set([
  "microsoft.net.sdk",
  "microsoft.net.sdk.web",
  "microsoft.net.sdk.worker",
  "microsoft.net.sdk.windowsdesktop",
  "microsoft.net.sdk.razor",
  "microsoft.net.sdk.blazorwebassembly",
]);

function usesOnlyBuiltInDotnetSdks(value: string): boolean {
  if (value.length === 0 || value.length > 512 || /\$[({]/u.test(value)) {
    return false;
  }
  const names = value.split(";").map((name) => name.trim().toLowerCase());
  return (
    names.length > 0 &&
    names.length <= 8 &&
    names.every((name) => BUILT_IN_DOTNET_SDKS.has(name))
  );
}

function canonicalRestoreSourceList(value: string): boolean {
  if (value.length === 0 || value.length > 8_192 || /\$[({]/u.test(value)) {
    return false;
  }
  const sources = value
    .split(";")
    .map((source) => source.trim())
    .filter((source) => source.length > 0);
  return (
    sources.length > 0 && sources.every((source) => canonicalNugetOrgSource(source))
  );
}

function xmlHasUnsupportedRestoreSource(
  xml: string,
  context: NugetParseContext,
): boolean {
  if (/<!DOCTYPE|<!ENTITY/iu.test(xml)) {
    context.addIssue(
      "INVALID_MANIFEST",
      "NuGet restore configuration must not contain a DOCTYPE or entity declaration",
    );
    return true;
  }
  const parser = new SaxesParser({ xmlns: false, position: true });
  let depth = 0;
  let elements = 0;
  let rejected = false;
  let unsupported = false;
  const conditionedStack: boolean[] = [];
  let active:
    | {
        readonly name: string;
        readonly depth: number;
        readonly conditioned: boolean;
        text: string;
      }
    | undefined;
  parser.on("doctype", () => {
    rejected = true;
  });
  parser.on("error", () => {
    rejected = true;
  });
  parser.on("opentag", (tag) => {
    context.checkCancellation();
    depth += 1;
    elements += 1;
    const conditioned =
      (conditionedStack.at(-1) ?? false) || attr(tag, "Condition") !== undefined;
    conditionedStack.push(conditioned);
    if (
      depth > context.limits.maxXmlDepth ||
      elements > MAX_NUGET_CONFIG_ELEMENTS
    ) {
      rejected = true;
      return;
    }
    if (active !== undefined) {
      unsupported = true;
    }
    const name = localXmlName(tag.name).toLowerCase();
    if (name === "import" || name === "importgroup") {
      // Imported MSBuild can inject RestoreSources/RestoreConfigFile after the
      // statically visible project/props content, so provenance is unprovable.
      unsupported = true;
    }
    if (name === "project") {
      const sdk = attr(tag, "Sdk");
      if (sdk !== undefined && !usesOnlyBuiltInDotnetSdks(sdk)) {
        unsupported = true;
      }
    } else if (name === "sdk") {
      const sdkName = attr(tag, "Name");
      if (
        sdkName === undefined ||
        attr(tag, "Version") !== undefined ||
        !usesOnlyBuiltInDotnetSdks(sdkName)
      ) {
        unsupported = true;
      }
    }
    if (
      RESTORE_SOURCE_PROPERTIES.has(name) ||
      AMBIGUOUS_RESTORE_PROPERTIES.has(name)
    ) {
      active = {
        name,
        depth,
        conditioned,
        text: "",
      };
    }
  });
  const appendText = (text: string): void => {
    if (active === undefined) {
      return;
    }
    if (active.text.length + text.length > 8_192) {
      unsupported = true;
      return;
    }
    active.text += text;
  };
  parser.on("text", appendText);
  parser.on("cdata", appendText);
  parser.on("closetag", (tag) => {
    const name = localXmlName(tag.name).toLowerCase();
    if (active !== undefined && active.name === name && active.depth === depth) {
      if (
        active.conditioned ||
        AMBIGUOUS_RESTORE_PROPERTIES.has(name) ||
        !canonicalRestoreSourceList(active.text.trim())
      ) {
        unsupported = true;
      }
      active = undefined;
    }
    conditionedStack.pop();
    depth -= 1;
  });
  try {
    parser.write(xml).close();
  } catch {
    rejected = true;
  }
  if (rejected || active !== undefined) {
    context.addIssue(
      "INVALID_MANIFEST",
      "NuGet restore configuration is malformed or unsafe",
    );
    return true;
  }
  return unsupported;
}

function hasUnsupportedNugetSource(
  input: NugetParserInput,
  context: NugetParseContext,
): boolean {
  const configurations = input.nugetConfigXmls ?? [];
  const centralFiles = input.directoryPackagesPropsXmls ?? [];
  const restoreConfigurationFiles = input.restoreConfigurationXmls ?? [];
  const restoreSourceFiles = [
    ...(input.projectXml === undefined ? [] : [input.projectXml]),
    ...centralFiles.slice(0, MAX_DIRECTORY_PACKAGES_PROPS),
    ...restoreConfigurationFiles.slice(0, MAX_RESTORE_CONFIGURATION_FILES),
  ];
  const restoreOverride = restoreSourceFiles.some((xml) =>
    xmlHasUnsupportedRestoreSource(xml, context),
  );
  let unsupported =
    configurations.length > MAX_NUGET_CONFIGS ||
    centralFiles.length > MAX_DIRECTORY_PACKAGES_PROPS ||
    restoreConfigurationFiles.length > MAX_RESTORE_CONFIGURATION_FILES ||
    restoreOverride;
  if (unsupported) {
    context.truncated = true;
    context.addIssue(
      "DEPENDENCY_LIMIT",
      "NuGet.config hierarchy exceeds its safety limit",
    );
  }
  for (const xml of configurations.slice(0, MAX_NUGET_CONFIGS)) {
    context.checkCancellation();
    if (nugetConfigHasCustomSource(xml, context)) {
      unsupported = true;
    }
  }
  if (unsupported) {
    context.addIssue(
      "UNSUPPORTED_PACKAGE_SOURCE",
      "NuGet configuration declares a custom or unresolvable package source; nuget.org identity cannot be assumed",
    );
  }
  return unsupported;
}

function applySourceProvenance(
  dependencies: readonly Dependency[],
  unsupported: boolean,
): readonly Dependency[] {
  if (!unsupported) {
    return dependencies;
  }
  return dependencies.map((dependency) => ({
    ...dependency,
    installedVersion: "",
    resolutionStatus: "unsupported",
    metadata: {
      ...dependency.metadata,
      packageSource: "custom-or-unresolved",
    },
  }));
}

interface PendingCentralVersion {
  name?: string;
  version?: string;
  childVersion: boolean;
  text: string;
  conditioned: boolean;
}

function parseCentralPackageVersions(
  xmls: readonly string[],
  context: NugetParseContext,
): { readonly versions: ReadonlyMap<string, string>; readonly valid: boolean } {
  const versions = new Map<string, string>();
  let valid = xmls.length <= MAX_DIRECTORY_PACKAGES_PROPS;
  if (!valid) {
    context.truncated = true;
    context.addIssue(
      "DEPENDENCY_LIMIT",
      "Directory.Packages.props hierarchy exceeds its safety limit",
    );
  }
  for (const xml of xmls.slice(0, MAX_DIRECTORY_PACKAGES_PROPS)) {
    context.checkCancellation();
    if (/<!DOCTYPE|<!ENTITY/iu.test(xml)) {
      valid = false;
      context.addIssue(
        "INVALID_MANIFEST",
        "Directory.Packages.props must not contain a DOCTYPE or entity declaration",
      );
      continue;
    }
    const parser = new SaxesParser({ xmlns: false, position: true });
    const conditionedStack: boolean[] = [];
    let depth = 0;
    let elements = 0;
    let rejected = false;
    let pending: PendingCentralVersion | undefined;
    parser.on("doctype", () => {
      rejected = true;
    });
    parser.on("error", () => {
      rejected = true;
    });
    parser.on("opentag", (tag) => {
      context.checkCancellation();
      depth += 1;
      elements += 1;
      if (
        depth > context.limits.maxXmlDepth ||
        elements > MAX_NUGET_CONFIG_ELEMENTS
      ) {
        rejected = true;
        return;
      }
      const parentConditioned = conditionedStack.at(-1) ?? false;
      const conditioned = parentConditioned || attr(tag, "Condition") !== undefined;
      conditionedStack.push(conditioned);
      const local = localXmlName(tag.name);
      if (local === "PackageVersion") {
        const name = attr(tag, "Include") ?? attr(tag, "Update");
        const version = attr(tag, "Version");
        pending = {
          ...(name === undefined ? {} : { name }),
          ...(version === undefined ? {} : { version }),
          childVersion: false,
          text: "",
          conditioned,
        };
      } else if (pending !== undefined && local === "Version") {
        pending.childVersion = true;
        pending.text = "";
      }
    });
    parser.on("text", (text) => {
      if (pending?.childVersion === true && pending.text.length <= 4_096) {
        pending.text += text;
      }
    });
    parser.on("closetag", (tag) => {
      const local = localXmlName(tag.name);
      if (pending?.childVersion === true && local === "Version") {
        pending.version = pending.text.trim();
        pending.childVersion = false;
        pending.text = "";
      }
      if (local === "PackageVersion" && pending !== undefined) {
        if (
          pending.conditioned ||
          !safePackageName(pending.name) ||
          !safeValue(pending.version, 256) ||
          /\$\(|\$\{/u.test(pending.version)
        ) {
          valid = false;
          context.addIssue(
            "DEPENDENCY_UNRESOLVED",
            "Directory.Packages.props contains a conditional or non-literal PackageVersion",
          );
        } else {
          versions.set(pending.name.toLowerCase(), pending.version);
        }
        pending = undefined;
      }
      conditionedStack.pop();
      depth -= 1;
    });
    try {
      parser.write(xml).close();
    } catch {
      rejected = true;
    }
    if (rejected) {
      valid = false;
      context.addIssue(
        "INVALID_MANIFEST",
        "Directory.Packages.props is malformed or unsafe",
      );
    }
  }
  return { versions, valid };
}

interface PendingReference {
  name?: string;
  version?: string;
  versionOverride?: string;
  privateAssets?: string;
  includeAssets?: string;
  conditioned: boolean;
  child?: string;
  text: string;
}

function parseProjectReferences(
  xml: string,
  context: NugetParseContext,
): readonly ProjectReference[] {
  const output: ProjectReference[] = [];
  const parser = new SaxesParser({ xmlns: false, position: true });
  let depth = 0;
  let rejected = false;
  let pending: PendingReference | undefined;
  parser.on("doctype", () => {
    rejected = true;
    context.addIssue("INVALID_MANIFEST", "NuGet project XML must not contain a DOCTYPE");
  });
  parser.on("error", (_error) => {
    rejected = true;
  });
  parser.on("opentag", (tag) => {
    context.checkCancellation();
    depth += 1;
    if (depth > context.limits.maxXmlDepth) {
      rejected = true;
      return;
    }
    const local = tag.name.includes(":")
      ? tag.name.slice(tag.name.lastIndexOf(":") + 1)
      : tag.name;
    if (local === "PackageReference") {
      const name = attr(tag, "Include") ?? attr(tag, "Update");
      const version = attr(tag, "Version");
      const versionOverride = attr(tag, "VersionOverride");
      const privateAssets = attr(tag, "PrivateAssets");
      const includeAssets = attr(tag, "IncludeAssets");
      pending = {
        ...(name === undefined ? {} : { name }),
        ...(version === undefined ? {} : { version }),
        ...(versionOverride === undefined ? {} : { versionOverride }),
        ...(privateAssets === undefined ? {} : { privateAssets }),
        ...(includeAssets === undefined ? {} : { includeAssets }),
        conditioned: attr(tag, "Condition") !== undefined,
        text: "",
      };
    } else if (
      pending !== undefined &&
      ["Version", "VersionOverride", "PrivateAssets", "IncludeAssets"].includes(local)
    ) {
      pending.child = local;
      pending.text = "";
    }
  });
  parser.on("text", (text) => {
    if (pending?.child !== undefined && pending.text.length <= 4_096) {
      pending.text += text;
    }
  });
  parser.on("closetag", (tag) => {
    const local = tag.name.includes(":")
      ? tag.name.slice(tag.name.lastIndexOf(":") + 1)
      : tag.name;
    if (pending?.child === local) {
      const value = pending.text.trim();
      switch (local) {
        case "Version":
          pending.version = value;
          break;
        case "VersionOverride":
          pending.versionOverride = value;
          break;
        case "PrivateAssets":
          pending.privateAssets = value;
          break;
        case "IncludeAssets":
          pending.includeAssets = value;
          break;
        default:
          break;
      }
      delete pending.child;
      pending.text = "";
    }
    if (local === "PackageReference" && pending !== undefined) {
      if (safePackageName(pending.name)) {
        const requested = safeValue(pending.versionOverride)
          ? pending.versionOverride
          : safeValue(pending.version)
            ? pending.version
            : undefined;
        output.push({
          name: pending.name,
          ...(requested === undefined ? {} : { requestedVersion: requested }),
          environment: "production",
          conditioned: pending.conditioned,
        });
      } else {
        context.addIssue(
          "DEPENDENCY_UNRESOLVED",
          "NuGet project contains a PackageReference with an invalid identity",
        );
      }
      pending = undefined;
    }
    depth -= 1;
  });
  try {
    parser.write(xml).close();
  } catch (_error: unknown) {
    rejected = true;
  }
  if (rejected) {
    context.addIssue("INVALID_MANIFEST", "NuGet project XML is malformed or unsafe");
    return [];
  }
  return output;
}

function parsePackagesConfig(
  xml: string,
  context: NugetParseContext,
): readonly ConfigPackage[] {
  const output: ConfigPackage[] = [];
  const parser = new SaxesParser({ xmlns: false, position: true });
  let depth = 0;
  let rejected = false;
  parser.on("doctype", () => {
    rejected = true;
    context.addIssue("INVALID_MANIFEST", "packages.config must not contain a DOCTYPE");
  });
  parser.on("error", (_error) => {
    rejected = true;
  });
  parser.on("opentag", (tag) => {
    context.checkCancellation();
    depth += 1;
    if (depth > context.limits.maxXmlDepth) {
      rejected = true;
      return;
    }
    const local = tag.name.includes(":")
      ? tag.name.slice(tag.name.lastIndexOf(":") + 1)
      : tag.name;
    if (local !== "package") {
      return;
    }
    const name = attr(tag, "id");
    const originalVersion = attr(tag, "version");
    const version = normalizedResolvedVersion(originalVersion);
    const allowedVersions = attr(tag, "allowedVersions");
    if (!safePackageName(name) || version === undefined) {
      context.addIssue(
        "DEPENDENCY_UNRESOLVED",
        "packages.config contains a package with an invalid identity or version",
      );
      return;
    }
    output.push({
      name,
      version,
      ...(originalVersion === version || originalVersion === undefined
        ? {}
        : { originalVersion }),
      ...(safeValue(allowedVersions)
        ? { requestedVersion: allowedVersions }
        : {}),
      environment:
        attr(tag, "developmentDependency")?.toLowerCase() === "true"
          ? "development"
          : "production",
    });
  });
  parser.on("closetag", () => {
    depth -= 1;
  });
  try {
    parser.write(xml).close();
  } catch (_error: unknown) {
    rejected = true;
  }
  if (rejected) {
    context.addIssue("INVALID_MANIFEST", "packages.config is malformed or unsafe");
    return [];
  }
  return output;
}

function packageType(value: unknown): LockPackage["type"] | undefined {
  if (
    value === "Direct" ||
    value === "Transitive" ||
    value === "CentralTransitive" ||
    value === "Project"
  ) {
    return value;
  }
  return undefined;
}

function packagesFromTarget(
  value: unknown,
  context: NugetParseContext,
): readonly LockPackage[] {
  if (!isRecord(value)) {
    context.addIssue("INVALID_LOCKFILE", "NuGet lock target must be an object");
    return [];
  }
  const output: LockPackage[] = [];
  const entries = Object.entries(value);
  if (entries.length > context.limits.maxPackages) {
    context.truncated = true;
    context.addIssue("DEPENDENCY_LIMIT", "NuGet lock target exceeded its package safety limit");
  }
  for (const [name, rawPackage] of entries.slice(0, context.limits.maxPackages)) {
    context.checkCancellation();
    if (!safePackageName(name) || !isRecord(rawPackage)) {
      context.addIssue("INVALID_LOCKFILE", "NuGet lock contains an invalid package entry");
      continue;
    }
    const type = packageType(rawPackage.type);
    if (type === undefined) {
      context.addIssue(
        "UNSUPPORTED_LOCKFILE",
        `NuGet lock package ${name} has an unsupported dependency type`,
      );
      continue;
    }
    const dependencies: Array<{
      readonly name: string;
      readonly constraint?: string;
    }> = [];
    if (rawPackage.dependencies !== undefined) {
      if (!isRecord(rawPackage.dependencies)) {
        context.addIssue(
          "INVALID_LOCKFILE",
          `NuGet lock package ${name} has malformed dependencies`,
        );
      } else {
        for (const [dependencyName, rawConstraint] of Object.entries(
          rawPackage.dependencies,
        )) {
          if (!context.consumeEdge()) {
            break;
          }
          if (safePackageName(dependencyName)) {
            if (rawConstraint !== undefined && !safeValue(rawConstraint, 256)) {
              context.addIssue(
                "INVALID_LOCKFILE",
                `NuGet lock dependency ${dependencyName} has a malformed constraint`,
              );
              dependencies.push({ name: dependencyName });
            } else {
              dependencies.push({
                name: dependencyName,
                ...(rawConstraint === undefined
                  ? {}
                  : { constraint: rawConstraint }),
              });
            }
          } else {
            context.addIssue("INVALID_LOCKFILE", "NuGet lock contains an invalid edge name");
          }
        }
      }
    }
    const originalResolvedVersion = rawPackage.resolved;
    const resolvedVersion = normalizedResolvedVersion(originalResolvedVersion);
    if (originalResolvedVersion !== undefined && resolvedVersion === undefined) {
      context.addIssue(
        "INVALID_LOCKFILE",
        `NuGet lock package ${name} has a non-exact resolved version`,
      );
    }
    output.push({
      name,
      type,
      ...(safeValue(rawPackage.requested)
        ? { requestedVersion: rawPackage.requested }
        : {}),
      ...(resolvedVersion === undefined ? {} : { resolvedVersion }),
      ...(resolvedVersion === undefined ||
      typeof originalResolvedVersion !== "string" ||
      originalResolvedVersion === resolvedVersion
        ? {}
        : { originalResolvedVersion }),
      dependencies,
    });
  }
  return output;
}

function parseLockfile(
  text: string,
  context: NugetParseContext,
): readonly LockTarget[] | undefined {
  let document: unknown;
  try {
    document = JSON.parse(text) as unknown;
  } catch (_error: unknown) {
    context.addIssue("INVALID_LOCKFILE", "packages.lock.json is not valid JSON");
    return undefined;
  }
  if (!isRecord(document) || !Number.isSafeInteger(document.version)) {
    context.addIssue("INVALID_LOCKFILE", "packages.lock.json has no valid format version");
    return undefined;
  }
  const version = Number(document.version);
  if (version < 1 || version > 3) {
    context.addIssue(
      "UNSUPPORTED_LOCKFILE",
      "packages.lock.json uses an unsupported format version",
    );
    return undefined;
  }
  const output: LockTarget[] = [];
  if (version < 3) {
    if (!isRecord(document.dependencies)) {
      context.addIssue("INVALID_LOCKFILE", "NuGet lock has no dependencies object");
      return undefined;
    }
    const targets = Object.entries(document.dependencies);
    if (targets.length > context.limits.maxTargets) {
      context.truncated = true;
      context.addIssue("DEPENDENCY_LIMIT", "NuGet lock exceeded its target safety limit");
    }
    for (const [name, target] of targets.slice(0, context.limits.maxTargets)) {
      output.push({
        name,
        framework: name.split("/")[0] ?? name,
        packages: packagesFromTarget(target, context),
      });
    }
  } else {
    const targets = Object.entries(document).filter(([key]) => key !== "version");
    if (targets.length > context.limits.maxTargets) {
      context.truncated = true;
      context.addIssue("DEPENDENCY_LIMIT", "NuGet lock exceeded its target safety limit");
    }
    for (const [name, rawTarget] of targets.slice(0, context.limits.maxTargets)) {
      if (!isRecord(rawTarget) || !safeValue(rawTarget.framework, 512)) {
        context.addIssue("INVALID_LOCKFILE", `NuGet V3 target ${name} is malformed`);
        continue;
      }
      output.push({
        name,
        framework: rawTarget.framework,
        packages: packagesFromTarget(rawTarget.dependencies, context),
      });
    }
  }
  return output;
}

function baseDependency(
  input: NugetParserInput,
  name: string,
  environment: DependencyEnvironment,
  requestedVersion: string | undefined,
  metadata: Readonly<Record<string, string | boolean | readonly string[]>>,
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
    ecosystem: "NuGet",
    manifestName: name,
    ...(requestedVersion === undefined ? {} : { requestedVersion }),
    environment,
    declaredEnvironment: environment,
    manifestPath: input.manifestPath,
    ...(input.lockfilePath === undefined
      ? {}
      : { lockfilePath: input.lockfilePath }),
    packageManager: "nuget",
    ...(input.projectPath === undefined
      ? {}
      : { projectPath: input.projectPath }),
    ...(input.workspacePath === undefined
      ? {}
      : { workspacePath: input.workspacePath }),
    metadata,
  };
}

function unresolvedProjectReference(
  input: NugetParserInput,
  reference: ProjectReference,
): Dependency {
  return {
    name: reference.name,
    ...baseDependency(
      input,
      reference.name,
      reference.environment,
      reference.requestedVersion,
      {
        manifestSection: "PackageReference",
        conditioned: reference.conditioned,
      },
    ),
    installedVersion: "",
    resolutionStatus: "unresolved",
    dependencyType: "direct",
    dependencyPath: [reference.name],
  };
}

function normalizedConstraintVersion(value: string): string | undefined {
  const match = /^(\d+(?:\.\d+){0,3})(-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u.exec(
    value.trim(),
  );
  if (match?.[1] === undefined) {
    return undefined;
  }
  const numeric = match[1]
    .split(".")
    .map((part) => Number(part).toString())
    .join(".");
  const prerelease = match[2]?.toLowerCase() ?? "";
  return `${numeric}${prerelease}`;
}

function canonicalNugetConstraint(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 256 || /[?]/u.test(trimmed)) {
    return undefined;
  }
  const floating = /^(\d+(?:\.\d+)*)\.\*$/u.exec(trimmed)?.[1];
  if (floating !== undefined) {
    return `${floating}.*`;
  }
  const floatingMinimum = /^\[\s*(\d+(?:\.\d+)*)\.\*\s*,\s*\)$/u.exec(
    trimmed,
  )?.[1];
  if (floatingMinimum !== undefined) {
    return `${floatingMinimum}.*`;
  }
  const bare = normalizedConstraintVersion(trimmed);
  if (bare !== undefined) {
    return `[${bare},)`;
  }
  const singleton = /^\[\s*([^,[\]()]+)\s*\]$/u.exec(trimmed)?.[1];
  if (singleton !== undefined) {
    const normalized = normalizedConstraintVersion(singleton);
    return normalized === undefined ? undefined : `[${normalized}]`;
  }
  const interval = /^([[(])\s*([^,]*)\s*,\s*([^\])]*?)\s*([\])])$/u.exec(
    trimmed,
  );
  if (interval === null) {
    return undefined;
  }
  const lowerRaw = interval[2] ?? "";
  const upperRaw = interval[3] ?? "";
  const lower =
    lowerRaw.length === 0 ? "" : normalizedConstraintVersion(lowerRaw);
  const upper =
    upperRaw.length === 0 ? "" : normalizedConstraintVersion(upperRaw);
  if (lower === undefined || upper === undefined) {
    return undefined;
  }
  return `${interval[1]}${lower},${upper}${interval[4]}`;
}

function compareStableNugetVersions(left: string, right: string): number | undefined {
  if (left.includes("-") || right.includes("-")) {
    return undefined;
  }
  const leftParts = left.split(".").map(Number);
  const rightParts = right.split(".").map(Number);
  const length = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
    if (difference !== 0) {
      return difference < 0 ? -1 : 1;
    }
  }
  return 0;
}

function resolvedSatisfiesNugetConstraint(
  resolved: string,
  canonicalConstraint: string,
): boolean {
  const normalized = normalizedConstraintVersion(resolved);
  if (normalized === undefined) {
    return false;
  }
  if (canonicalConstraint.endsWith(".*")) {
    const prefix = canonicalConstraint.slice(0, -2).split(".").map(Number);
    const selected = normalizedConstraintVersion(resolved);
    if (selected === undefined || selected.includes("-")) {
      return false;
    }
    const selectedParts = selected.split(".").map(Number);
    return prefix.every((part, index) => selectedParts[index] === part);
  }
  const singleton = /^\[([^\]]+)\]$/u.exec(canonicalConstraint)?.[1];
  if (singleton !== undefined) {
    return normalized === singleton;
  }
  const interval = /^([[(])([^,]*),([^\])]*)([\])])$/u.exec(
    canonicalConstraint,
  );
  if (interval === null) {
    return false;
  }
  const lower = interval[2] ?? "";
  const upper = interval[3] ?? "";
  if (lower.length > 0) {
    const comparison = compareStableNugetVersions(normalized, lower);
    if (
      comparison === undefined ||
      comparison < 0 ||
      (comparison === 0 && interval[1] === "(")
    ) {
      return false;
    }
  }
  if (upper.length > 0) {
    const comparison = compareStableNugetVersions(normalized, upper);
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

function directLockMatchesManifest(
  reference: ProjectReference | undefined,
  entry: LockPackage,
  centralConfigurationPresent: boolean,
): boolean {
  if (
    reference === undefined ||
    entry.requestedVersion === undefined ||
    entry.resolvedVersion === undefined
  ) {
    return false;
  }
  const lockConstraint = canonicalNugetConstraint(entry.requestedVersion);
  if (
    lockConstraint === undefined ||
    !resolvedSatisfiesNugetConstraint(entry.resolvedVersion, lockConstraint)
  ) {
    return false;
  }
  if (reference.requestedVersion === undefined) {
    return !centralConfigurationPresent;
  }
  const manifestConstraint = canonicalNugetConstraint(reference.requestedVersion);
  return (
    manifestConstraint !== undefined &&
    resolvedSatisfiesNugetConstraint(entry.resolvedVersion, manifestConstraint)
  );
}

export function parseNugetDependencies(
  input: NugetParserInput,
): NugetParseResult {
  const context = new NugetParseContext(parserLimits(input.limits), input.signal);
  try {
    context.checkCancellation();
    const unsupportedSource = hasUnsupportedNugetSource(input, context);
    const rawProjectReferences =
      input.projectXml === undefined
        ? []
        : parseProjectReferences(input.projectXml, context);
    const centralVersions = parseCentralPackageVersions(
      input.directoryPackagesPropsXmls ?? [],
      context,
    );
    const centralConfigurationPresent =
      (input.directoryPackagesPropsXmls?.length ?? 0) > 0;
    const projectReferences = rawProjectReferences.map<ProjectReference>((reference) => {
      if (reference.requestedVersion !== undefined) {
        return reference;
      }
      const centralVersion = centralVersions.versions.get(reference.name.toLowerCase());
      if (centralVersion !== undefined && centralVersions.valid) {
        return { ...reference, requestedVersion: centralVersion };
      }
      if (centralConfigurationPresent) {
        context.addIssue(
          "DEPENDENCY_UNRESOLVED",
          `NuGet PackageReference ${reference.name} has no literal version in the project or applicable Directory.Packages.props`,
        );
      }
      return reference;
    });
    const configPackages =
      input.packagesConfigXml === undefined
        ? []
        : parsePackagesConfig(input.packagesConfigXml, context);

    if (input.lockfile === undefined) {
      if (projectReferences.length > 0) {
        context.addIssue(
          "NO_LOCKFILE",
          "NuGet PackageReference versions are constraints; packages.lock.json is required for exact resolution",
        );
      }
      const configDependencies = configPackages.map<Dependency>((entry) => ({
        name: entry.name,
        ...baseDependency(
          input,
          entry.name,
          entry.environment,
          entry.requestedVersion,
          {
            manifestSection: "packages.config",
            relationshipDetail: "flat-list-directness-unavailable",
            ...(entry.originalVersion === undefined
              ? {}
              : { originalResolvedVersion: entry.originalVersion }),
          },
        ),
        installedVersion: entry.version,
        resolutionStatus: "resolved",
        dependencyType: "direct",
        dependencyPath: [entry.name],
      }));
      if (configPackages.length > 0) {
        context.addIssue(
          "DEPENDENCY_UNRESOLVED",
          "packages.config is a flat installed-package list and does not preserve dependency relationships",
        );
      }
      return {
        dependencies: applySourceProvenance(
          [
            ...configDependencies,
            ...projectReferences.map((reference) =>
              unresolvedProjectReference(input, reference),
            ),
          ],
          unsupportedSource,
        ),
        issues: context.issues,
        truncated: context.truncated,
        cancelled: false,
      };
    }

    const targets = parseLockfile(input.lockfile, context);
    if (targets === undefined) {
      return {
        dependencies: applySourceProvenance(
          projectReferences.map((reference) =>
            unresolvedProjectReference(input, reference),
          ),
          unsupportedSource,
        ),
        issues: context.issues,
        truncated: context.truncated,
        cancelled: false,
      };
    }
    const referencesByName = new Map(
      projectReferences.map((reference) => [reference.name.toLowerCase(), reference]),
    );
    const aggregate = new Map<string, Dependency>();
    const frameworks = new Map<string, Set<string>>();

    for (const target of targets) {
      context.checkCancellation();
      const nodesByName = new Map(
        target.packages.map((entry) => [entry.name.toLowerCase(), entry]),
      );
      const parents = new Map<string, string>();
      const paths = new Map<string, readonly string[]>();
      const queue = target.packages
        .filter((entry) => {
          if (entry.type === "Project") {
            return true;
          }
          if (entry.type !== "Direct") {
            return false;
          }
          return directLockMatchesManifest(
            referencesByName.get(entry.name.toLowerCase()),
            entry,
            centralConfigurationPresent,
          );
        })
        .map((entry) => ({ entry, path: [entry.name] as readonly string[] }));
      let index = 0;
      while (index < queue.length) {
        const current = queue[index];
        index += 1;
        if (current === undefined || paths.has(current.entry.name.toLowerCase())) {
          continue;
        }
        paths.set(current.entry.name.toLowerCase(), current.path);
        for (const requirement of current.entry.dependencies) {
          const child = nodesByName.get(requirement.name.toLowerCase());
          const constraint =
            requirement.constraint === undefined
              ? undefined
              : canonicalNugetConstraint(requirement.constraint);
          if (
            child?.resolvedVersion === undefined ||
            constraint === undefined ||
            !resolvedSatisfiesNugetConstraint(child.resolvedVersion, constraint)
          ) {
            context.addIssue(
              "DEPENDENCY_UNRESOLVED",
              `NuGet lock edge ${current.entry.name} -> ${requirement.name} does not match a selected child version`,
            );
            continue;
          }
          parents.set(child.name.toLowerCase(), current.entry.name);
          queue.push({ entry: child, path: [...current.path, child.name] });
        }
      }

      for (const entry of target.packages) {
        if (entry.type === "Project") {
          continue;
        }
        const manifestReference = referencesByName.get(entry.name.toLowerCase());
        const resolved = entry.resolvedVersion;
        const dependencyType = entry.type === "Direct" ? "direct" : "transitive";
        const manifestMatches =
          dependencyType !== "direct" ||
          directLockMatchesManifest(
            manifestReference,
            entry,
            centralConfigurationPresent,
          );
        const dependencyPath = paths.get(entry.name.toLowerCase());
        const reachable = dependencyType === "direct" || dependencyPath !== undefined;
        const safelyResolved =
          resolved !== undefined && manifestMatches && reachable;
        const parent = parents.get(entry.name.toLowerCase());
        const dependency: Dependency = {
          name: entry.name,
          ...baseDependency(
            input,
            manifestReference?.name ?? entry.name,
            manifestReference?.environment ?? "production",
            entry.requestedVersion ?? manifestReference?.requestedVersion,
            {
              manifestSection:
                dependencyType === "direct"
                  ? "PackageReference"
                  : "packages.lock.json",
              targetFrameworks: [target.framework],
              lockDependencyType: entry.type,
              ...(entry.requestedVersion === undefined
                ? {}
                : { lockRequestedVersion: entry.requestedVersion }),
              ...(manifestReference?.requestedVersion === undefined
                ? {}
                : {
                    manifestRequestedVersion:
                      manifestReference.requestedVersion,
                  }),
              ...(entry.originalResolvedVersion === undefined
                ? {}
                : {
                    originalResolvedVersion: entry.originalResolvedVersion,
                  }),
            },
          ),
          installedVersion: safelyResolved ? resolved : "",
          resolutionStatus: safelyResolved ? "resolved" : "unresolved",
          dependencyType,
          ...(dependencyType === "transitive" && parent !== undefined
            ? { parent }
            : {}),
          dependencyPath: [...(dependencyPath ?? [entry.name])],
        };
        if (resolved === undefined) {
          context.addIssue(
            "DEPENDENCY_UNRESOLVED",
            `NuGet lock package ${entry.name} has no resolved version`,
          );
        } else if (!manifestMatches) {
          context.addIssue(
            "DEPENDENCY_UNRESOLVED",
            `NuGet lock request for ${entry.name} does not match the manifest PackageReference constraint`,
          );
        } else if (!reachable) {
          context.addIssue(
            "DEPENDENCY_UNRESOLVED",
            `NuGet lock package ${entry.name} is unreachable from reconciled Direct/Project roots`,
          );
        }
        const key = `${entry.name.toLowerCase()}\u0000${
          safelyResolved ? resolved : ""
        }`;
        const seenFrameworks = frameworks.get(key) ?? new Set<string>();
        seenFrameworks.add(target.framework);
        frameworks.set(key, seenFrameworks);
        const previous = aggregate.get(key);
        if (
          previous === undefined ||
          (dependencyType === "direct" && previous.dependencyType === "transitive")
        ) {
          aggregate.set(key, dependency);
        }
      }
    }

    for (const [key, dependency] of aggregate) {
      const targetFrameworks = [...(frameworks.get(key) ?? [])].sort();
      aggregate.set(key, {
        ...dependency,
        metadata: {
          ...dependency.metadata,
          targetFrameworks,
        },
      });
    }
    const lockedDirectNames = new Set(
      [...aggregate.values()]
        .filter((dependency) => dependency.dependencyType === "direct")
        .map((dependency) => dependency.name.toLowerCase()),
    );
    for (const reference of projectReferences) {
      if (!lockedDirectNames.has(reference.name.toLowerCase())) {
        context.addIssue(
          "DEPENDENCY_UNRESOLVED",
          `NuGet PackageReference ${reference.name} is absent from the lockfile`,
        );
        aggregate.set(
          `${reference.name.toLowerCase()}\u0000`,
          unresolvedProjectReference(input, reference),
        );
      }
    }
    return {
      dependencies: applySourceProvenance(
        [...aggregate.values()].sort((left, right) =>
          `${left.name.toLowerCase()}\u0000${left.installedVersion}`.localeCompare(
            `${right.name.toLowerCase()}\u0000${right.installedVersion}`,
          ),
        ),
        unsupportedSource,
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
    context.addIssue("INVALID_MANIFEST", "NuGet dependency parsing failed");
    return {
      dependencies: [],
      issues: context.issues,
      truncated: context.truncated,
      cancelled: false,
    };
  }
}
