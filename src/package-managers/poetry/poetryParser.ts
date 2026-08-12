import type {
  Dependency,
  DependencyEnvironment,
  DependencyMetadataValue,
} from "../../models/Dependency";
import type { ScanError } from "../../models/ScanResult";
import { satisfies as satisfiesSemver } from "semver";
import { MAX_PARSED_DEPENDENCIES as MAX_DEPENDENCIES } from "../python/parserLimits";
import { normalizePythonName } from "../python/requirementsParser";

interface DirectDeclaration {
  readonly requested?: string;
  readonly environment: DependencyEnvironment;
  readonly sourceUnsupported: boolean;
  readonly sourceName?: string;
}

interface LockedPackage {
  readonly name: string;
  readonly version: string;
  readonly raw: Record<string, unknown>;
  readonly dependencies: readonly LockedRequirement[];
}

interface LockedRequirement {
  readonly name: string;
  readonly constraint?: string;
}

export interface PoetryParseInput {
  readonly pyprojectText: string;
  readonly lockfileText: string;
  readonly manifestPath: string;
  readonly lockfilePath: string;
  readonly projectPath: string;
  readonly workspacePath: string;
  readonly signal?: AbortSignal;
}

export interface PoetryParseResult {
  readonly dependencies: readonly Dependency[];
  readonly errors: readonly ScanError[];
  readonly truncated: boolean;
}

export interface PoetryManifestParseInput {
  readonly pyprojectText: string;
  readonly manifestPath: string;
  readonly projectPath: string;
  readonly workspacePath: string;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

const MAX_PACKAGE_SOURCES = 256;
const MAX_SOURCE_NAME_LENGTH = 128;
const MAX_SOURCE_URL_LENGTH = 2_048;

interface PoetrySourceConfiguration {
  readonly safeNames: ReadonlySet<string>;
  readonly customPrimary: boolean;
  readonly malformed: boolean;
}

function normalizedSourceName(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  return normalized.length > 0 && normalized.length <= MAX_SOURCE_NAME_LENGTH
    ? normalized
    : undefined;
}

function canonicalPypiIndexUrl(value: unknown): boolean {
  if (typeof value !== "string" || value.length > MAX_SOURCE_URL_LENGTH) {
    return false;
  }
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.username.length === 0 &&
      url.password.length === 0 &&
      url.port.length === 0 &&
      url.hostname.toLowerCase() === "pypi.org" &&
      (url.pathname === "/simple" || url.pathname === "/simple/") &&
      url.search.length === 0 &&
      url.hash.length === 0
    );
  } catch {
    return false;
  }
}

function poetrySourceConfiguration(
  document: Record<string, unknown>,
): PoetrySourceConfiguration {
  const poetry = record(record(document.tool)?.poetry);
  if (poetry?.source === undefined) {
    return {
      safeNames: new Set<string>(),
      customPrimary: false,
      malformed: false,
    };
  }
  if (!Array.isArray(poetry.source) || poetry.source.length === 0) {
    return {
      safeNames: new Set<string>(),
      customPrimary: true,
      malformed: true,
    };
  }

  const safeNames = new Set<string>();
  let malformed = poetry.source.length > MAX_PACKAGE_SOURCES;
  let customPrimary = malformed;
  for (const value of poetry.source.slice(0, MAX_PACKAGE_SOURCES)) {
    const source = record(value);
    const name = normalizedSourceName(source?.name);
    const rawPriority = source?.priority;
    const priority =
      typeof rawPriority === "string" ? rawPriority.toLowerCase() : undefined;
    const recognizedPriority =
      priority === undefined ||
      priority === "primary" ||
      priority === "supplemental" ||
      priority === "explicit";
    const primary =
      source?.default === true ||
      (source?.secondary !== true &&
        (priority === undefined || priority === "primary"));
    const canonical =
      name === "pypi" &&
      (source?.url === undefined || canonicalPypiIndexUrl(source.url));

    if (source === undefined || name === undefined || !recognizedPriority) {
      malformed = true;
      customPrimary = true;
      continue;
    }
    if (canonical) {
      safeNames.add(name);
    } else if (primary || priority === "supplemental") {
      customPrimary = true;
    }
  }
  return { safeNames, customPrimary, malformed };
}

function stringArray(value: unknown): readonly string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function requirementName(value: string): string | undefined {
  const match = /^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)/u.exec(
    value,
  );
  return match?.[1] === undefined
    ? undefined
    : normalizePythonName(match[1]);
}

function requestedFromPoetryValue(value: unknown): {
  readonly requested?: string;
  readonly sourceUnsupported: boolean;
  readonly sourceName?: string;
} {
  if (typeof value === "string") {
    return {
      requested: value,
      sourceUnsupported:
        /^\s*@/u.test(value) ||
        /(?:git\+|https?:|file:|\.\.?[\\/])/iu.test(value),
    };
  }
  const table = record(value);
  if (table === undefined) {
    return { sourceUnsupported: false };
  }
  const requested =
    typeof table.version === "string" ? table.version : undefined;
  const rawSourceName = table.source;
  const sourceName = normalizedSourceName(rawSourceName);
  const sourceUnsupported =
    ["git", "path", "url"].some(
      (key) => typeof table[key] === "string",
    ) ||
    (rawSourceName !== undefined && sourceName === undefined);
  return {
    ...(requested === undefined ? {} : { requested }),
    sourceUnsupported,
    ...(sourceName === undefined ? {} : { sourceName }),
  };
}

function priority(environment: DependencyEnvironment): number {
  if (environment === "production") {
    return 3;
  }
  if (environment === "optional") {
    return 2;
  }
  return 1;
}

function collectDirectDeclarations(
  document: Record<string, unknown>,
): Map<string, DirectDeclaration> {
  const declarations = new Map<string, DirectDeclaration>();
  const add = (
    rawName: string,
    value: unknown,
    environment: DependencyEnvironment,
  ): void => {
    if (rawName.toLowerCase() === "python") {
      return;
    }
    const name = normalizePythonName(rawName);
    const parsed = requestedFromPoetryValue(value);
    const next: DirectDeclaration = {
      environment,
      sourceUnsupported: parsed.sourceUnsupported,
      ...(parsed.requested === undefined ? {} : { requested: parsed.requested }),
      ...(parsed.sourceName === undefined ? {} : { sourceName: parsed.sourceName }),
    };
    const existing = declarations.get(name);
    if (
      existing === undefined ||
      priority(next.environment) > priority(existing.environment)
    ) {
      declarations.set(name, next);
    }
  };
  const addRequirementStrings = (
    values: unknown,
    environment: DependencyEnvironment,
  ): void => {
    for (const value of stringArray(values)) {
      const name = requirementName(value);
      if (name !== undefined) {
        const remainder = value.slice(
          value.toLowerCase().indexOf(name.toLowerCase()) + name.length,
        );
        add(name, remainder.trim(), environment);
      }
    }
  };

  const project = record(document.project);
  if (project !== undefined) {
    addRequirementStrings(project.dependencies, "production");
    const optional = record(project["optional-dependencies"]);
    if (optional !== undefined) {
      for (const values of Object.values(optional)) {
        addRequirementStrings(values, "optional");
      }
    }
  }
  const dependencyGroups = record(document["dependency-groups"]);
  if (dependencyGroups !== undefined) {
    for (const values of Object.values(dependencyGroups)) {
      addRequirementStrings(values, "development");
    }
  }

  const poetry = record(record(document.tool)?.poetry);
  if (poetry !== undefined) {
    const main = record(poetry.dependencies);
    if (main !== undefined) {
      for (const [name, value] of Object.entries(main)) {
        add(name, value, "production");
      }
    }
    const legacyDev = record(poetry["dev-dependencies"]);
    if (legacyDev !== undefined) {
      for (const [name, value] of Object.entries(legacyDev)) {
        add(name, value, "development");
      }
    }
    const groups = record(poetry.group);
    if (groups !== undefined) {
      for (const group of Object.values(groups)) {
        const dependencies = record(record(group)?.dependencies);
        if (dependencies !== undefined) {
          for (const [name, value] of Object.entries(dependencies)) {
            add(name, value, "development");
          }
        }
      }
    }
  }
  return declarations;
}

export async function parsePoetryManifest(
  input: PoetryManifestParseInput,
): Promise<PoetryParseResult> {
  const { parse: parseToml } = await import("smol-toml");
  let document: Record<string, unknown>;
  try {
    document = record(parseToml(input.pyprojectText)) ?? {};
  } catch (error: unknown) {
    return {
      dependencies: [],
      errors: [
        {
          code: "INVALID_MANIFEST",
          message:
            error instanceof Error ? error.message : "invalid pyproject.toml",
          path: input.manifestPath,
        },
      ],
      truncated: false,
    };
  }
  const direct = collectDirectDeclarations(document);
  const sourceConfiguration = poetrySourceConfiguration(document);
  const dependencies: Dependency[] = [];
  const errors: ScanError[] = [];
  for (const [name, declaration] of direct) {
    const unsupported =
      declaration.sourceUnsupported ||
      (declaration.sourceName !== undefined &&
        !sourceConfiguration.safeNames.has(declaration.sourceName)) ||
      (sourceConfiguration.customPrimary && declaration.sourceName === undefined);
    dependencies.push({
      name,
      ecosystem: "PyPI",
      ...(declaration.requested === undefined
        ? {}
        : { requestedVersion: declaration.requested }),
      installedVersion: "",
      resolutionStatus: unsupported ? "unsupported" : "unresolved",
      dependencyType: "direct",
      environment: declaration.environment,
      declaredEnvironment: declaration.environment,
      manifestPath: input.manifestPath,
      packageManager: "poetry",
      projectPath: input.projectPath,
      workspacePath: input.workspacePath,
    });
    errors.push({
      code: unsupported
        ? "UNSUPPORTED_PACKAGE_SOURCE"
        : "DEPENDENCY_UNRESOLVED",
      message: unsupported
        ? "Poetry dependency uses a local or non-registry source"
        : "poetry.lock is required to determine the selected version",
      packageName: name,
      path: input.manifestPath,
    });
  }
  return { dependencies, errors, truncated: false };
}

function packageGroups(raw: Record<string, unknown>): readonly string[] {
  const groups = stringArray(raw.groups);
  if (groups.length > 0) {
    return groups.map(normalizePythonName);
  }
  return typeof raw.category === "string" ? [raw.category] : [];
}

function packageEnvironment(
  raw: Record<string, unknown>,
  direct: DirectDeclaration | undefined,
): DependencyEnvironment {
  if (direct !== undefined) {
    return direct.environment;
  }
  const groups = packageGroups(raw);
  if (groups.includes("main")) {
    return raw.optional === true ? "optional" : "production";
  }
  return groups.length > 0 ? "development" : "production";
}

function lockedSource(raw: Record<string, unknown>): {
  readonly kind: "implicit" | "pypi" | "unsupported";
  readonly type?: string;
} {
  if (raw.source === undefined) {
    return { kind: "implicit" };
  }
  const source = record(raw.source);
  if (source === undefined) {
    return { kind: "unsupported", type: "malformed" };
  }
  const type =
    typeof source.type === "string" ? source.type.toLowerCase() : "unknown";
  if (type === "legacy" && canonicalPypiIndexUrl(source.url)) {
    return { kind: "pypi", type };
  }
  if (
    type === "pypi" &&
    (source.url === undefined || canonicalPypiIndexUrl(source.url)) &&
    (source.reference === undefined ||
      normalizedSourceName(source.reference) === "pypi")
  ) {
    return { kind: "pypi", type };
  }
  return { kind: "unsupported", type };
}

function dependencyRequirements(
  raw: Record<string, unknown>,
): readonly LockedRequirement[] {
  const dependencies = record(raw.dependencies);
  if (dependencies === undefined) {
    return [];
  }
  return Object.entries(dependencies).map(([name, value]) => {
    const normalizedName = normalizePythonName(name);
    if (typeof value === "string") {
      return { name: normalizedName, constraint: value };
    }
    const table = record(value);
    const constraint =
      table !== undefined && typeof table.version === "string"
        ? table.version
        : undefined;
    return {
      name: normalizedName,
      ...(constraint === undefined ? {} : { constraint }),
    };
  });
}

function exactPypiVersion(value: string): boolean {
  const match = /^(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)(?:(?:a|b|rc)([0-9]+))?(?:\.post([0-9]+))?(?:\.dev([0-9]+))?$/u.exec(
    value,
  );
  const numeric = [
    ...(match?.[1] === undefined ? [] : [match[1]]),
    ...(match?.[2]?.split(".") ?? []),
    ...(match?.[3] === undefined ? [] : [match[3]]),
    ...(match?.[4] === undefined ? [] : [match[4]]),
    ...(match?.[5] === undefined ? [] : [match[5]]),
  ];
  return (
    match !== null &&
    numeric.every((part) => part === "0" || !part.startsWith("0"))
  );
}

function normalizedNumericPythonVersion(value: string): string | undefined {
  const match = /^v?(\d+(?:\.\d+){0,2})$/iu.exec(value.trim());
  if (match?.[1] === undefined) {
    return undefined;
  }
  const parts = match[1].split(".").map((part) => Number(part).toString());
  while (parts.length < 3) {
    parts.push("0");
  }
  return parts.join(".");
}

function poetryConstraintSatisfied(requested: string, locked: string): boolean {
  const constraint = requested.trim();
  if (constraint === "*") {
    return true;
  }
  const exact = /^(?:={2,3}\s*)?v?(\d+(?:\.\d+){0,2})$/iu.exec(constraint)?.[1];
  if (exact !== undefined) {
    return (
      normalizedNumericPythonVersion(exact) ===
      normalizedNumericPythonVersion(locked)
    );
  }
  const selected = normalizedNumericPythonVersion(locked);
  if (selected === undefined || constraint.length === 0 || constraint.length > 256) {
    return false;
  }
  const normalized = constraint
    .replace(/~=\s*/gu, "~")
    .replace(/\s*,\s*/gu, " ");
  try {
    return satisfiesSemver(selected, normalized, { includePrerelease: true });
  } catch {
    return false;
  }
}

interface PoetryGraphGap {
  readonly name: string;
  readonly constraint?: string;
  readonly parent?: string;
  readonly path: readonly string[];
}

function buildReachableGraph(
  packages: readonly LockedPackage[],
  direct: ReadonlyMap<string, DirectDeclaration>,
  projectPath: string,
  errors: ScanError[],
  manifestPath: string,
): {
  readonly paths: ReadonlyMap<string, readonly string[]>;
  readonly rootKeys: ReadonlySet<string>;
  readonly matchedDirectNames: ReadonlySet<string>;
  readonly gaps: readonly PoetryGraphGap[];
} {
  const byName = new Map<string, LockedPackage[]>();
  for (const item of packages) {
    const entries = byName.get(item.name) ?? [];
    entries.push(item);
    byName.set(item.name, entries);
  }
  const paths = new Map<string, readonly string[]>();
  const rootKeys = new Set<string>();
  const matchedDirectNames = new Set<string>();
  const gaps: PoetryGraphGap[] = [];
  const queue: LockedPackage[] = [];
  for (const [name, declaration] of direct) {
    const candidates = (byName.get(name) ?? []).filter(
      (candidate) =>
        declaration.requested === undefined
          ? declaration.sourceUnsupported
          : poetryConstraintSatisfied(declaration.requested, candidate.version),
    );
    if (candidates.length === 1 && candidates[0] !== undefined) {
      const item = candidates[0];
      const key = `${item.name}\u0000${item.version}`;
      paths.set(key, [
        projectPath,
        `${item.name}@${item.version}`,
      ]);
      rootKeys.add(key);
      matchedDirectNames.add(name);
      queue.push(item);
    } else {
      errors.push({
        code: "DEPENDENCY_UNRESOLVED",
        message: `Poetry dependency ${name} has ${candidates.length.toString()} lock selections satisfying its manifest constraint`,
        packageName: name,
        path: manifestPath,
      });
    }
  }
  let queueIndex = 0;
  while (queueIndex < queue.length && paths.size <= MAX_DEPENDENCIES) {
    const parent = queue[queueIndex];
    queueIndex += 1;
    if (parent === undefined) {
      break;
    }
    const parentPath = paths.get(`${parent.name}\u0000${parent.version}`);
    if (parentPath === undefined) {
      continue;
    }
    for (const requirement of parent.dependencies) {
      const candidates = (byName.get(requirement.name) ?? []).filter(
        (candidate) =>
          requirement.constraint !== undefined &&
          poetryConstraintSatisfied(requirement.constraint, candidate.version),
      );
      if (candidates.length !== 1 || candidates[0] === undefined) {
        const gap: PoetryGraphGap = {
          name: requirement.name,
          ...(requirement.constraint === undefined
            ? {}
            : { constraint: requirement.constraint }),
          parent: `${parent.name}@${parent.version}`,
          path: [...parentPath, requirement.name],
        };
        gaps.push(gap);
        errors.push({
          code: "DEPENDENCY_UNRESOLVED",
          message: `Poetry lock edge ${parent.name} -> ${requirement.name} has ${candidates.length.toString()} selected packages satisfying its constraint`,
          packageName: requirement.name,
          path: manifestPath,
        });
        continue;
      }
      const child = candidates[0];
      const key = `${child.name}\u0000${child.version}`;
      if (!paths.has(key)) {
        paths.set(key, [...parentPath, `${child.name}@${child.version}`]);
        queue.push(child);
      }
    }
  }
  return { paths, rootKeys, matchedDirectNames, gaps };
}

export async function parsePoetryProject(
  input: PoetryParseInput,
): Promise<PoetryParseResult> {
  const { parse: parseToml } = await import("smol-toml");
  const errors: ScanError[] = [];
  let pyproject: Record<string, unknown>;
  let lockfile: Record<string, unknown>;
  try {
    pyproject = record(parseToml(input.pyprojectText)) ?? {};
  } catch (error: unknown) {
    return {
      dependencies: [],
      errors: [
        {
          code: "INVALID_MANIFEST",
          message:
            error instanceof Error ? error.message : "invalid pyproject.toml",
          path: input.manifestPath,
        },
      ],
      truncated: false,
    };
  }
  try {
    lockfile = record(parseToml(input.lockfileText)) ?? {};
  } catch (error: unknown) {
    return {
      dependencies: [],
      errors: [
        {
          code: "INVALID_LOCKFILE",
          message:
            error instanceof Error ? error.message : "invalid poetry.lock",
          path: input.lockfilePath,
        },
      ],
      truncated: false,
    };
  }
  const lockVersion = record(lockfile.metadata)?.["lock-version"];
  if (
    typeof lockVersion !== "string" ||
    !/^[12](?:\.|$)/u.test(lockVersion)
  ) {
    return {
      dependencies: [],
      errors: [
        {
          code: "UNSUPPORTED_LOCKFILE",
          message: "Poetry lock format is missing or outside the supported >=1,<3 range",
          path: input.lockfilePath,
        },
      ],
      truncated: false,
    };
  }
  const direct = collectDirectDeclarations(pyproject);
  const sourceConfiguration = poetrySourceConfiguration(pyproject);
  const rawPackages = Array.isArray(lockfile.package) ? lockfile.package : [];
  let truncated = rawPackages.length > MAX_DEPENDENCIES;
  const packages: LockedPackage[] = [];
  for (const value of rawPackages.slice(0, MAX_DEPENDENCIES)) {
    if (input.signal?.aborted === true) {
      return { dependencies: [], errors, truncated };
    }
    const raw = record(value);
    if (
      raw === undefined ||
      typeof raw.name !== "string" ||
      typeof raw.version !== "string" ||
      raw.name.length === 0 ||
      !exactPypiVersion(raw.version)
    ) {
      errors.push({
        code: "INVALID_LOCKFILE",
        message: "Poetry lock package is missing a valid name or version",
        path: input.lockfilePath,
      });
      continue;
    }
    packages.push({
      name: normalizePythonName(raw.name),
      version: raw.version,
      raw,
      dependencies: dependencyRequirements(raw),
    });
  }
  if (truncated) {
    errors.push({
      code: "DEPENDENCY_LIMIT",
      message: `Poetry lock exceeds the ${MAX_DEPENDENCIES.toString()}-package limit`,
      path: input.lockfilePath,
    });
  }
  const graph = buildReachableGraph(
    packages,
    direct,
    input.projectPath,
    errors,
    input.manifestPath,
  );
  const paths = graph.paths;
  const dependencies: Dependency[] = [];
  for (const item of packages) {
    const itemKey = `${item.name}\u0000${item.version}`;
    const itemPath = paths.get(itemKey);
    if (itemPath === undefined) {
      continue;
    }
    const root = graph.rootKeys.has(itemKey);
    const declaration = root ? direct.get(item.name) : undefined;
    const source = lockedSource(item.raw);
    const explicitSourceUnsupported =
      declaration?.sourceUnsupported === true ||
      (declaration?.sourceName !== undefined &&
        !sourceConfiguration.safeNames.has(declaration.sourceName));
    const unsupported =
      explicitSourceUnsupported ||
      source.kind === "unsupported" ||
      (source.kind === "implicit" &&
        sourceConfiguration.customPrimary &&
        declaration?.sourceName === undefined);
    const constraintMatches =
      declaration === undefined ||
      (declaration.requested !== undefined &&
        poetryConstraintSatisfied(declaration.requested, item.version));
    const groups = packageGroups(item.raw);
    const parent =
      itemPath !== undefined && itemPath.length >= 3
        ? itemPath.at(-2)
        : undefined;
    const metadata: Record<string, DependencyMetadataValue> = {
      lockVersion,
      ...(groups.length > 0 ? { groups } : {}),
      ...(typeof item.raw.markers === "string"
        ? { markers: item.raw.markers }
        : {}),
      ...(source.type === undefined ? {} : { sourceType: source.type }),
      ...(sourceConfiguration.malformed
        ? { sourceConfiguration: "malformed" }
        : {}),
    };
    const dependency: Dependency = {
      name: item.name,
      ecosystem: "PyPI",
      ...(declaration?.requested === undefined
        ? {}
        : { requestedVersion: declaration.requested }),
      installedVersion: unsupported || !constraintMatches ? "" : item.version,
      resolutionStatus: unsupported
        ? "unsupported"
        : constraintMatches
          ? "resolved"
          : "unresolved",
      dependencyType: root ? "direct" : "transitive",
      environment: packageEnvironment(item.raw, declaration),
      ...(declaration === undefined
        ? {}
        : { declaredEnvironment: declaration.environment }),
      ...(itemPath === undefined ? {} : { dependencyPath: [...itemPath] }),
      ...(parent === undefined ? {} : { parent }),
      manifestPath: input.manifestPath,
      lockfilePath: input.lockfilePath,
      packageManager: "poetry",
      projectPath: input.projectPath,
      workspacePath: input.workspacePath,
      metadata,
    };
    dependencies.push(dependency);
    if (unsupported) {
      errors.push({
        code: "UNSUPPORTED_PACKAGE_SOURCE",
        message: "Poetry dependency comes from a non-PyPI or local source",
        packageName: item.name,
        path: input.lockfilePath,
      });
    } else if (!constraintMatches) {
      errors.push({
        code: "DEPENDENCY_UNRESOLVED",
        message:
          "Poetry lock selection does not satisfy the manifest dependency constraint",
        packageName: item.name,
        path: input.manifestPath,
      });
    }
  }
  for (const [name, declaration] of direct) {
    if (graph.matchedDirectNames.has(name)) {
      continue;
    }
    if (dependencies.length >= MAX_DEPENDENCIES) {
      truncated = true;
      errors.push({
        code: "DEPENDENCY_LIMIT",
        message: "Poetry dependency output exceeds its package limit",
        path: input.lockfilePath,
      });
      break;
    }
    const unsupported =
      declaration.sourceUnsupported ||
      (declaration.sourceName !== undefined &&
        !sourceConfiguration.safeNames.has(declaration.sourceName)) ||
      (sourceConfiguration.customPrimary && declaration.sourceName === undefined);
    dependencies.push({
      name,
      ecosystem: "PyPI",
      ...(declaration.requested === undefined
        ? {}
        : { requestedVersion: declaration.requested }),
      installedVersion: "",
      resolutionStatus: unsupported ? "unsupported" : "unresolved",
      dependencyType: "direct",
      environment: declaration.environment,
      declaredEnvironment: declaration.environment,
      manifestPath: input.manifestPath,
      lockfilePath: input.lockfilePath,
      packageManager: "poetry",
      projectPath: input.projectPath,
      workspacePath: input.workspacePath,
      metadata: { manifestSection: "dependency" },
    });
    errors.push({
      code: unsupported
        ? "UNSUPPORTED_PACKAGE_SOURCE"
        : "DEPENDENCY_UNRESOLVED",
      message: unsupported
        ? "Poetry dependency comes from a non-PyPI or local source"
        : "Poetry manifest dependency is absent from poetry.lock",
      packageName: name,
      path: input.manifestPath,
    });
  }
  const gapNames = new Set<string>();
  const emittedGaps = new Set<string>();
  for (const gap of graph.gaps) {
    gapNames.add(gap.name);
    const key = `${gap.name}\u0000${gap.constraint ?? ""}\u0000${gap.parent ?? ""}`;
    if (emittedGaps.has(key)) {
      continue;
    }
    emittedGaps.add(key);
    if (dependencies.length >= MAX_DEPENDENCIES) {
      truncated = true;
      break;
    }
    dependencies.push({
      name: gap.name,
      ecosystem: "PyPI",
      ...(gap.constraint === undefined
        ? {}
        : { requestedVersion: gap.constraint }),
      installedVersion: "",
      resolutionStatus: "unresolved",
      dependencyType: "transitive",
      environment: "production",
      ...(gap.parent === undefined ? {} : { parent: gap.parent }),
      dependencyPath: [...gap.path],
      manifestPath: input.manifestPath,
      lockfilePath: input.lockfilePath,
      packageManager: "poetry",
      projectPath: input.projectPath,
      workspacePath: input.workspacePath,
      metadata: {
        lockVersion,
        resolutionBasis: "lock edge constraint could not be reconciled",
      },
    });
  }
  const orphans = packages.filter(
    (item) =>
      !paths.has(`${item.name}\u0000${item.version}`) &&
      !direct.has(item.name) &&
      !gapNames.has(item.name),
  );
  if (orphans.length > 0) {
    errors.push({
      code: "DEPENDENCY_UNRESOLVED",
      message: `${orphans.length.toString()} poetry.lock package(s) are unreachable from reconciled manifest roots`,
      path: input.lockfilePath,
    });
  }
  for (const orphan of orphans) {
    if (dependencies.length >= MAX_DEPENDENCIES) {
      truncated = true;
      break;
    }
    dependencies.push({
      name: orphan.name,
      ecosystem: "PyPI",
      installedVersion: "",
      resolutionStatus: "unresolved",
      dependencyType: "transitive",
      environment: packageEnvironment(orphan.raw, undefined),
      manifestPath: input.manifestPath,
      lockfilePath: input.lockfilePath,
      packageManager: "poetry",
      projectPath: input.projectPath,
      workspacePath: input.workspacePath,
      metadata: {
        lockVersion,
        lockedVersion: orphan.version,
        resolutionBasis: "unreachable lock package",
      },
    });
  }
  if (truncated) {
    errors.push({
      code: "DEPENDENCY_LIMIT",
      message: "Poetry dependency output exceeds its package limit",
      path: input.lockfilePath,
    });
  }
  return { dependencies, errors, truncated };
}
