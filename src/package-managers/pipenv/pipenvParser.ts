import type {
  Dependency,
  DependencyEnvironment,
  DependencyMetadataValue,
} from "../../models/Dependency";
import type { ScanError } from "../../models/ScanResult";
import { MAX_PARSED_DEPENDENCIES as MAX_DEPENDENCIES } from "../python/parserLimits";
import { normalizePythonName } from "../python/requirementsParser";

interface PipfileDeclaration {
  readonly requested?: string;
  readonly environment: DependencyEnvironment;
  readonly sourceUnsupported: boolean;
  readonly indexName?: string;
}

export interface PipenvParseInput {
  readonly pipfileText: string;
  readonly lockfileText?: string;
  readonly manifestPath: string;
  readonly lockfilePath?: string;
  readonly projectPath: string;
  readonly workspacePath: string;
  readonly signal?: AbortSignal;
}

export interface PipenvParseResult {
  readonly dependencies: readonly Dependency[];
  readonly errors: readonly ScanError[];
  readonly truncated: boolean;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

const MAX_PACKAGE_SOURCES = 256;
const MAX_SOURCE_NAME_LENGTH = 128;
const MAX_SOURCE_URL_LENGTH = 2_048;

interface PackageSourceConfiguration {
  readonly present: boolean;
  readonly valid: boolean;
  readonly entries: readonly {
    readonly name: string;
    readonly safe: boolean;
  }[];
  readonly safeNames: ReadonlySet<string>;
  readonly defaultSafe: boolean;
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

function packageSourceConfiguration(value: unknown): PackageSourceConfiguration {
  if (value === undefined) {
    return {
      present: false,
      valid: false,
      entries: [],
      safeNames: new Set<string>(),
      defaultSafe: false,
    };
  }
  if (!Array.isArray(value) || value.length === 0) {
    return {
      present: true,
      valid: false,
      entries: [],
      safeNames: new Set<string>(),
      defaultSafe: false,
    };
  }

  const entries: Array<{ readonly name: string; readonly safe: boolean }> = [];
  const safeNames = new Set<string>();
  const seenNames = new Set<string>();
  let valid = value.length <= MAX_PACKAGE_SOURCES;
  for (const item of value.slice(0, MAX_PACKAGE_SOURCES)) {
    const source = record(item);
    const name = normalizedSourceName(source?.name);
    if (
      source === undefined ||
      name === undefined ||
      typeof source.url !== "string" ||
      seenNames.has(name)
    ) {
      valid = false;
      continue;
    }
    seenNames.add(name);
    const safe = canonicalPypiIndexUrl(source.url);
    entries.push({ name, safe });
    if (safe) {
      safeNames.add(name);
    }
  }
  return {
    present: true,
    valid: valid && entries.length === value.length,
    entries,
    safeNames,
    defaultSafe: entries[0]?.safe === true,
  };
}

function sourceConfigurationsMatch(
  manifest: PackageSourceConfiguration,
  lockfile: PackageSourceConfiguration,
): boolean {
  return (
    manifest.present &&
    manifest.valid &&
    lockfile.present &&
    lockfile.valid &&
    manifest.entries.length === lockfile.entries.length &&
    manifest.entries.every(
      (entry, index) =>
        entry.name === lockfile.entries[index]?.name &&
        entry.safe === lockfile.entries[index]?.safe,
    )
  );
}

function declarationValue(value: unknown): {
  readonly requested?: string;
  readonly sourceUnsupported: boolean;
  readonly indexName?: string;
} {
  if (typeof value === "string") {
    return {
      requested: value,
      sourceUnsupported:
        /^(?:git\+|https?:|file:|\.\.?[\\/])/iu.test(value.trim()),
    };
  }
  const table = record(value);
  if (table === undefined) {
    return { sourceUnsupported: false };
  }
  const requested =
    typeof table.version === "string" ? table.version : undefined;
  const rawIndexName = table.index;
  const indexName = normalizedSourceName(rawIndexName);
  return {
    ...(requested === undefined ? {} : { requested }),
    sourceUnsupported:
      ["git", "path", "file", "uri"].some(
        (key) => typeof table[key] === "string",
      ) ||
      (rawIndexName !== undefined && indexName === undefined),
    ...(indexName === undefined ? {} : { indexName }),
  };
}

function collectDeclarations(
  document: Record<string, unknown>,
): Map<string, PipfileDeclaration> {
  const declarations = new Map<string, PipfileDeclaration>();
  const addSection = (
    section: unknown,
    environment: DependencyEnvironment,
  ): void => {
    const values = record(section);
    if (values === undefined) {
      return;
    }
    for (const [rawName, value] of Object.entries(values)) {
      const name = normalizePythonName(rawName);
      const parsed = declarationValue(value);
      const existing = declarations.get(name);
      if (existing !== undefined && existing.environment === "production") {
        continue;
      }
      declarations.set(name, {
        environment,
        sourceUnsupported: parsed.sourceUnsupported,
        ...(parsed.requested === undefined ? {} : { requested: parsed.requested }),
        ...(parsed.indexName === undefined ? {} : { indexName: parsed.indexName }),
      });
    }
  };
  addSection(document.packages, "production");
  addSection(document["dev-packages"], "development");
  return declarations;
}

function lockedSourceUnsupported(
  entry: Record<string, unknown>,
  safeSources: ReadonlySet<string>,
  defaultSafe: boolean,
): boolean {
  if (
    ["git", "path", "file", "uri"].some(
      (key) => typeof entry[key] === "string",
    )
  ) {
    return true;
  }
  return entry.index !== undefined
    ? !safeSources.has(normalizedSourceName(entry.index) ?? "")
    : !defaultSafe;
}

function exactLockedVersion(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const match = /^==\s*((?:[0-9]+!)?([0-9]+(?:\.[0-9]+)*)(?:(?:a|b|rc)([0-9]+))?(?:\.post([0-9]+))?(?:\.dev([0-9]+))?)$/u.exec(
    value,
  );
  const numeric = [
    ...(match?.[1]?.includes("!") === true
      ? [match[1].slice(0, match[1].indexOf("!"))]
      : []),
    ...(match?.[2]?.split(".") ?? []),
    ...(match?.[3] === undefined ? [] : [match[3]]),
    ...(match?.[4] === undefined ? [] : [match[4]]),
    ...(match?.[5] === undefined ? [] : [match[5]]),
  ];
  return match?.[1] !== undefined &&
    numeric.every((part) => part === "0" || !part.startsWith("0"))
    ? match[1]
    : undefined;
}

function numericPythonParts(value: string): readonly number[] | undefined {
  const match = /^v?(\d+(?:\.\d+){0,3})$/iu.exec(value.trim())?.[1];
  return match === undefined ? undefined : match.split(".").map(Number);
}

function comparePythonNumericVersions(
  left: readonly number[],
  right: readonly number[],
): number {
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) {
      return difference < 0 ? -1 : 1;
    }
  }
  return 0;
}

function pipenvConstraintSatisfied(requested: string, locked: string): boolean {
  const constraint = requested.trim();
  if (constraint === "*") {
    return true;
  }
  const exact = /^={2,3}\s*([^\s,]+)$/u.exec(constraint)?.[1];
  if (exact !== undefined && !exact.includes("*")) {
    const exactParts = numericPythonParts(exact);
    const lockedParts = numericPythonParts(locked);
    return exactParts !== undefined && lockedParts !== undefined
      ? comparePythonNumericVersions(exactParts, lockedParts) === 0
      : exact.toLowerCase() === locked.toLowerCase();
  }
  const wildcard = /^==\s*(\d+(?:\.\d+)*)\.\*$/u.exec(constraint)?.[1];
  if (wildcard !== undefined) {
    const selected = numericPythonParts(locked);
    const prefix = wildcard.split(".").map(Number);
    return (
      selected !== undefined &&
      prefix.every((part, index) => selected[index] === part)
    );
  }
  const bare = numericPythonParts(constraint);
  const selected = numericPythonParts(locked);
  if (bare !== undefined) {
    return (
      selected !== undefined && comparePythonNumericVersions(bare, selected) === 0
    );
  }
  if (selected === undefined || constraint.length === 0 || constraint.length > 256) {
    return false;
  }
  const specifiers = constraint.split(",").map((value) => value.trim());
  if (specifiers.length === 0 || specifiers.some((value) => value.length === 0)) {
    return false;
  }
  return specifiers.every((specifier) => {
    const match = /^(~=|>=|<=|!=|==|>|<)\s*(\d+(?:\.\d+){0,3})$/u.exec(
      specifier,
    );
    if (match?.[1] === undefined || match[2] === undefined) {
      return false;
    }
    const bound = numericPythonParts(match[2]);
    if (bound === undefined) {
      return false;
    }
    const comparison = comparePythonNumericVersions(selected, bound);
    switch (match[1]) {
      case "==":
        return comparison === 0;
      case "!=":
        return comparison !== 0;
      case ">=":
        return comparison >= 0;
      case "<=":
        return comparison <= 0;
      case ">":
        return comparison > 0;
      case "<":
        return comparison < 0;
      case "~=": {
        if (comparison < 0) {
          return false;
        }
        const upper = [...bound];
        const incrementIndex = bound.length >= 3 ? bound.length - 2 : 0;
        upper[incrementIndex] = (upper[incrementIndex] ?? 0) + 1;
        upper.splice(incrementIndex + 1);
        return comparePythonNumericVersions(selected, upper) < 0;
      }
    }
    return false;
  });
}

export async function parsePipenvProject(
  input: PipenvParseInput,
): Promise<PipenvParseResult> {
  const { parse: parseToml } = await import("smol-toml");
  let pipfile: Record<string, unknown>;
  try {
    pipfile = record(parseToml(input.pipfileText)) ?? {};
  } catch (error: unknown) {
    return {
      dependencies: [],
      errors: [
        {
          code: "INVALID_MANIFEST",
          message: error instanceof Error ? error.message : "invalid Pipfile",
          path: input.manifestPath,
        },
      ],
      truncated: false,
    };
  }
  const declarations = collectDeclarations(pipfile);
  const manifestSources = packageSourceConfiguration(pipfile.source);
  if (input.lockfileText === undefined || input.lockfilePath === undefined) {
    const dependencies: Dependency[] = [];
    const errors: ScanError[] = [];
    for (const [name, declaration] of declarations) {
      const unsupported =
        declaration.sourceUnsupported ||
        (declaration.indexName !== undefined
          ? !manifestSources.valid ||
            !manifestSources.safeNames.has(declaration.indexName)
          : manifestSources.present &&
            (!manifestSources.valid || !manifestSources.defaultSafe));
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
        packageManager: "pipenv",
        projectPath: input.projectPath,
        workspacePath: input.workspacePath,
      });
      errors.push({
        code: unsupported
          ? "UNSUPPORTED_PACKAGE_SOURCE"
          : "DEPENDENCY_UNRESOLVED",
        message: unsupported
          ? "Pipfile dependency uses a local or non-registry source"
          : "Pipfile.lock is required to determine the selected version",
        packageName: name,
        path: input.manifestPath,
      });
    }
    return { dependencies, errors, truncated: false };
  }

  let lockfile: Record<string, unknown>;
  try {
    lockfile = record(JSON.parse(input.lockfileText) as unknown) ?? {};
  } catch (error: unknown) {
    return {
      dependencies: [],
      errors: [
        {
          code: "INVALID_LOCKFILE",
          message:
            error instanceof Error ? error.message : "invalid Pipfile.lock",
          path: input.lockfilePath,
        },
      ],
      truncated: false,
    };
  }
  const meta = record(lockfile._meta) ?? {};
  const spec = meta["pipfile-spec"];
  if (typeof spec !== "number" || !Number.isInteger(spec) || spec > 6) {
    return {
      dependencies: [],
      errors: [
        {
          code: "UNSUPPORTED_LOCKFILE",
          message: "Pipfile.lock uses an unsupported or missing pipfile-spec",
          path: input.lockfilePath,
        },
      ],
      truncated: false,
    };
  }
  const lockSources = packageSourceConfiguration(meta.sources);
  const provenanceValid = manifestSources.present
    ? sourceConfigurationsMatch(manifestSources, lockSources)
    : !lockSources.present || lockSources.valid;
  const effectiveSafeSources = lockSources.present
    ? lockSources.safeNames
    : new Set<string>();
  const effectiveDefaultSafe = lockSources.present
    ? lockSources.defaultSafe && lockSources.entries.every((entry) => entry.safe)
    : true;
  const sectionEntries: Array<{
    readonly rawName: string;
    readonly value: unknown;
    readonly environment: DependencyEnvironment;
  }> = [];
  for (const [sectionName, environment] of [
    ["default", "production"],
    ["develop", "development"],
  ] as const) {
    const section = record(lockfile[sectionName]);
    if (section !== undefined) {
      for (const [rawName, value] of Object.entries(section)) {
        sectionEntries.push({ rawName, value, environment });
      }
    }
  }
  let truncated = sectionEntries.length > MAX_DEPENDENCIES;
  const dependencies: Dependency[] = [];
  const errors: ScanError[] = [];
  const lockedNames = new Set(
    sectionEntries
      .slice(0, MAX_DEPENDENCIES)
      .map((item) => normalizePythonName(item.rawName)),
  );
  for (const item of sectionEntries.slice(0, MAX_DEPENDENCIES)) {
    if (input.signal?.aborted === true) {
      return { dependencies: [], errors, truncated };
    }
    const name = normalizePythonName(item.rawName);
    const entry = record(item.value);
    if (entry === undefined) {
      errors.push({
        code: "INVALID_LOCKFILE",
        message: "Pipfile.lock package entry is not an object",
        packageName: name,
        path: input.lockfilePath,
      });
      continue;
    }
    const declaration = declarations.get(name);
    const version = exactLockedVersion(entry.version);
    const declarationSourceUnsupported =
      declaration?.sourceUnsupported === true ||
      (declaration?.indexName !== undefined &&
        (!manifestSources.valid ||
          !manifestSources.safeNames.has(declaration.indexName))) ||
      (declaration !== undefined &&
        declaration.indexName === undefined &&
        manifestSources.present &&
        (!manifestSources.valid || !manifestSources.defaultSafe));
    const unsupported =
      !provenanceValid ||
      declarationSourceUnsupported ||
      lockedSourceUnsupported(
        entry,
        effectiveSafeSources,
        effectiveDefaultSafe,
      );
    const constraintMatches =
      declaration === undefined ||
      (declaration.requested !== undefined &&
        version !== undefined &&
        pipenvConstraintSatisfied(declaration.requested, version));
    const environment =
      declaration?.environment ?? item.environment;
    const status = unsupported
      ? "unsupported"
      : version === undefined || !constraintMatches
        ? "unresolved"
        : "resolved";
    const itemMetadata: Record<string, DependencyMetadataValue> = {
      pipfileSpec: spec,
      lockSection: item.environment === "production" ? "default" : "develop",
      ...(typeof entry.markers === "string" ? { markers: entry.markers } : {}),
      ...(Array.isArray(entry.extras)
        ? {
            extras: entry.extras.filter(
              (value): value is string => typeof value === "string",
            ),
          }
        : {}),
      ...(!provenanceValid ? { sourceConfiguration: "mismatch" } : {}),
    };
    dependencies.push({
      name,
      ecosystem: "PyPI",
      ...(declaration?.requested === undefined
        ? typeof entry.version === "string"
          ? { requestedVersion: entry.version }
          : {}
        : { requestedVersion: declaration.requested }),
      installedVersion: status === "resolved" ? (version ?? "") : "",
      resolutionStatus: status,
      dependencyType: declaration === undefined ? "transitive" : "direct",
      environment,
      ...(declaration === undefined
        ? {}
        : { declaredEnvironment: declaration.environment }),
      ...(status === "resolved"
        ? { dependencyPath: [input.projectPath, `${name}@${version ?? ""}`] }
        : {}),
      manifestPath: input.manifestPath,
      lockfilePath: input.lockfilePath,
      packageManager: "pipenv",
      projectPath: input.projectPath,
      workspacePath: input.workspacePath,
      metadata: itemMetadata,
    });
    if (status !== "resolved") {
      errors.push({
        code: unsupported
          ? "UNSUPPORTED_PACKAGE_SOURCE"
          : "DEPENDENCY_UNRESOLVED",
        message: unsupported
          ? "Pipenv dependency comes from a non-PyPI or local source"
          : version === undefined
            ? "Pipfile.lock entry does not contain one exact == version"
            : "Pipfile.lock selection does not satisfy the Pipfile dependency constraint",
        packageName: name,
        path: input.lockfilePath,
      });
    }
  }
  for (const [name, declaration] of declarations) {
    if (lockedNames.has(name)) {
      continue;
    }
    if (dependencies.length >= MAX_DEPENDENCIES) {
      truncated = true;
      errors.push({
        code: "DEPENDENCY_LIMIT",
        message: "Pipenv dependency output exceeds its package limit",
        path: input.lockfilePath,
      });
      break;
    }
    const unsupported =
      !provenanceValid ||
      declaration.sourceUnsupported ||
      (declaration.indexName !== undefined
        ? !manifestSources.valid ||
          !manifestSources.safeNames.has(declaration.indexName)
        : manifestSources.present &&
          (!manifestSources.valid || !manifestSources.defaultSafe));
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
      packageManager: "pipenv",
      projectPath: input.projectPath,
      workspacePath: input.workspacePath,
      metadata: {
        pipfileSpec: spec,
        manifestSection: declaration.environment === "development"
          ? "dev-packages"
          : "packages",
        ...(!provenanceValid ? { sourceConfiguration: "mismatch" } : {}),
      },
    });
    errors.push({
      code: unsupported
        ? "UNSUPPORTED_PACKAGE_SOURCE"
        : "DEPENDENCY_UNRESOLVED",
      message: unsupported
        ? "Pipenv dependency comes from a non-PyPI or local source"
        : "Pipfile dependency is absent from Pipfile.lock",
      packageName: name,
      path: input.manifestPath,
    });
  }
  if (truncated) {
    errors.push({
      code: "DEPENDENCY_LIMIT",
      message: `Pipfile.lock exceeds the ${MAX_DEPENDENCIES.toString()}-dependency limit`,
      path: input.lockfilePath,
    });
  }
  return { dependencies, errors, truncated };
}
