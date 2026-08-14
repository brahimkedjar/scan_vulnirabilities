/**
 * Host-neutral monorepo version analysis. This module deliberately treats
 * project locations as opaque grouping keys: it never resolves, opens, logs,
 * or returns a workspace path.
 */

export type MonorepoVersionFindingKind =
  | "DUPLICATE_VERSION"
  | "VERSION_DRIFT";

export interface MonorepoProjectDependencyRecord {
  readonly workspacePath?: string;
  readonly projectPath?: string;
  readonly manifestPath?: string;
  readonly ecosystem: string;
  readonly name: string;
  readonly installedVersion: string;
  readonly resolutionStatus?: "resolved" | "unresolved" | "unsupported";
}

export interface MonorepoVersionEvidence {
  readonly version: string;
  readonly occurrenceCount: number;
  /** Deterministic, result-local references. They are not path hashes. */
  readonly projectRefs: readonly string[];
}

export interface MonorepoVersionFinding {
  readonly findingKey: string;
  readonly kind: MonorepoVersionFindingKind;
  readonly ecosystem: string;
  readonly packageName: string;
  readonly projectRefs: readonly string[];
  readonly versions: readonly MonorepoVersionEvidence[];
  readonly affectedProjectCount: number;
  readonly occurrenceCount: number;
  readonly summary: string;
}

export interface MonorepoVersionAnalysisLimits {
  readonly maximumRecords?: number;
  readonly maximumProjects?: number;
  readonly maximumFindings?: number;
  readonly maximumVersionsPerDependency?: number;
}

export interface MonorepoVersionAnalysisOptions {
  readonly limits?: MonorepoVersionAnalysisLimits;
  readonly signal?: AbortSignal;
}

export interface MonorepoVersionCoverage {
  readonly recordsTotal: number;
  readonly recordsExamined: number;
  readonly recordsEligible: number;
  readonly recordsAnalyzed: number;
  readonly recordsIneligible: number;
  readonly recordsInvalid: number;
  readonly recordsOmitted: number;
  readonly projectsObserved: number;
  readonly projectsAnalyzed: number;
  readonly projectsOmitted: number;
  readonly identitiesAnalyzed: number;
  readonly identitiesOmittedByVersionLimit: number;
  readonly findingsEmitted: number;
  readonly findingsOmitted: number;
  readonly hardLimitExceeded: boolean;
  readonly truncated: boolean;
  readonly cancelled: boolean;
  /** False whenever any record could not contribute trustworthy evidence. */
  readonly analysisComplete: boolean;
}

export interface MonorepoVersionAnalysisResult {
  readonly findings: readonly MonorepoVersionFinding[];
  readonly coverage: MonorepoVersionCoverage;
}

export const MONOREPO_VERSION_ANALYSIS_HARD_LIMITS = Object.freeze({
  maximumRecords: 100_000,
  maximumProjects: 10_000,
  maximumFindings: 50_000,
  maximumVersionsPerDependency: 1_024,
});

export const DEFAULT_MONOREPO_VERSION_ANALYSIS_LIMITS = Object.freeze({
  maximumRecords: 100_000,
  maximumProjects: 10_000,
  maximumFindings: 10_000,
  maximumVersionsPerDependency: 256,
});

const MAXIMUM_IDENTITY_LENGTH = 512;
const MAXIMUM_VERSION_LENGTH = 512;
const MAXIMUM_PATH_LENGTH = 4_096;
const UNSAFE_TEXT =
  /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u;
const UNSAFE_IDENTITY_MARKUP = /[<>&"'`]/u;

interface ResolvedLimits {
  readonly maximumRecords: number;
  readonly maximumProjects: number;
  readonly maximumFindings: number;
  readonly maximumVersionsPerDependency: number;
}

interface NormalizedRecord {
  readonly projectKey: string;
  readonly ecosystem: string;
  readonly packageName: string;
  readonly version: string;
}

type NormalizationResult =
  | { readonly kind: "eligible"; readonly record: NormalizedRecord }
  | { readonly kind: "ineligible" }
  | { readonly kind: "invalid" };

interface IdentityState {
  readonly ecosystem: string;
  readonly packageName: string;
  readonly byProject: Map<string, Map<string, number>>;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareNormalizedRecords(
  left: NormalizedRecord,
  right: NormalizedRecord,
): number {
  return (
    compareText(left.ecosystem, right.ecosystem) ||
    compareText(left.packageName, right.packageName) ||
    compareText(left.version, right.version) ||
    compareText(left.projectKey, right.projectKey)
  );
}

function boundedText(
  value: unknown,
  maximumLength: number,
  rejectMarkup: boolean,
): string | undefined {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumLength ||
    value.trim() !== value ||
    UNSAFE_TEXT.test(value) ||
    (rejectMarkup && UNSAFE_IDENTITY_MARKUP.test(value))
  ) {
    return undefined;
  }
  const normalized = value.normalize("NFC");
  return normalized.length === 0 || normalized.length > maximumLength
    ? undefined
    : normalized;
}

function boundedPath(value: unknown): string | undefined {
  return boundedText(value, MAXIMUM_PATH_LENGTH, false);
}

function normalizeRecord(value: unknown): NormalizationResult {
  if (typeof value !== "object" || value === null) {
    return { kind: "invalid" };
  }

  try {
    const candidate = value as Partial<MonorepoProjectDependencyRecord>;
    if (
      candidate.resolutionStatus === "unresolved" ||
      candidate.resolutionStatus === "unsupported"
    ) {
      return { kind: "ineligible" };
    }
    if (
      candidate.resolutionStatus !== undefined &&
      candidate.resolutionStatus !== "resolved"
    ) {
      return { kind: "invalid" };
    }

    const ecosystem = boundedText(
      candidate.ecosystem,
      MAXIMUM_IDENTITY_LENGTH,
      true,
    );
    const packageName = boundedText(
      candidate.name,
      MAXIMUM_IDENTITY_LENGTH,
      true,
    );
    const version = boundedText(
      candidate.installedVersion,
      MAXIMUM_VERSION_LENGTH,
      true,
    );
    const workspacePath =
      candidate.workspacePath === undefined
        ? ""
        : boundedPath(candidate.workspacePath);
    const projectPath = boundedPath(
      candidate.projectPath ?? candidate.workspacePath,
    );
    if (
      ecosystem === undefined ||
      packageName === undefined ||
      version === undefined ||
      workspacePath === undefined ||
      projectPath === undefined
    ) {
      return { kind: "invalid" };
    }

    return {
      kind: "eligible",
      record: {
        projectKey: JSON.stringify([workspacePath, projectPath]),
        ecosystem,
        packageName,
        version,
      },
    };
  } catch {
    return { kind: "invalid" };
  }
}

function checkedLimit(
  value: number | undefined,
  fallback: number,
  hardMaximum: number,
  label: string,
): number {
  const selected = value ?? fallback;
  if (
    !Number.isSafeInteger(selected) ||
    selected < 1 ||
    selected > hardMaximum
  ) {
    throw new RangeError(
      `${label} must be an integer between 1 and ${hardMaximum.toString()}`,
    );
  }
  return selected;
}

function resolveLimits(
  supplied: MonorepoVersionAnalysisLimits | undefined,
): ResolvedLimits {
  return {
    maximumRecords: checkedLimit(
      supplied?.maximumRecords,
      DEFAULT_MONOREPO_VERSION_ANALYSIS_LIMITS.maximumRecords,
      MONOREPO_VERSION_ANALYSIS_HARD_LIMITS.maximumRecords,
      "maximumRecords",
    ),
    maximumProjects: checkedLimit(
      supplied?.maximumProjects,
      DEFAULT_MONOREPO_VERSION_ANALYSIS_LIMITS.maximumProjects,
      MONOREPO_VERSION_ANALYSIS_HARD_LIMITS.maximumProjects,
      "maximumProjects",
    ),
    maximumFindings: checkedLimit(
      supplied?.maximumFindings,
      DEFAULT_MONOREPO_VERSION_ANALYSIS_LIMITS.maximumFindings,
      MONOREPO_VERSION_ANALYSIS_HARD_LIMITS.maximumFindings,
      "maximumFindings",
    ),
    maximumVersionsPerDependency: checkedLimit(
      supplied?.maximumVersionsPerDependency,
      DEFAULT_MONOREPO_VERSION_ANALYSIS_LIMITS.maximumVersionsPerDependency,
      MONOREPO_VERSION_ANALYSIS_HARD_LIMITS.maximumVersionsPerDependency,
      "maximumVersionsPerDependency",
    ),
  };
}

function cancelled(signal: AbortSignal | undefined): boolean {
  try {
    return signal?.aborted === true;
  } catch {
    return true;
  }
}

function frozenCoverage(
  coverage: MonorepoVersionCoverage,
): MonorepoVersionCoverage {
  return Object.freeze(coverage);
}

function result(
  findings: readonly MonorepoVersionFinding[],
  coverage: MonorepoVersionCoverage,
): MonorepoVersionAnalysisResult {
  return Object.freeze({
    findings: Object.freeze([...findings]),
    coverage: frozenCoverage(coverage),
  });
}

function emptyCoverage(
  recordsTotal: number,
  isCancelled: boolean,
  hardLimitExceeded: boolean,
): MonorepoVersionCoverage {
  return {
    recordsTotal,
    recordsExamined: 0,
    recordsEligible: 0,
    recordsAnalyzed: 0,
    recordsIneligible: 0,
    recordsInvalid: 0,
    recordsOmitted: recordsTotal,
    projectsObserved: 0,
    projectsAnalyzed: 0,
    projectsOmitted: 0,
    identitiesAnalyzed: 0,
    identitiesOmittedByVersionLimit: 0,
    findingsEmitted: 0,
    findingsOmitted: 0,
    hardLimitExceeded,
    truncated: hardLimitExceeded,
    cancelled: isCancelled,
    analysisComplete: false,
  };
}

function projectRef(index: number): string {
  return `project-${(index + 1).toString().padStart(4, "0")}`;
}

function identityKey(ecosystem: string, packageName: string): string {
  return JSON.stringify([ecosystem, packageName]);
}

function freezeEvidence(
  evidence: MonorepoVersionEvidence,
): MonorepoVersionEvidence {
  return Object.freeze({
    ...evidence,
    projectRefs: Object.freeze([...evidence.projectRefs]),
  });
}

function freezeFinding(
  finding: MonorepoVersionFinding,
): MonorepoVersionFinding {
  return Object.freeze({
    ...finding,
    projectRefs: Object.freeze([...finding.projectRefs]),
    versions: Object.freeze(finding.versions.map(freezeEvidence)),
  });
}

function versionEvidence(
  byProject: ReadonlyMap<string, ReadonlyMap<string, number>>,
  projectRefs: ReadonlyMap<string, string>,
  includedProjects: ReadonlySet<string>,
): readonly MonorepoVersionEvidence[] {
  const versions = new Map<
    string,
    { occurrenceCount: number; projectRefs: Set<string> }
  >();
  for (const [projectKey, projectVersions] of byProject) {
    if (!includedProjects.has(projectKey)) {
      continue;
    }
    const ref = projectRefs.get(projectKey);
    if (ref === undefined) {
      continue;
    }
    for (const [version, count] of projectVersions) {
      const current = versions.get(version) ?? {
        occurrenceCount: 0,
        projectRefs: new Set<string>(),
      };
      current.occurrenceCount += count;
      current.projectRefs.add(ref);
      versions.set(version, current);
    }
  }
  return [...versions]
    .sort(([left], [right]) => compareText(left, right))
    .map(([version, evidence]) =>
      freezeEvidence({
        version,
        occurrenceCount: evidence.occurrenceCount,
        projectRefs: [...evidence.projectRefs].sort(compareText),
      }),
    );
}

function makeFinding(
  kind: MonorepoVersionFindingKind,
  identity: IdentityState,
  projectKeys: readonly string[],
  projectRefs: ReadonlyMap<string, string>,
): MonorepoVersionFinding {
  const includedProjects = new Set(projectKeys);
  const refs = projectKeys
    .map((key) => projectRefs.get(key))
    .filter((value): value is string => value !== undefined)
    .sort(compareText);
  const versions = versionEvidence(
    identity.byProject,
    projectRefs,
    includedProjects,
  );
  const occurrenceCount = versions.reduce(
    (total, version) => total + version.occurrenceCount,
    0,
  );
  return freezeFinding({
    findingKey: JSON.stringify([
      kind,
      identity.ecosystem,
      identity.packageName,
      refs,
      versions.map((version) => version.version),
    ]),
    kind,
    ecosystem: identity.ecosystem,
    packageName: identity.packageName,
    projectRefs: refs,
    versions,
    affectedProjectCount: refs.length,
    occurrenceCount,
    summary:
      kind === "DUPLICATE_VERSION"
        ? "One project resolves this dependency to multiple versions."
        : "Projects resolve this dependency to different version sets.",
  });
}

/**
 * Finds resolved-version duplication inside projects and version drift across
 * projects. The input is never mutated, and incomplete evidence is exposed in
 * coverage instead of being converted into a negative security conclusion.
 */
export function analyzeMonorepoVersions(
  records: readonly MonorepoProjectDependencyRecord[],
  options: MonorepoVersionAnalysisOptions = {},
): MonorepoVersionAnalysisResult {
  if (!Array.isArray(records)) {
    throw new TypeError("records must be an array");
  }
  const limits = resolveLimits(options.limits);
  const recordsTotal = records.length;
  if (cancelled(options.signal)) {
    return result([], emptyCoverage(recordsTotal, true, false));
  }
  if (recordsTotal > MONOREPO_VERSION_ANALYSIS_HARD_LIMITS.maximumRecords) {
    return result([], emptyCoverage(recordsTotal, false, true));
  }

  const normalized: NormalizedRecord[] = [];
  let recordsExamined = 0;
  let recordsIneligible = 0;
  let recordsInvalid = 0;
  for (let index = 0; index < recordsTotal; index += 1) {
    if (cancelled(options.signal)) {
      return result(
        [],
        {
          ...emptyCoverage(recordsTotal, true, false),
          recordsExamined,
          recordsEligible: normalized.length,
          recordsIneligible,
          recordsInvalid,
        },
      );
    }
    let normalizedRecord: NormalizationResult;
    try {
      normalizedRecord = normalizeRecord(records[index]);
    } catch {
      normalizedRecord = { kind: "invalid" };
    }
    recordsExamined += 1;
    if (normalizedRecord.kind === "eligible") {
      normalized.push(normalizedRecord.record);
    } else if (normalizedRecord.kind === "ineligible") {
      recordsIneligible += 1;
    } else {
      recordsInvalid += 1;
    }
  }

  normalized.sort(compareNormalizedRecords);
  const allProjects = [...new Set(normalized.map((record) => record.projectKey))]
    .sort(compareText);
  const selectedProjects = allProjects.slice(0, limits.maximumProjects);
  const selectedProjectSet = new Set(selectedProjects);
  const projectRefs = new Map(
    selectedProjects.map((key, index) => [key, projectRef(index)]),
  );
  const projectRecords = normalized.filter((record) =>
    selectedProjectSet.has(record.projectKey),
  );
  const analyzedRecords = projectRecords.slice(0, limits.maximumRecords);
  const analyzedProjectKeys = new Set(
    analyzedRecords.map((record) => record.projectKey),
  );

  const identities = new Map<string, IdentityState>();
  for (const record of analyzedRecords) {
    if (cancelled(options.signal)) {
      return result(
        [],
        {
          recordsTotal,
          recordsExamined,
          recordsEligible: normalized.length,
          recordsAnalyzed: 0,
          recordsIneligible,
          recordsInvalid,
          recordsOmitted: normalized.length,
          projectsObserved: allProjects.length,
          projectsAnalyzed: 0,
          projectsOmitted: allProjects.length,
          identitiesAnalyzed: 0,
          identitiesOmittedByVersionLimit: 0,
          findingsEmitted: 0,
          findingsOmitted: 0,
          hardLimitExceeded: false,
          truncated: normalized.length > analyzedRecords.length,
          cancelled: true,
          analysisComplete: false,
        },
      );
    }
    const key = identityKey(record.ecosystem, record.packageName);
    const identity = identities.get(key) ?? {
      ecosystem: record.ecosystem,
      packageName: record.packageName,
      byProject: new Map<string, Map<string, number>>(),
    };
    const versions = identity.byProject.get(record.projectKey) ?? new Map();
    versions.set(record.version, (versions.get(record.version) ?? 0) + 1);
    identity.byProject.set(record.projectKey, versions);
    identities.set(key, identity);
  }

  const generatedFindings: MonorepoVersionFinding[] = [];
  let identitiesOmittedByVersionLimit = 0;
  const sortedIdentities = [...identities.values()].sort(
    (left, right) =>
      compareText(left.ecosystem, right.ecosystem) ||
      compareText(left.packageName, right.packageName),
  );
  for (const identity of sortedIdentities) {
    if (cancelled(options.signal)) {
      break;
    }
    const unionVersions = new Set(
      [...identity.byProject.values()].flatMap((versions) => [
        ...versions.keys(),
      ]),
    );
    if (unionVersions.size > limits.maximumVersionsPerDependency) {
      identitiesOmittedByVersionLimit += 1;
      continue;
    }

    const sortedProjects = [...identity.byProject.keys()].sort(compareText);
    for (const projectKey of sortedProjects) {
      const versions = identity.byProject.get(projectKey);
      if (versions !== undefined && versions.size > 1) {
        generatedFindings.push(
          makeFinding(
            "DUPLICATE_VERSION",
            identity,
            [projectKey],
            projectRefs,
          ),
        );
      }
    }

    if (sortedProjects.length > 1) {
      const versionSets = new Set(
        sortedProjects.map((projectKey) =>
          JSON.stringify(
            [...(identity.byProject.get(projectKey)?.keys() ?? [])].sort(
              compareText,
            ),
          ),
        ),
      );
      if (versionSets.size > 1) {
        generatedFindings.push(
          makeFinding(
            "VERSION_DRIFT",
            identity,
            sortedProjects,
            projectRefs,
          ),
        );
      }
    }
  }

  generatedFindings.sort((left, right) =>
    compareText(left.findingKey, right.findingKey),
  );
  const selectedFindings = generatedFindings.slice(0, limits.maximumFindings);
  const findingsOmitted = generatedFindings.length - selectedFindings.length;
  const recordsOmitted = normalized.length - analyzedRecords.length;
  const projectsAnalyzed = analyzedProjectKeys.size;
  const projectsOmitted = allProjects.length - projectsAnalyzed;
  const wasCancelled = cancelled(options.signal);
  const truncated =
    recordsOmitted > 0 ||
    projectsOmitted > 0 ||
    identitiesOmittedByVersionLimit > 0 ||
    findingsOmitted > 0;
  const analysisComplete =
    !wasCancelled &&
    !truncated &&
    recordsIneligible === 0 &&
    recordsInvalid === 0 &&
    recordsExamined === recordsTotal;

  return result(selectedFindings, {
    recordsTotal,
    recordsExamined,
    recordsEligible: normalized.length,
    recordsAnalyzed: analyzedRecords.length,
    recordsIneligible,
    recordsInvalid,
    recordsOmitted,
    projectsObserved: allProjects.length,
    projectsAnalyzed,
    projectsOmitted,
    identitiesAnalyzed: identities.size - identitiesOmittedByVersionLimit,
    identitiesOmittedByVersionLimit,
    findingsEmitted: selectedFindings.length,
    findingsOmitted,
    hardLimitExceeded: false,
    truncated,
    cancelled: wasCancelled,
    analysisComplete,
  });
}
