import type { Dependency } from "../models/Dependency";
import {
  scanResultKnownVulnerabilities,
  type ScanResult,
} from "../models/ScanResult";
import type { Severity, Vulnerability } from "../models/Vulnerability";
import { classifyScanCoverage } from "../services/ScanResultStore";
import type {
  IgnoredAdvisoryPolicy,
  PolicyFindingIntelligence,
  PolicyReason,
  PolicyScanCoverage,
  SecurityGateResult,
  SecurityGateSummary,
  SecurityGateStatus,
  SecurityPolicy,
  SecurityPolicyEngineOptions,
  SecurityPolicyEvaluationContext,
} from "./PolicyModels";

const HARD_MAXIMUM_RESULTS = 64;
const HARD_MAXIMUM_DEPENDENCIES = 10_000;
const HARD_MAXIMUM_FINDINGS = 50_000;
const HARD_MAXIMUM_POLICY_ENTRIES = 2_000;
const HARD_MAXIMUM_REASONS = 20_000;
const MAXIMUM_PACKAGE_NAME_LENGTH = 512;
const MAXIMUM_ECOSYSTEM_LENGTH = 64;
const MAXIMUM_ADVISORY_ID_LENGTH = 512;
const MAXIMUM_REASON_LENGTH = 1_024;
const UNSAFE_TEXT =
  /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u;
const RFC3339_UTC =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$/u;

const POLICY_KEYS = new Set([
  "schemaVersion",
  "maxCritical",
  "maxHigh",
  "minimumSeverity",
  "minimumCvss",
  "requireKnownExploitedAbsent",
  "allowedEcosystems",
  "blockedPackages",
  "allowedPackages",
  "ignoredAdvisories",
]);
const SELECTOR_KEYS = new Set(["name", "ecosystem"]);
const IGNORE_KEYS = new Set(["id", "expiresAt", "reason"]);
const COVERAGES = new Set<PolicyScanCoverage>([
  "not-scanned",
  "complete",
  "partial",
  "unavailable",
  "cancelled",
]);
const SEVERITIES = new Set<Severity>([
  "UNKNOWN",
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
]);
const SEVERITY_RANK: Readonly<Record<Severity, number>> = Object.freeze({
  UNKNOWN: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
});

interface NormalizedSelector {
  readonly name: string;
  readonly ecosystem?: string;
}

interface NormalizedPolicy {
  readonly maxCritical?: number;
  readonly maxHigh?: number;
  readonly minimumSeverity?: Severity;
  readonly minimumCvss?: number;
  readonly requireKnownExploitedAbsent: boolean;
  readonly allowedEcosystems: readonly string[];
  readonly blockedPackages: readonly NormalizedSelector[];
  readonly allowedPackages: readonly NormalizedSelector[];
  readonly ignoredAdvisories: readonly IgnoredAdvisoryPolicy[];
}

type PolicyParseResult =
  | { readonly valid: true; readonly policy: NormalizedPolicy }
  | { readonly valid: false; readonly message: string };

interface InputCounts {
  readonly dependencies: number;
  readonly findings: number;
}

interface PackageCoordinate {
  readonly ecosystem: string;
  readonly packageName: string;
  readonly installedVersion: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
}

function hasOnlyKeys(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
): boolean {
  return Object.keys(value).every((key) => allowed.has(key));
}

function isBoundedSafeString(
  value: unknown,
  maximumLength: number,
): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximumLength &&
    value.trim() === value &&
    !UNSAFE_TEXT.test(value)
  );
}

function isBoundedSafeText(
  value: unknown,
  maximumLength: number,
  allowEmpty: boolean,
): value is string {
  return (
    typeof value === "string" &&
    value.length <= maximumLength &&
    (allowEmpty || value.length > 0) &&
    value.trim() === value &&
    !UNSAFE_TEXT.test(value)
  );
}

function isPolicyFinding(value: unknown): value is Vulnerability {
  return (
    isRecord(value) &&
    isBoundedSafeString(value.id, MAXIMUM_ADVISORY_ID_LENGTH) &&
    Array.isArray(value.aliases) &&
    value.aliases.length <= 256 &&
    value.aliases.every((alias) =>
      isBoundedSafeString(alias, MAXIMUM_ADVISORY_ID_LENGTH),
    ) &&
    isBoundedSafeString(value.packageName, MAXIMUM_PACKAGE_NAME_LENGTH) &&
    isBoundedSafeString(value.ecosystem, MAXIMUM_ECOSYSTEM_LENGTH) &&
    isBoundedSafeString(value.installedVersion, 256) &&
    typeof value.severity === "string" &&
    SEVERITIES.has(value.severity as Severity) &&
    (value.cvssScore === undefined ||
      (typeof value.cvssScore === "number" &&
        Number.isFinite(value.cvssScore) &&
        value.cvssScore >= 0 &&
        value.cvssScore <= 10)) &&
    isBoundedSafeString(value.source, 64)
  );
}

function isPolicyDependency(value: unknown): value is Dependency {
  return (
    isRecord(value) &&
    isBoundedSafeString(value.name, MAXIMUM_PACKAGE_NAME_LENGTH) &&
    isBoundedSafeString(value.ecosystem, MAXIMUM_ECOSYSTEM_LENGTH) &&
    isBoundedSafeText(value.installedVersion, 256, true)
  );
}

function isProviderResult(value: unknown): boolean {
  if (
    !isRecord(value) ||
    !isBoundedSafeString(value.provider, 64) ||
    (value.status !== "available" &&
      value.status !== "partial" &&
      value.status !== "unavailable")
  ) {
    return false;
  }
  return [
    value.dependenciesEligible,
    value.dependenciesSubmitted,
    value.successful,
    value.failed,
    value.cacheHits,
    value.staleCacheFallbacks,
    value.vulnerabilitiesFound,
  ].every(
    (entry) =>
      typeof entry === "number" &&
      Number.isSafeInteger(entry) &&
      entry >= 0,
  );
}

function safeDisplay(value: unknown, maximumLength: number): string {
  if (typeof value !== "string") {
    return "UNKNOWN";
  }
  const withoutUnsafe = value.replace(
    /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/gu,
    "�",
  );
  return withoutUnsafe.length <= maximumLength
    ? withoutUnsafe
    : `${withoutUnsafe.slice(0, Math.max(0, maximumLength - 1))}…`;
}

function parseTimestamp(value: string): number | undefined {
  const match = RFC3339_UTC.exec(value);
  const parsed = Date.parse(value);
  if (match === null || !Number.isFinite(parsed)) {
    return undefined;
  }
  const date = new Date(parsed);
  const expected = match.slice(1, 7).map(Number);
  const actual = [
    date.getUTCFullYear(),
    date.getUTCMonth() + 1,
    date.getUTCDate(),
    date.getUTCHours(),
    date.getUTCMinutes(),
    date.getUTCSeconds(),
  ];
  return expected.some((part, index) => part !== actual[index])
    ? undefined
    : parsed;
}

function boundedOption(
  value: number | undefined,
  fallback: number,
  hardMaximum: number,
  name: string,
): number {
  const selected = value ?? fallback;
  if (
    !Number.isSafeInteger(selected) ||
    selected < 1 ||
    selected > hardMaximum
  ) {
    throw new RangeError(
      `${name} must be between 1 and ${hardMaximum.toString()}`,
    );
  }
  return selected;
}

function parseLimit(value: unknown): number | undefined {
  return typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= HARD_MAXIMUM_FINDINGS
    ? value
    : undefined;
}

function parseSelector(value: unknown): NormalizedSelector | undefined {
  if (isBoundedSafeString(value, MAXIMUM_PACKAGE_NAME_LENGTH)) {
    return Object.freeze({ name: value });
  }
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, SELECTOR_KEYS) ||
    !isBoundedSafeString(value.name, MAXIMUM_PACKAGE_NAME_LENGTH)
  ) {
    return undefined;
  }
  if (
    value.ecosystem !== undefined &&
    !isBoundedSafeString(value.ecosystem, MAXIMUM_ECOSYSTEM_LENGTH)
  ) {
    return undefined;
  }
  return Object.freeze({
    name: value.name,
    ...(value.ecosystem === undefined ? {} : { ecosystem: value.ecosystem }),
  });
}

function parseSelectors(
  value: unknown,
  maximumEntries: number,
): readonly NormalizedSelector[] | undefined {
  if (value === undefined) {
    return Object.freeze([]);
  }
  if (!Array.isArray(value) || value.length > maximumEntries) {
    return undefined;
  }
  const selectors: NormalizedSelector[] = [];
  const unique = new Set<string>();
  for (const entry of value) {
    const selector = parseSelector(entry);
    if (selector === undefined) {
      return undefined;
    }
    const key = JSON.stringify([selector.ecosystem ?? "*", selector.name]);
    if (unique.has(key)) {
      return undefined;
    }
    unique.add(key);
    selectors.push(selector);
  }
  selectors.sort((left, right) =>
    JSON.stringify([left.ecosystem ?? "*", left.name]).localeCompare(
      JSON.stringify([right.ecosystem ?? "*", right.name]),
      "en",
    ),
  );
  return Object.freeze(selectors);
}

function parseStringList(
  value: unknown,
  maximumEntries: number,
  maximumLength: number,
): readonly string[] | undefined {
  if (value === undefined) {
    return Object.freeze([]);
  }
  if (!Array.isArray(value) || value.length > maximumEntries) {
    return undefined;
  }
  const entries: string[] = [];
  const unique = new Set<string>();
  for (const entry of value) {
    if (!isBoundedSafeString(entry, maximumLength) || unique.has(entry)) {
      return undefined;
    }
    unique.add(entry);
    entries.push(entry);
  }
  entries.sort((left, right) => left.localeCompare(right, "en"));
  return Object.freeze(entries);
}

function parseIgnores(
  value: unknown,
  maximumEntries: number,
): readonly IgnoredAdvisoryPolicy[] | undefined {
  if (value === undefined) {
    return Object.freeze([]);
  }
  if (!Array.isArray(value) || value.length > maximumEntries) {
    return undefined;
  }
  const ignores: IgnoredAdvisoryPolicy[] = [];
  const unique = new Set<string>();
  for (const entry of value) {
    if (
      !isRecord(entry) ||
      !hasOnlyKeys(entry, IGNORE_KEYS) ||
      !isBoundedSafeString(entry.id, MAXIMUM_ADVISORY_ID_LENGTH) ||
      !isBoundedSafeString(entry.expiresAt, 128) ||
      parseTimestamp(entry.expiresAt) === undefined ||
      (entry.reason !== undefined &&
        !isBoundedSafeString(entry.reason, MAXIMUM_REASON_LENGTH)) ||
      unique.has(entry.id)
    ) {
      return undefined;
    }
    unique.add(entry.id);
    ignores.push(
      Object.freeze({
        id: entry.id,
        expiresAt: entry.expiresAt,
        ...(entry.reason === undefined ? {} : { reason: entry.reason }),
      }),
    );
  }
  ignores.sort((left, right) => left.id.localeCompare(right.id, "en"));
  return Object.freeze(ignores);
}

function parsePolicy(
  raw: unknown,
  maximumEntries: number,
): PolicyParseResult {
  try {
    if (!isRecord(raw) || !hasOnlyKeys(raw, POLICY_KEYS)) {
      return {
        valid: false,
        message: "Security policy must be an object containing only supported fields.",
      };
    }
    if (raw.schemaVersion !== undefined && raw.schemaVersion !== 1) {
      return { valid: false, message: "Unsupported security policy schema version." };
    }
    const maxCritical =
      raw.maxCritical === undefined ? undefined : parseLimit(raw.maxCritical);
    const maxHigh = raw.maxHigh === undefined ? undefined : parseLimit(raw.maxHigh);
    if (
      (raw.maxCritical !== undefined && maxCritical === undefined) ||
      (raw.maxHigh !== undefined && maxHigh === undefined)
    ) {
      return {
        valid: false,
        message: "Vulnerability count limits must be bounded non-negative integers.",
      };
    }
    const minimumSeverity = raw.minimumSeverity;
    if (
      minimumSeverity !== undefined &&
      (typeof minimumSeverity !== "string" ||
        !SEVERITIES.has(minimumSeverity as Severity))
    ) {
      return { valid: false, message: "minimumSeverity is invalid." };
    }
    const minimumCvss = raw.minimumCvss;
    if (
      minimumCvss !== undefined &&
      (typeof minimumCvss !== "number" ||
        !Number.isFinite(minimumCvss) ||
        minimumCvss < 0 ||
        minimumCvss > 10)
    ) {
      return { valid: false, message: "minimumCvss must be between 0 and 10." };
    }
    if (
      raw.requireKnownExploitedAbsent !== undefined &&
      typeof raw.requireKnownExploitedAbsent !== "boolean"
    ) {
      return {
        valid: false,
        message: "requireKnownExploitedAbsent must be boolean.",
      };
    }
    const allowedEcosystems = parseStringList(
      raw.allowedEcosystems,
      maximumEntries,
      MAXIMUM_ECOSYSTEM_LENGTH,
    );
    const blockedPackages = parseSelectors(raw.blockedPackages, maximumEntries);
    const allowedPackages = parseSelectors(raw.allowedPackages, maximumEntries);
    const ignoredAdvisories = parseIgnores(
      raw.ignoredAdvisories,
      maximumEntries,
    );
    if (
      allowedEcosystems === undefined ||
      blockedPackages === undefined ||
      allowedPackages === undefined ||
      ignoredAdvisories === undefined ||
      allowedEcosystems.length +
        blockedPackages.length +
        allowedPackages.length +
        ignoredAdvisories.length >
        maximumEntries
    ) {
      return {
        valid: false,
        message: "Security policy entries are malformed, duplicated, or exceed the configured limit.",
      };
    }
    return {
      valid: true,
      policy: Object.freeze({
        ...(maxCritical === undefined ? {} : { maxCritical }),
        ...(maxHigh === undefined ? {} : { maxHigh }),
        ...(minimumSeverity === undefined
          ? {}
          : { minimumSeverity: minimumSeverity as Severity }),
        ...(minimumCvss === undefined ? {} : { minimumCvss }),
        requireKnownExploitedAbsent:
          raw.requireKnownExploitedAbsent === true,
        allowedEcosystems,
        blockedPackages,
        allowedPackages,
        ignoredAdvisories,
      }),
    };
  } catch {
    return { valid: false, message: "Security policy could not be read safely." };
  }
}

function findingKey(vulnerability: Vulnerability): string {
  return JSON.stringify([
    vulnerability.source,
    vulnerability.id,
    vulnerability.ecosystem,
    vulnerability.packageName,
    vulnerability.installedVersion,
  ]);
}

function packageKey(coordinate: PackageCoordinate): string {
  return JSON.stringify([
    coordinate.ecosystem,
    coordinate.packageName,
    coordinate.installedVersion,
  ]);
}

function dependencyCoordinate(dependency: Dependency): PackageCoordinate {
  return {
    ecosystem: dependency.ecosystem,
    packageName: dependency.name,
    installedVersion: dependency.installedVersion,
  };
}

function selectorMatches(
  selector: NormalizedSelector,
  coordinate: PackageCoordinate,
): boolean {
  return (
    selector.name === coordinate.packageName &&
    (selector.ecosystem === undefined ||
      selector.ecosystem === coordinate.ecosystem)
  );
}

function reasonKey(reason: PolicyReason): string {
  return JSON.stringify([
    reason.code,
    reason.disposition,
    reason.advisoryId ?? "",
    reason.ecosystem ?? "",
    reason.packageName ?? "",
    reason.installedVersion ?? "",
    reason.actual ?? "",
    reason.limit ?? "",
    reason.message,
  ]);
}

function findingFields(vulnerability: Vulnerability): Pick<
  PolicyReason,
  "advisoryId" | "ecosystem" | "packageName" | "installedVersion"
> {
  return {
    advisoryId: safeDisplay(vulnerability.id, MAXIMUM_ADVISORY_ID_LENGTH),
    ecosystem: safeDisplay(vulnerability.ecosystem, MAXIMUM_ECOSYSTEM_LENGTH),
    packageName: safeDisplay(
      vulnerability.packageName,
      MAXIMUM_PACKAGE_NAME_LENGTH,
    ),
    installedVersion: safeDisplay(vulnerability.installedVersion, 256),
  };
}

function packageFields(coordinate: PackageCoordinate): Pick<
  PolicyReason,
  "ecosystem" | "packageName" | "installedVersion"
> {
  return {
    ecosystem: safeDisplay(coordinate.ecosystem, MAXIMUM_ECOSYSTEM_LENGTH),
    packageName: safeDisplay(coordinate.packageName, MAXIMUM_PACKAGE_NAME_LENGTH),
    installedVersion: safeDisplay(coordinate.installedVersion, 256),
  };
}

function statusForReasons(reasons: readonly PolicyReason[]): SecurityGateStatus {
  if (reasons.some((reason) => reason.disposition === "FAIL")) {
    return "FAIL";
  }
  return reasons.length > 0 ? "WARN" : "PASS";
}

function parseIntelligence(
  entries: readonly PolicyFindingIntelligence[] | undefined,
  maximumEntries: number,
):
  | { readonly valid: true; readonly values: ReadonlyMap<string, string> }
  | { readonly valid: false } {
  if (entries === undefined) {
    return { valid: true, values: new Map() };
  }
  if (!Array.isArray(entries) || entries.length > maximumEntries) {
    return { valid: false };
  }
  const values = new Map<string, string>();
  for (const entry of entries as readonly unknown[]) {
    if (
      !isRecord(entry) ||
      !hasOnlyKeys(
        entry,
        new Set([
          "advisoryId",
          "ecosystem",
          "packageName",
          "installedVersion",
          "knownExploitation",
        ]),
      ) ||
      !isBoundedSafeString(entry.advisoryId, MAXIMUM_ADVISORY_ID_LENGTH) ||
      !isBoundedSafeString(entry.ecosystem, MAXIMUM_ECOSYSTEM_LENGTH) ||
      !isBoundedSafeString(entry.packageName, MAXIMUM_PACKAGE_NAME_LENGTH) ||
      !isBoundedSafeString(entry.installedVersion, 256) ||
      (entry.knownExploitation !== "known-exploited" &&
        entry.knownExploitation !== "not-known-exploited" &&
        entry.knownExploitation !== "unknown")
    ) {
      return { valid: false };
    }
    const key = JSON.stringify([
      entry.advisoryId,
      entry.ecosystem,
      entry.packageName,
      entry.installedVersion,
    ]);
    if (values.has(key)) {
      return { valid: false };
    }
    values.set(key, entry.knownExploitation);
  }
  return { valid: true, values };
}

function exploitationStatuses(
  vulnerability: Vulnerability,
  intelligence: ReadonlyMap<string, string>,
): readonly string[] {
  const statuses = new Set<string>();
  for (const advisoryId of [vulnerability.id, ...vulnerability.aliases]) {
    const status = intelligence.get(
      JSON.stringify([
        advisoryId,
        vulnerability.ecosystem,
        vulnerability.packageName,
        vulnerability.installedVersion,
      ]),
    );
    if (status !== undefined) {
      statuses.add(status);
    }
  }
  return [...statuses].sort((left, right) => left.localeCompare(right, "en"));
}

export class SecurityPolicyEngine {
  private readonly clock: () => number;
  private readonly maximumResults: number;
  private readonly maximumDependencies: number;
  private readonly maximumFindings: number;
  private readonly maximumPolicyEntries: number;
  private readonly maximumReasons: number;

  public constructor(options: SecurityPolicyEngineOptions = {}) {
    this.clock = options.clock ?? Date.now;
    this.maximumResults = boundedOption(
      options.maximumResults,
      HARD_MAXIMUM_RESULTS,
      HARD_MAXIMUM_RESULTS,
      "maximumResults",
    );
    this.maximumDependencies = boundedOption(
      options.maximumDependencies,
      HARD_MAXIMUM_DEPENDENCIES,
      HARD_MAXIMUM_DEPENDENCIES,
      "maximumDependencies",
    );
    this.maximumFindings = boundedOption(
      options.maximumFindings,
      HARD_MAXIMUM_FINDINGS,
      HARD_MAXIMUM_FINDINGS,
      "maximumFindings",
    );
    this.maximumPolicyEntries = boundedOption(
      options.maximumPolicyEntries,
      HARD_MAXIMUM_POLICY_ENTRIES,
      HARD_MAXIMUM_POLICY_ENTRIES,
      "maximumPolicyEntries",
    );
    this.maximumReasons = boundedOption(
      options.maximumReasons,
      HARD_MAXIMUM_REASONS,
      HARD_MAXIMUM_REASONS,
      "maximumReasons",
    );
  }

  public evaluate(
    scanResults: readonly ScanResult[],
    rawPolicy: SecurityPolicy | unknown,
    context: SecurityPolicyEvaluationContext = {},
  ): SecurityGateResult {
    const now = this.clock();
    if (!Number.isFinite(now)) {
      throw new RangeError("SecurityPolicyEngine clock returned a non-finite value");
    }
    const evaluatedAt = new Date(now).toISOString();
    const reasons: PolicyReason[] = [];
    const reasonKeys = new Set<string>();
    let reasonsOmitted = false;
    const addReason = (reason: PolicyReason): void => {
      const frozen = Object.freeze(reason);
      const key = reasonKey(frozen);
      if (reasonKeys.has(key)) {
        return;
      }
      reasonKeys.add(key);
      if (reasons.length < Math.max(0, this.maximumReasons - 1)) {
        reasons.push(frozen);
      } else {
        reasonsOmitted = true;
      }
    };
    let coverage: PolicyScanCoverage = "not-scanned";
    const emptySummary: SecurityGateSummary = {
      dependenciesEvaluated: 0,
      findingsEvaluated: 0,
      ignoredFindings: 0,
      criticalFindings: 0,
      highFindings: 0,
      hiddenFindings: 0,
    };
    const finish = (
      summary: SecurityGateSummary,
      policyValid: boolean,
      cancelled: boolean,
      evidenceComplete: boolean,
    ): SecurityGateResult => {
      if (reasonsOmitted) {
        reasons.splice(
          Math.max(0, this.maximumReasons - 1),
          1,
          Object.freeze({
            code: "INPUT_LIMIT_EXCEEDED",
            disposition: "FAIL",
            message:
              "Policy reasons exceeded the configured output limit; additional failures were omitted.",
          }),
        );
      }
      reasons.sort((left, right) =>
        reasonKey(left).localeCompare(reasonKey(right), "en"),
      );
      Object.freeze(reasons);
      const frozenSummary = Object.freeze({ ...summary });
      return Object.freeze({
        status: statusForReasons(reasons),
        complete:
          policyValid &&
          !cancelled &&
          evidenceComplete &&
          coverage === "complete" &&
          !reasonsOmitted,
        cancelled,
        policyValid,
        coverage,
        evaluatedAt,
        reasons,
        summary: frozenSummary,
      });
    };

    const parsedPolicy = parsePolicy(rawPolicy, this.maximumPolicyEntries);
    if (!parsedPolicy.valid) {
      addReason({
        code: "POLICY_INVALID",
        disposition: "FAIL",
        message: parsedPolicy.message,
      });
      return finish(emptySummary, false, false, false);
    }

    if (isAborted(context.signal)) {
      addReason({
        code: "EVALUATION_CANCELLED",
        disposition: "FAIL",
        message: "Security policy evaluation was cancelled; no gate pass was produced.",
      });
      coverage = context.coverage ?? "not-scanned";
      return finish(emptySummary, true, true, false);
    }

    let counts: InputCounts = { dependencies: 0, findings: 0 };
    let inputValid = Array.isArray(scanResults) && scanResults.length <= this.maximumResults;
    if (inputValid) {
      for (const result of scanResults as readonly unknown[]) {
        if (
          !isRecord(result) ||
          !Array.isArray(result.dependencies) ||
          !Array.isArray(result.vulnerabilities) ||
          (result.unfilteredVulnerabilities !== undefined &&
            !Array.isArray(result.unfilteredVulnerabilities)) ||
          !Array.isArray(result.providerResults)
        ) {
          inputValid = false;
          break;
        }
        const knownFindings =
          result.unfilteredVulnerabilities ?? result.vulnerabilities;
        if (
          !result.dependencies.every(isPolicyDependency) ||
          !result.vulnerabilities.every(isPolicyFinding) ||
          !knownFindings.every(isPolicyFinding) ||
          !result.providerResults.every(isProviderResult)
        ) {
          inputValid = false;
          break;
        }
        counts = {
          dependencies: counts.dependencies + result.dependencies.length,
          findings: counts.findings + knownFindings.length,
        };
        if (
          counts.dependencies > this.maximumDependencies ||
          counts.findings > this.maximumFindings
        ) {
          inputValid = false;
          break;
        }
      }
    }
    if (!inputValid) {
      addReason({
        code: "INPUT_LIMIT_EXCEEDED",
        disposition: "FAIL",
        message:
          "Scan results are malformed or exceed a configured policy-evaluation limit.",
      });
      return finish(emptySummary, true, false, false);
    }

    if (context.coverage !== undefined && !COVERAGES.has(context.coverage)) {
      addReason({
        code: "INPUT_INVALID",
        disposition: "FAIL",
        message: "Latest-attempt coverage is invalid.",
      });
      return finish(emptySummary, true, false, false);
    }
    if (context.coverage === undefined) {
      try {
        coverage = classifyScanCoverage(scanResults) as PolicyScanCoverage;
      } catch {
        addReason({
          code: "INPUT_INVALID",
          disposition: "FAIL",
          message: "Scan coverage metadata is malformed.",
        });
        return finish(emptySummary, true, false, false);
      }
    } else {
      coverage = context.coverage;
    }
    let evidenceComplete = true;
    if (coverage === "not-scanned" || coverage === "unavailable") {
      evidenceComplete = false;
      addReason({
        code: "SCAN_NOT_AVAILABLE",
        disposition: "FAIL",
        message:
          coverage === "not-scanned"
            ? "No completed latest scan is available; the security gate fails closed."
            : "The latest vulnerability-provider attempt is unavailable; the security gate fails closed.",
      });
    } else if (coverage !== "complete") {
      evidenceComplete = false;
      addReason({
        code: "SCAN_INCOMPLETE",
        disposition: "FAIL",
        message: `The latest scan coverage is ${coverage}; incomplete evidence cannot pass the security gate.`,
      });
    }

    const intelligence = parseIntelligence(
      context.findingIntelligence,
      this.maximumFindings,
    );
    if (!intelligence.valid) {
      addReason({
        code: "INTELLIGENCE_INVALID",
        disposition: "FAIL",
        message:
          "Known-exploitation enrichment is malformed, duplicated, or exceeds its safety limit.",
      });
      return finish(emptySummary, true, false, false);
    }

    const findingsByKey = new Map<string, Vulnerability>();
    const packagesByKey = new Map<string, PackageCoordinate>();
    let hiddenFindings = 0;
    for (const result of scanResults) {
      if (isAborted(context.signal)) {
        addReason({
          code: "EVALUATION_CANCELLED",
          disposition: "FAIL",
          message:
            "Security policy evaluation was cancelled; no gate pass was produced.",
        });
        return finish(emptySummary, true, true, false);
      }
      let providerFindings = 0;
      let providerCountsValid = true;
      for (const provider of result.providerResults) {
        if (
          !Number.isSafeInteger(provider.vulnerabilitiesFound) ||
          provider.vulnerabilitiesFound < 0
        ) {
          providerCountsValid = false;
          break;
        }
        providerFindings += provider.vulnerabilitiesFound;
        if (!Number.isSafeInteger(providerFindings)) {
          providerCountsValid = false;
          break;
        }
      }
      const knownVulnerabilities = scanResultKnownVulnerabilities(result);
      if (!providerCountsValid || providerFindings < knownVulnerabilities.length) {
        addReason({
          code: "INPUT_INVALID",
          disposition: "FAIL",
          message: "Provider finding totals are malformed or inconsistent.",
        });
        evidenceComplete = false;
      } else {
        hiddenFindings += providerFindings - knownVulnerabilities.length;
      }
      for (const vulnerability of knownVulnerabilities) {
        const key = findingKey(vulnerability);
        if (!findingsByKey.has(key)) {
          findingsByKey.set(key, vulnerability);
        }
      }
      for (const dependency of result.dependencies) {
        const coordinate = dependencyCoordinate(dependency);
        const key = packageKey(coordinate);
        if (!packagesByKey.has(key)) {
          packagesByKey.set(key, coordinate);
        }
      }
    }
    if (hiddenFindings > 0) {
      evidenceComplete = false;
      addReason({
        code: "HIDDEN_FINDINGS",
        disposition: "FAIL",
        message: `${hiddenFindings.toString()} provider-reported finding record(s) are unavailable to the policy evaluator, usually because of the display severity filter.`,
        actual: hiddenFindings,
        limit: 0,
      });
    }

    const policy = parsedPolicy.policy;
    const activeIgnoreIds = new Set<string>();
    for (const ignore of policy.ignoredAdvisories) {
      const expiration = parseTimestamp(ignore.expiresAt);
      if (expiration === undefined || expiration <= now) {
        addReason({
          code: "ADVISORY_IGNORE_EXPIRED",
          disposition: "WARN",
          message: `The ignore for ${safeDisplay(ignore.id, MAXIMUM_ADVISORY_ID_LENGTH)} expired at ${safeDisplay(ignore.expiresAt, 128)} and was not applied.`,
          advisoryId: safeDisplay(ignore.id, MAXIMUM_ADVISORY_ID_LENGTH),
        });
      } else {
        activeIgnoreIds.add(ignore.id);
      }
    }

    const findings = [...findingsByKey.values()].sort((left, right) =>
      findingKey(left).localeCompare(findingKey(right), "en"),
    );
    const evaluatedFindings: Vulnerability[] = [];
    let ignoredFindings = 0;
    for (const vulnerability of findings) {
      const identifiers = [vulnerability.id, ...vulnerability.aliases];
      if (identifiers.some((id) => activeIgnoreIds.has(id))) {
        ignoredFindings += 1;
      } else {
        evaluatedFindings.push(vulnerability);
      }
    }
    const criticalFindings = evaluatedFindings.filter(
      (finding) => finding.severity === "CRITICAL",
    ).length;
    const highFindings = evaluatedFindings.filter(
      (finding) => finding.severity === "HIGH",
    ).length;
    if (
      policy.maxCritical !== undefined &&
      criticalFindings > policy.maxCritical
    ) {
      addReason({
        code: "CRITICAL_LIMIT_EXCEEDED",
        disposition: "FAIL",
        message: `${criticalFindings.toString()} critical finding(s) exceed the configured maximum of ${policy.maxCritical.toString()}.`,
        actual: criticalFindings,
        limit: policy.maxCritical,
      });
    }
    if (policy.maxHigh !== undefined && highFindings > policy.maxHigh) {
      addReason({
        code: "HIGH_LIMIT_EXCEEDED",
        disposition: "FAIL",
        message: `${highFindings.toString()} high finding(s) exceed the configured maximum of ${policy.maxHigh.toString()}.`,
        actual: highFindings,
        limit: policy.maxHigh,
      });
    }

    const severityRulesEnabled =
      policy.maxCritical !== undefined ||
      policy.maxHigh !== undefined ||
      policy.minimumSeverity !== undefined;
    for (const vulnerability of evaluatedFindings) {
      if (isAborted(context.signal)) {
        addReason({
          code: "EVALUATION_CANCELLED",
          disposition: "FAIL",
          message:
            "Security policy evaluation was cancelled; no gate pass was produced.",
        });
        return finish(
          {
            dependenciesEvaluated: packagesByKey.size,
            findingsEvaluated: evaluatedFindings.length,
            ignoredFindings,
            criticalFindings,
            highFindings,
            hiddenFindings,
          },
          true,
          true,
          false,
        );
      }
      const fields = findingFields(vulnerability);
      if (severityRulesEnabled && vulnerability.severity === "UNKNOWN") {
        evidenceComplete = false;
        addReason({
          code: "SEVERITY_UNKNOWN",
          disposition: "FAIL",
          message: `${fields.advisoryId} has unknown severity; the configured severity policy cannot prove compliance.`,
          ...fields,
        });
      } else if (
        policy.minimumSeverity !== undefined &&
        SEVERITY_RANK[vulnerability.severity] >=
          SEVERITY_RANK[policy.minimumSeverity]
      ) {
        addReason({
          code: "SEVERITY_THRESHOLD_EXCEEDED",
          disposition: "FAIL",
          message: `${fields.advisoryId} has ${vulnerability.severity} severity, meeting the blocking threshold ${policy.minimumSeverity}.`,
          ...fields,
        });
      }
      if (policy.minimumCvss !== undefined) {
        if (
          vulnerability.cvssScore === undefined ||
          !Number.isFinite(vulnerability.cvssScore) ||
          vulnerability.cvssScore < 0 ||
          vulnerability.cvssScore > 10
        ) {
          evidenceComplete = false;
          addReason({
            code: "CVSS_UNKNOWN",
            disposition: "FAIL",
            message: `${fields.advisoryId} has no valid CVSS score; the configured CVSS policy cannot prove compliance.`,
            ...fields,
          });
        } else if (vulnerability.cvssScore >= policy.minimumCvss) {
          addReason({
            code: "CVSS_THRESHOLD_EXCEEDED",
            disposition: "FAIL",
            message: `${fields.advisoryId} has CVSS ${vulnerability.cvssScore.toFixed(1)}, meeting the blocking threshold ${policy.minimumCvss.toFixed(1)}.`,
            ...fields,
            actual: vulnerability.cvssScore,
            limit: policy.minimumCvss,
          });
        }
      }
      if (policy.requireKnownExploitedAbsent) {
        const statuses = exploitationStatuses(vulnerability, intelligence.values);
        if (statuses.length === 1 && statuses[0] === "known-exploited") {
          addReason({
            code: "KNOWN_EXPLOITED",
            disposition: "FAIL",
            message: `${fields.advisoryId} is listed as known exploited by supplied intelligence.`,
            ...fields,
          });
        } else if (
          statuses.length !== 1 ||
          statuses[0] !== "not-known-exploited"
        ) {
          evidenceComplete = false;
          addReason({
            code: "KNOWN_EXPLOITATION_UNKNOWN",
            disposition: "FAIL",
            message: `${fields.advisoryId} lacks unambiguous known-exploitation evidence; absence cannot be assumed.`,
            ...fields,
          });
        }
      }
    }

    const packageCoordinates = [...packagesByKey.values()].sort((left, right) =>
      packageKey(left).localeCompare(packageKey(right), "en"),
    );
    const allowedEcosystems = new Set(policy.allowedEcosystems);
    for (const coordinate of packageCoordinates) {
      const fields = packageFields(coordinate);
      if (
        allowedEcosystems.size > 0 &&
        !allowedEcosystems.has(coordinate.ecosystem)
      ) {
        addReason({
          code: "ECOSYSTEM_NOT_ALLOWED",
          disposition: "FAIL",
          message: `${fields.ecosystem} is not in the configured ecosystem allowlist.`,
          ...fields,
        });
      }
      if (
        policy.blockedPackages.some((selector) =>
          selectorMatches(selector, coordinate),
        )
      ) {
        addReason({
          code: "PACKAGE_BLOCKED",
          disposition: "FAIL",
          message: `${fields.packageName} in ${fields.ecosystem} matches a blocked package selector.`,
          ...fields,
        });
      } else if (
        policy.allowedPackages.length > 0 &&
        !policy.allowedPackages.some((selector) =>
          selectorMatches(selector, coordinate),
        )
      ) {
        addReason({
          code: "PACKAGE_NOT_ALLOWED",
          disposition: "FAIL",
          message: `${fields.packageName} in ${fields.ecosystem} is not in the configured package allowlist.`,
          ...fields,
        });
      }
    }

    const summary = {
      dependenciesEvaluated: packageCoordinates.length,
      findingsEvaluated: evaluatedFindings.length,
      ignoredFindings,
      criticalFindings,
      highFindings,
      hiddenFindings,
    } as const;
    return finish(summary, true, false, evidenceComplete);
  }
}
