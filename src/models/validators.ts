import type {
  Severity,
  Vulnerability,
  VulnerabilitySeverityDetail,
} from "./Vulnerability";

const SEVERITIES = new Set<Severity>([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "UNKNOWN",
]);
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/u;
const UNSAFE_VERSION_CHARACTERS =
  /[\u0000-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isBoundedString(
  value: unknown,
  maximumLength: number,
  allowEmpty = false,
): value is string {
  return (
    typeof value === "string" &&
    value.length <= maximumLength &&
    (allowEmpty || value.length > 0) &&
    !CONTROL_CHARACTERS.test(value)
  );
}

function isOptionalBoundedString(
  value: unknown,
  maximumLength: number,
  allowEmpty = false,
): value is string | undefined {
  return (
    value === undefined || isBoundedString(value, maximumLength, allowEmpty)
  );
}

function isOptionalBoundedText(
  value: unknown,
  maximumLength: number,
): value is string | undefined {
  return (
    value === undefined ||
    (typeof value === "string" && value.length <= maximumLength)
  );
}

function isStringArray(
  value: unknown,
  maximumItems: number,
  maximumLength: number,
): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= maximumItems &&
    value.every((item) => isBoundedString(item, maximumLength))
  );
}

function isFixedVersion(value: unknown): value is string {
  return (
    isBoundedString(value, 256) &&
    value.trim() === value &&
    !UNSAFE_VERSION_CHARACTERS.test(value)
  );
}

function isFixedVersionArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= 32 &&
    value.every(isFixedVersion) &&
    new Set(value).size === value.length
  );
}

function isSeverityDetail(
  value: unknown,
): value is VulnerabilitySeverityDetail {
  return (
    isRecord(value) &&
    isBoundedString(value.type, 64) &&
    isBoundedString(value.score, 2_048) &&
    isOptionalBoundedString(value.source, 256)
  );
}

function isSafeReference(value: string): boolean {
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.username.length === 0 &&
      url.password.length === 0
    );
  } catch {
    return false;
  }
}

export function isVulnerability(value: unknown): value is Vulnerability {
  if (!isRecord(value)) {
    return false;
  }
  if (
    !isBoundedString(value.id, 512) ||
    !isStringArray(value.aliases, 256, 512) ||
    !isBoundedString(value.packageName, 512) ||
    !isBoundedString(value.ecosystem, 64) ||
    !isBoundedString(value.installedVersion, 256) ||
    typeof value.severity !== "string" ||
    !SEVERITIES.has(value.severity as Severity) ||
    !isOptionalBoundedText(value.summary, 8_192) ||
    typeof value.summary !== "string" ||
    !isOptionalBoundedText(value.details, 1024 * 1024) ||
    !isOptionalBoundedString(value.affectedRange, 32_768, true) ||
    !isFixedVersionArray(value.fixedVersions) ||
    !isFixedVersionArray(value.remediationCandidates) ||
    (value.fixedVersion !== undefined && !isFixedVersion(value.fixedVersion)) ||
    (value.fixedVersionConflict !== undefined &&
      typeof value.fixedVersionConflict !== "boolean") ||
    !isStringArray(value.references, 512, 4_096) ||
    !(value.references as string[]).every(isSafeReference) ||
    !isOptionalBoundedString(value.published, 128) ||
    !isOptionalBoundedString(value.modified, 128) ||
    !isBoundedString(value.source, 64) ||
    !isOptionalBoundedString(value.providerSeverity, 256, true)
  ) {
    return false;
  }
  if (
    value.fixedVersion !== undefined &&
    !(value.fixedVersions as string[]).includes(value.fixedVersion as string)
  ) {
    return false;
  }
  if (
    value.cvssScore !== undefined &&
    (typeof value.cvssScore !== "number" ||
      !Number.isFinite(value.cvssScore) ||
      value.cvssScore < 0 ||
      value.cvssScore > 10)
  ) {
    return false;
  }
  return (
    value.severityDetails === undefined ||
    (Array.isArray(value.severityDetails) &&
      value.severityDetails.length <= 64 &&
      value.severityDetails.every(isSeverityDetail))
  );
}

export function isVulnerabilityArray(
  value: unknown,
): value is Vulnerability[] {
  if (
    !Array.isArray(value) ||
    value.length > 4_096 ||
    !value.every(isVulnerability)
  ) {
    return false;
  }

  // A remediation candidate can be supplied by a different advisory returned
  // for the same provider query, so this invariant cannot be checked by the
  // standalone validator. Prove every candidate against the bounded union of
  // authoritative fixed events for its exact package coordinate here.
  const vulnerabilities = value as Array<
    Vulnerability & {
      readonly fixedVersions: string[];
      readonly remediationCandidates: string[];
    }
  >;
  const authoritativeByCoordinate = new Map<string, Set<string>>();
  for (const vulnerability of vulnerabilities) {
    const coordinate = JSON.stringify([
      vulnerability.ecosystem,
      vulnerability.packageName,
      vulnerability.installedVersion,
    ]);
    let authoritative = authoritativeByCoordinate.get(coordinate);
    if (authoritative === undefined) {
      authoritative = new Set<string>();
      authoritativeByCoordinate.set(coordinate, authoritative);
    }
    for (const fixedVersion of vulnerability.fixedVersions) {
      authoritative.add(fixedVersion);
    }
  }

  return vulnerabilities.every((vulnerability) => {
    const coordinate = JSON.stringify([
      vulnerability.ecosystem,
      vulnerability.packageName,
      vulnerability.installedVersion,
    ]);
    const authoritative = authoritativeByCoordinate.get(coordinate);
    return vulnerability.remediationCandidates.every((candidate) =>
      authoritative?.has(candidate),
    );
  });
}
