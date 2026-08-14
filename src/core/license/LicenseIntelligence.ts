import {
  boundedEvidenceText,
  boundedOpaqueId,
  boundedPositiveLimit,
  boundedRelativeId,
  compareText,
  freezeStrings,
  isAnalysisCancelled,
} from "../evidence/EvidenceControls";

export type LicenseDependencyType = "direct" | "transitive";
export type LicenseAttribution = LicenseDependencyType | "unknown";
export type LicenseDetectionStatus = "DECLARED" | "UNKNOWN";
export type LicensePolicyOutcome =
  | "ALLOWED"
  | "DENIED"
  | "REVIEW_REQUIRED"
  | "UNKNOWN";

export interface LicenseEvidenceInput {
  readonly dependencyId: string;
  readonly name: string;
  readonly ecosystem: string;
  readonly version: string;
  readonly dependencyType: LicenseDependencyType;
  /** Explicit metadata only. No license is inferred from package identity. */
  readonly declaredLicense?: string | readonly string[];
  readonly evidenceSource?: string;
  readonly dependencyPath?: readonly string[];
}

export interface LicensePolicy {
  readonly allowedLicenses?: readonly string[];
  readonly deniedLicenses?: readonly string[];
  readonly reviewRequiredLicenses?: readonly string[];
  readonly unknownLicense: "allow" | "deny" | "review";
}

export interface LicenseFinding {
  readonly outcome: LicensePolicyOutcome;
  readonly reason: string;
  /** Legal interpretation still requires review; this is metadata policy only. */
  readonly authoritative: false;
}

export interface LicenseInventoryEntry {
  readonly dependencyId: string;
  readonly name: string;
  readonly ecosystem: string;
  readonly version: string;
  readonly dependencyType: LicenseAttribution;
  readonly detectionStatus: LicenseDetectionStatus;
  readonly declaredLicenses: readonly string[];
  readonly normalizedExpressions: readonly string[];
  readonly identifiers: readonly string[];
  readonly evidenceSource?: string;
  readonly dependencyPath: readonly string[];
  readonly finding: LicenseFinding;
  readonly limitations: readonly string[];
}

export interface LicenseInventoryCoverage {
  readonly totalRecords: number;
  readonly processedRecords: number;
  readonly knownLicenseRecords: number;
  readonly unknownLicenseRecords: number;
  readonly omittedRecords: number;
  readonly truncated: boolean;
  readonly cancelled: boolean;
  readonly analysisComplete: boolean;
  readonly policyValid: boolean;
}

export interface LicenseInventory {
  readonly entries: readonly LicenseInventoryEntry[];
  readonly coverage: LicenseInventoryCoverage;
}

export interface LicenseAnalysisOptions {
  readonly maximumRecords?: number;
  readonly maximumDeclaredLicensesPerRecord?: number;
  readonly signal?: AbortSignal;
}

const HARD_MAXIMUM_RECORDS = 100_000;
const HARD_MAXIMUM_DECLARATIONS = 16;
const MAXIMUM_IDENTITY_LENGTH = 256;
const MAXIMUM_LICENSE_LENGTH = 256;
const MAXIMUM_PATH_LENGTH = 64;

const SPDX_IDS = new Map<string, string>(
  [
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "LGPL-2.0-only",
    "LGPL-2.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "MPL-1.1",
    "MPL-2.0",
    "EPL-1.0",
    "EPL-2.0",
    "CDDL-1.0",
    "CDDL-1.1",
    "SSPL-1.0",
    "LicenseRef-Proprietary",
  ].map((identifier) => [identifier.toLowerCase(), identifier]),
);

const ALIASES = new Map<string, string>([
  ["apache 2.0", "Apache-2.0"],
  ["apache-2", "Apache-2.0"],
  ["gpl-2.0", "GPL-2.0-only"],
  ["gpl-3.0", "GPL-3.0-only"],
  ["lgpl-2.0", "LGPL-2.0-only"],
  ["lgpl-2.1", "LGPL-2.1-only"],
  ["lgpl-3.0", "LGPL-3.0-only"],
  ["agpl-3.0", "AGPL-3.0-only"],
  ["mpl", "MPL-2.0"],
  ["epl", "EPL-2.0"],
  ["cddl", "CDDL-1.0"],
  ["sspl", "SSPL-1.0"],
  ["proprietary", "LicenseRef-Proprietary"],
]);

interface ParsedExpression {
  readonly normalized?: string;
  readonly identifiers: readonly string[];
  readonly compound: boolean;
}

function normalizeIdentifier(value: string): string | undefined {
  const key = value.trim().toLowerCase();
  return SPDX_IDS.get(key) ?? ALIASES.get(key);
}

function parseExpression(value: string): ParsedExpression {
  if (
    value.length > MAXIMUM_LICENSE_LENGTH ||
    !/^[A-Za-z0-9.+()\- ]+$/u.test(value) ||
    /\bWITH\b/iu.test(value)
  ) {
    return { identifiers: Object.freeze([]), compound: false };
  }
  const parts = value
    .replaceAll("(", " ( ")
    .replaceAll(")", " ) ")
    .trim()
    .split(/\s+/u);
  const normalizedParts: string[] = [];
  const identifiers: string[] = [];
  let compound = false;
  let expectIdentifier = true;
  let parentheses = 0;
  for (const part of parts) {
    if (part === "(") {
      if (!expectIdentifier) {
        return { identifiers: Object.freeze([]), compound: false };
      }
      parentheses += 1;
      normalizedParts.push(part);
      continue;
    }
    if (part === ")") {
      if (expectIdentifier || parentheses === 0) {
        return { identifiers: Object.freeze([]), compound: false };
      }
      parentheses -= 1;
      normalizedParts.push(part);
      continue;
    }
    if (/^(?:AND|OR)$/iu.test(part)) {
      if (expectIdentifier) {
        return { identifiers: Object.freeze([]), compound: false };
      }
      normalizedParts.push(part.toUpperCase());
      compound = true;
      expectIdentifier = true;
      continue;
    }
    if (!expectIdentifier) {
      return { identifiers: Object.freeze([]), compound: false };
    }
    const normalized = normalizeIdentifier(part);
    if (normalized === undefined) {
      return { identifiers: Object.freeze([]), compound: false };
    }
    normalizedParts.push(normalized);
    identifiers.push(normalized);
    expectIdentifier = false;
  }
  if (expectIdentifier || identifiers.length === 0 || parentheses !== 0) {
    return { identifiers: Object.freeze([]), compound: false };
  }
  return {
    normalized: normalizedParts.join(" "),
    identifiers: Object.freeze([...new Set(identifiers)].sort(compareText)),
    compound,
  };
}

interface NormalizedPolicy {
  readonly allowed: ReadonlySet<string>;
  readonly denied: ReadonlySet<string>;
  readonly review: ReadonlySet<string>;
  readonly valid: boolean;
}

function policySet(values: readonly string[] | undefined): {
  readonly values: ReadonlySet<string>;
  readonly valid: boolean;
} {
  const normalized = new Set<string>();
  let valid = true;
  for (const value of values ?? []) {
    const parsed = boundedEvidenceText(value, MAXIMUM_LICENSE_LENGTH);
    const identifier = parsed === undefined ? undefined : normalizeIdentifier(parsed);
    if (identifier === undefined) {
      valid = false;
    } else {
      normalized.add(identifier);
    }
  }
  return { values: normalized, valid };
}

function normalizePolicy(policy: LicensePolicy): NormalizedPolicy {
  const allowed = policySet(policy.allowedLicenses);
  const denied = policySet(policy.deniedLicenses);
  const review = policySet(policy.reviewRequiredLicenses);
  const overlap = [...allowed.values].some(
    (identifier) => denied.values.has(identifier) || review.values.has(identifier),
  ) || [...denied.values].some((identifier) => review.values.has(identifier));
  return {
    allowed: allowed.values,
    denied: denied.values,
    review: review.values,
    valid:
      allowed.valid &&
      denied.valid &&
      review.valid &&
      !overlap &&
      (policy.unknownLicense === "allow" ||
        policy.unknownLicense === "deny" ||
        policy.unknownLicense === "review"),
  };
}

function finding(
  identifiers: readonly string[],
  compound: boolean,
  policy: LicensePolicy,
  normalizedPolicy: NormalizedPolicy,
): LicenseFinding {
  let outcome: LicensePolicyOutcome;
  let reason: string;
  if (!normalizedPolicy.valid) {
    outcome = "UNKNOWN";
    reason = "License policy is invalid or contradictory; no decision was inferred.";
  } else if (identifiers.length === 0) {
    outcome =
      policy.unknownLicense === "allow"
        ? "ALLOWED"
        : policy.unknownLicense === "deny"
          ? "DENIED"
          : "REVIEW_REQUIRED";
    reason = `No supported explicit license metadata was available; unknown-license policy is ${policy.unknownLicense}.`;
  } else if (identifiers.some((identifier) => normalizedPolicy.denied.has(identifier))) {
    outcome = "DENIED";
    reason = "At least one declared license identifier is denied by policy.";
  } else if (
    compound ||
    identifiers.some((identifier) => normalizedPolicy.review.has(identifier))
  ) {
    outcome = "REVIEW_REQUIRED";
    reason = compound
      ? "Compound license expressions require review; no legal choice was inferred."
      : "At least one declared license identifier requires policy review.";
  } else if (
    identifiers.every((identifier) => normalizedPolicy.allowed.has(identifier))
  ) {
    outcome = "ALLOWED";
    reason = "Every declared license identifier is explicitly allowed by policy.";
  } else {
    outcome = "REVIEW_REQUIRED";
    reason = "A known license is not explicitly classified by policy.";
  }
  return Object.freeze({ outcome, reason, authoritative: false });
}

function safeIdentity(value: unknown): string {
  return boundedOpaqueId(value, MAXIMUM_IDENTITY_LENGTH) ?? "UNKNOWN";
}

function safeDependencyPath(value: readonly string[] | undefined): readonly string[] {
  const path: string[] = [];
  if ((value?.length ?? 0) > MAXIMUM_PATH_LENGTH) {
    return Object.freeze([]);
  }
  for (const segment of value ?? []) {
    const safe = boundedEvidenceText(segment, MAXIMUM_IDENTITY_LENGTH);
    if (
      safe === undefined ||
      /^(?:[a-zA-Z]:[\\/]|[\\/]|file:)/iu.test(safe) ||
      safe.includes("\\") ||
      safe.includes("://") ||
      safe.split("/").some((piece) => piece === "." || piece === "..")
    ) {
      return Object.freeze([]);
    }
    path.push(safe);
  }
  return freezeStrings(path);
}

function analyzeEntry(
  input: LicenseEvidenceInput,
  policy: LicensePolicy,
  normalizedPolicy: NormalizedPolicy,
  declarationLimit: number,
): LicenseInventoryEntry {
  const rawDeclarations =
    typeof input.declaredLicense === "string"
      ? [input.declaredLicense]
      : Array.isArray(input.declaredLicense)
        ? input.declaredLicense.slice(0, declarationLimit)
        : [];
  const declarations: string[] = [];
  const expressions: string[] = [];
  const identifiers = new Set<string>();
  let compound = rawDeclarations.length > 1;
  let invalidDeclaration = false;
  for (const raw of rawDeclarations) {
    const declaration = boundedEvidenceText(raw, MAXIMUM_LICENSE_LENGTH);
    if (declaration === undefined) {
      invalidDeclaration = true;
      continue;
    }
    declarations.push(declaration);
    const parsed = parseExpression(declaration);
    if (parsed.normalized === undefined) {
      invalidDeclaration = true;
      continue;
    }
    expressions.push(parsed.normalized);
    parsed.identifiers.forEach((identifier) => identifiers.add(identifier));
    compound ||= parsed.compound;
  }
  if (rawDeclarations.length === declarationLimit && Array.isArray(input.declaredLicense) && input.declaredLicense.length > declarationLimit) {
    invalidDeclaration = true;
  }
  const normalizedIdentifiers = invalidDeclaration
    ? Object.freeze([] as string[])
    : Object.freeze([...identifiers].sort(compareText));
  const detectionStatus: LicenseDetectionStatus =
    normalizedIdentifiers.length > 0 ? "DECLARED" : "UNKNOWN";
  const limitations = [
    "License evidence is derived only from caller-supplied metadata and is not authoritative legal analysis.",
  ];
  if (detectionStatus === "UNKNOWN") {
    limitations.push(
      "License metadata was absent, unsupported, invalid, or truncated; no license was inferred.",
    );
  }
  if (rawDeclarations.length > 1) {
    limitations.push(
      "Multiple metadata values do not establish AND/OR legal semantics.",
    );
  }
  const evidenceSource = boundedRelativeId(input.evidenceSource, 256);
  return Object.freeze({
    dependencyId: safeIdentity(input.dependencyId),
    name: safeIdentity(input.name),
    ecosystem: safeIdentity(input.ecosystem),
    version: safeIdentity(input.version),
    dependencyType:
      input.dependencyType === "direct" || input.dependencyType === "transitive"
        ? input.dependencyType
        : "unknown",
    detectionStatus,
    declaredLicenses: freezeStrings(declarations),
    normalizedExpressions: freezeStrings(expressions.sort(compareText)),
    identifiers: normalizedIdentifiers,
    ...(evidenceSource === undefined ? {} : { evidenceSource }),
    dependencyPath: safeDependencyPath(input.dependencyPath),
    finding: finding(normalizedIdentifiers, compound, policy, normalizedPolicy),
    limitations: freezeStrings(limitations),
  });
}

export function analyzeLicenseInventory(
  inputs: readonly LicenseEvidenceInput[],
  policy: LicensePolicy,
  options: LicenseAnalysisOptions = {},
): LicenseInventory {
  const maximumRecords = boundedPositiveLimit(
    options.maximumRecords,
    10_000,
    HARD_MAXIMUM_RECORDS,
  );
  const declarationLimit = boundedPositiveLimit(
    options.maximumDeclaredLicensesPerRecord,
    8,
    HARD_MAXIMUM_DECLARATIONS,
  );
  const normalizedPolicy = normalizePolicy(policy);
  const entries: LicenseInventoryEntry[] = [];
  let cancelled = isAnalysisCancelled(options.signal);
  for (let index = 0; !cancelled && index < Math.min(inputs.length, maximumRecords); index += 1) {
    const input = inputs[index];
    if (input !== undefined) {
      entries.push(analyzeEntry(input, policy, normalizedPolicy, declarationLimit));
    }
    cancelled = isAnalysisCancelled(options.signal);
  }
  entries.sort((left, right) =>
    compareText(
      JSON.stringify([left.ecosystem, left.name, left.version, left.dependencyId]),
      JSON.stringify([right.ecosystem, right.name, right.version, right.dependencyId]),
    ),
  );
  const truncated = inputs.length > entries.length && !cancelled;
  const knownLicenseRecords = entries.filter(
    (entry) => entry.detectionStatus === "DECLARED",
  ).length;
  const coverage = Object.freeze({
    totalRecords: inputs.length,
    processedRecords: entries.length,
    knownLicenseRecords,
    unknownLicenseRecords: entries.length - knownLicenseRecords,
    omittedRecords: inputs.length - entries.length,
    truncated,
    cancelled,
    analysisComplete: !truncated && !cancelled,
    policyValid: normalizedPolicy.valid,
  });
  return Object.freeze({ entries: Object.freeze(entries), coverage });
}
