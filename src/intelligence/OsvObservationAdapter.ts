import { isVulnerability } from "../models/validators";
import type { Vulnerability } from "../models/Vulnerability";
import type {
  AdvisoryEvidence,
  AdvisoryObservation,
  AdvisorySeverityDetail,
  IntelligenceFreshness,
  IntelligenceSourceError,
  IntelligenceSourceResult,
  IntelligenceSourceStatus,
} from "./IntelligenceModels";
import {
  assertAdvisoryObservation,
  assertIntelligenceSourceResult,
} from "./IntelligenceValidators";

export interface OsvSourceResultOptions {
  readonly status?: Exclude<IntelligenceSourceStatus, "unavailable">;
  readonly freshness: IntelligenceFreshness;
  readonly retrievedAt?: string;
  readonly errors?: readonly IntelligenceSourceError[];
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function frozenStrings(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values)].sort(compareText));
}

function evidence(
  vulnerability: Vulnerability,
  field: AdvisoryEvidence["field"],
  value: string,
  reference?: string,
): AdvisoryEvidence {
  return Object.freeze({
    provider: "OSV",
    advisoryId: vulnerability.id,
    field,
    value,
    ...(vulnerability.modified === undefined
      ? {}
      : { timestamp: vulnerability.modified }),
    ...(reference === undefined ? {} : { reference }),
  });
}

function cloneSeverityDetails(
  values: readonly NonNullable<Vulnerability["severityDetails"]>[number][],
): readonly AdvisorySeverityDetail[] {
  return Object.freeze(
    values
      .map((entry) =>
        Object.freeze({
          type: entry.type,
          score: entry.score,
          ...(entry.source === undefined ? {} : { source: entry.source }),
        }),
      )
      .sort(
        (left, right) =>
          compareText(left.type, right.type) ||
          compareText(left.score, right.score) ||
          compareText(left.source ?? "", right.source ?? ""),
      ),
  );
}

/**
 * Adapts a normalized OSV finding without re-evaluating ranges or selecting a
 * fix. The existing normalizer emits a record only when the exact query
 * coordinate is affected and drops withdrawn OSV records, so those two states
 * are part of this adapter's input contract rather than new inferences.
 */
export function osvVulnerabilityToObservation(
  vulnerability: Vulnerability,
): AdvisoryObservation {
  if (!isVulnerability(vulnerability) || vulnerability.source !== "OSV") {
    throw new TypeError(
      "OSV observation input must be a validated normalized OSV vulnerability",
    );
  }

  const aliases = frozenStrings(
    vulnerability.aliases.filter((alias) => alias !== vulnerability.id),
  );
  const references = frozenStrings(vulnerability.references);
  const fixedVersions =
    vulnerability.fixedVersions === undefined
      ? undefined
      : frozenStrings(vulnerability.fixedVersions);
  const affectedRanges =
    vulnerability.affectedRange === undefined
      ? undefined
      : Object.freeze([vulnerability.affectedRange]);
  const severityDetails =
    vulnerability.severityDetails === undefined
      ? undefined
      : cloneSeverityDetails(vulnerability.severityDetails);

  const retainedEvidence: AdvisoryEvidence[] = [
    evidence(vulnerability, "identifier", vulnerability.id),
    ...aliases.map((alias) => evidence(vulnerability, "identifier", alias)),
    ...(vulnerability.summary.length === 0
      ? []
      : [evidence(vulnerability, "summary", vulnerability.summary)]),
    evidence(vulnerability, "severity", vulnerability.severity),
    ...(vulnerability.cvssScore === undefined
      ? []
      : [evidence(vulnerability, "cvss", vulnerability.cvssScore.toString())]),
    ...(vulnerability.providerSeverity === undefined ||
    vulnerability.providerSeverity.length === 0
      ? []
      : [evidence(vulnerability, "severity", vulnerability.providerSeverity)]),
    ...(severityDetails ?? []).map((entry) =>
      evidence(vulnerability, "severity", entry.score),
    ),
    evidence(vulnerability, "affectedness", "affected"),
    ...(affectedRanges ?? []).map((range) =>
      evidence(vulnerability, "affected-range", range),
    ),
    ...(fixedVersions ?? []).map((version) =>
      evidence(vulnerability, "fixed-version", version),
    ),
    evidence(vulnerability, "advisory-status", "active"),
    ...(vulnerability.published === undefined
      ? []
      : [evidence(vulnerability, "published", vulnerability.published)]),
    ...(vulnerability.modified === undefined
      ? []
      : [evidence(vulnerability, "modified", vulnerability.modified)]),
    ...references.map((reference) =>
      evidence(vulnerability, "reference", reference, reference),
    ),
  ];
  retainedEvidence.sort(
    (left, right) =>
      compareText(left.field, right.field) ||
      compareText(left.value, right.value) ||
      compareText(left.reference ?? "", right.reference ?? ""),
  );
  Object.freeze(retainedEvidence);

  const observation: AdvisoryObservation = Object.freeze({
    provider: "OSV",
    advisoryId: vulnerability.id,
    aliases,
    coordinate: Object.freeze({
      ecosystem: vulnerability.ecosystem,
      packageName: vulnerability.packageName,
      installedVersion: vulnerability.installedVersion,
    }),
    summary: vulnerability.summary,
    ...(vulnerability.details === undefined
      ? {}
      : { details: vulnerability.details }),
    severity: vulnerability.severity,
    ...(vulnerability.cvssScore === undefined
      ? {}
      : { cvssScore: vulnerability.cvssScore }),
    ...(vulnerability.providerSeverity === undefined ||
    vulnerability.providerSeverity.length === 0
      ? {}
      : { providerSeverity: vulnerability.providerSeverity }),
    ...(severityDetails === undefined ? {} : { severityDetails }),
    affectedness: "affected",
    ...(affectedRanges === undefined ? {} : { affectedRanges }),
    ...(fixedVersions === undefined ? {} : { fixedVersions }),
    advisoryStatus: "active",
    ...(vulnerability.published === undefined
      ? {}
      : { publishedAt: vulnerability.published }),
    ...(vulnerability.modified === undefined
      ? {}
      : { modifiedAt: vulnerability.modified }),
    references,
    evidence: retainedEvidence,
  });
  assertAdvisoryObservation(observation);
  return observation;
}

export function osvVulnerabilitiesToObservations(
  vulnerabilities: readonly Vulnerability[],
): readonly AdvisoryObservation[] {
  return Object.freeze(
    vulnerabilities
      .map(osvVulnerabilityToObservation)
      .sort(
        (left, right) =>
          compareText(left.coordinate.ecosystem, right.coordinate.ecosystem) ||
          compareText(left.coordinate.packageName, right.coordinate.packageName) ||
          compareText(
            left.coordinate.installedVersion,
            right.coordinate.installedVersion,
          ) ||
          compareText(left.advisoryId, right.advisoryId),
      ),
  );
}

/** Builds a validated source envelope; it performs no provider I/O. */
export function osvVulnerabilitiesToSourceResult(
  vulnerabilities: readonly Vulnerability[],
  options: OsvSourceResultOptions,
): IntelligenceSourceResult {
  const observations = osvVulnerabilitiesToObservations(vulnerabilities);
  const errors = Object.freeze(
    (options.errors ?? []).map((entry) =>
      Object.freeze({ code: entry.code, message: entry.message }),
    ),
  );
  const result: IntelligenceSourceResult = Object.freeze({
    source: "OSV",
    status: options.status ?? "available",
    freshness: options.freshness,
    ...(options.retrievedAt === undefined
      ? {}
      : { retrievedAt: options.retrievedAt }),
    observations,
    errors,
  });
  assertIntelligenceSourceResult(result);
  return result;
}
