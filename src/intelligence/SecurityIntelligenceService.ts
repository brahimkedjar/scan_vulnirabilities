import type { Vulnerability } from "../models/Vulnerability";
import type { PolicyFindingIntelligence } from "../policy/PolicyModels";
import {
  assessCisaKev,
  type CisaKevAssessment,
  type CisaKevSourceResult,
} from "./enrichment";
import type { VulnerabilityIntelligenceResult } from "./IntelligenceModels";
import { osvVulnerabilitiesToSourceResult } from "./OsvObservationAdapter";
import {
  SecurityRiskAnalyzer,
  type SecurityRiskScore,
} from "./SecurityRiskAnalyzer";
import { aggregateVulnerabilityIntelligence } from "./VulnerabilityIntelligenceAggregator";

const HARD_MAXIMUM_FINDINGS = 50_000;
const HARD_MAXIMUM_POLICY_IDENTITIES = 50_000;

export interface CisaKevSourceLoader {
  load(signal?: AbortSignal): Promise<CisaKevSourceResult>;
}

export interface FindingSecurityIntelligence {
  readonly advisoryId: string;
  readonly ecosystem: string;
  readonly packageName: string;
  readonly installedVersion: string;
  readonly knownExploitation: CisaKevAssessment;
  readonly risk: SecurityRiskScore;
}

export interface SecurityIntelligenceSnapshot {
  readonly generatedAt: string;
  readonly source: Readonly<{
    name: "CISA KEV";
    status: CisaKevSourceResult["status"];
    fetchedAt?: string;
    errorCode?: CisaKevSourceResult["errorCode"];
  }>;
  readonly intelligence: VulnerabilityIntelligenceResult;
  readonly findings: readonly FindingSecurityIntelligence[];
  readonly policyFindings: readonly PolicyFindingIntelligence[];
  readonly complete: boolean;
}

export interface SecurityIntelligenceServiceOptions {
  readonly clock?: () => number;
  readonly maximumFindings?: number;
  readonly maximumPolicyIdentities?: number;
}

export type SecurityIntelligenceErrorCode = "CANCELLED" | "LIMIT_EXCEEDED";

export class SecurityIntelligenceError extends Error {
  public constructor(
    public readonly code: SecurityIntelligenceErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "SecurityIntelligenceError";
  }
}

function boundedMaximumFindings(value: number | undefined): number {
  const selected = value ?? HARD_MAXIMUM_FINDINGS;
  if (
    !Number.isSafeInteger(selected) ||
    selected < 1 ||
    selected > HARD_MAXIMUM_FINDINGS
  ) {
    throw new RangeError(
      `maximumFindings must be between 1 and ${HARD_MAXIMUM_FINDINGS.toString()}`,
    );
  }
  return selected;
}

function boundedMaximumPolicyIdentities(value: number | undefined): number {
  const selected = value ?? HARD_MAXIMUM_POLICY_IDENTITIES;
  if (
    !Number.isSafeInteger(selected) ||
    selected < 1 ||
    selected > HARD_MAXIMUM_POLICY_IDENTITIES
  ) {
    throw new RangeError(
      `maximumPolicyIdentities must be between 1 and ${HARD_MAXIMUM_POLICY_IDENTITIES.toString()}`,
    );
  }
  return selected;
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw new SecurityIntelligenceError(
      "CANCELLED",
      "Security intelligence analysis was cancelled",
    );
  }
}

function compareFinding(
  left: FindingSecurityIntelligence,
  right: FindingSecurityIntelligence,
): number {
  return JSON.stringify([
    left.ecosystem,
    left.packageName,
    left.installedVersion,
    left.advisoryId,
  ]).localeCompare(
    JSON.stringify([
      right.ecosystem,
      right.packageName,
      right.installedVersion,
      right.advisoryId,
    ]),
    "en",
  );
}

function policyStatus(
  assessment: CisaKevAssessment,
): PolicyFindingIntelligence["knownExploitation"] {
  switch (assessment.status) {
    case "KNOWN_EXPLOITED":
      return "known-exploited";
    case "NOT_LISTED":
      return "not-known-exploited";
    case "UNKNOWN":
      return "unknown";
  }
}

function currentCveAliases(vulnerability: Vulnerability): readonly string[] {
  return [vulnerability.id, ...vulnerability.aliases]
    .map((identifier) => identifier.trim().toUpperCase())
    .filter((identifier) => /^CVE-(?:19|20)\d{2}-\d{4,19}$/u.test(identifier));
}

function policyAdvisoryIds(vulnerability: Vulnerability): ReadonlySet<string> {
  return new Set([
    vulnerability.id,
    ...vulnerability.aliases,
    ...currentCveAliases(vulnerability),
  ]);
}

/**
 * Joins normalized advisory evidence with the public CISA KEV catalog. It
 * performs no package lookup and sends no workspace/package data to CISA.
 */
export class SecurityIntelligenceService {
  private readonly clock: () => number;
  private readonly maximumFindings: number;
  private readonly maximumPolicyIdentities: number;
  private readonly riskAnalyzer: SecurityRiskAnalyzer;

  public constructor(
    private readonly kevSource: CisaKevSourceLoader,
    options: SecurityIntelligenceServiceOptions = {},
  ) {
    this.clock = options.clock ?? Date.now;
    this.maximumFindings = boundedMaximumFindings(options.maximumFindings);
    this.maximumPolicyIdentities = boundedMaximumPolicyIdentities(
      options.maximumPolicyIdentities,
    );
    this.riskAnalyzer = new SecurityRiskAnalyzer();
  }

  public async analyze(
    vulnerabilities: readonly Vulnerability[],
    options: { readonly signal?: AbortSignal } = {},
  ): Promise<SecurityIntelligenceSnapshot> {
    if (vulnerabilities.length > this.maximumFindings) {
      throw new SecurityIntelligenceError(
        "LIMIT_EXCEEDED",
        "Security intelligence input exceeds the configured finding limit",
      );
    }
    let policyIdentityCount = 0;
    for (const vulnerability of vulnerabilities) {
      if (!Array.isArray(vulnerability.aliases)) {
        throw new SecurityIntelligenceError(
          "LIMIT_EXCEEDED",
          "Security intelligence input contains an invalid alias collection",
        );
      }
      policyIdentityCount += policyAdvisoryIds(vulnerability).size;
      if (
        !Number.isSafeInteger(policyIdentityCount) ||
        policyIdentityCount > this.maximumPolicyIdentities
      ) {
        throw new SecurityIntelligenceError(
          "LIMIT_EXCEEDED",
          "Security intelligence policy identity input exceeds the configured limit",
        );
      }
    }
    throwIfAborted(options.signal);
    const now = this.clock();
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new RangeError(
        "Security intelligence clock must return a non-negative safe integer",
      );
    }
    const generatedAt = new Date(now).toISOString();
    const kev = await this.kevSource.load(options.signal);
    throwIfAborted(options.signal);

    const osv = osvVulnerabilitiesToSourceResult(vulnerabilities, {
      freshness: "unknown",
      retrievedAt: generatedAt,
    });
    const intelligence = aggregateVulnerabilityIntelligence([osv], {
      ...(options.signal === undefined ? {} : { signal: options.signal }),
      maximumObservations: this.maximumFindings,
      maximumFindings: this.maximumFindings,
    });

    const findings: FindingSecurityIntelligence[] = [];
    const policyByKey = new Map<string, PolicyFindingIntelligence>();
    for (let index = 0; index < vulnerabilities.length; index += 1) {
      if ((index & 127) === 0) {
        throwIfAborted(options.signal);
      }
      const vulnerability = vulnerabilities[index];
      if (vulnerability === undefined) {
        continue;
      }
      const knownExploitation = assessCisaKev(vulnerability, kev, {
        clock: this.clock,
      });
      const normalizedStatus = policyStatus(knownExploitation);
      const risk = this.riskAnalyzer.analyze(vulnerability, {
        knownExploitation: {
          status: normalizedStatus,
          source: "CISA KEV",
        },
        reachability: { status: "unknown" },
      });
      findings.push(
        Object.freeze({
          advisoryId: vulnerability.id,
          ecosystem: vulnerability.ecosystem,
          packageName: vulnerability.packageName,
          installedVersion: vulnerability.installedVersion,
          knownExploitation,
          risk,
        }),
      );
      // Policy matching accepts either the provider ID or an alias. Emit the
      // same exact assessment for every validated identity so a CVE-based
      // ignore/gate cannot be separated from its OSV/GHSA record.
      for (const advisoryId of policyAdvisoryIds(vulnerability)) {
        const policyFinding: PolicyFindingIntelligence = Object.freeze({
          advisoryId,
          ecosystem: vulnerability.ecosystem,
          packageName: vulnerability.packageName,
          installedVersion: vulnerability.installedVersion,
          knownExploitation: normalizedStatus,
        });
        const policyKey = JSON.stringify([
          policyFinding.advisoryId,
          policyFinding.ecosystem,
          policyFinding.packageName,
          policyFinding.installedVersion,
        ]);
        const previous = policyByKey.get(policyKey);
        if (
          previous === undefined ||
          (previous.knownExploitation !== "known-exploited" &&
            normalizedStatus === "known-exploited")
        ) {
          policyByKey.set(policyKey, policyFinding);
        }
      }
    }
    findings.sort(compareFinding);
    Object.freeze(findings);
    const policyFindings = [...policyByKey.values()].sort((left, right) =>
      JSON.stringify([
        left.ecosystem,
        left.packageName,
        left.installedVersion,
        left.advisoryId,
      ]).localeCompare(
        JSON.stringify([
          right.ecosystem,
          right.packageName,
          right.installedVersion,
          right.advisoryId,
        ]),
        "en",
      ),
    );
    Object.freeze(policyFindings);
    const source = Object.freeze({
      name: "CISA KEV" as const,
      status: kev.status,
      ...(kev.fetchedAt === undefined ? {} : { fetchedAt: kev.fetchedAt }),
      ...(kev.errorCode === undefined ? {} : { errorCode: kev.errorCode }),
    });
    return Object.freeze({
      generatedAt,
      source,
      intelligence,
      findings,
      policyFindings,
      complete:
        kev.status === "available" && intelligence.completeness === "complete",
    });
  }
}
