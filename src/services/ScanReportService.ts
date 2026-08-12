import type { ScanResult } from "../models/ScanResult";
import type { Severity, Vulnerability } from "../models/Vulnerability";
import type { Logger } from "./Logger";

const SEVERITY_ORDER: readonly Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "UNKNOWN",
];
const MAX_REPORTED_VULNERABILITIES = 500;

function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

function preferredIdentifier(vulnerability: Vulnerability): string {
  return (
    vulnerability.aliases.find((alias) => alias.startsWith("CVE-")) ??
    vulnerability.aliases.find((alias) => alias.startsWith("GHSA-")) ??
    vulnerability.id
  );
}

function privacySafePath(path: string): string {
  if (!/^[A-Za-z][A-Za-z0-9+.-]*:\/\//u.test(path)) {
    return path;
  }
  try {
    const uri = new URL(path);
    return `${uri.protocol.slice(0, -1)}:${uri.pathname}`;
  } catch {
    return "remote:unavailable";
  }
}

export class ScanReportService {
  public constructor(private readonly logger: Logger) {}

  public log(result: ScanResult): void {
    const providerVulnerabilityCount = result.providerResults.reduce(
      (total, provider) => total + provider.vulnerabilitiesFound,
      0,
    );
    const suppressedVulnerabilityCount = Math.max(
      0,
      providerVulnerabilityCount - result.vulnerabilities.length,
    );
    this.logger.info("========================================");
    this.logger.info("Dependency Vulnerability Auditor");
    this.logger.info("========================================");
    this.logger.info(`Workspace: ${result.workspacePath}`);
    this.logger.info(
      `Package manager: ${result.packageManagers.length === 0 ? "none" : result.packageManagers.join(", ")}`,
    );
    this.logger.info(
      `Dependencies scanned: ${result.dependenciesScanned.toString()}`,
    );
    this.logger.info(
      `Vulnerable dependencies: ${result.vulnerableDependencies.toString()}`,
    );
    this.logger.info(
      `Displayed vulnerabilities: ${result.vulnerabilities.length.toString()}`,
    );
    if ((result.ecosystemCoverage?.length ?? 0) > 0) {
      this.logger.info("Dependency coverage by ecosystem:");
      for (const coverage of result.ecosystemCoverage ?? []) {
        this.logger.info(
          `${coverage.ecosystem}: discovered=${coverage.discovered.toString()}, resolved=${coverage.resolved.toString()}, checked=${coverage.checked.toString()}, vulnerable=${coverage.vulnerable.toString()}, unresolved=${coverage.unresolved.toString()}, unsupported=${coverage.unsupported.toString()}`,
        );
      }
    }
    if (suppressedVulnerabilityCount > 0) {
      this.logger.info(
        `Known vulnerabilities hidden by severity filter: ${suppressedVulnerabilityCount.toString()}`,
      );
    }

    for (const severity of SEVERITY_ORDER) {
      const count = result.vulnerabilities.filter(
        (vulnerability) => vulnerability.severity === severity,
      ).length;
      this.logger.info(`${severity}: ${count.toString()}`);
    }

    this.logger.info("----------------------------------------");
    this.logger.info("Vulnerabilities");
    this.logger.info("----------------------------------------");

    const vulnerabilities = [...result.vulnerabilities].sort((left, right) => {
      const severityDifference =
        severityRank(left.severity) - severityRank(right.severity);
      if (severityDifference !== 0) {
        return severityDifference;
      }
      return `${left.packageName}:${left.id}`.localeCompare(
        `${right.packageName}:${right.id}`,
      );
    });

    for (const vulnerability of vulnerabilities.slice(
      0,
      MAX_REPORTED_VULNERABILITIES,
    )) {
      this.logger.info(`[${vulnerability.severity}]`);
      this.logger.info(`Package: ${vulnerability.packageName}`);
      this.logger.info(`Ecosystem: ${vulnerability.ecosystem}`);
      this.logger.info(`Version: ${vulnerability.installedVersion}`);
      this.logger.info(`ID: ${preferredIdentifier(vulnerability)}`);
      this.logger.info(`Source: ${vulnerability.source}`);
      this.logger.info(
        `Fixed: ${vulnerability.fixedVersion ?? "No known fixed version"}`,
      );
      const dependency = result.dependencies
        .filter(
          (candidate) =>
            candidate.ecosystem === vulnerability.ecosystem &&
            candidate.name === vulnerability.packageName &&
            candidate.installedVersion === vulnerability.installedVersion,
        )
        .sort(
          (left, right) =>
            (left.dependencyPath?.length ?? Number.MAX_SAFE_INTEGER) -
            (right.dependencyPath?.length ?? Number.MAX_SAFE_INTEGER),
        )[0];
      if (dependency?.dependencyPath !== undefined) {
        this.logger.info(`Dependency path: ${dependency.dependencyPath.join(" -> ")}`);
      }
      if (dependency !== undefined) {
        this.logger.info(`Type: ${dependency.dependencyType}`);
        this.logger.info(`Environment: ${dependency.environment}`);
        if (
          dependency.declaredEnvironment !== undefined &&
          dependency.declaredEnvironment !== dependency.environment
        ) {
          this.logger.info(
            `Declared environment: ${dependency.declaredEnvironment}`,
          );
        }
      }
      this.logger.info("");
    }

    if (vulnerabilities.length > MAX_REPORTED_VULNERABILITIES) {
      this.logger.warn(
        `${(vulnerabilities.length - MAX_REPORTED_VULNERABILITIES).toString()} additional vulnerabilities were omitted from the Output Channel`,
      );
    }

    this.logger.info("Vulnerability database coverage:");
    for (const provider of result.providerResults) {
      this.logger.info(`Provider: ${provider.provider}`);
      this.logger.info(`Status: ${provider.status}`);
      this.logger.info(
        `Dependencies eligible: ${provider.dependenciesEligible.toString()}`,
      );
      this.logger.info(
        `Dependencies submitted: ${provider.dependenciesSubmitted.toString()}`,
      );
      this.logger.info(`Successful: ${provider.successful.toString()}`);
      this.logger.info(`Failed: ${provider.failed.toString()}`);
      this.logger.info(`Cache hits: ${provider.cacheHits.toString()}`);
      this.logger.info(
        `Stale cache fallbacks: ${provider.staleCacheFallbacks.toString()}`,
      );
      this.logger.info(
        `Vulnerabilities found: ${provider.vulnerabilitiesFound.toString()}`,
      );
    }

    if (result.errors.length > 0) {
      this.logger.warn(`Scan errors: ${result.errors.length.toString()}`);
      for (const error of result.errors.slice(0, 50)) {
        const context = [
          error.provider === undefined ? undefined : `provider=${error.provider}`,
          error.packageName === undefined
            ? undefined
            : `package=${error.packageName}`,
          error.path === undefined
            ? undefined
            : `path=${privacySafePath(error.path)}`,
        ].filter((value): value is string => value !== undefined);
        this.logger.warn(
          `[${error.code}] ${error.message}${context.length === 0 ? "" : ` (${context.join(", ")})`}`,
        );
      }
    }
    this.logger.info("========================================");
  }
}
