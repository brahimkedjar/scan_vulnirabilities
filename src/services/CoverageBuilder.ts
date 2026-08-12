import type { Dependency } from "../models/Dependency";
import type {
  EcosystemCoverage,
  ProjectCoverage,
} from "../models/ScanResult";
import { mapDependencyToOsv } from "../vulnerability/EcosystemMapper";
import type { DependencyAuditResult } from "./DependencyAuditService";

function subjectKey(
  ecosystem: string,
  packageName: string,
  version: string,
): string {
  return JSON.stringify([ecosystem, packageName, version]);
}

/**
 * Reconciles adapter record coverage with provider subjects. Adapter totals
 * are retained when the scan-wide record cap omits dependency objects, while
 * a checked provider subject covers each retained project occurrence of that
 * exact identity.
 */
export function buildCoverage(
  adapterCoverage: readonly ProjectCoverage[],
  dependencies: readonly Dependency[],
  audit: DependencyAuditResult,
): {
  readonly projects: readonly ProjectCoverage[];
  readonly ecosystems: readonly EcosystemCoverage[];
} {
  const checkedSubjects = new Set(
    audit.subjectResults
      .filter((subject) => subject.checked)
      .map((subject) =>
        subjectKey(subject.ecosystem, subject.packageName, subject.version),
      ),
  );
  const vulnerableSubjects = new Set(
    audit.vulnerabilities.map((vulnerability) =>
      subjectKey(
        vulnerability.ecosystem,
        vulnerability.packageName,
        vulnerability.installedVersion,
      ),
    ),
  );
  const projects = adapterCoverage.map((coverage) => {
    const projectDependencies = dependencies.filter(
      (dependency) =>
        dependency.ecosystem === coverage.ecosystem &&
        (dependency.packageManager === undefined ||
          coverage.packageManagers.includes(dependency.packageManager)) &&
        (dependency.projectPath ?? dependency.workspacePath) ===
          coverage.projectPath,
    );
    const resolvedSubjectKeys: string[] = [];
    const unresolvedSubjects = new Set<string>();
    const unsupportedSubjects = new Set<string>();
    for (const dependency of projectDependencies) {
      const result = mapDependencyToOsv(dependency);
      if (result.supported) {
        resolvedSubjectKeys.push(
          subjectKey(
            result.identity.ecosystem,
            result.identity.packageName,
            result.identity.version,
          ),
        );
        continue;
      }
      const gapKey = JSON.stringify([
        dependency.ecosystem,
        dependency.name,
        dependency.requestedVersion ?? dependency.installedVersion,
        dependency.manifestPath ?? dependency.packageJsonPath ?? "",
      ]);
      if (
        dependency.resolutionStatus === "unsupported" ||
        result.kind === "ecosystem" ||
        result.kind === "identity"
      ) {
        unsupportedSubjects.add(gapKey);
      } else {
        unresolvedSubjects.add(gapKey);
      }
    }
    const checked = resolvedSubjectKeys.filter((key) =>
      checkedSubjects.has(key),
    ).length;
    const vulnerable = resolvedSubjectKeys.filter((key) =>
      vulnerableSubjects.has(key),
    ).length;
    const resolved = Math.max(coverage.resolved, resolvedSubjectKeys.length);
    const unresolved = Math.max(coverage.unresolved, unresolvedSubjects.size);
    const unsupported = Math.max(coverage.unsupported, unsupportedSubjects.size);
    return {
      ...coverage,
      discovered: Math.max(
        coverage.discovered,
        resolved + unresolved + unsupported,
      ),
      resolved,
      checked,
      vulnerable,
      unresolved,
      unsupported,
    };
  });
  const byEcosystem = new Map<string, EcosystemCoverage>();
  for (const project of projects) {
    const existing = byEcosystem.get(project.ecosystem);
    byEcosystem.set(project.ecosystem, {
      ecosystem: project.ecosystem,
      packageManagers: [
        ...new Set([
          ...(existing?.packageManagers ?? []),
          ...project.packageManagers,
        ]),
      ].sort(),
      discovered: (existing?.discovered ?? 0) + project.discovered,
      resolved: (existing?.resolved ?? 0) + project.resolved,
      checked: (existing?.checked ?? 0) + project.checked,
      vulnerable: (existing?.vulnerable ?? 0) + project.vulnerable,
      unresolved: (existing?.unresolved ?? 0) + project.unresolved,
      unsupported: (existing?.unsupported ?? 0) + project.unsupported,
    });
  }
  return {
    projects,
    ecosystems: [...byEcosystem.values()].sort((left, right) =>
      left.ecosystem.localeCompare(right.ecosystem),
    ),
  };
}
