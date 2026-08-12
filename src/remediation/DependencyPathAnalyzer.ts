import {
  dependencyManifestPath,
  type Dependency,
} from "../models/Dependency";

export interface DependencyPathAnalysis {
  readonly dependencyPath: readonly string[];
  readonly direct: boolean;
  readonly directParent?: Dependency;
  readonly parentProven: boolean;
}

function originValue(value: string | undefined): string {
  return value ?? "";
}

export function dependencyOccurrenceKey(dependency: Dependency): string {
  return JSON.stringify([
    originValue(dependency.workspacePath),
    originValue(dependency.projectPath),
    originValue(dependencyManifestPath(dependency)),
    originValue(dependency.lockfilePath),
    originValue(dependency.packageManager),
    dependency.ecosystem,
    dependency.name,
    originValue(dependency.manifestName),
    originValue(dependency.requestedVersion),
    dependency.installedVersion,
    dependency.resolutionStatus ?? "resolved",
    dependency.dependencyType,
    dependency.environment,
    originValue(dependency.declaredEnvironment),
    originValue(dependency.parent),
    dependency.dependencyPath ?? [],
  ]);
}

function sameOrigin(left: Dependency, right: Dependency): boolean {
  const leftManifest = dependencyManifestPath(left);
  const rightManifest = dependencyManifestPath(right);
  const hasExactStableOrigin =
    (leftManifest !== undefined &&
      leftManifest.length > 0 &&
      leftManifest === rightManifest) ||
    (left.projectPath !== undefined &&
      left.projectPath.length > 0 &&
      left.projectPath === right.projectPath) ||
    (left.lockfilePath !== undefined &&
      left.lockfilePath.length > 0 &&
      left.lockfilePath === right.lockfilePath);
  return (
    hasExactStableOrigin &&
    originValue(left.workspacePath) === originValue(right.workspacePath) &&
    originValue(left.projectPath) === originValue(right.projectPath) &&
    originValue(leftManifest) === originValue(rightManifest) &&
    originValue(left.lockfilePath) === originValue(right.lockfilePath) &&
    originValue(left.packageManager) === originValue(right.packageManager)
  );
}

function isStrictPathPrefix(
  prefix: readonly string[] | undefined,
  path: readonly string[],
): boolean {
  return (
    prefix !== undefined &&
    prefix.length > 0 &&
    prefix.length < path.length &&
    prefix.every((segment, index) => segment === path[index])
  );
}

/**
 * Establishes a transitive remediation point only from an exact stored path
 * prefix belonging to a direct dependency in the same manifest/project
 * origin. It never guesses a parent from a display segment alone.
 */
export function analyzeDependencyPath(
  dependency: Dependency,
  allDependencies: readonly Dependency[],
): DependencyPathAnalysis {
  const dependencyPath = Object.freeze([...(dependency.dependencyPath ?? [])]);
  if (dependency.dependencyType === "direct") {
    return { dependencyPath, direct: true, parentProven: false };
  }
  if (dependencyPath.length === 0) {
    return { dependencyPath, direct: false, parentProven: false };
  }

  const candidates = new Map<string, Dependency>();
  let longestPrefix = 0;
  for (const candidate of allDependencies) {
    if (
      candidate.dependencyType !== "direct" ||
      !sameOrigin(dependency, candidate) ||
      !isStrictPathPrefix(candidate.dependencyPath, dependencyPath)
    ) {
      continue;
    }
    const prefixLength = candidate.dependencyPath?.length ?? 0;
    if (prefixLength < longestPrefix) {
      continue;
    }
    if (prefixLength > longestPrefix) {
      longestPrefix = prefixLength;
      candidates.clear();
    }
    candidates.set(dependencyOccurrenceKey(candidate), candidate);
  }
  if (candidates.size !== 1) {
    return { dependencyPath, direct: false, parentProven: false };
  }
  const directParent = candidates.values().next().value as Dependency | undefined;
  if (directParent === undefined) {
    return { dependencyPath, direct: false, parentProven: false };
  }
  return {
    dependencyPath,
    direct: false,
    directParent,
    parentProven: true,
  };
}
