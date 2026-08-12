import type * as vscode from "vscode";

import type { Dependency } from "../models/Dependency";
import type { ProjectCoverage, ScanError } from "../models/ScanResult";

export interface DetectedDependencyProject {
  readonly id: string;
  readonly rootUri: vscode.Uri;
  readonly manifestUris: readonly vscode.Uri[];
  readonly lockfileUris: readonly vscode.Uri[];
}

export interface DetectionResult {
  readonly detected: boolean;
  readonly projects: readonly DetectedDependencyProject[];
  readonly errors: readonly ScanError[];
  readonly truncated: boolean;
}

export interface ScanOptions {
  readonly includeDevDependencies: boolean;
  readonly includeTransitiveDependencies: boolean;
  readonly cancellationToken?: vscode.CancellationToken;
  /** Detection already completed by the workspace orchestrator. */
  readonly preDetectedResult?: DetectionResult;
  /**
   * One project selected for this bounded work unit. The full detection result
   * remains available so adapters can preserve nested-lock and workspace
   * ownership context without rescanning sibling projects.
   */
  readonly targetProject?: DetectedDependencyProject;
}

export function projectsSelectedForScan(
  detection: DetectionResult,
  options: ScanOptions,
): readonly DetectedDependencyProject[] {
  const target = options.targetProject;
  if (target === undefined) {
    return detection.projects;
  }
  const selected = detection.projects.find(
    (project) =>
      project === target ||
      (project.id === target.id &&
        project.rootUri.toString() === target.rootUri.toString()),
  );
  return selected === undefined ? [] : [selected];
}

export interface DependencyScanResult {
  readonly adapterId: string;
  readonly displayName: string;
  readonly ecosystems: readonly string[];
  readonly dependencies: readonly Dependency[];
  readonly errors: readonly ScanError[];
  readonly projectCoverage: readonly ProjectCoverage[];
  readonly cancelled: boolean;
}

/**
 * Static package metadata adapter. Implementations may read workspace files,
 * but must never execute project code, package managers, or build tools and
 * must never call vulnerability providers directly.
 */
export interface PackageManagerAdapter {
  readonly id: string;
  readonly displayName: string;
  readonly ecosystems: readonly string[];

  detect(
    workspaceFolder: vscode.Uri,
    cancellationToken?: vscode.CancellationToken,
  ): Promise<DetectionResult>;

  scan(
    workspaceFolder: vscode.Uri,
    options: ScanOptions,
    signal?: AbortSignal,
  ): Promise<DependencyScanResult>;
}
