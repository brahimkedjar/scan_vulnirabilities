export const PACKAGE_MANAGER_IDS = [
  "npm",
  "yarn",
  "pnpm",
  "bun",
  "pip",
  "poetry",
  "pipenv",
  "maven",
  "gradle",
  "nuget",
  "cargo",
  "go",
  "composer",
] as const;

export type PackageManagerId = (typeof PACKAGE_MANAGER_IDS)[number];

export interface DetectedPackageManager {
  readonly id: PackageManagerId;
  readonly displayName: string;
  readonly evidence: readonly string[];
  readonly inferred: boolean;
}

export interface PackageManagerHint {
  readonly source: string;
  readonly value: string;
}

export interface WorkspaceDiscoveryResult {
  readonly workspaceName: string;
  readonly workspaceLocation: string;
  readonly dependencyFiles: readonly string[];
  readonly packageManagers: readonly DetectedPackageManager[];
  readonly unsupportedPackageManagerHints: readonly string[];
  readonly truncated: boolean;
}

export interface WorkspaceScanOutcome {
  readonly results: readonly WorkspaceDiscoveryResult[];
  readonly failedWorkspaceCount: number;
  readonly cancelled: boolean;
}
