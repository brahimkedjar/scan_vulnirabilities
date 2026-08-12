export type DependencyType = "direct" | "transitive";

export type DependencyEnvironment =
  | "production"
  | "development"
  | "optional"
  | "peer";

export type DependencyResolutionStatus =
  | "resolved"
  | "unresolved"
  | "unsupported";

export type DependencyMetadataValue =
  | string
  | number
  | boolean
  | null
  | readonly string[];

export interface Dependency {
  readonly name: string;
  readonly ecosystem: string;
  readonly requestedVersion?: string;
  /** Dependency key as declared in the owning manifest (differs for npm aliases). */
  readonly manifestName?: string;
  readonly installedVersion: string;
  /**
   * Missing on Phase 1-3 records, where a non-empty installedVersion implies
   * resolved. New adapters set this explicitly. Unresolved records always use
   * an empty installedVersion and are never submitted to a provider.
   */
  readonly resolutionStatus?: DependencyResolutionStatus;
  readonly dependencyType: DependencyType;
  readonly environment: DependencyEnvironment;
  /** Owning manifest section for direct dependencies, when it differs from runtime exposure. */
  readonly declaredEnvironment?: DependencyEnvironment;
  readonly parent?: string;
  readonly dependencyPath?: string[];
  /** Ecosystem-independent source manifest location. */
  readonly manifestPath?: string;
  /** @deprecated Phase 1-3 compatibility alias for manifestPath. */
  readonly packageJsonPath?: string;
  readonly lockfilePath?: string;
  readonly packageManager?: string;
  /** Root of the independently detected dependency project. */
  readonly projectPath?: string;
  /** Owning VS Code workspace folder. */
  readonly workspacePath?: string;
  readonly metadata?: Readonly<Record<string, DependencyMetadataValue>>;
}

export function dependencyManifestPath(
  dependency: Dependency,
): string | undefined {
  return dependency.manifestPath ?? dependency.packageJsonPath;
}

export function dependencyIsResolved(dependency: Dependency): boolean {
  return (
    dependency.resolutionStatus !== "unresolved" &&
    dependency.resolutionStatus !== "unsupported" &&
    dependency.installedVersion.length > 0
  );
}
