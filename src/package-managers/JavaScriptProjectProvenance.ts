import type * as vscode from "vscode";

import type { ProjectCoverage, ScanError } from "../models/ScanResult";
import type { DetectedDependencyProject } from "./PackageManagerAdapter";

export interface MissingProjectManifest {
  readonly error: ScanError;
  readonly coverage: ProjectCoverage;
}

function uriPath(uri: vscode.Uri): string {
  return uri.scheme === "file" ? uri.fsPath : uri.toString();
}

export function missingJavaScriptProjectManifest(
  adapterId: string,
  displayName: string,
  workspaceFolder: vscode.Uri,
  project: DetectedDependencyProject,
): MissingProjectManifest | undefined {
  if (project.manifestUris.length > 0) {
    return undefined;
  }
  return {
    error: {
      code: "INVALID_MANIFEST",
      message: `${displayName} lockfile has no discovered package.json manifest`,
      path: uriPath(project.lockfileUris[0] ?? project.rootUri),
    },
    coverage: {
      ecosystem: "npm",
      packageManagers: [adapterId],
      discovered: 0,
      resolved: 0,
      checked: 0,
      vulnerable: 0,
      unresolved: 0,
      unsupported: 0,
      workspacePath: uriPath(workspaceFolder),
      projectPath: uriPath(project.rootUri),
      manifestPaths: [],
    },
  };
}
