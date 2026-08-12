import type * as vscode from "vscode";

import type { Dependency } from "../../models/Dependency";
import type { ProjectCoverage, ScanError } from "../../models/ScanResult";
import {
  projectsSelectedForScan,
  type DependencyScanResult,
  type DetectionResult,
  type PackageManagerAdapter,
  type ScanOptions,
} from "../PackageManagerAdapter";
import { missingJavaScriptProjectManifest } from "../JavaScriptProjectProvenance";
import {
  applyWorkspaceRegistryGateToParseResult,
  workspaceRegistryCoverageError,
} from "../npm/NpmRegistryProvenance";
import { discoverWorkspaceRegistrySnapshot } from "../npm/NpmRegistryProvenanceReader";
import {
  coverageFor,
  detectJavaScriptProjects,
  discoverProjectManifests,
  emptyScanResult,
  isCancellation,
  issueToScanError,
  MAX_LOCKFILE_BYTES,
  readBoundedText,
  readManifestInputs,
  throwIfCancelled,
  uriPath,
} from "../yarn/JavaScriptAdapterUtils";
import { parseBunDependencies } from "./BunDependencyParser";

export class BunAdapter implements PackageManagerAdapter {
  public readonly id = "bun";
  public readonly displayName = "Bun";
  public readonly ecosystems = ["npm"] as const;

  public async detect(
    workspaceFolder: vscode.Uri,
    cancellationToken?: vscode.CancellationToken,
  ): Promise<DetectionResult> {
    return detectJavaScriptProjects(
      workspaceFolder,
      this.id,
      "**/{bun.lock,bun.lockb}",
      cancellationToken,
    );
  }

  public async scan(
    workspaceFolder: vscode.Uri,
    options: ScanOptions,
    signal?: AbortSignal,
  ): Promise<DependencyScanResult> {
    const detection =
      options.preDetectedResult ??
      (await this.detect(workspaceFolder, options.cancellationToken));
    if (!detection.detected) {
      return emptyScanResult(this.id, this.displayName, detection.errors, false);
    }
    const dependencies: Dependency[] = [];
    const errors: ScanError[] = [...detection.errors];
    const projectCoverage: ProjectCoverage[] = [];
    try {
      const registrySnapshot = await discoverWorkspaceRegistrySnapshot(
        workspaceFolder,
        signal,
        options.cancellationToken,
      );
      for (const project of projectsSelectedForScan(detection, options)) {
        throwIfCancelled(signal, options.cancellationToken);
        const missingManifest = missingJavaScriptProjectManifest(
          this.id,
          this.displayName,
          workspaceFolder,
          project,
        );
        if (missingManifest !== undefined) {
          errors.push(missingManifest.error);
          projectCoverage.push(missingManifest.coverage);
          continue;
        }
        const textLock = project.lockfileUris.find((uri) =>
          uri.path.endsWith("/bun.lock"),
        );
        if (textLock === undefined) {
          const binaryLock = project.lockfileUris.find((uri) =>
            uri.path.endsWith("/bun.lockb"),
          );
          errors.push({
            code: "UNSUPPORTED_LOCKFILE",
            message:
              "bun.lockb detected but resolved dependency extraction is unavailable.",
            path: binaryLock === undefined
              ? uriPath(project.rootUri)
              : uriPath(binaryLock),
          });
          projectCoverage.push({
            ecosystem: "npm",
            packageManagers: [this.id],
            discovered: 0,
            resolved: 0,
            checked: 0,
            vulnerable: 0,
            unresolved: 0,
            unsupported: 0,
            workspacePath: uriPath(workspaceFolder),
            projectPath: uriPath(project.rootUri),
            manifestPaths: project.manifestUris.map(uriPath),
          });
          continue;
        }
        try {
          const manifestUris = await discoverProjectManifests(
            project,
            detection.projects,
            signal,
            options.cancellationToken,
          );
          const manifests = await readManifestInputs(
            project,
            manifestUris,
            signal,
            options.cancellationToken,
          );
          const parsed = parseBunDependencies({
            lockfile: await readBoundedText(
              textLock,
              MAX_LOCKFILE_BYTES,
              signal,
              options.cancellationToken,
            ),
            lockfilePath: uriPath(textLock),
            projectPath: uriPath(project.rootUri),
            workspacePath: uriPath(workspaceFolder),
            manifests,
            options,
            ...(signal === undefined ? {} : { signal }),
          });
          const projectPath = uriPath(project.rootUri);
          const registryGate = applyWorkspaceRegistryGateToParseResult(
            parsed,
            registrySnapshot,
            projectPath,
          );
          const result = registryGate.result;
          dependencies.push(...result.dependencies);
          errors.push(
            ...result.issues.map((issue) =>
              issueToScanError(issue, uriPath(textLock)),
            ),
          );
          if (registryGate.affectedCount > 0) {
            errors.push(
              workspaceRegistryCoverageError(
                registryGate.affectedCount,
                projectPath,
              ),
            );
          }
          projectCoverage.push(
            coverageFor(
              uriPath(workspaceFolder),
              projectPath,
              manifests.map((manifest) => manifest.path),
              this.id,
              result,
            ),
          );
          if (result.cancelled) {
            return this.result(dependencies, errors, projectCoverage, true);
          }
        } catch (error: unknown) {
          if (isCancellation(error)) {
            throw error;
          }
          errors.push({
            code: error instanceof RangeError ? "DEPENDENCY_LIMIT" : "INVALID_LOCKFILE",
            message:
              error instanceof RangeError
                ? error.message
                : "Could not read Bun dependency metadata",
            path: uriPath(textLock),
          });
          projectCoverage.push({
            ecosystem: "npm",
            packageManagers: [this.id],
            discovered: 0,
            resolved: 0,
            checked: 0,
            vulnerable: 0,
            unresolved: 0,
            unsupported: 0,
            workspacePath: uriPath(workspaceFolder),
            projectPath: uriPath(project.rootUri),
            manifestPaths: project.manifestUris.map(uriPath),
          });
        }
      }
    } catch (error: unknown) {
      if (!isCancellation(error)) {
        throw error;
      }
      return this.result(dependencies, errors, projectCoverage, true);
    }
    return this.result(dependencies, errors, projectCoverage, false);
  }

  private result(
    dependencies: readonly Dependency[],
    errors: readonly ScanError[],
    projectCoverage: readonly ProjectCoverage[],
    cancelled: boolean,
  ): DependencyScanResult {
    return {
      adapterId: this.id,
      displayName: this.displayName,
      ecosystems: this.ecosystems,
      dependencies,
      errors,
      projectCoverage,
      cancelled,
    };
  }
}
