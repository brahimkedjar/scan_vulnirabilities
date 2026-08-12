import * as vscode from "vscode";

import { dependencyManifestPath } from "../models/Dependency";
import type { ScanResult } from "../models/ScanResult";
import {
  buildDependencyDiagnosticPlans,
  buildRetainedDependencyDiagnosticPlans,
  type DependencyDiagnosticPlan,
  type DiagnosticLevel,
} from "./diagnosticModels";
import type { RetainedVulnerabilityFinding } from "../services/ScanResultStore";
import type { RemediationAnalysisResult } from "../remediation/RemediationModels";
import { findManifestDependencyOffsets } from "./manifestDependencyLocator";

const MAX_DIAGNOSTICS = 2_000;
const MAX_DIAGNOSTIC_DOCUMENTS = 256;
const MAX_DIAGNOSTIC_DOCUMENT_CHARACTERS = 2 * 1024 * 1024;
const MAX_TOTAL_DIAGNOSTIC_DOCUMENT_CHARACTERS = 16 * 1024 * 1024;

interface DocumentPlanGroup {
  readonly uri: vscode.Uri;
  readonly plans: DependencyDiagnosticPlan[];
}

function isAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
}

function diagnosticSeverity(level: DiagnosticLevel): vscode.DiagnosticSeverity {
  switch (level) {
    case "error":
      return vscode.DiagnosticSeverity.Error;
    case "warning":
      return vscode.DiagnosticSeverity.Warning;
    case "information":
      return vscode.DiagnosticSeverity.Information;
  }
}

function pathToUri(filePath: string): vscode.Uri {
  const isWindowsDrivePath = /^[A-Za-z]:[\\/]/u.test(filePath);
  return !isWindowsDrivePath && /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(filePath)
    ? vscode.Uri.parse(filePath, true)
    : vscode.Uri.file(filePath);
}

export class DiagnosticManager implements vscode.Disposable {
  private publishedUris = new Map<string, vscode.Uri>();

  public constructor(
    private readonly collection: vscode.DiagnosticCollection,
  ) {}

  public async replace(
    scanResults: readonly ScanResult[],
    signal?: AbortSignal,
    retainedFindings: readonly RetainedVulnerabilityFinding[] = [],
    remediationAnalysis?: RemediationAnalysisResult,
  ): Promise<boolean> {
    const entries = new Map<string, { uri: vscode.Uri; diagnostics: vscode.Diagnostic[] }>();
    const currentPlans = buildDependencyDiagnosticPlans(
      scanResults,
      MAX_DIAGNOSTICS,
      remediationAnalysis,
    );
    const plans = [
      ...currentPlans,
      ...buildRetainedDependencyDiagnosticPlans(
        retainedFindings,
        MAX_DIAGNOSTICS - currentPlans.length,
      ),
    ];
    const groups = new Map<string, DocumentPlanGroup>();

    for (const plan of plans) {
      if (isAborted(signal)) {
        return false;
      }
      try {
        const manifestPath = dependencyManifestPath(plan.targetDependency);
        if (manifestPath === undefined || manifestPath.length === 0) {
          continue;
        }
        const uri = pathToUri(manifestPath);
        const key = uri.toString();
        const group = groups.get(key);
        if (group === undefined) {
          groups.set(key, { uri, plans: [plan] });
        } else {
          group.plans.push(plan);
        }
      } catch {
        // A malformed source URI is not a safe diagnostic location.
      }
    }

    let attemptedDocuments = 0;
    let processedCharacters = 0;
    for (const group of groups.values()) {
      if (
        isAborted(signal) ||
        attemptedDocuments >= MAX_DIAGNOSTIC_DOCUMENTS ||
        processedCharacters >= MAX_TOTAL_DIAGNOSTIC_DOCUMENT_CHARACTERS
      ) {
        if (isAborted(signal)) {
          return false;
        }
        break;
      }
      attemptedDocuments += 1;
      try {
        const budgetBeforeDocument = processedCharacters;
        const remainingDocumentBudget =
          MAX_TOTAL_DIAGNOSTIC_DOCUMENT_CHARACTERS - budgetBeforeDocument;
        const stat = await vscode.workspace.fs.stat(group.uri);
        if (isAborted(signal)) {
          return false;
        }
        const statSize = stat.size;
        if (
          !Number.isSafeInteger(statSize) ||
          statSize < 0
        ) {
          continue;
        }

        // FileStat.size is a byte count. Charging it before opening is a
        // conservative reservation against the character budget and prevents
        // an attacker from making VS Code load many oversized manifests only
        // for the post-open check to reject them. Stat failures are handled by
        // the surrounding best-effort catch and never fall through to open.
        processedCharacters =
          budgetBeforeDocument +
          Math.min(statSize, remainingDocumentBudget);
        if (
          statSize > MAX_DIAGNOSTIC_DOCUMENT_CHARACTERS ||
          statSize > remainingDocumentBudget
        ) {
          continue;
        }

        const document = await vscode.workspace.openTextDocument(group.uri);
        if (isAborted(signal)) {
          return false;
        }
        const documentCharacters = document.offsetAt(
          new vscode.Position(document.lineCount, 0),
        );
        if (
          !Number.isSafeInteger(documentCharacters) ||
          documentCharacters < 0
        ) {
          continue;
        }
        const chargedDocumentSize = Math.max(statSize, documentCharacters);
        processedCharacters =
          budgetBeforeDocument +
          Math.min(chargedDocumentSize, remainingDocumentBudget);
        if (
          documentCharacters > MAX_DIAGNOSTIC_DOCUMENT_CHARACTERS ||
          chargedDocumentSize > remainingDocumentBudget
        ) {
          continue;
        }
        const offsets = findManifestDependencyOffsets(
          document.getText(),
          group.uri.path,
          group.plans.map((plan) => plan.targetDependency),
        );

        for (const plan of group.plans) {
          if (isAborted(signal)) {
            return false;
          }
          const dependency = plan.targetDependency;
          const manifestName = dependency.manifestName ?? dependency.name;
          const offset = offsets.get(manifestName);
          if (offset === undefined) {
            continue;
          }
          const start = document.positionAt(offset);
          const end = document.positionAt(offset + manifestName.length);
          const range = new vscode.Range(start, end);
          const diagnostic = new vscode.Diagnostic(
            range,
            plan.message,
            diagnosticSeverity(plan.level),
          );
          diagnostic.code = plan.identifier;
          diagnostic.source = "Dependency Vulnerability Auditor";
          if (plan.dependencyPath !== undefined) {
            diagnostic.relatedInformation = [
              new vscode.DiagnosticRelatedInformation(
                new vscode.Location(group.uri, range),
                `Dependency path: ${plan.dependencyPath}`,
              ),
            ];
          }
          let entry = entries.get(group.uri.toString());
          if (entry === undefined) {
            entry = { uri: group.uri, diagnostics: [] };
            entries.set(group.uri.toString(), entry);
          }
          entry.diagnostics.push(diagnostic);
        }
      } catch {
        // Diagnostics are best-effort; scan coverage remains in the result/output.
      }
    }

    if (isAborted(signal)) {
      return false;
    }
    const nextUris = new Map(
      [...entries.values()].map((entry) => [entry.uri.toString(), entry.uri]),
    );
    const updates: Array<
      [vscode.Uri, readonly vscode.Diagnostic[] | undefined]
    > = [...entries.values()].map((entry) => [entry.uri, entry.diagnostics]);
    for (const [key, uri] of this.publishedUris) {
      if (!nextUris.has(key)) {
        updates.push([uri, undefined]);
      }
    }
    this.collection.set(updates);
    this.publishedUris = nextUris;
    return true;
  }

  public clear(): void {
    this.collection.clear();
    this.publishedUris.clear();
  }

  public dispose(): void {
    this.publishedUris.clear();
    this.collection.dispose();
  }
}
