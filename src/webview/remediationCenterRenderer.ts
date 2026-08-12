import type { ScanResult } from "../models/ScanResult";
import type {
  RemediationAnalysisResult,
  RemediationRecommendation,
} from "../remediation/RemediationModels";
import { assertWebviewNonce, escapeHtml } from "./webviewSecurity";
import type {
  RemediationApplySnapshot,
  RemediationCapabilityView,
  RemediationLifecycleView,
  RemediationPreviewView,
} from "./webviewTypes";

const MAXIMUM_ROWS = 250;
const MAXIMUM_EVIDENCE = 8;
const MAXIMUM_PREVIEW_FILES = 10;
const MAXIMUM_DIFF_CHARACTERS = 65_536;
const SEVERITY_RANK = Object.freeze({
  UNKNOWN: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
});

export interface RemediationCenterRow {
  readonly rowId: string;
  readonly recommendation: RemediationRecommendation;
  readonly severity: keyof typeof SEVERITY_RANK;
  readonly capability: RemediationCapabilityView;
  readonly lifecycle?: RemediationLifecycleView;
  readonly preview?: RemediationPreviewView;
}

export interface RemediationCenterRenderContext {
  readonly workspaceOpen: boolean;
  readonly rows: readonly RemediationCenterRow[];
  readonly analysisComplete: boolean;
  readonly activeOperation?: RemediationApplySnapshot["activeOperation"];
  readonly productionApplyAvailable: boolean;
}

function maximumSeverity(
  results: readonly ScanResult[],
  recommendation: RemediationRecommendation,
): keyof typeof SEVERITY_RANK {
  let selected: keyof typeof SEVERITY_RANK = "UNKNOWN";
  const ids = new Set(recommendation.vulnerabilityIds);
  for (const result of results) {
    for (const vulnerability of result.vulnerabilities) {
      if (
        ids.has(vulnerability.id) &&
        vulnerability.packageName === recommendation.dependency.name &&
        vulnerability.ecosystem === recommendation.dependency.ecosystem &&
        SEVERITY_RANK[vulnerability.severity] > SEVERITY_RANK[selected]
      ) {
        selected = vulnerability.severity;
      }
    }
  }
  return selected;
}

export function buildRemediationCenterRows(
  results: readonly ScanResult[],
  analysis: RemediationAnalysisResult,
  snapshot: RemediationApplySnapshot,
): readonly RemediationCenterRow[] {
  const capabilities = new Map<string, RemediationCapabilityView>();
  for (const capability of snapshot.capabilities) {
    if (!capabilities.has(capability.recommendationKey)) {
      capabilities.set(capability.recommendationKey, capability);
    } else {
      capabilities.set(capability.recommendationKey, {
        recommendationKey: capability.recommendationKey,
        capability: "unsupported",
        reason: "Conflicting remediation capability records require manual review.",
      });
    }
  }
  const lifecycles = new Map<string, RemediationLifecycleView>();
  for (const lifecycle of snapshot.lifecycles ?? []) {
    if (!lifecycles.has(lifecycle.recommendationKey)) {
      lifecycles.set(lifecycle.recommendationKey, lifecycle);
    }
  }
  return Object.freeze(
    analysis.recommendations.slice(0, MAXIMUM_ROWS).map((recommendation, index) => {
      const capability = capabilities.get(recommendation.recommendationKey) ?? {
        recommendationKey: recommendation.recommendationKey,
        capability: "unsupported" as const,
        reason: "No applicable remediation capability is available.",
      };
      const preview =
        snapshot.preview?.recommendationKey === recommendation.recommendationKey
          ? snapshot.preview
          : undefined;
      const lifecycle = lifecycles.get(recommendation.recommendationKey);
      return Object.freeze({
        rowId: `remediation-${index.toString()}`,
        recommendation,
        severity: maximumSeverity(results, recommendation),
        capability,
        ...(lifecycle === undefined ? {} : { lifecycle }),
        ...(preview === undefined ? {} : { preview }),
      });
    }),
  );
}

function renderButton(
  label: string,
  action: string,
  rowId: string,
  disabled = false,
): string {
  return `<button type="button" data-remediation-center-action="${escapeHtml(action, 32)}" data-row-id="${escapeHtml(rowId, 64)}"${disabled ? " disabled" : ""}>${escapeHtml(label, 64)}</button>`;
}

function renderActions(row: RemediationCenterRow): string {
  const lifecycle = row.lifecycle?.state;
  const preview = row.preview;
  const buttons: string[] = [];
  if (preview === undefined) {
    if (row.capability.capability !== "unsupported") {
      buttons.push(renderButton("View Preview", "preview", row.rowId));
    }
  } else {
    buttons.push(renderButton("Rebuild Preview", "preview", row.rowId));
    for (let index = 0; index < Math.min(preview.files.length, MAXIMUM_PREVIEW_FILES); index += 1) {
      const escapedRowId = escapeHtml(row.rowId, 64);
      const fileIndex = index.toString();
      const label = escapeHtml(preview.files[index]?.displayPath ?? "file", 128);
      buttons.push(
        `<button type="button" data-remediation-center-action="viewDiff" data-row-id="${escapedRowId}" data-file-index="${fileIndex}">Open ${label} Diff</button>`,
      );
      buttons.push(
        `<button type="button" data-remediation-center-action="copyPatch" data-row-id="${escapedRowId}" data-file-index="${fileIndex}">Copy ${label} Patch</button>`,
      );
      buttons.push(
        `<button type="button" data-remediation-center-action="openFile" data-row-id="${escapedRowId}" data-file-index="${fileIndex}">Open ${label}</button>`,
      );
    }
    if (
      lifecycle === "awaitingApproval" &&
      preview.valid &&
      preview.capability === "safe"
    ) {
      buttons.push(renderButton("Approve Fix", "approve", row.rowId));
    }
    if (
      lifecycle === "approved" &&
      preview.valid &&
      preview.capability === "safe"
    ) {
      buttons.push(renderButton("Apply Fix", "apply", row.rowId));
    }
    buttons.push(renderButton("Cancel", "cancel", row.rowId));
  }
  if (
    lifecycle === "stale" ||
    lifecycle === "failed" ||
    lifecycle === "rolledBack" ||
    lifecycle === "manualActionRequired" ||
    lifecycle === "stillVulnerable" ||
    lifecycle === "incompleteCoverage" ||
    lifecycle === "providerUnavailable"
  ) {
    buttons.push(renderButton("Re-scan", "rescan", row.rowId));
  }
  return buttons.length === 0
    ? '<span class="muted">Manual review required.</span>'
    : buttons.join(" ");
}

function renderPreview(preview: RemediationPreviewView | undefined): string {
  if (preview === undefined) return "";
  const files = preview.files.slice(0, MAXIMUM_PREVIEW_FILES).map((file) => {
    const diff = file.unifiedDiff.slice(0, MAXIMUM_DIFF_CHARACTERS);
    return `<section class="file-preview"><h4>${escapeHtml(file.displayPath, 256)}</h4><p>${escapeHtml(file.description, 1_024)}</p><p><code>${escapeHtml(file.beforeHash, 128)}</code> &rarr; <code>${escapeHtml(file.afterHash ?? "not available", 128)}</code></p><p>Git: <strong>${escapeHtml(file.gitState ?? "unavailable", 64)}</strong> (advisory only)</p><pre>${escapeHtml(diff, MAXIMUM_DIFF_CHARACTERS)}</pre></section>`;
  });
  return `<section class="preview"><h3>Remediation Preview</h3><p><strong>This change has NOT been applied.</strong></p>${files.join("")}<ul>${preview.warnings.slice(0, 20).map((warning) => `<li>${escapeHtml(warning, 2_048)}</li>`).join("")}</ul></section>`;
}

function renderTimeline(lifecycle: RemediationLifecycleView | undefined): string {
  if (lifecycle === undefined) {
    return '<p class="muted">No proposal state has been created.</p>';
  }
  return `<ol class="timeline">${lifecycle.transitions.map((transition) => `<li><strong>${escapeHtml(transition.to, 64)}</strong> &mdash; ${escapeHtml(transition.reason, 128)} <time>${escapeHtml(transition.timestamp, 64)}</time>${transition.errorCode === undefined ? "" : ` <code>${escapeHtml(transition.errorCode, 128)}</code>`}</li>`).join("")}</ol>`;
}

function renderRow(row: RemediationCenterRow): string {
  const recommendation = row.recommendation;
  const state = row.lifecycle?.state ?? "preview";
  return `<article class="finding" data-row="${escapeHtml(row.rowId, 64)}">
    <header><span class="severity ${escapeHtml(row.severity.toLowerCase(), 16)}">${escapeHtml(row.severity, 16)}</span> <strong>${escapeHtml(recommendation.dependency.name, 512)}</strong> <code>${escapeHtml(recommendation.currentVersion, 256)}</code></header>
    <p>Proposed target: <strong>${escapeHtml(recommendation.recommendedVersion ?? "No proven target", 256)}</strong></p>
    <p>State: <strong>${escapeHtml(state, 64)}</strong> &middot; Capability: <strong>${escapeHtml(row.capability.capability, 32)}</strong></p>
    <p>${escapeHtml(row.capability.reason, 2_048)}</p>
    <details><summary>View evidence and rationale</summary>
      <dl><dt>Vulnerabilities</dt><dd>${recommendation.vulnerabilityIds.map((id) => `<code>${escapeHtml(id, 512)}</code>`).join(" ")}</dd>
      <dt>Reason</dt><dd>${escapeHtml(recommendation.reason, 4_096)}</dd>
      <dt>Confidence</dt><dd>${escapeHtml(recommendation.confidence, 16)}</dd>
      <dt>Compatibility risk</dt><dd>${escapeHtml(recommendation.breakingChangeRisk, 16)}</dd>
      <dt>Strategy</dt><dd>${escapeHtml(recommendation.strategy, 64)}</dd></dl>
      <ul>${recommendation.evidence.slice(0, MAXIMUM_EVIDENCE).map((evidence) => `<li>${escapeHtml(evidence.source, 32)}: ${escapeHtml(evidence.description, 2_048)}</li>`).join("")}</ul>
    </details>
    <div class="actions">${renderActions(row)}</div>
    ${renderPreview(row.preview)}
    <details><summary>State transition history</summary>${renderTimeline(row.lifecycle)}</details>
  </article>`;
}

export function renderRemediationCenterDocument(
  context: RemediationCenterRenderContext,
  nonce: string,
  scriptUri: string,
): string {
  const safeNonce = assertWebviewNonce(nonce);
  const rows = context.rows.map(renderRow).join("");
  return `<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; frame-src 'none'; style-src 'nonce-${safeNonce}'; script-src 'nonce-${safeNonce}';"><style nonce="${safeNonce}">
  body{font-family:var(--vscode-font-family);color:var(--vscode-foreground);padding:12px}.notice,.finding{border:1px solid var(--vscode-panel-border);padding:12px;margin:0 0 12px;border-radius:4px}.warning{border-color:var(--vscode-inputValidation-warningBorder)}.finding header{font-size:1.1rem}.severity{display:inline-block;padding:2px 6px;border-radius:3px}.critical,.high{background:var(--vscode-inputValidation-errorBackground)}.medium{background:var(--vscode-inputValidation-warningBackground)}.low,.unknown{background:var(--vscode-badge-background)}button{margin:4px 4px 4px 0}pre{white-space:pre-wrap;word-break:break-word;max-height:28rem;overflow:auto;background:var(--vscode-textCodeBlock-background);padding:8px}.muted,time{color:var(--vscode-descriptionForeground)}dt{font-weight:600;margin-top:6px}dd{margin-left:0}.timeline{padding-left:20px}.file-preview{border-top:1px solid var(--vscode-panel-border);margin-top:8px}
  </style><title>Dependency Remediation</title></head><body><h1>Remediation</h1>
  ${context.productionApplyAvailable ? '<section class="notice warning"><strong>Apply remains restricted.</strong><p>Only an explicitly approved proposal with a proven conditional atomic replacement primitive may proceed.</p></section>' : '<section class="notice warning"><strong>Production Apply is unavailable in this build.</strong><p>The current VS Code/Node host cannot prove an atomic identity-and-byte compare-and-replace operation. All ecosystems remain preview-only; no package-manager, Git, terminal, task, or workspace write is executed.</p></section>'}
  ${context.workspaceOpen ? "" : '<section class="notice">No workspace is open.</section>'}
  ${context.analysisComplete ? "" : '<section class="notice warning">Remediation analysis is incomplete. Automatic actions are refused.</section>'}
  ${context.activeOperation === undefined ? "" : `<section class="notice">Operation: <strong>${escapeHtml(context.activeOperation.stage, 64)}</strong> ${escapeHtml(context.activeOperation.message ?? "", 512)}</section>`}
  ${rows.length === 0 ? '<section class="notice">No remediation recommendations are available from the current stored scan.</section>' : rows}
  <script nonce="${safeNonce}" src="${escapeHtml(scriptUri, 4_096)}"></script></body></html>`;
}
