import * as vscode from "vscode";

import { DEPENDENCY_FILE_GLOB } from "../discovery/dependencyFiles";
import type { DependencyAuditorConfiguration } from "./DependencyAuditorConfiguration";

export interface ScanTriggerControllerOptions {
  readonly getConfiguration: () => DependencyAuditorConfiguration;
  readonly scan: () => Promise<void>;
  readonly debounceMs?: number;
}

const DEFAULT_DEBOUNCE_MS = 1_000;
const MAXIMUM_DEBOUNCE_MS = 60_000;
const IGNORED_DIRECTORY_NAMES = new Set([
  ".git",
  ".next",
  ".turbo",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "out",
  "vendor",
]);

function shouldIgnore(uri: vscode.Uri): boolean {
  return uri.path
    .split("/")
    .some((segment) => IGNORED_DIRECTORY_NAMES.has(segment.toLowerCase()));
}

function boundedDebounce(value: number | undefined): number {
  const selected = value ?? DEFAULT_DEBOUNCE_MS;
  if (
    !Number.isSafeInteger(selected) ||
    selected < 100 ||
    selected > MAXIMUM_DEBOUNCE_MS
  ) {
    throw new RangeError("debounceMs must be between 100 and 60000");
  }
  return selected;
}

export class ScanTriggerController implements vscode.Disposable {
  private readonly disposables: vscode.Disposable[] = [];
  private readonly debounceMs: number;
  private debounceHandle: NodeJS.Timeout | undefined;
  private running: Promise<void> | undefined;
  private rerunRequested = false;
  private remediationSuspended = false;
  private disposed = false;

  public constructor(private readonly options: ScanTriggerControllerOptions) {
    this.debounceMs = boundedDebounce(options.debounceMs);
    const watcher = vscode.workspace.createFileSystemWatcher(
      DEPENDENCY_FILE_GLOB,
    );
    this.disposables.push(
      watcher,
      watcher.onDidCreate((uri) => this.scheduleChangeScan(uri)),
      watcher.onDidChange((uri) => this.scheduleChangeScan(uri)),
      watcher.onDidDelete((uri) => this.scheduleChangeScan(uri)),
    );
    this.disposables.push(
      vscode.workspace.onDidChangeConfiguration((event) => {
        if (
          event.affectsConfiguration("dependencyAuditor.enabled") ||
          event.affectsConfiguration("dependencyAuditor.scanOnChange") ||
          event.affectsConfiguration("dependencyAuditor.enabledEcosystems")
        ) {
          this.cancelPendingChangeScan();
        }
      }),
    );
  }

  public triggerStartupScan(): void {
    const configuration = this.options.getConfiguration();
    if (
      configuration.enabled &&
      configuration.scanOnStartup &&
      (vscode.workspace.workspaceFolders?.length ?? 0) > 0
    ) {
      this.requestScan();
    }
  }

  public dispose(): void {
    this.disposed = true;
    this.cancelPendingChangeScan();
    for (const disposable of this.disposables.splice(0)) {
      disposable.dispose();
    }
  }

  /** Suppresses automatic file-change scans while a remediation owns files. */
  public setRemediationSuspended(suspended: boolean): void {
    this.remediationSuspended = suspended;
    if (suspended) {
      this.cancelPendingChangeScan();
      this.rerunRequested = false;
    }
  }

  private scheduleChangeScan(uri?: vscode.Uri): void {
    if (
      this.disposed ||
      this.remediationSuspended ||
      (uri !== undefined && shouldIgnore(uri))
    ) {
      return;
    }
    const configuration = this.options.getConfiguration();
    if (!configuration.enabled || !configuration.scanOnChange) {
      return;
    }
    this.cancelPendingChangeScan();
    this.debounceHandle = setTimeout(() => {
      this.debounceHandle = undefined;
      this.requestScan();
    }, this.debounceMs);
  }

  private cancelPendingChangeScan(): void {
    if (this.debounceHandle !== undefined) {
      clearTimeout(this.debounceHandle);
      this.debounceHandle = undefined;
    }
  }

  private requestScan(): void {
    if (this.disposed || this.remediationSuspended) {
      return;
    }
    if (this.running !== undefined) {
      this.rerunRequested = true;
      return;
    }
    this.running = this.options.scan().finally(() => {
      this.running = undefined;
      if (this.rerunRequested && !this.disposed) {
        this.rerunRequested = false;
        this.scheduleChangeScan();
      }
    });
    void this.running.catch(() => {
      // The command owns user-facing error reporting.
    });
  }
}
