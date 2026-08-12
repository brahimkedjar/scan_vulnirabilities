import type * as vscode from "vscode";

export type FileChangeOperation = "modify" | "create" | "delete";

export interface FileChange {
  readonly uri: vscode.Uri;
  readonly operation: FileChangeOperation;
  readonly beforeHash: string;
  readonly afterHash?: string;
  readonly beforeContent?: string;
  readonly afterContent?: string;
  readonly description: string;
  /** A bounded, HTML/control/bidi-safe unified diff for display only. */
  readonly unifiedDiff?: string;
}

export const EMPTY_SHA256 =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
