import { createHash } from "node:crypto";

import type * as vscode from "vscode";

export interface FileIdentity {
  readonly value: string;
}

export interface RemediationFileInspection {
  readonly kind: "file" | "directory" | "symbolic-link" | "other";
  readonly size: number;
  readonly writable: boolean;
  readonly reparsePoint: boolean;
  readonly identity: FileIdentity;
  readonly canonicalPath: string;
  readonly mode?: number;
}

export interface FileSnapshot {
  readonly uri: vscode.Uri;
  readonly bytes: Uint8Array;
  readonly hash: string;
  readonly inspection: RemediationFileInspection;
}

export function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}
