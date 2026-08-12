import { randomUUID } from "node:crypto";

import type * as vscode from "vscode";

import { ApplyError } from "./ApplyError";
import type { FileSnapshot, RemediationFileInspection } from "./FileSnapshot";
import type { RemediationPlan } from "./RemediationPlan";

export const MAX_FILES_PER_REMEDIATION = 8;
export const MAX_REMEDIATION_FILE_BYTES = 32 * 1024 * 1024;
export const MAX_REMEDIATION_TOTAL_BYTES = 64 * 1024 * 1024;

export interface TransactionOwnedWrite {
  readonly uri: vscode.Uri;
  readonly snapshot: FileSnapshot;
  readonly writtenHash: string;
  readonly writtenInspection: RemediationFileInspection;
}

function uriKey(uri: vscode.Uri): string {
  return uri.toString();
}

function copyInspection(
  inspection: RemediationFileInspection,
): RemediationFileInspection {
  return Object.freeze({
    ...inspection,
    identity: Object.freeze({ ...inspection.identity }),
  });
}

function copySnapshot(snapshot: FileSnapshot): FileSnapshot {
  return Object.freeze({
    uri: snapshot.uri,
    bytes: new Uint8Array(snapshot.bytes),
    hash: snapshot.hash,
    inspection: copyInspection(snapshot.inspection),
  });
}

/** In-memory exact-byte snapshot and ownership ledger for one apply attempt. */
export class RemediationTransaction {
  public readonly id: string;
  private readonly snapshotsByUri = new Map<string, FileSnapshot>();
  private readonly ownedWrites: TransactionOwnedWrite[] = [];
  private state: "open" | "committed" | "rolled-back" = "open";

  public constructor(
    public readonly plan: RemediationPlan,
    snapshots: readonly FileSnapshot[],
    id: string = randomUUID(),
  ) {
    if (
      snapshots.length === 0 ||
      snapshots.length > MAX_FILES_PER_REMEDIATION ||
      snapshots.length !== plan.files.length
    ) {
      throw new ApplyError("RESOURCE_LIMIT");
    }
    let totalBytes = 0;
    for (const snapshot of snapshots) {
      const key = uriKey(snapshot.uri);
      if (
        this.snapshotsByUri.has(key) ||
        snapshot.bytes.byteLength > MAX_REMEDIATION_FILE_BYTES
      ) {
        throw new ApplyError("RESOURCE_LIMIT");
      }
      totalBytes += snapshot.bytes.byteLength;
      if (totalBytes > MAX_REMEDIATION_TOTAL_BYTES) {
        throw new ApplyError("RESOURCE_LIMIT");
      }
      this.snapshotsByUri.set(key, copySnapshot(snapshot));
    }
    if (
      plan.files.some(
        (change) => !this.snapshotsByUri.has(uriKey(change.uri)),
      )
    ) {
      throw new ApplyError("UNEXPECTED", "Transaction snapshots do not match the plan.");
    }
    this.id = id;
  }

  public get snapshots(): readonly FileSnapshot[] {
    return Object.freeze([...this.snapshotsByUri.values()]);
  }

  public get changedFiles(): number {
    return this.ownedWrites.length;
  }

  public snapshotFor(uri: vscode.Uri): FileSnapshot {
    const snapshot = this.snapshotsByUri.get(uriKey(uri));
    if (snapshot === undefined) {
      throw new ApplyError("UNEXPECTED", "The transaction does not own this target.");
    }
    return snapshot;
  }

  public recordOwnedWrite(
    uri: vscode.Uri,
    writtenHash: string,
    writtenInspection: RemediationFileInspection,
  ): void {
    if (this.state !== "open") {
      throw new ApplyError("UNEXPECTED", "The transaction is no longer open.");
    }
    const snapshot = this.snapshotFor(uri);
    if (this.ownedWrites.some((entry) => uriKey(entry.uri) === uriKey(uri))) {
      throw new ApplyError("UNEXPECTED", "The target was already modified.");
    }
    this.ownedWrites.push(
      Object.freeze({
        uri,
        snapshot,
        writtenHash,
        writtenInspection: copyInspection(writtenInspection),
      }),
    );
  }

  public ownedWritesInReverse(): readonly TransactionOwnedWrite[] {
    return Object.freeze([...this.ownedWrites].reverse());
  }

  public commit(): void {
    if (this.state !== "open") {
      throw new ApplyError("UNEXPECTED", "The transaction is no longer open.");
    }
    this.state = "committed";
  }

  public markRolledBack(): void {
    if (this.state !== "open") {
      throw new ApplyError("UNEXPECTED", "The transaction is no longer open.");
    }
    this.state = "rolled-back";
  }
}
