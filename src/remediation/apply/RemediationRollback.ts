import type * as vscode from "vscode";

import type { RollbackResult } from "./ApplyResult";
import type {
  FileIdentity,
  RemediationFileInspection,
} from "./FileSnapshot";
import { sha256 } from "./FileSnapshot";
import type { RemediationTransaction } from "./RemediationTransaction";

export interface RemediationFileSystem {
  inspect(uri: vscode.Uri): Promise<RemediationFileInspection>;
  readFile(uri: vscode.Uri): Promise<Uint8Array>;
  /**
   * Returns true only when this exact target can be replaced atomically through
   * a no-follow primitive conditional on both identity and exact content hash.
   * Ordinary path-based rename is not sufficient because a parent, leaf, or
   * in-place content may be exchanged after checking.
   */
  canGuaranteeAtomicReplace(
    uri: vscode.Uri,
  ): boolean | Promise<boolean>;
  /**
   * Atomically replaces a regular file while preserving relevant metadata.
   * The implementation must reject if the open target no longer has
   * `expectedIdentity`, its exact bytes no longer hash to `expectedHash`, or it
   * became a link/reparse point. Identity and content comparison must be part
   * of the same exclusive/conditional operation as replacement; a path-based
   * check followed by rename is not sufficient. A rejection must leave the
   * current bytes intact. Once the replacement commits, this method MUST
   * resolve with its replacement identity; it must never throw after commit.
   * Success returns the replacement identity.
   */
  replaceFileAtomic(
    uri: vscode.Uri,
    bytes: Uint8Array,
    expectedIdentity: FileIdentity,
    expectedHash: string,
  ): Promise<RemediationFileInspection>;
}

function sameIdentity(first: FileIdentity, second: FileIdentity): boolean {
  return first.value === second.value;
}

function safeRegularFile(inspection: RemediationFileInspection): boolean {
  return inspection.kind === "file" && !inspection.reparsePoint;
}

/** Restores only output still provably owned by the active transaction. */
export class RemediationRollback {
  public constructor(private readonly fileSystem: RemediationFileSystem) {}

  public async rollback(
    transaction: RemediationTransaction,
  ): Promise<RollbackResult> {
    const writes = transaction.ownedWritesInReverse();
    if (writes.length === 0) {
      transaction.markRolledBack();
      return Object.freeze({ attempted: false, restoredFiles: 0, verified: true });
    }

    let restoredFiles = 0;
    let verified = true;
    for (const write of writes) {
      try {
        const beforeRestore = await this.fileSystem.inspect(write.uri);
        if (
          !safeRegularFile(beforeRestore) ||
          !sameIdentity(beforeRestore.identity, write.writtenInspection.identity)
        ) {
          verified = false;
          continue;
        }
        const currentBytes = await this.fileSystem.readFile(write.uri);
        const afterRead = await this.fileSystem.inspect(write.uri);
        if (
          !safeRegularFile(afterRead) ||
          !sameIdentity(beforeRestore.identity, afterRead.identity) ||
          sha256(currentBytes) !== write.writtenHash
        ) {
          verified = false;
          continue;
        }
        const restoredInspection = await this.fileSystem.replaceFileAtomic(
          write.uri,
          write.snapshot.bytes,
          afterRead.identity,
          write.writtenHash,
        );
        const restored = await this.fileSystem.readFile(write.uri);
        const afterRestore = await this.fileSystem.inspect(write.uri);
        if (
          !safeRegularFile(restoredInspection) ||
          !safeRegularFile(afterRestore) ||
          !sameIdentity(restoredInspection.identity, afterRestore.identity) ||
          sha256(restored) !== write.snapshot.hash
        ) {
          verified = false;
          continue;
        }
        restoredFiles += 1;
      } catch {
        verified = false;
      }
    }
    transaction.markRolledBack();
    return Object.freeze({
      attempted: true,
      restoredFiles,
      verified,
      ...(verified
        ? {}
        : {
            criticalWarning:
              "Remediation failed and rollback could not be fully verified. Please inspect the affected files.",
          }),
    });
  }
}
