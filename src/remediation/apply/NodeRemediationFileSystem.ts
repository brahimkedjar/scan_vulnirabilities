import { constants } from "node:fs";
import {
  access,
  lstat,
  open,
  realpath,
} from "node:fs/promises";
import { dirname, parse, resolve } from "node:path";

import type * as vscode from "vscode";

import { ApplyError } from "./ApplyError";
import type {
  FileIdentity,
  RemediationFileInspection,
} from "./FileSnapshot";
import type { RemediationFileSystem } from "./RemediationRollback";

const FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
const MAX_LOCAL_REMEDIATION_READ_BYTES = 32 * 1024 * 1024;
const READ_CHUNK_BYTES = 64 * 1024;

function identity(stats: Awaited<ReturnType<typeof lstat>>): FileIdentity {
  return Object.freeze({
    value: `${stats.dev.toString()}:${stats.ino.toString()}:${stats.birthtimeMs.toString()}`,
  });
}

function reparsePoint(stats: Awaited<ReturnType<typeof lstat>>): boolean {
  const attributes = (stats as typeof stats & { fileAttributes?: number })
    .fileAttributes;
  return (
    stats.isSymbolicLink() ||
    (attributes !== undefined &&
      (attributes & FILE_ATTRIBUTE_REPARSE_POINT) === FILE_ATTRIBUTE_REPARSE_POINT)
  );
}

function sameIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.value === right.value;
}

interface ParentChainEntry {
  readonly path: string;
  readonly identity: FileIdentity;
  readonly canonicalPath: string;
}

async function captureSafeParentChain(
  target: string,
): Promise<readonly ParentChainEntry[]> {
  const root = parse(target).root;
  let current = dirname(target);
  const reversed: ParentChainEntry[] = [];
  for (;;) {
    const stats = await lstat(current);
    if (!stats.isDirectory() || reparsePoint(stats)) {
      throw new ApplyError("UNSAFE_FILE_TYPE");
    }
    const canonicalPath = await realpath(current);
    reversed.push({
      path: current,
      identity: identity(stats),
      canonicalPath,
    });
    if (current === root) {
      break;
    }
    const parent = dirname(current);
    if (parent === current) {
      throw new ApplyError("WORKSPACE_BOUNDARY");
    }
    current = parent;
  }
  return Object.freeze(reversed.reverse().map((entry) => Object.freeze(entry)));
}

function sameParentChain(
  first: readonly ParentChainEntry[],
  second: readonly ParentChainEntry[],
): boolean {
  return (
    first.length === second.length &&
    first.every((entry, index) => {
      const candidate = second[index];
      return (
        candidate !== undefined &&
        entry.path === candidate.path &&
        entry.canonicalPath === candidate.canonicalPath &&
        sameIdentity(entry.identity, candidate.identity)
      );
    })
  );
}

async function requireStableParentChain(
  target: string,
  expected: readonly ParentChainEntry[],
): Promise<void> {
  const current = await captureSafeParentChain(target);
  if (!sameParentChain(expected, current)) {
    throw new ApplyError("FILES_CHANGED");
  }
}

async function readBounded(
  handle: Awaited<ReturnType<typeof open>>,
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const remaining = MAX_LOCAL_REMEDIATION_READ_BYTES + 1 - total;
    const chunk = Buffer.allocUnsafe(Math.min(READ_CHUNK_BYTES, remaining));
    const { bytesRead } = await handle.read(chunk, 0, chunk.byteLength, null);
    if (bytesRead === 0) break;
    chunks.push(chunk.subarray(0, bytesRead));
    total += bytesRead;
    if (total > MAX_LOCAL_REMEDIATION_READ_BYTES) {
      throw new ApplyError("RESOURCE_LIMIT");
    }
  }
  return new Uint8Array(Buffer.concat(chunks, total));
}

/** Local no-follow file adapter. Boundary checks remain an independent guard. */
export class NodeRemediationFileSystem implements RemediationFileSystem {
  public async inspect(uri: vscode.Uri): Promise<RemediationFileInspection> {
    if (uri.scheme !== "file") throw new ApplyError("UNSAFE_URI");
    const path = resolve(uri.fsPath);
    const parents = await captureSafeParentChain(path);
    const stats = await lstat(path);
    const isReparse = reparsePoint(stats);
    let canonicalPath = path;
    if (!isReparse) {
      canonicalPath = await realpath(path);
    }
    await requireStableParentChain(path, parents);
    let writable = false;
    try {
      await access(path, constants.W_OK);
      writable = true;
    } catch {
      writable = false;
    }
    return Object.freeze({
      kind: stats.isFile()
        ? "file"
        : stats.isDirectory()
          ? "directory"
          : stats.isSymbolicLink()
            ? "symbolic-link"
            : "other",
      size: stats.size,
      writable,
      reparsePoint: isReparse,
      identity: identity(stats),
      canonicalPath,
      mode: stats.mode,
    });
  }

  public async readFile(uri: vscode.Uri): Promise<Uint8Array> {
    if (uri.scheme !== "file") throw new ApplyError("UNSAFE_URI");
    const target = resolve(uri.fsPath);
    const parents = await captureSafeParentChain(target);
    const leafBeforeOpen = await lstat(target);
    if (!leafBeforeOpen.isFile() || reparsePoint(leafBeforeOpen)) {
      throw new ApplyError("UNSAFE_FILE_TYPE");
    }
    if (leafBeforeOpen.size > MAX_LOCAL_REMEDIATION_READ_BYTES) {
      throw new ApplyError("RESOURCE_LIMIT");
    }
    const expectedLeafIdentity = identity(leafBeforeOpen);
    const handle = await open(
      target,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    try {
      const before = await handle.stat();
      if (!before.isFile() || reparsePoint(before)) {
        throw new ApplyError("UNSAFE_FILE_TYPE");
      }
      if (!sameIdentity(expectedLeafIdentity, identity(before))) {
        throw new ApplyError("FILES_CHANGED");
      }
      if (before.size > MAX_LOCAL_REMEDIATION_READ_BYTES) {
        throw new ApplyError("RESOURCE_LIMIT");
      }
      const bytes = await readBounded(handle);
      const after = await handle.stat();
      const leafAfterRead = await lstat(target);
      if (
        !after.isFile() ||
        reparsePoint(after) ||
        !leafAfterRead.isFile() ||
        reparsePoint(leafAfterRead)
      ) {
        throw new ApplyError("UNSAFE_FILE_TYPE");
      }
      if (
        !sameIdentity(identity(before), identity(after)) ||
        !sameIdentity(identity(after), identity(leafAfterRead)) ||
        bytes.byteLength !== after.size
      ) {
        throw new ApplyError("FILES_CHANGED");
      }
      await requireStableParentChain(target, parents);
      return bytes;
    } finally {
      await handle.close();
    }
  }

  /**
   * Node's FileHandle API exposes neither rename nor a mandatory exclusive
   * lock, while fsPromises.rename is an unconditional two-path operation.
   * Native rename/replace operations also do not compare an expected identity
   * and content hash. A path-based check followed by rename therefore remains
   * vulnerable to a final parent, leaf, or in-place content change, so the
   * built-in adapter deliberately never authorizes automatic writes.
   */
  public canGuaranteeAtomicReplace(_uri: vscode.Uri): false {
    return false;
  }

  public async replaceFileAtomic(
    uri: vscode.Uri,
    bytes: Uint8Array,
    expectedIdentity: FileIdentity,
    expectedHash: string,
  ): Promise<RemediationFileInspection> {
    void bytes;
    void expectedIdentity;
    void expectedHash;
    // Preserve the more specific file-type rejection for direct adapter use,
    // while guaranteeing that no stage file or target mutation is attempted.
    const inspection = await this.inspect(uri);
    if (inspection.kind !== "file" || inspection.reparsePoint) {
      throw new ApplyError("UNSAFE_FILE_TYPE");
    }
    throw new ApplyError("ATOMIC_REPLACE_UNAVAILABLE");
  }
}
