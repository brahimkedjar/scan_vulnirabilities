import { constants as fileConstants, type Stats } from "node:fs";
import {
  lstat,
  open,
  opendir,
  realpath,
  type FileHandle,
} from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

import {
  throwIfCoreCancelled,
  type CoreDirectoryEntry,
  type CoreFileIdentity,
  type CoreFileSystem,
  type CoreFileSystemRoot,
  type CoreFileType,
  type CoreTextFile,
} from "./HostContracts";

export type NodeFileSystemErrorCode =
  | "INVALID_PATH"
  | "NOT_FOUND"
  | "NOT_DIRECTORY"
  | "NOT_REGULAR_FILE"
  | "SYMLINK_REJECTED"
  | "PATH_ESCAPE"
  | "FILE_TOO_LARGE"
  | "INVALID_UTF8"
  | "FILE_CHANGED"
  | "IO_ERROR";

export class NodeFileSystemError extends Error {
  public constructor(
    public readonly code: NodeFileSystemErrorCode,
    message: string,
    options: { readonly cause?: unknown; readonly path?: string } = {},
  ) {
    super(message, options);
    this.name = "NodeFileSystemError";
    this.path = options.path;
  }

  public readonly path: string | undefined;
}

const MAXIMUM_DIRECTORY_ENTRIES = 1_000_000;
const READ_CHUNK_BYTES = 64 * 1024;
const UNSAFE_PATH_TEXT = /[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/u;

function errorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) {
    return undefined;
  }
  return typeof error.code === "string" ? error.code : undefined;
}

function normalizeIoError(error: unknown, path: string): NodeFileSystemError {
  if (error instanceof NodeFileSystemError) {
    return error;
  }
  const code = errorCode(error);
  return new NodeFileSystemError(
    code === "ENOENT" ? "NOT_FOUND" : "IO_ERROR",
    code === "ENOENT"
      ? "A dependency metadata path no longer exists."
      : "A dependency metadata path could not be read safely.",
    { cause: error, path },
  );
}

function requireMaximumBytes(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError("maximumBytes must be a non-negative safe integer");
  }
  return value;
}

function checkedPath(value: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 32_768 ||
    UNSAFE_PATH_TEXT.test(value)
  ) {
    throw new NodeFileSystemError("INVALID_PATH", "The filesystem path is invalid.");
  }
  return resolve(value);
}

function comparable(value: string): string {
  const normalized = resolve(value);
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function isContained(root: string, candidate: string): boolean {
  const rootValue = comparable(root);
  const candidateValue = comparable(candidate);
  if (rootValue === candidateValue) {
    return true;
  }
  const suffix = rootValue.endsWith(sep) ? rootValue : `${rootValue}${sep}`;
  return candidateValue.startsWith(suffix);
}

async function assertNoLinkedComponents(
  root: string,
  candidate: string,
): Promise<void> {
  const boundary = resolve(root);
  const tail = relative(boundary, candidate);
  if (tail === "") {
    const stat = await lstat(boundary);
    if (stat.isSymbolicLink()) {
      throw new NodeFileSystemError(
        "SYMLINK_REJECTED",
        "A scan path component cannot be a symbolic link or junction.",
        { path: boundary },
      );
    }
    return;
  }
  let current = boundary;
  for (const segment of tail.split(sep)) {
    current = join(current, segment);
    const stat = await lstat(current);
    if (stat.isSymbolicLink()) {
      throw new NodeFileSystemError(
        "SYMLINK_REJECTED",
        "A scan path component cannot be a symbolic link or junction.",
        { path: current },
      );
    }
    if (process.platform === "win32") {
      const constants = fileConstants as typeof fileConstants & {
        readonly FILE_ATTRIBUTE_REPARSE_POINT?: number;
      };
      const attributes = (stat as Stats & { readonly fileAttributes?: number })
        .fileAttributes;
      if (
        attributes !== undefined &&
        constants.FILE_ATTRIBUTE_REPARSE_POINT !== undefined &&
        (attributes & constants.FILE_ATTRIBUTE_REPARSE_POINT) !== 0
      ) {
        throw new NodeFileSystemError(
          "SYMLINK_REJECTED",
          "A scan path component cannot be a reparse point.",
          { path: current },
        );
      }
    }
  }
}

function requireContained(root: CoreFileSystemRoot, candidate: string): string {
  const absolute = checkedPath(candidate);
  if (!isContained(root.path, absolute)) {
    throw new NodeFileSystemError(
      "PATH_ESCAPE",
      "The dependency metadata path escapes the scan root.",
      { path: absolute },
    );
  }
  return absolute;
}

function fileType(stat: Stats): CoreFileType {
  if (stat.isSymbolicLink()) {
    return "symlink";
  }
  if (stat.isFile()) {
    return "file";
  }
  if (stat.isDirectory()) {
    return "directory";
  }
  return "other";
}

function identity(stat: Stats): CoreFileIdentity {
  return {
    device: stat.dev.toString(),
    inode: stat.ino.toString(),
    size: stat.size,
    modifiedMs: stat.mtimeMs,
  };
}

function sameIdentity(left: CoreFileIdentity, right: CoreFileIdentity): boolean {
  return (
    left.device === right.device &&
    left.inode === right.inode &&
    left.size === right.size &&
    left.modifiedMs === right.modifiedMs
  );
}

async function closeQuietly(handle: FileHandle | undefined): Promise<void> {
  try {
    await handle?.close();
  } catch {
    // Preserve the primary safety failure.
  }
}

async function canonicalContainedPath(
  root: CoreFileSystemRoot,
  path: string,
): Promise<string> {
  const canonical = await realpath(path);
  if (!isContained(root.realPath, canonical)) {
    throw new NodeFileSystemError(
      "PATH_ESCAPE",
      "The canonical dependency metadata path escapes the scan root.",
      { path },
    );
  }
  return canonical;
}

async function assertOpenedBeneathRoot(
  root: CoreFileSystemRoot,
  handle: FileHandle,
  path: string,
): Promise<void> {
  if (process.platform !== "linux") {
    return;
  }
  try {
    const openedPath = await realpath(`/proc/self/fd/${handle.fd.toString()}`);
    if (!isContained(root.realPath, openedPath)) {
      throw new NodeFileSystemError(
        "PATH_ESCAPE",
        "The opened dependency metadata handle escaped the scan root.",
        { path },
      );
    }
  } catch (error: unknown) {
    if (error instanceof NodeFileSystemError) {
      throw error;
    }
    throw new NodeFileSystemError(
      "IO_ERROR",
      "The opened dependency metadata handle could not be anchored safely.",
      { cause: error, path },
    );
  }
}

export class NodeFileSystem implements CoreFileSystem {
  public async openRoot(
    path: string,
    signal?: AbortSignal,
  ): Promise<CoreFileSystemRoot> {
    throwIfCoreCancelled(signal);
    const absolute = checkedPath(path);
    try {
      const before = await lstat(absolute);
      throwIfCoreCancelled(signal);
      if (before.isSymbolicLink()) {
        throw new NodeFileSystemError(
          "SYMLINK_REJECTED",
          "A scan root cannot be a symbolic link or junction.",
          { path: absolute },
        );
      }
      if (!before.isDirectory()) {
        throw new NodeFileSystemError(
          "NOT_DIRECTORY",
          "The scan root is not a directory.",
          { path: absolute },
        );
      }
      await assertNoLinkedComponents(absolute, absolute);
      const canonical = await realpath(absolute);
      const after = await lstat(absolute);
      if (!sameIdentity(identity(before), identity(after))) {
        throw new NodeFileSystemError(
          "FILE_CHANGED",
          "The scan root changed while it was being opened.",
          { path: absolute },
        );
      }
      return Object.freeze({ path: absolute, realPath: canonical });
    } catch (error: unknown) {
      throw normalizeIoError(error, absolute);
    }
  }

  public async readDirectory(
    root: CoreFileSystemRoot,
    directory: string,
    signal?: AbortSignal,
  ): Promise<readonly CoreDirectoryEntry[]> {
    throwIfCoreCancelled(signal);
    const absolute = requireContained(root, directory);
    let iterator: Awaited<ReturnType<typeof opendir>> | undefined;
    try {
      const before = await lstat(absolute);
      await assertNoLinkedComponents(root.path, absolute);
      if (before.isSymbolicLink()) {
        throw new NodeFileSystemError(
          "SYMLINK_REJECTED",
          "A symbolic-link directory was not traversed.",
          { path: absolute },
        );
      }
      if (!before.isDirectory()) {
        throw new NodeFileSystemError(
          "NOT_DIRECTORY",
          "The dependency metadata directory is not a directory.",
          { path: absolute },
        );
      }
      await canonicalContainedPath(root, absolute);
      iterator = await opendir(absolute);
      const entries: CoreDirectoryEntry[] = [];
      for await (const directoryEntry of iterator) {
        throwIfCoreCancelled(signal);
        if (entries.length >= MAXIMUM_DIRECTORY_ENTRIES) {
          throw new NodeFileSystemError(
            "IO_ERROR",
            "A directory exceeds the hard entry safety limit.",
            { path: absolute },
          );
        }
        const name = directoryEntry.name;
        if (
          name === "." ||
          name === ".." ||
          name.length === 0 ||
          name.length > 4_096 ||
          name.includes("/") ||
          name.includes("\\") ||
          UNSAFE_PATH_TEXT.test(name)
        ) {
          throw new NodeFileSystemError(
            "INVALID_PATH",
            "A directory contains an unsafe entry name.",
            { path: absolute },
          );
        }
        const child = join(absolute, name);
        const stat = await lstat(child);
        entries.push({
          name,
          path: child,
          type: fileType(stat),
          size: stat.size,
          identity: identity(stat),
        });
      }
      iterator = undefined;
      const after = await lstat(absolute);
      await assertNoLinkedComponents(root.path, absolute);
      await canonicalContainedPath(root, absolute);
      if (!sameIdentity(identity(before), identity(after))) {
        throw new NodeFileSystemError(
          "FILE_CHANGED",
          "A dependency metadata directory changed during enumeration.",
          { path: absolute },
        );
      }
      return entries.sort((left, right) =>
        left.name.localeCompare(right.name, "en"),
      );
    } catch (error: unknown) {
      throw normalizeIoError(error, absolute);
    } finally {
      try {
        await iterator?.close();
      } catch {
        // Enumeration already finished or failed; no correctness claim depends on close.
      }
    }
  }

  public async readTextFile(
    root: CoreFileSystemRoot,
    file: string,
    maximumBytes: number,
    signal?: AbortSignal,
  ): Promise<CoreTextFile> {
    throwIfCoreCancelled(signal);
    const budget = requireMaximumBytes(maximumBytes);
    const absolute = requireContained(root, file);
    let handle: FileHandle | undefined;
    try {
      const beforeStat = await lstat(absolute);
      await assertNoLinkedComponents(root.path, absolute);
      const before = identity(beforeStat);
      if (beforeStat.isSymbolicLink()) {
        throw new NodeFileSystemError(
          "SYMLINK_REJECTED",
          "A symbolic-link dependency metadata file was not read.",
          { path: absolute },
        );
      }
      if (!beforeStat.isFile()) {
        throw new NodeFileSystemError(
          "NOT_REGULAR_FILE",
          "The dependency metadata path is not a regular file.",
          { path: absolute },
        );
      }
      if (before.size > budget) {
        throw new NodeFileSystemError(
          "FILE_TOO_LARGE",
          "The dependency metadata file exceeds the remaining byte budget.",
          { path: absolute },
        );
      }
      await canonicalContainedPath(root, absolute);
      handle = await open(
        absolute,
        fileConstants.O_RDONLY | (fileConstants.O_NOFOLLOW ?? 0),
      );
      await assertOpenedBeneathRoot(root, handle, absolute);
      const opened = identity(await handle.stat());
      if (!sameIdentity(before, opened)) {
        throw new NodeFileSystemError(
          "FILE_CHANGED",
          "The dependency metadata file changed while it was being opened.",
          { path: absolute },
        );
      }
      const bytes = new Uint8Array(before.size);
      let offset = 0;
      while (offset < bytes.length) {
        throwIfCoreCancelled(signal);
        const length = Math.min(READ_CHUNK_BYTES, bytes.length - offset);
        const chunk = await handle.read(bytes, offset, length, offset);
        if (chunk.bytesRead <= 0) {
          throw new NodeFileSystemError(
            "FILE_CHANGED",
            "The dependency metadata file ended before its measured size.",
            { path: absolute },
          );
        }
        offset += chunk.bytesRead;
      }
      const openedAfter = identity(await handle.stat());
      const pathAfter = identity(await lstat(absolute));
      await assertNoLinkedComponents(root.path, absolute);
      await canonicalContainedPath(root, absolute);
      if (
        !sameIdentity(opened, openedAfter) ||
        !sameIdentity(opened, pathAfter)
      ) {
        throw new NodeFileSystemError(
          "FILE_CHANGED",
          "The dependency metadata file changed while it was being read.",
          { path: absolute },
        );
      }
      let text: string;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      } catch (error: unknown) {
        throw new NodeFileSystemError(
          "INVALID_UTF8",
          "The dependency metadata file is not valid UTF-8.",
          { cause: error, path: absolute },
        );
      }
      return { path: absolute, text, bytes: bytes.byteLength, identity: opened };
    } catch (error: unknown) {
      throw normalizeIoError(error, absolute);
    } finally {
      await closeQuietly(handle);
    }
  }
}

export function nodePathIsWithin(root: string, candidate: string): boolean {
  if (!isAbsolute(root) || !isAbsolute(candidate)) {
    return false;
  }
  const result = relative(root, candidate);
  return (
    result === "" ||
    (!result.startsWith(`..${sep}`) && result !== ".." && !isAbsolute(result))
  );
}
