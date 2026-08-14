export interface CoreLogger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string, error?: unknown): void;
}

export interface CoreClock {
  now(): number;
}

export const SYSTEM_CLOCK: CoreClock = Object.freeze({
  now: Date.now,
});

export type CoreFileType = "file" | "directory" | "symlink" | "other";

export interface CoreFileIdentity {
  readonly device: string;
  readonly inode: string;
  readonly size: number;
  readonly modifiedMs: number;
}

export interface CoreFileSystemRoot {
  /** Absolute path supplied by the caller after lexical normalization. */
  readonly path: string;
  /** Canonical root used for every containment decision. */
  readonly realPath: string;
}

export interface CoreDirectoryEntry {
  readonly name: string;
  readonly path: string;
  readonly type: CoreFileType;
  readonly size: number;
  readonly identity: CoreFileIdentity;
}

export interface CoreTextFile {
  readonly path: string;
  readonly text: string;
  readonly bytes: number;
  readonly identity: CoreFileIdentity;
}

export interface CoreFileSystem {
  openRoot(path: string, signal?: AbortSignal): Promise<CoreFileSystemRoot>;

  readDirectory(
    root: CoreFileSystemRoot,
    directory: string,
    signal?: AbortSignal,
  ): Promise<readonly CoreDirectoryEntry[]>;

  readTextFile(
    root: CoreFileSystemRoot,
    file: string,
    maximumBytes: number,
    signal?: AbortSignal,
  ): Promise<CoreTextFile>;
}

export function throwIfCoreCancelled(signal?: AbortSignal): void {
  if (signal?.aborted === true) {
    throw new DOMException("The security scan was cancelled", "AbortError");
  }
}

export function isCoreCancellation(error: unknown): boolean {
  return (
    (error instanceof DOMException && error.name === "AbortError") ||
    (error instanceof Error && error.name === "AbortError")
  );
}

