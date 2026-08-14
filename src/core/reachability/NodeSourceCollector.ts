import { extname, relative, resolve, sep } from "node:path";

import type { CoreFileSystem } from "../host/HostContracts";
import {
  analyzeStaticReachability,
  type ReachabilityTargetInput,
  type StaticReachabilityLimits,
  type StaticReachabilityResult,
  type StaticSourceInput,
  type StaticSourceLanguage,
} from "./StaticReachability";

export interface AnalyzeWorkspaceReachabilityOptions {
  readonly signal?: AbortSignal;
  readonly limits?: StaticReachabilityLimits;
  readonly maximumEntries?: number;
  readonly maximumCandidateBytes?: number;
  readonly maximumSourceBytesPerFile?: number;
}

const EXCLUDED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  ".yarn",
  "__pycache__",
  "bower_components",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "obj",
  "out",
  "target",
  "vendor",
  "venv",
  ".venv",
]);
const HARD_MAXIMUM_ENTRIES = 2_000_000;
const HARD_MAXIMUM_BYTES = 32 * 1024 * 1024;
const HARD_MAXIMUM_FILE_BYTES = 2 * 1024 * 1024;

function language(path: string): StaticSourceLanguage | undefined {
  switch (extname(path).toLowerCase()) {
    case ".js":
    case ".mjs":
    case ".cjs":
      return "javascript";
    case ".ts":
    case ".mts":
    case ".cts":
      return "typescript";
    case ".jsx":
      return "jsx";
    case ".tsx":
      return "tsx";
    case ".py":
    case ".pyi":
      return "python";
    default:
      return undefined;
  }
}

function limit(
  value: number | undefined,
  fallback: number,
  maximum: number,
  name: string,
): number {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > maximum) {
    throw new RangeError(`${name} is outside the supported safety range`);
  }
  return selected;
}

function relativeId(root: string, path: string): string {
  return relative(root, path).split(sep).join("/");
}

function inferredEntrypoint(path: string): boolean {
  const lower = path.toLowerCase();
  const base = lower.split("/").at(-1) ?? "";
  return (
    !lower.includes("/") ||
    base === "index.js" ||
    base === "index.ts" ||
    base === "index.mjs" ||
    base === "index.cjs" ||
    base === "main.py" ||
    base === "__main__.py" ||
    lower.startsWith("src/index.") ||
    lower.startsWith("src/main.")
  );
}

/**
 * Collects bounded local JS/TS/Python source through the host-neutral,
 * no-follow filesystem port and runs the static evidence analyzer. It never
 * resolves node_modules, imports a module, or executes source code.
 */
export async function analyzeWorkspaceReachability(
  fileSystem: CoreFileSystem,
  workspacePath: string,
  targets: readonly ReachabilityTargetInput[],
  options: AnalyzeWorkspaceReachabilityOptions = {},
): Promise<StaticReachabilityResult> {
  const maximumEntries = limit(
    options.maximumEntries,
    100_000,
    HARD_MAXIMUM_ENTRIES,
    "maximumEntries",
  );
  const maximumBytes = limit(
    options.maximumCandidateBytes,
    8 * 1024 * 1024,
    HARD_MAXIMUM_BYTES,
    "maximumCandidateBytes",
  );
  const maximumFileBytes = limit(
    options.maximumSourceBytesPerFile,
    512 * 1024,
    HARD_MAXIMUM_FILE_BYTES,
    "maximumSourceBytesPerFile",
  );
  const root = await fileSystem.openRoot(workspacePath, options.signal);
  const pending = [root.path];
  const sources: StaticSourceInput[] = [];
  let entries = 0;
  let remainingBytes = maximumBytes;
  let incomplete = false;
  while (pending.length > 0) {
    if (options.signal?.aborted === true) {
      incomplete = true;
      break;
    }
    const directory = pending.pop();
    if (directory === undefined) {
      continue;
    }
    const children = await fileSystem.readDirectory(
      root,
      directory,
      options.signal,
    );
    for (const child of children) {
      entries += 1;
      if (entries > maximumEntries) {
        incomplete = true;
        pending.length = 0;
        break;
      }
      if (child.type === "directory") {
        if (!EXCLUDED_DIRECTORIES.has(child.name.toLowerCase())) {
          pending.push(child.path);
          pending.sort((left, right) => right.localeCompare(left, "en"));
        }
        continue;
      }
      if (child.type !== "file") {
        incomplete = true;
        continue;
      }
      const selectedLanguage = language(child.path);
      if (selectedLanguage === undefined) {
        continue;
      }
      if (child.size > maximumFileBytes || child.size > remainingBytes) {
        incomplete = true;
        continue;
      }
      const source = await fileSystem.readTextFile(
        root,
        child.path,
        Math.min(maximumFileBytes, remainingBytes),
        options.signal,
      );
      remainingBytes -= source.bytes;
      const fileId = relativeId(resolve(root.path), child.path);
      sources.push(Object.freeze({
        fileId,
        language: selectedLanguage,
        content: source.text,
        entrypoint: inferredEntrypoint(fileId),
      }));
    }
  }
  if (sources.length === 0 || incomplete) {
    const sentinel = `phase8-evidence-incomplete-${entries.toString()}.ts`;
    sources.push(Object.freeze({
      fileId: sentinel,
      language: "typescript",
      content: "const phase8Dynamic = require(process.env.UNKNOWN_MODULE);",
      entrypoint: true,
    }));
  }
  return analyzeStaticReachability(
    { sources: Object.freeze(sources), targets },
    {
      ...(options.signal === undefined ? {} : { signal: options.signal }),
      ...(options.limits === undefined ? {} : { limits: options.limits }),
    },
  );
}

