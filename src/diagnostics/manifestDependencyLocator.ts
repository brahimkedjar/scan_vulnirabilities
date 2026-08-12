import type { Dependency } from "../models/Dependency";
import {
  findDependencyOffsets,
  findDependencyOffsetsInSections,
} from "./jsonDependencyLocator";

const MAXIMUM_TEXT_LENGTH = 2 * 1024 * 1024;
const MAXIMUM_LINES = 250_000;
const MAXIMUM_REQUESTS = 2_000;
const NAME_PATTERN = /^[A-Za-z0-9@][A-Za-z0-9@._/+:-]*$/u;

function requestedNames(
  dependencies: readonly Dependency[],
): ReadonlySet<string> {
  const values = new Set<string>();
  for (const dependency of dependencies.slice(0, MAXIMUM_REQUESTS)) {
    const name = dependency.manifestName ?? dependency.name;
    if (
      name.length > 0 &&
      name.length <= 512 &&
      NAME_PATTERN.test(name)
    ) {
      values.add(name);
    }
  }
  return values;
}

function unquotedCommentIndex(line: string, marker: "#" | "//"): number {
  let quote: '"' | "'" | undefined;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (quote !== undefined) {
      if (character === "\\") {
        index += 1;
      } else if (character === quote) {
        quote = undefined;
      }
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }
    if (line.startsWith(marker, index)) {
      return index;
    }
  }
  return -1;
}

function linesWithOffsets(text: string): Array<{
  readonly line: string;
  readonly offset: number;
}> {
  const lines: Array<{ line: string; offset: number }> = [];
  let offset = 0;
  while (offset <= text.length && lines.length < MAXIMUM_LINES) {
    const end = text.indexOf("\n", offset);
    const lineEnd = end === -1 ? text.length : end;
    const line = text.slice(offset, lineEnd).replace(/\r$/u, "");
    lines.push({ line, offset });
    if (end === -1) {
      break;
    }
    offset = end + 1;
  }
  return lines;
}

function safeRecordedOffsets(
  text: string,
  dependencies: readonly Dependency[],
): Map<string, number> {
  const offsets = new Map<string, number>();
  for (const dependency of dependencies.slice(0, MAXIMUM_REQUESTS)) {
    const name = dependency.manifestName ?? dependency.name;
    const candidate = dependency.metadata?.sourceOffset;
    if (
      typeof candidate === "number" &&
      Number.isSafeInteger(candidate) &&
      candidate >= 0 &&
      candidate + name.length <= text.length &&
      text.slice(candidate, candidate + name.length) === name
    ) {
      offsets.set(name, candidate);
    }
  }
  return offsets;
}

function locateRequirements(
  text: string,
  names: ReadonlySet<string>,
): Map<string, number> {
  const offsets = new Map<string, number>();
  for (const { line, offset } of linesWithOffsets(text)) {
    const comment = unquotedCommentIndex(line, "#");
    const source = (comment === -1 ? line : line.slice(0, comment)).trimStart();
    if (source.length === 0 || source.startsWith("-")) {
      continue;
    }
    const leading = line.length - line.trimStart().length;
    const match = /^[A-Za-z0-9][A-Za-z0-9._-]*/u.exec(source);
    const name = match?.[0];
    if (name !== undefined && names.has(name)) {
      offsets.set(name, offset + leading);
    }
  }
  return offsets;
}

function tomlSectionSupported(manager: string, section: string): boolean {
  const normalized = section.toLowerCase();
  if (manager === "poetry") {
    return (
      normalized === "tool.poetry.dependencies" ||
      /^tool\.poetry\.group\.[^.]+\.dependencies$/u.test(normalized)
    );
  }
  if (manager === "pipenv") {
    return normalized === "packages" || normalized === "dev-packages";
  }
  if (manager === "cargo") {
    return (
      normalized === "dependencies" ||
      normalized === "dev-dependencies" ||
      normalized === "build-dependencies" ||
      normalized === "workspace.dependencies" ||
      /\.dependencies$/u.test(normalized)
    );
  }
  return false;
}

function locateToml(
  text: string,
  names: ReadonlySet<string>,
  manager: string,
): Map<string, number> {
  const offsets = new Map<string, number>();
  let section = "";
  for (const { line, offset } of linesWithOffsets(text)) {
    const comment = unquotedCommentIndex(line, "#");
    const source = comment === -1 ? line : line.slice(0, comment);
    const trimmed = source.trim();
    if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
      section = trimmed.replace(/^\[+/u, "").replace(/\]+$/u, "").trim();
      continue;
    }
    if (!tomlSectionSupported(manager, section)) {
      continue;
    }
    const equals = source.indexOf("=");
    if (equals <= 0) {
      continue;
    }
    const rawKey = source.slice(0, equals).trim();
    const key =
      (rawKey.startsWith('"') && rawKey.endsWith('"')) ||
      (rawKey.startsWith("'") && rawKey.endsWith("'"))
        ? rawKey.slice(1, -1)
        : rawKey;
    if (!names.has(key) || !source.includes(key)) {
      continue;
    }
    const keyOffset = source.indexOf(key);
    if (keyOffset >= 0) {
      offsets.set(key, offset + keyOffset);
    }
  }
  return offsets;
}

function locateGoMod(
  text: string,
  names: ReadonlySet<string>,
): Map<string, number> {
  const offsets = new Map<string, number>();
  let requireBlock = false;
  for (const { line, offset } of linesWithOffsets(text)) {
    const comment = unquotedCommentIndex(line, "//");
    const source = (comment === -1 ? line : line.slice(0, comment)).trim();
    if (source === "require (") {
      requireBlock = true;
      continue;
    }
    if (requireBlock && source === ")") {
      requireBlock = false;
      continue;
    }
    const declaration = requireBlock
      ? source
      : source.startsWith("require ")
        ? source.slice("require ".length).trim()
        : "";
    const name = declaration.split(/\s+/u)[0];
    if (name !== undefined && names.has(name)) {
      const local = line.indexOf(name);
      if (local >= 0) {
        offsets.set(name, offset + local);
      }
    }
  }
  return offsets;
}

function locateGradle(
  text: string,
  names: ReadonlySet<string>,
): Map<string, number> {
  const offsets = new Map<string, number>();
  for (const { line, offset } of linesWithOffsets(text)) {
    const comment = unquotedCommentIndex(line, "//");
    const source = comment === -1 ? line : line.slice(0, comment);
    for (const match of source.matchAll(/(["'])([^"'\\]{1,1024})\1/gu)) {
      const coordinate = match[2];
      if (coordinate === undefined) {
        continue;
      }
      const parts = coordinate.split(":");
      const name = parts.length >= 2 ? `${parts[0]}:${parts[1]}` : undefined;
      if (name !== undefined && names.has(name)) {
        const local = (match.index ?? 0) + 1;
        offsets.set(name, offset + local);
      }
    }
  }
  return offsets;
}

function locateXml(
  text: string,
  names: ReadonlySet<string>,
  manager: string,
): Map<string, number> {
  const offsets = new Map<string, number>();
  for (const { line, offset } of linesWithOffsets(text)) {
    if (manager === "nuget") {
      for (const attribute of ["Include", "Update", "id"]) {
        for (const quote of ['"', "'"]) {
          const prefix = `${attribute}=${quote}`;
          let start = line.indexOf(prefix);
          while (start >= 0) {
            const valueStart = start + prefix.length;
            const end = line.indexOf(quote, valueStart);
            if (end === -1) {
              break;
            }
            const name = line.slice(valueStart, end);
            if (names.has(name)) {
              offsets.set(name, offset + valueStart);
            }
            start = line.indexOf(prefix, end + 1);
          }
        }
      }
      continue;
    }
    const open = "<artifactId>";
    const close = "</artifactId>";
    let start = line.indexOf(open);
    while (start >= 0) {
      const valueStart = start + open.length;
      const end = line.indexOf(close, valueStart);
      if (end === -1) {
        break;
      }
      const artifact = line.slice(valueStart, end).trim();
      const whitespace = line.slice(valueStart, end).indexOf(artifact);
      // Full Maven coordinates cannot be highlighted with a safe source
      // length. Adapters set manifestName=artifactId; otherwise no diagnostic
      // is published.
      if (names.has(artifact)) {
        offsets.set(artifact, offset + valueStart + whitespace);
      }
      start = line.indexOf(open, end + close.length);
    }
  }
  return offsets;
}

export function findManifestDependencyOffsets(
  text: string,
  manifestPath: string,
  dependencies: readonly Dependency[],
): ReadonlyMap<string, number> {
  if (text.length === 0 || text.length > MAXIMUM_TEXT_LENGTH) {
    return new Map();
  }
  const names = requestedNames(dependencies);
  if (names.size === 0) {
    return new Map();
  }
  const recorded = safeRecordedOffsets(text, dependencies);
  const manager = dependencies[0]?.packageManager?.toLowerCase() ?? "";
  let located: ReadonlyMap<string, number>;
  if (manager === "composer") {
    located = findDependencyOffsetsInSections(text, [...names], [
      "require",
      "require-dev",
    ]);
  } else if (["npm", "yarn", "pnpm", "bun"].includes(manager)) {
    located = findDependencyOffsets(text, [...names]);
  } else if (manager === "pip") {
    located = locateRequirements(text, names);
  } else if (["poetry", "pipenv", "cargo"].includes(manager)) {
    located = locateToml(text, names, manager);
  } else if (manager === "go") {
    located = locateGoMod(text, names);
  } else if (manager === "gradle") {
    located = locateGradle(text, names);
  } else if (manager === "maven" || manager === "nuget") {
    located = locateXml(text, names, manager);
  } else if (manifestPath.toLowerCase().endsWith(".json")) {
    located = findDependencyOffsets(text, [...names]);
  } else {
    located = new Map();
  }
  for (const [name, offset] of located) {
    if (!recorded.has(name)) {
      recorded.set(name, offset);
    }
  }
  return recorded;
}
