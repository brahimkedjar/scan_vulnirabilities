import type {
  Dependency,
  DependencyEnvironment,
  DependencyMetadataValue,
} from "../../models/Dependency";
import type { ScanError } from "../../models/ScanResult";
import { MAX_PARSED_DEPENDENCIES } from "./parserLimits";

const MAX_LOGICAL_LINES = MAX_PARSED_DEPENDENCIES;
const MAX_LOGICAL_LINE_LENGTH = 64 * 1024;
const PYTHON_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?/u;
const EXACT_VERSION = /^={2,3}\s*([A-Za-z0-9][A-Za-z0-9.!+_-]{0,254})$/u;

export interface RequirementsParseInput {
  readonly text: string;
  readonly manifestPath: string;
  readonly projectPath: string;
  readonly workspacePath: string;
  readonly environment: DependencyEnvironment;
  readonly signal?: AbortSignal;
}

export interface RequirementsParseResult {
  readonly dependencies: readonly Dependency[];
  readonly errors: readonly ScanError[];
  readonly includes: readonly string[];
  readonly truncated: boolean;
}

export function normalizePythonName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/gu, "-");
}

function logicalLines(text: string): {
  readonly lines: readonly { readonly text: string; readonly line: number }[];
  readonly truncated: boolean;
} {
  const physical = text.split(/\r?\n/u);
  const retained = physical.slice(0, MAX_LOGICAL_LINES);
  const lines: Array<{ readonly text: string; readonly line: number }> = [];
  let current = "";
  let startLine = 1;
  for (let index = 0; index < retained.length; index += 1) {
    const raw = retained[index] ?? "";
    if (current.length === 0) {
      startLine = index + 1;
    }
    const continued = /(?<!\\)\\\s*$/u.test(raw);
    const part = continued ? raw.replace(/\\\s*$/u, "") : raw;
    current += part;
    if (!continued) {
      lines.push({
        text: current.slice(0, MAX_LOGICAL_LINE_LENGTH + 1),
        line: startLine,
      });
      current = "";
    }
  }
  if (current.length > 0) {
    lines.push({ text: current, line: startLine });
  }
  return { lines, truncated: physical.length > MAX_LOGICAL_LINES };
}

function stripInlineComment(line: string): string {
  let quote: "'" | '"' | undefined;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (character === "'" || character === '"') {
      quote = quote === undefined ? character : quote === character ? undefined : quote;
      continue;
    }
    if (
      character === "#" &&
      quote === undefined &&
      (index === 0 || /\s/u.test(line[index - 1] ?? ""))
    ) {
      return line.slice(0, index).trim();
    }
  }
  return line.trim();
}

function splitMarker(value: string): {
  readonly requirement: string;
  readonly marker?: string;
} {
  let quote: "'" | '"' | undefined;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character === "'" || character === '"') {
      quote = quote === undefined ? character : quote === character ? undefined : quote;
    } else if (character === ";" && quote === undefined) {
      const marker = value.slice(index + 1).trim();
      return {
        requirement: value.slice(0, index).trim(),
        ...(marker.length > 0 ? { marker } : {}),
      };
    }
  }
  return { requirement: value.trim() };
}

function withoutHashes(value: string): string {
  return value.replace(/\s+--hash(?:=|\s+)\S+/gu, "").trim();
}

function usesUnsupportedPackageSource(line: string): boolean {
  if (
    /^--no-index/u.test(line) ||
    /^-f/u.test(line) ||
    /^--find-links/u.test(line)
  ) {
    return true;
  }
  if (!/^--(?:extra-)?index-url/u.test(line)) {
    return false;
  }
  const match = /^--(?:extra-)?index-url(?:=|\s+)(\S+)/u.exec(line);
  return (
    match?.[1] === undefined ||
    !/^https:\/\/(?:pypi\.org\/simple|files\.pythonhosted\.org)(?:\/|$)/iu.test(
      match[1],
    )
  );
}

function metadata(
  extras: readonly string[],
  marker: string | undefined,
  line: number,
): Readonly<Record<string, DependencyMetadataValue>> {
  return {
    sourceLine: line,
    ...(extras.length > 0 ? { extras } : {}),
    ...(marker === undefined ? {} : { marker }),
  };
}

export function parseRequirements(
  input: RequirementsParseInput,
): RequirementsParseResult {
  const dependencies: Dependency[] = [];
  const errors: ScanError[] = [];
  const includes: string[] = [];
  const prepared = logicalLines(input.text);
  let truncated = prepared.truncated;
  const unsupportedPackageSource = prepared.lines.some((logical) => {
    const line = stripInlineComment(logical.text);
    return usesUnsupportedPackageSource(line);
  });

  for (const logical of prepared.lines) {
    if (input.signal?.aborted === true) {
      return { dependencies: [], errors, includes, truncated };
    }
    if (logical.text.length > MAX_LOGICAL_LINE_LENGTH) {
      truncated = true;
      errors.push({
        code: "DEPENDENCY_LIMIT",
        message: `requirements line ${logical.line.toString()} exceeds its length limit`,
        path: input.manifestPath,
      });
      continue;
    }
    const line = stripInlineComment(logical.text);
    if (line.length === 0) {
      continue;
    }
    const includeMatch = /^(?:-r|--requirement)(?:=|\s+)(\S+)$/u.exec(line);
    if (includeMatch?.[1] !== undefined) {
      includes.push(includeMatch[1]);
      continue;
    }
    if (/^(?:-c|--constraint)(?:=|\s+)/u.test(line)) {
      continue;
    }
    if (line.startsWith("-")) {
      if (/^(?:-e|--editable)(?:=|\s+)/u.test(line)) {
        errors.push({
          code: "UNSUPPORTED_PACKAGE_SOURCE",
          message: `editable requirement on line ${logical.line.toString()} cannot be mapped safely to PyPI`,
          path: input.manifestPath,
        });
      }
      continue;
    }

    const split = splitMarker(withoutHashes(line));
    const nameMatch = PYTHON_NAME.exec(split.requirement);
    const rawName = nameMatch?.[0];
    if (rawName === undefined) {
      errors.push({
        code: "INVALID_MANIFEST",
        message: `unsupported or malformed requirement on line ${logical.line.toString()}`,
        path: input.manifestPath,
      });
      continue;
    }
    let remainder = split.requirement.slice(rawName.length).trimStart();
    const extras: string[] = [];
    if (remainder.startsWith("[")) {
      const close = remainder.indexOf("]");
      if (close === -1) {
        errors.push({
          code: "INVALID_MANIFEST",
          message: `unterminated extras on line ${logical.line.toString()}`,
          packageName: rawName,
          path: input.manifestPath,
        });
        continue;
      }
      for (const extra of remainder
        .slice(1, close)
        .split(",")
        .map((value) => value.trim())
        .filter((value) => value.length > 0)) {
        extras.push(normalizePythonName(extra));
      }
      remainder = remainder.slice(close + 1).trim();
    }

    const name = normalizePythonName(rawName);
    const base = {
      name,
      ecosystem: "PyPI",
      manifestName: rawName,
      installedVersion: "",
      dependencyType: "direct" as const,
      environment: input.environment,
      declaredEnvironment: input.environment,
      manifestPath: input.manifestPath,
      packageManager: "pip",
      projectPath: input.projectPath,
      workspacePath: input.workspacePath,
      metadata: metadata(extras, split.marker, logical.line),
    };
    if (remainder.startsWith("@")) {
      dependencies.push({
        ...base,
        requestedVersion: remainder,
        resolutionStatus: "unsupported",
      });
      errors.push({
        code: "UNSUPPORTED_PACKAGE_SOURCE",
        message: "direct URL Python dependency cannot be represented safely as a PyPI release",
        packageName: name,
        path: input.manifestPath,
      });
      continue;
    }
    if (unsupportedPackageSource) {
      dependencies.push({
        ...base,
        ...(remainder.length > 0 ? { requestedVersion: remainder } : {}),
        resolutionStatus: "unsupported",
      });
      errors.push({
        code: "UNSUPPORTED_PACKAGE_SOURCE",
        message: "requirements file changes package sources, so package identity cannot be assumed to be PyPI",
        packageName: name,
        path: input.manifestPath,
      });
      continue;
    }
    const exact = EXACT_VERSION.exec(remainder);
    if (exact?.[1] !== undefined && !exact[1].includes("*")) {
      dependencies.push({
        ...base,
        requestedVersion: remainder,
        installedVersion: exact[1],
        resolutionStatus: "resolved",
        dependencyPath: [input.projectPath, `${name}@${exact[1]}`],
      });
      continue;
    }

    dependencies.push({
      ...base,
      ...(remainder.length > 0 ? { requestedVersion: remainder } : {}),
      resolutionStatus: "unresolved",
    });
    errors.push({
      code: "DEPENDENCY_UNRESOLVED",
      message:
        remainder.length === 0
          ? "requirement does not declare an exact installed version"
          : "requirement range is not an installed version",
      packageName: name,
      path: input.manifestPath,
    });
  }

  if (prepared.truncated) {
    errors.push({
      code: "DEPENDENCY_LIMIT",
      message: "requirements file exceeds its logical-line limit",
      path: input.manifestPath,
    });
  }
  return { dependencies, errors, includes, truncated };
}
