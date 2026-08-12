import { createHash } from "node:crypto";
import path from "node:path";

import type { Dependency } from "../models/Dependency";
import {
  mapDependencyToOsv,
  type SupportedOsvEcosystem,
} from "../vulnerability/EcosystemMapper";

export interface CanonicalComponentIdentity {
  readonly ecosystem: SupportedOsvEcosystem;
  readonly name: string;
  readonly version: string;
}

export interface ComponentDisplayIdentity {
  readonly group?: string;
  readonly name: string;
}

const MAXIMUM_PATH_LENGTH = 4_096;
const MAXIMUM_WORKSPACE_ROOTS = 64;
const UNSAFE_TEXT =
  /[\u0000-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;
const URI_SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:/u;
const WINDOWS_ABSOLUTE = /^(?:[A-Za-z]:[\\/]|[\\/]{2})/u;

function encodePurlPart(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/gu, (character) =>
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function encodePathSegments(segments: readonly string[]): string {
  return segments.map(encodePurlPart).join("/");
}

export function canonicalComponentIdentity(
  dependency: Dependency,
): CanonicalComponentIdentity {
  const mapped = mapDependencyToOsv(dependency);
  if (!mapped.supported) {
    throw new TypeError(`Dependency has no canonical package identity: ${mapped.reason}`);
  }
  return {
    ecosystem: mapped.identity.ecosystem,
    name: mapped.identity.packageName,
    version: mapped.identity.version,
  };
}

export function canonicalComponentIdentityForCoordinate(
  ecosystem: string,
  name: string,
  version: string,
): CanonicalComponentIdentity {
  return canonicalComponentIdentity({
    ecosystem,
    name,
    installedVersion: version,
    resolutionStatus: "resolved",
    dependencyType: "direct",
    environment: "production",
  });
}

export function componentCoordinateKey(
  identity: CanonicalComponentIdentity,
): string {
  return JSON.stringify([identity.ecosystem, identity.name, identity.version]);
}

export function stableSha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function componentBomRef(identity: CanonicalComponentIdentity): string {
  return `urn:dependency-auditor:component:sha256:${stableSha256(componentCoordinateKey(identity))}`;
}

export function packageUrlForIdentity(
  identity: CanonicalComponentIdentity,
): string {
  const version = encodePurlPart(identity.version);
  switch (identity.ecosystem) {
    case "npm": {
      if (identity.name.startsWith("@")) {
        const slash = identity.name.indexOf("/");
        if (slash <= 1 || slash === identity.name.length - 1) {
          throw new TypeError("Scoped npm package identity is invalid");
        }
        const namespace = identity.name.slice(0, slash);
        const name = identity.name.slice(slash + 1);
        return `pkg:npm/${encodePurlPart(namespace)}/${encodePurlPart(name)}@${version}`;
      }
      return `pkg:npm/${encodePurlPart(identity.name)}@${version}`;
    }
    case "PyPI":
      return `pkg:pypi/${encodePurlPart(identity.name)}@${version}`;
    case "Maven": {
      const separator = identity.name.indexOf(":");
      if (separator <= 0 || separator === identity.name.length - 1) {
        throw new TypeError("Maven package identity is invalid");
      }
      return `pkg:maven/${encodePurlPart(identity.name.slice(0, separator))}/${encodePurlPart(identity.name.slice(separator + 1))}@${version}`;
    }
    case "crates.io":
      return `pkg:cargo/${encodePurlPart(identity.name)}@${version}`;
    case "Go": {
      const segments = identity.name.split("/");
      return `pkg:golang/${encodePathSegments(segments)}@${version}`;
    }
    case "NuGet":
      return `pkg:nuget/${encodePurlPart(identity.name)}@${version}`;
    case "Packagist": {
      const separator = identity.name.indexOf("/");
      if (separator <= 0 || separator === identity.name.length - 1) {
        throw new TypeError("Composer package identity is invalid");
      }
      return `pkg:composer/${encodePurlPart(identity.name.slice(0, separator))}/${encodePurlPart(identity.name.slice(separator + 1))}@${version}`;
    }
  }
}

export function componentDisplayIdentity(
  identity: CanonicalComponentIdentity,
): ComponentDisplayIdentity {
  switch (identity.ecosystem) {
    case "npm": {
      const separator = identity.name.startsWith("@")
        ? identity.name.indexOf("/")
        : -1;
      return separator > 0
        ? {
            group: identity.name.slice(0, separator),
            name: identity.name.slice(separator + 1),
          }
        : { name: identity.name };
    }
    case "Maven": {
      const separator = identity.name.indexOf(":");
      return {
        group: identity.name.slice(0, separator),
        name: identity.name.slice(separator + 1),
      };
    }
    case "Packagist": {
      const separator = identity.name.indexOf("/");
      return {
        group: identity.name.slice(0, separator),
        name: identity.name.slice(separator + 1),
      };
    }
    case "Go": {
      const separator = identity.name.lastIndexOf("/");
      return separator > 0
        ? {
            group: identity.name.slice(0, separator),
            name: identity.name.slice(separator + 1),
          }
        : { name: identity.name };
    }
    case "PyPI":
    case "crates.io":
    case "NuGet":
      return { name: identity.name };
  }
}

function safeRelativePath(value: string): string | undefined {
  if (
    value.length === 0 ||
    value.length > MAXIMUM_PATH_LENGTH ||
    UNSAFE_TEXT.test(value) ||
    URI_SCHEME.test(value) ||
    value.startsWith("/") ||
    value.startsWith("\\")
  ) {
    return undefined;
  }
  const segments = value.replaceAll("\\", "/").split("/");
  const normalized: string[] = [];
  for (const segment of segments) {
    if (segment.length === 0 || segment === ".") {
      continue;
    }
    if (segment === ".." || UNSAFE_TEXT.test(segment)) {
      return undefined;
    }
    normalized.push(segment);
  }
  const result = normalized.join("/");
  return result.length > 0 && result.length <= MAXIMUM_PATH_LENGTH
    ? result
    : undefined;
}

function relativeWindowsPath(
  candidate: string,
  workspaceRoot: string,
): string | undefined {
  if (
    !WINDOWS_ABSOLUTE.test(candidate) ||
    !WINDOWS_ABSOLUTE.test(workspaceRoot)
  ) {
    return undefined;
  }
  const normalizedCandidate = path.win32.normalize(candidate);
  const normalizedRoot = path.win32.normalize(workspaceRoot).replace(
    /[\\/]+$/u,
    "",
  );
  const candidateKey = normalizedCandidate.toLocaleLowerCase("en-US");
  const rootKey = normalizedRoot.toLocaleLowerCase("en-US");
  if (candidateKey === rootKey) {
    return undefined;
  }
  const prefix = `${rootKey}\\`;
  if (!candidateKey.startsWith(prefix)) {
    return undefined;
  }
  return safeRelativePath(normalizedCandidate.slice(normalizedRoot.length + 1));
}

function relativePosixPath(
  candidate: string,
  workspaceRoot: string,
): string | undefined {
  if (!candidate.startsWith("/") || !workspaceRoot.startsWith("/")) {
    return undefined;
  }
  const normalizedCandidate = path.posix.normalize(candidate);
  const normalizedRoot = path.posix.normalize(workspaceRoot).replace(/\/+$/u, "");
  if (
    normalizedCandidate === normalizedRoot ||
    !normalizedCandidate.startsWith(`${normalizedRoot}/`)
  ) {
    return undefined;
  }
  return safeRelativePath(normalizedCandidate.slice(normalizedRoot.length + 1));
}

interface NormalizedWorkspaceRoot {
  readonly path: string;
  readonly key: string;
}

function normalizedWorkspaceRoots(
  workspaceRoots: readonly string[],
): readonly NormalizedWorkspaceRoot[] {
  const roots = new Map<string, NormalizedWorkspaceRoot>();
  for (const workspaceRoot of workspaceRoots) {
    if (
      workspaceRoot.length === 0 ||
      workspaceRoot.length > MAXIMUM_PATH_LENGTH ||
      UNSAFE_TEXT.test(workspaceRoot)
    ) {
      continue;
    }
    if (WINDOWS_ABSOLUTE.test(workspaceRoot)) {
      const normalized = path.win32
        .normalize(workspaceRoot)
        .replace(/[\\/]+$/u, "");
      const key = `windows:${normalized.toLocaleLowerCase("en-US")}`;
      if (!roots.has(key)) {
        roots.set(key, { path: normalized, key });
      }
    } else if (workspaceRoot.startsWith("/")) {
      const normalized = path.posix.normalize(workspaceRoot).replace(/\/+$/u, "");
      const key = `posix:${normalized}`;
      if (!roots.has(key)) {
        roots.set(key, { path: normalized, key });
      }
    }
  }
  return [...roots.values()].sort((left, right) =>
    left.key.localeCompare(right.key, "en"),
  );
}

/**
 * Returns a normalized workspace-relative path or `undefined`. Absolute paths,
 * authorities, drive names, and workspace roots are never returned.
 */
export function safeWorkspaceRelativePath(
  candidate: string | undefined,
  workspaceRoots: readonly string[] = [],
): string | undefined {
  if (
    candidate === undefined ||
    candidate.length === 0 ||
    candidate.length > MAXIMUM_PATH_LENGTH ||
    UNSAFE_TEXT.test(candidate) ||
    workspaceRoots.length > MAXIMUM_WORKSPACE_ROOTS
  ) {
    return undefined;
  }
  if (!WINDOWS_ABSOLUTE.test(candidate) && !candidate.startsWith("/")) {
    return safeRelativePath(candidate);
  }

  const normalizedRoots = normalizedWorkspaceRoots(workspaceRoots);
  let selected: { readonly relative: string; readonly rootIndex: number } | undefined;
  for (let rootIndex = 0; rootIndex < normalizedRoots.length; rootIndex += 1) {
    const workspaceRoot = normalizedRoots[rootIndex];
    if (workspaceRoot === undefined) {
      continue;
    }
    const relative = WINDOWS_ABSOLUTE.test(candidate)
      ? relativeWindowsPath(candidate, workspaceRoot.path)
      : relativePosixPath(candidate, workspaceRoot.path);
    if (
      relative !== undefined &&
      (selected === undefined || relative.length < selected.relative.length)
    ) {
      selected = { relative, rootIndex };
    }
  }
  if (selected === undefined) {
    return undefined;
  }
  if (normalizedRoots.length < 2) {
    return selected.relative;
  }
  const qualified = `workspace-root-${(selected.rootIndex + 1).toString()}/${selected.relative}`;
  return qualified.length <= MAXIMUM_PATH_LENGTH ? qualified : undefined;
}

/** A relative path encoded as an RFC 3986 URI reference for SARIF. */
export function safeRelativeArtifactUri(
  candidate: string | undefined,
  workspaceRoots: readonly string[] = [],
): string | undefined {
  const relative = safeWorkspaceRelativePath(candidate, workspaceRoots);
  return relative === undefined
    ? undefined
    : relative.split("/").map(encodePurlPart).join("/");
}
