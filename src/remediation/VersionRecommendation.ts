import {
  compare as compareSemver,
  major as semverMajor,
  valid as validSemver,
} from "semver";

import type { SupportedOsvEcosystem } from "../vulnerability/EcosystemMapper";

interface ComparableVersion {
  readonly original: string;
  readonly release: readonly number[];
  readonly compare: (other: ComparableVersion) => number;
  readonly major: number;
}

interface PythonParts {
  readonly epoch: number;
  readonly release: readonly number[];
  readonly preStage: number;
  readonly preNumber: number;
  readonly postNumber: number;
  readonly devNumber: number;
}

const PYTHON_VERSION =
  /^(?:(\d+)!)?(\d+(?:\.\d+)*)(?:(a|b|rc)(\d+))?(?:\.post(\d+))?(?:\.dev(\d+))?$/u;
const NUMERIC_RELEASE = /^\d+(?:\.\d+)*$/u;
const PACKAGIST_VERSION =
  /^v?(\d+(?:\.\d+){0,2})(-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const NUGET_VERSION =
  /^(\d+(?:\.\d+){1,3})(?:-([0-9A-Za-z]+(?:[.-][0-9A-Za-z-]+)*))?$/u;

function safeInteger(value: string): number | undefined {
  if (
    !/^\d+$/u.test(value) ||
    value.length > 15 ||
    (value.length > 1 && value.startsWith("0"))
  ) {
    return undefined;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : undefined;
}

function numericParts(value: string): number[] | undefined {
  const parts = value.split(".").map(safeInteger);
  return parts.every((part): part is number => part !== undefined)
    ? parts
    : undefined;
}

function compareNumericParts(
  left: readonly number[],
  right: readonly number[],
): number {
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) {
      return difference < 0 ? -1 : 1;
    }
  }
  return 0;
}

function comparePrerelease(
  left: string | undefined,
  right: string | undefined,
): number {
  if (left === undefined || right === undefined) {
    return left === right ? 0 : left === undefined ? 1 : -1;
  }
  const leftParts = left.split(/[.-]/u);
  const rightParts = right.split(/[.-]/u);
  const length = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < length; index += 1) {
    const leftPart = leftParts[index];
    const rightPart = rightParts[index];
    if (leftPart === undefined || rightPart === undefined) {
      return leftPart === rightPart ? 0 : leftPart === undefined ? -1 : 1;
    }
    const leftNumber = safeInteger(leftPart);
    const rightNumber = safeInteger(rightPart);
    if (leftNumber !== undefined || rightNumber !== undefined) {
      if (leftNumber === undefined || rightNumber === undefined) {
        return leftNumber === undefined ? 1 : -1;
      }
      if (leftNumber !== rightNumber) {
        return leftNumber < rightNumber ? -1 : 1;
      }
      continue;
    }
    const comparison = leftPart.toLowerCase().localeCompare(
      rightPart.toLowerCase(),
      "en",
    );
    if (comparison !== 0) {
      return comparison < 0 ? -1 : 1;
    }
  }
  return 0;
}

function semverComparable(
  value: string,
  stripPrefix = false,
  allowShort = false,
): ComparableVersion | undefined {
  const unprefixed = stripPrefix && value.startsWith("v") ? value.slice(1) : value;
  const match = allowShort ? PACKAGIST_VERSION.exec(value) : undefined;
  let normalized = match?.[1] ?? unprefixed;
  if (match !== null && match !== undefined) {
    const parts = normalized.split(".");
    while (parts.length < 3) {
      parts.push("0");
    }
    normalized = `${parts.join(".")}${match[2] ?? ""}`;
  }
  const valid = validSemver(normalized);
  if (valid === null || valid !== normalized) {
    return undefined;
  }
  return {
    original: value,
    release: valid.split(/[+-]/u)[0]?.split(".").map(Number) ?? [],
    major: semverMajor(valid),
    compare(other): number {
      const otherComparable = semverComparable(
        other.original,
        stripPrefix,
        allowShort,
      );
      if (otherComparable === undefined) {
        throw new TypeError("Version schemes are not comparable");
      }
      const otherUnprefixed =
        stripPrefix && other.original.startsWith("v")
          ? other.original.slice(1)
          : other.original;
      const otherMatch = allowShort
        ? PACKAGIST_VERSION.exec(other.original)
        : undefined;
      let otherNormalized = otherMatch?.[1] ?? otherUnprefixed;
      if (otherMatch !== null && otherMatch !== undefined) {
        const parts = otherNormalized.split(".");
        while (parts.length < 3) {
          parts.push("0");
        }
        otherNormalized = `${parts.join(".")}${otherMatch[2] ?? ""}`;
      }
      return compareSemver(normalized, otherNormalized);
    },
  };
}

function pythonParts(value: string): PythonParts | undefined {
  const match = PYTHON_VERSION.exec(value);
  const release = match?.[2] === undefined ? undefined : numericParts(match[2]);
  const epoch = safeInteger(match?.[1] ?? "0");
  if (match === null || release === undefined || epoch === undefined) {
    return undefined;
  }
  const preKind = match[3];
  const post = match[5];
  const dev = match[6];
  // PEP 440 permits combined pre/dev and post/dev forms, but their ordering is
  // subtle. Keep those forms manual-review rather than approximating them.
  if (dev !== undefined && (preKind !== undefined || post !== undefined)) {
    return undefined;
  }
  const preStage =
    preKind === "rc"
      ? 2
      : preKind === "b"
        ? 1
        : preKind === "a"
          ? 0
          : dev !== undefined && post === undefined
            ? -1
            : 3;
  const preNumber = safeInteger(match[4] ?? "0");
  const postNumber = post === undefined ? -1 : safeInteger(post);
  const devNumber = dev === undefined ? Number.POSITIVE_INFINITY : safeInteger(dev);
  return preNumber === undefined || postNumber === undefined || devNumber === undefined
    ? undefined
    : { epoch, release, preStage, preNumber, postNumber, devNumber };
}

function comparePythonParts(left: PythonParts, right: PythonParts): number {
  if (left.epoch !== right.epoch) {
    return left.epoch < right.epoch ? -1 : 1;
  }
  const release = compareNumericParts(left.release, right.release);
  if (release !== 0) {
    return release;
  }
  if (left.preStage !== right.preStage) {
    return left.preStage < right.preStage ? -1 : 1;
  }
  if (left.preNumber !== right.preNumber) {
    return left.preNumber < right.preNumber ? -1 : 1;
  }
  if (left.postNumber !== right.postNumber) {
    return left.postNumber < right.postNumber ? -1 : 1;
  }
  if (left.devNumber !== right.devNumber) {
    return left.devNumber < right.devNumber ? -1 : 1;
  }
  return 0;
}

function pythonComparable(value: string): ComparableVersion | undefined {
  const parts = pythonParts(value);
  if (parts === undefined) {
    return undefined;
  }
  return {
    original: value,
    release: parts.release,
    major: parts.release[0] ?? 0,
    compare(other): number {
      const otherParts = pythonParts(other.original);
      if (otherParts === undefined) {
        throw new TypeError("Version schemes are not comparable");
      }
      return comparePythonParts(parts, otherParts);
    },
  };
}

function numericComparable(value: string): ComparableVersion | undefined {
  if (!NUMERIC_RELEASE.test(value)) {
    return undefined;
  }
  const release = numericParts(value);
  if (release === undefined) {
    return undefined;
  }
  return {
    original: value,
    release,
    major: release[0] ?? 0,
    compare(other): number {
      const otherParts = NUMERIC_RELEASE.test(other.original)
        ? numericParts(other.original)
        : undefined;
      if (otherParts === undefined) {
        throw new TypeError("Version schemes are not comparable");
      }
      return compareNumericParts(release, otherParts);
    },
  };
}

function nugetComparable(value: string): ComparableVersion | undefined {
  const match = NUGET_VERSION.exec(value);
  const release = match?.[1] === undefined ? undefined : numericParts(match[1]);
  if (match === null || release === undefined) {
    return undefined;
  }
  const prerelease = match[2];
  if (
    prerelease
      ?.split(/[.-]/u)
      .some(
        (identifier) =>
          /^\d+$/u.test(identifier) && safeInteger(identifier) === undefined,
      ) === true
  ) {
    return undefined;
  }
  return {
    original: value,
    release,
    major: release[0] ?? 0,
    compare(other): number {
      const otherMatch = NUGET_VERSION.exec(other.original);
      const otherRelease =
        otherMatch?.[1] === undefined ? undefined : numericParts(otherMatch[1]);
      if (otherMatch === null || otherRelease === undefined) {
        throw new TypeError("Version schemes are not comparable");
      }
      const releaseComparison = compareNumericParts(release, otherRelease);
      return releaseComparison === 0
        ? comparePrerelease(prerelease, otherMatch[2])
        : releaseComparison;
    },
  };
}

function comparableVersion(
  ecosystem: SupportedOsvEcosystem,
  value: string,
): ComparableVersion | undefined {
  switch (ecosystem) {
    case "npm":
    case "crates.io":
      return semverComparable(value);
    case "Go":
      return value.startsWith("v") ? semverComparable(value, true) : undefined;
    case "Packagist":
      return semverComparable(value, true, true);
    case "PyPI":
      return pythonComparable(value);
    case "Maven":
      // Maven ComparableVersion has qualifier and token rules that are unsafe
      // to approximate. Numeric release coordinates remain unambiguous.
      return numericComparable(value);
    case "NuGet":
      return nugetComparable(value);
  }
}

export interface VersionSelection {
  readonly kind: "selected" | "no-forward-candidate" | "unsupported";
  readonly version?: string;
}

export function compareEcosystemVersions(
  ecosystem: SupportedOsvEcosystem,
  left: string,
  right: string,
): number | undefined {
  const leftVersion = comparableVersion(ecosystem, left);
  const rightVersion = comparableVersion(ecosystem, right);
  if (leftVersion === undefined || rightVersion === undefined) {
    return undefined;
  }
  try {
    return leftVersion.compare(rightVersion);
  } catch {
    return undefined;
  }
}

export function versionMajor(
  ecosystem: SupportedOsvEcosystem,
  value: string,
): number | undefined {
  return comparableVersion(ecosystem, value)?.major;
}

/**
 * Selects only from exact provider-listed candidates. Nothing in this function
 * infers that a later release is safe merely because an earlier fixed event
 * exists.
 */
export function selectRecommendedVersion(
  ecosystem: SupportedOsvEcosystem,
  currentVersion: string,
  fixedVersions: readonly string[],
): VersionSelection {
  const current = comparableVersion(ecosystem, currentVersion);
  if (current === undefined) {
    return { kind: "unsupported" };
  }
  const candidates: Array<{ readonly value: string; readonly parsed: ComparableVersion }> = [];
  for (const value of [...new Set(fixedVersions)]) {
    const parsed = comparableVersion(ecosystem, value);
    if (parsed === undefined) {
      return { kind: "unsupported" };
    }
    let comparison: number;
    try {
      comparison = parsed.compare(current);
    } catch {
      return { kind: "unsupported" };
    }
    if (comparison > 0) {
      candidates.push({ value, parsed });
    }
  }
  if (candidates.length === 0) {
    return { kind: "no-forward-candidate" };
  }
  const sameMajor = candidates.filter(
    (candidate) => candidate.parsed.major === current.major,
  );
  const pool = sameMajor.length > 0 ? sameMajor : candidates;
  pool.sort((left, right) => {
    const compared = left.parsed.compare(right.parsed);
    return compared === 0 ? left.value.localeCompare(right.value, "en") : compared;
  });
  const selected = pool[0];
  return selected === undefined
    ? { kind: "no-forward-candidate" }
    : { kind: "selected", version: selected.value };
}

export function intersectFixedVersions(
  versionSets: readonly (readonly string[])[],
): string[] {
  const first = versionSets[0];
  if (first === undefined) {
    return [];
  }
  const remaining = versionSets.slice(1).map((values) => new Set(values));
  return [...new Set(first)].filter((candidate) =>
    remaining.every((values) => values.has(candidate)),
  );
}
