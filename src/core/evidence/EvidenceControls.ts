const UNSAFE_TEXT =
  /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u;

const ABSOLUTE_OR_URI = /^(?:[a-zA-Z]:[\\/]|[\\/]{1,2}|[a-zA-Z][a-zA-Z0-9+.-]*:)/u;

/** Returns a bounded value only when it is safe to retain as evidence. */
export function boundedEvidenceText(
  value: unknown,
  maximumLength: number,
): string | undefined {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumLength ||
    UNSAFE_TEXT.test(value)
  ) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length === 0 ? undefined : trimmed;
}

/**
 * Retains only relative, traversal-free identifiers. This prevents host paths,
 * URI credentials, and control sequences from entering reports or snapshots.
 */
export function boundedRelativeId(
  value: unknown,
  maximumLength = 512,
): string | undefined {
  const text = boundedEvidenceText(value, maximumLength);
  if (text === undefined || ABSOLUTE_OR_URI.test(text)) {
    return undefined;
  }
  const normalized = text.replaceAll("\\", "/");
  const segments = normalized.split("/");
  if (
    segments.some(
      (segment) =>
        segment.length === 0 || segment === "." || segment === "..",
    )
  ) {
    return undefined;
  }
  return normalized;
}

/** Retains an opaque identifier while refusing values shaped like host paths or URLs. */
export function boundedOpaqueId(
  value: unknown,
  maximumLength = 512,
): string | undefined {
  const text = boundedEvidenceText(value, maximumLength);
  if (
    text === undefined ||
    /^(?:[a-zA-Z]:[\\/]|[\\/]|file:)/iu.test(text) ||
    text.includes("\\") ||
    text.includes("://") ||
    text.split("/").some((segment) => segment === "." || segment === "..")
  ) {
    return undefined;
  }
  return text;
}

export function boundedPositiveLimit(
  value: unknown,
  fallback: number,
  hardMaximum: number,
): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0
    ? Math.min(value, hardMaximum)
    : fallback;
}

export function isAnalysisCancelled(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
}

export function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function freezeStrings(values: readonly string[]): readonly string[] {
  return Object.freeze([...values]);
}
