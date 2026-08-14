import {
  BoundedJsonError,
  canonicalJson,
  deepFreezeJson,
  parseBoundedJson,
  sha256CanonicalJson,
  type JsonValue,
  type ParseBoundedJsonOptions,
} from "../security/BoundedJson";
import {
  parseSecuritySnapshotJson,
  SecuritySnapshotError,
  serializeSecuritySnapshot,
  type SecuritySnapshot,
} from "./SecuritySnapshot";

export const SECURITY_BASELINE_SCHEMA =
  "dependency-auditor/security-baseline" as const;
export const SECURITY_BASELINE_SCHEMA_VERSION = 1 as const;

export interface SecurityBaseline {
  readonly schema: typeof SECURITY_BASELINE_SCHEMA;
  readonly schemaVersion: typeof SECURITY_BASELINE_SCHEMA_VERSION;
  readonly createdAt: string;
  readonly snapshot: SecuritySnapshot;
  readonly integrity: Readonly<{
    algorithm: "SHA-256";
    digest: string;
  }>;
}

export type SecurityBaselineErrorCode =
  | "CANCELLED"
  | "INVALID_INPUT"
  | "LIMIT_EXCEEDED"
  | "INTEGRITY_MISMATCH";

export class SecurityBaselineError extends Error {
  public constructor(
    public readonly code: SecurityBaselineErrorCode,
    message: string,
    options: { readonly cause?: unknown } = {},
  ) {
    super(message, options);
    this.name = "SecurityBaselineError";
  }
}

const RFC3339_UTC =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

function json(value: unknown): JsonValue {
  return value as JsonValue;
}

function validTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 128) {
    return false;
  }
  const match = RFC3339_UTC.exec(value);
  const parsed = Date.parse(value);
  if (match === null || !Number.isFinite(parsed)) {
    return false;
  }
  const date = new Date(parsed);
  const expected = match.slice(1, 7).map(Number);
  const actual = [
    date.getUTCFullYear(),
    date.getUTCMonth() + 1,
    date.getUTCDate(),
    date.getUTCHours(),
    date.getUTCMinutes(),
    date.getUTCSeconds(),
  ];
  return !expected.some((part, index) => part !== actual[index]);
}

function payload(baseline: SecurityBaseline): JsonValue {
  return json({
    schema: baseline.schema,
    schemaVersion: baseline.schemaVersion,
    createdAt: baseline.createdAt,
    snapshot: baseline.snapshot,
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const keys = [...expected].sort();
  return actual.length === keys.length && actual.every((key, index) => key === keys[index]);
}

export function createSecurityBaseline(
  snapshot: SecuritySnapshot,
  options: { readonly createdAt: string },
): SecurityBaseline {
  // Parsing the canonical form verifies nested hashes and rejects mutated
  // objects before they become accepted baseline evidence.
  const verified = parseSecuritySnapshotJson(serializeSecuritySnapshot(snapshot));
  if (!validTimestamp(options.createdAt)) {
    throw new SecurityBaselineError(
      "INVALID_INPUT",
      "Baseline creation timestamp is invalid",
    );
  }
  const partial = {
    schema: SECURITY_BASELINE_SCHEMA,
    schemaVersion: SECURITY_BASELINE_SCHEMA_VERSION,
    createdAt: options.createdAt,
    snapshot: verified,
  };
  const baseline: SecurityBaseline = {
    ...partial,
    integrity: Object.freeze({
      algorithm: "SHA-256" as const,
      digest: sha256CanonicalJson(json(partial)),
    }),
  };
  return deepFreezeJson(json(baseline)) as unknown as SecurityBaseline;
}

function parseValue(
  value: JsonValue,
  options: ParseBoundedJsonOptions,
): SecurityBaseline {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "schema",
      "schemaVersion",
      "createdAt",
      "snapshot",
      "integrity",
    ]) ||
    value.schema !== SECURITY_BASELINE_SCHEMA ||
    value.schemaVersion !== SECURITY_BASELINE_SCHEMA_VERSION ||
    !validTimestamp(value.createdAt) ||
    !isRecord(value.integrity) ||
    !hasExactKeys(value.integrity, ["algorithm", "digest"]) ||
    value.integrity.algorithm !== "SHA-256" ||
    typeof value.integrity.digest !== "string" ||
    !SHA256.test(value.integrity.digest)
  ) {
    throw new SecurityBaselineError(
      "INVALID_INPUT",
      "Security baseline has an invalid shape",
    );
  }
  const snapshot = parseSecuritySnapshotJson(canonicalJson(json(value.snapshot)), options);
  const baseline: SecurityBaseline = {
    schema: SECURITY_BASELINE_SCHEMA,
    schemaVersion: SECURITY_BASELINE_SCHEMA_VERSION,
    createdAt: value.createdAt,
    snapshot,
    integrity: Object.freeze({
      algorithm: "SHA-256" as const,
      digest: value.integrity.digest,
    }),
  };
  if (sha256CanonicalJson(payload(baseline)) !== baseline.integrity.digest) {
    throw new SecurityBaselineError(
      "INTEGRITY_MISMATCH",
      "Security baseline SHA-256 verification failed",
    );
  }
  return deepFreezeJson(json(baseline)) as unknown as SecurityBaseline;
}

export function parseSecurityBaselineJson(
  text: string,
  options: ParseBoundedJsonOptions = {},
): SecurityBaseline {
  try {
    return parseValue(parseBoundedJson(text, options), options);
  } catch (error: unknown) {
    if (error instanceof SecurityBaselineError) {
      throw error;
    }
    if (error instanceof SecuritySnapshotError) {
      throw new SecurityBaselineError(
        error.code === "CANCELLED"
          ? "CANCELLED"
          : error.code === "LIMIT_EXCEEDED"
            ? "LIMIT_EXCEEDED"
            : error.code === "INTEGRITY_MISMATCH"
              ? "INTEGRITY_MISMATCH"
              : "INVALID_INPUT",
        error.message,
        { cause: error },
      );
    }
    if (error instanceof BoundedJsonError) {
      throw new SecurityBaselineError(
        error.code === "CANCELLED"
          ? "CANCELLED"
          : error.code === "LIMIT_EXCEEDED"
            ? "LIMIT_EXCEEDED"
            : "INVALID_INPUT",
        error.message,
        { cause: error },
      );
    }
    throw new SecurityBaselineError(
      "INVALID_INPUT",
      "Security baseline could not be parsed safely",
      { cause: error },
    );
  }
}

export function verifySecurityBaseline(baseline: SecurityBaseline): boolean {
  try {
    parseSecurityBaselineJson(canonicalJson(json(baseline)));
    return true;
  } catch {
    return false;
  }
}

export function serializeSecurityBaseline(baseline: SecurityBaseline): string {
  if (!verifySecurityBaseline(baseline)) {
    throw new SecurityBaselineError(
      "INTEGRITY_MISMATCH",
      "Refusing to serialize an invalid security baseline",
    );
  }
  return `${canonicalJson(json(baseline))}\n`;
}
