import { createHash } from "node:crypto";

import {
  parseTree,
  printParseErrorCode,
  type Node as JsonNode,
  type ParseError,
} from "jsonc-parser";

export type JsonPrimitive = null | boolean | number | string;
export type JsonValue =
  | JsonPrimitive
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

export interface BoundedJsonLimits {
  readonly maximumBytes: number;
  readonly maximumDepth: number;
  readonly maximumNodes: number;
  readonly maximumObjectProperties: number;
  readonly maximumArrayItems: number;
  readonly maximumStringLength: number;
}

export interface ParseBoundedJsonOptions {
  readonly signal?: AbortSignal;
  readonly limits?: Partial<BoundedJsonLimits>;
}

export type BoundedJsonErrorCode =
  | "CANCELLED"
  | "INVALID_JSON"
  | "LIMIT_EXCEEDED"
  | "UNSAFE_KEY"
  | "UNSAFE_VALUE";

export class BoundedJsonError extends Error {
  public constructor(
    public readonly code: BoundedJsonErrorCode,
    message: string,
    options: { readonly cause?: unknown } = {},
  ) {
    super(message, options);
    this.name = "BoundedJsonError";
  }
}

export const BOUNDED_JSON_LIMITS: Readonly<BoundedJsonLimits> = Object.freeze({
  maximumBytes: 32 * 1024 * 1024,
  maximumDepth: 64,
  maximumNodes: 1_000_000,
  maximumObjectProperties: 100_000,
  maximumArrayItems: 250_000,
  maximumStringLength: 1024 * 1024,
});

const LIMIT_KEYS = Object.freeze([
  "maximumBytes",
  "maximumDepth",
  "maximumNodes",
  "maximumObjectProperties",
  "maximumArrayItems",
  "maximumStringLength",
] as const satisfies readonly (keyof BoundedJsonLimits)[]);
const FORBIDDEN_KEYS: ReadonlySet<string> = new Set([
  "__proto__",
  "prototype",
  "constructor",
]);
const UNSAFE_KEY_TEXT =
  /[\u0000-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function throwIfCancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw new BoundedJsonError("CANCELLED", "JSON processing was cancelled");
  }
}

function resolveLimits(
  requested: Partial<BoundedJsonLimits> | undefined,
): BoundedJsonLimits {
  const resolved = { ...BOUNDED_JSON_LIMITS };
  for (const key of LIMIT_KEYS) {
    const value = requested?.[key];
    if (value === undefined) {
      continue;
    }
    if (
      !Number.isSafeInteger(value) ||
      value < 1 ||
      value > BOUNDED_JSON_LIMITS[key]
    ) {
      throw new BoundedJsonError(
        "LIMIT_EXCEEDED",
        `${key} is outside the supported safety range`,
      );
    }
    resolved[key] = value;
  }
  return Object.freeze(resolved);
}

interface PendingNode {
  readonly node: JsonNode;
  readonly depth: number;
}

function validateSyntaxTree(
  root: JsonNode,
  limits: BoundedJsonLimits,
  signal: AbortSignal | undefined,
): void {
  const pending: PendingNode[] = [{ node: root, depth: 1 }];
  let nodes = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined) {
      continue;
    }
    nodes += 1;
    if ((nodes & 255) === 0) {
      throwIfCancelled(signal);
    }
    if (nodes > limits.maximumNodes) {
      throw new BoundedJsonError(
        "LIMIT_EXCEEDED",
        "JSON node count exceeds the safety limit",
      );
    }
    if (current.depth > limits.maximumDepth) {
      throw new BoundedJsonError(
        "LIMIT_EXCEEDED",
        "JSON nesting depth exceeds the safety limit",
      );
    }
    const children = current.node.children ?? [];
    if (
      current.node.type === "array" &&
      children.length > limits.maximumArrayItems
    ) {
      throw new BoundedJsonError(
        "LIMIT_EXCEEDED",
        "JSON array length exceeds the safety limit",
      );
    }
    if (current.node.type === "object") {
      if (children.length > limits.maximumObjectProperties) {
        throw new BoundedJsonError(
          "LIMIT_EXCEEDED",
          "JSON object property count exceeds the safety limit",
        );
      }
      const keys = new Set<string>();
      for (const property of children) {
        const keyNode = property.children?.[0];
        const key = keyNode?.value;
        if (typeof key !== "string") {
          throw new BoundedJsonError(
            "INVALID_JSON",
            "JSON object contains an invalid property",
          );
        }
        if (
          FORBIDDEN_KEYS.has(key) ||
          key.length > limits.maximumStringLength ||
          UNSAFE_KEY_TEXT.test(key)
        ) {
          throw new BoundedJsonError(
            "UNSAFE_KEY",
            "JSON contains an unsafe property name",
          );
        }
        if (keys.has(key)) {
          throw new BoundedJsonError(
            "INVALID_JSON",
            "JSON object contains a duplicate property name",
          );
        }
        keys.add(key);
      }
    }
    if (
      current.node.type === "string" &&
      typeof current.node.value === "string" &&
      current.node.value.length > limits.maximumStringLength
    ) {
      throw new BoundedJsonError(
        "LIMIT_EXCEEDED",
        "JSON string length exceeds the safety limit",
      );
    }
    for (let index = children.length - 1; index >= 0; index -= 1) {
      const child = children[index];
      if (child === undefined) {
        continue;
      }
      if (current.node.type === "object" && child.type === "property") {
        const valueNode = child.children?.[1];
        if (valueNode !== undefined) {
          pending.push({ node: valueNode, depth: current.depth + 1 });
        }
      } else {
        pending.push({ node: child, depth: current.depth + 1 });
      }
    }
  }
  throwIfCancelled(signal);
}

function isJsonValue(value: unknown): value is JsonValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return true;
  }
  if (typeof value === "number") {
    return Number.isFinite(value);
  }
  return typeof value === "object";
}

/**
 * Parses strict JSON only. A syntax-tree pass rejects duplicate and
 * prototype-sensitive keys before the native parser creates the value.
 */
export function parseBoundedJson(
  text: string,
  options: ParseBoundedJsonOptions = {},
): JsonValue {
  throwIfCancelled(options.signal);
  const limits = resolveLimits(options.limits);
  if (Buffer.byteLength(text, "utf8") > limits.maximumBytes) {
    throw new BoundedJsonError(
      "LIMIT_EXCEEDED",
      "JSON input exceeds the byte safety limit",
    );
  }
  const errors: ParseError[] = [];
  const root = parseTree(text, errors, {
    allowTrailingComma: false,
    disallowComments: true,
    allowEmptyContent: false,
  });
  if (root === undefined || errors.length > 0) {
    const first = errors[0];
    const detail =
      first === undefined ? "empty input" : printParseErrorCode(first.error);
    throw new BoundedJsonError(
      "INVALID_JSON",
      `Input is not strict JSON (${detail})`,
    );
  }
  validateSyntaxTree(root, limits, options.signal);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch (error: unknown) {
    throw new BoundedJsonError("INVALID_JSON", "Input is not strict JSON", {
      cause: error,
    });
  }
  if (!isJsonValue(parsed)) {
    throw new BoundedJsonError("UNSAFE_VALUE", "JSON value is unsupported");
  }
  throwIfCancelled(options.signal);
  return parsed;
}

function assertCanonicalValue(
  value: unknown,
  depth: number,
  maximumDepth: number,
  state: { nodes: number },
): asserts value is JsonValue {
  state.nodes += 1;
  if (state.nodes > BOUNDED_JSON_LIMITS.maximumNodes) {
    throw new BoundedJsonError(
      "LIMIT_EXCEEDED",
      "Canonical JSON node count exceeds the safety limit",
    );
  }
  if (depth > maximumDepth) {
    throw new BoundedJsonError(
      "LIMIT_EXCEEDED",
      "Canonical JSON nesting depth exceeds the safety limit",
    );
  }
  if (
    value === null ||
    typeof value === "boolean"
  ) {
    return;
  }
  if (typeof value === "string") {
    if (value.length > BOUNDED_JSON_LIMITS.maximumStringLength) {
      throw new BoundedJsonError(
        "LIMIT_EXCEEDED",
        "Canonical JSON string exceeds the safety limit",
      );
    }
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new BoundedJsonError(
        "UNSAFE_VALUE",
        "Canonical JSON cannot contain a non-finite number",
      );
    }
    return;
  }
  if (typeof value !== "object") {
    throw new BoundedJsonError(
      "UNSAFE_VALUE",
      "Canonical JSON contains an unsupported value",
    );
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (
    !Array.isArray(value) &&
    prototype !== Object.prototype &&
    prototype !== null
  ) {
    throw new BoundedJsonError(
      "UNSAFE_VALUE",
      "Canonical JSON objects must use a plain prototype",
    );
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const descriptorEntries = Object.entries(descriptors);
  if (
    (Array.isArray(value) &&
      value.length > BOUNDED_JSON_LIMITS.maximumArrayItems) ||
    (!Array.isArray(value) &&
      descriptorEntries.length > BOUNDED_JSON_LIMITS.maximumObjectProperties)
  ) {
    throw new BoundedJsonError(
      "LIMIT_EXCEEDED",
      "Canonical JSON collection exceeds the safety limit",
    );
  }
  for (const [key, descriptor] of descriptorEntries) {
    if (
      FORBIDDEN_KEYS.has(key) ||
      UNSAFE_KEY_TEXT.test(key) ||
      key.length > BOUNDED_JSON_LIMITS.maximumStringLength ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      throw new BoundedJsonError(
        "UNSAFE_KEY",
        "Canonical JSON contains an unsafe property",
      );
    }
    // Array length is an implementation detail, not a JSON child node.
    if (!(Array.isArray(value) && key === "length")) {
      assertCanonicalValue(
        descriptor.value,
        depth + 1,
        maximumDepth,
        state,
      );
    }
  }
}

function canonicalize(value: JsonValue, depth: number): JsonValue {
  if (depth > BOUNDED_JSON_LIMITS.maximumDepth) {
    throw new BoundedJsonError(
      "LIMIT_EXCEEDED",
      "Canonical JSON nesting depth exceeds the safety limit",
    );
  }
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalize(entry, depth + 1));
  }
  const source = value as { readonly [key: string]: JsonValue };
  const result: Record<string, JsonValue> = Object.create(null) as Record<
    string,
    JsonValue
  >;
  for (const key of Object.keys(source).sort(compareText)) {
    const entry = source[key];
    if (entry !== undefined) {
      result[key] = canonicalize(entry, depth + 1);
    }
  }
  return result;
}

export function canonicalJson(value: JsonValue): string {
  assertCanonicalValue(value, 1, BOUNDED_JSON_LIMITS.maximumDepth, {
    nodes: 0,
  });
  return JSON.stringify(canonicalize(value, 1));
}

export function sha256CanonicalJson(value: JsonValue): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

export function deepFreezeJson<T extends JsonValue>(value: T): Readonly<T> {
  assertCanonicalValue(value, 1, BOUNDED_JSON_LIMITS.maximumDepth, {
    nodes: 0,
  });
  const pending: object[] = [];
  if (typeof value === "object" && value !== null) {
    pending.push(value);
  }
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined || Object.isFrozen(current)) {
      continue;
    }
    for (const child of Object.values(current)) {
      if (typeof child === "object" && child !== null) {
        pending.push(child);
      }
    }
    Object.freeze(current);
  }
  return value as Readonly<T>;
}
