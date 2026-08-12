import { basename } from "node:path";

import type * as vscode from "vscode";
import { SaxesParser } from "saxes";
import { parseDocument } from "yaml";

import { ApplyError } from "./ApplyError";
import type { RemediationPlan } from "./RemediationPlan";

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

interface SmolTomlModule {
  readonly parse: (text: string) => unknown;
}

// A literal CommonJS require selects smol-toml's CJS export and lets esbuild
// include the parser in the dependency-free VSIX bundle.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const smolToml = require("smol-toml") as SmolTomlModule;

function fileName(uri: vscode.Uri): string {
  return basename(uri.path.length > 0 ? uri.path : uri.fsPath).toLowerCase();
}

function decodeText(bytes: Uint8Array): string {
  try {
    const value = UTF8_DECODER.decode(bytes);
    return value.startsWith("\uFEFF") ? value.slice(1) : value;
  } catch (error: unknown) {
    throw new ApplyError("INVALID_METADATA", undefined, { cause: error });
  }
}

function objectRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function parseJsonObject(text: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(text);
    const record = objectRecord(value);
    if (record === undefined) {
      throw new TypeError("Dependency metadata must contain a JSON object.");
    }
    return record;
  } catch (error: unknown) {
    throw new ApplyError("INVALID_METADATA", undefined, { cause: error });
  }
}

function validatePackageManifest(
  value: Record<string, unknown>,
  plan: RemediationPlan,
): void {
  const manifestName =
    plan.recommendation.dependency.manifestName ??
    plan.expectedOutcome.packageName;
  const sections = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
  ];
  const specification = sections
    .map((section) => objectRecord(value[section])?.[manifestName])
    .find((candidate) => typeof candidate === "string");
  const target = plan.expectedOutcome.toVersion;
  const expectedSpecification =
    target === undefined
      ? undefined
      : new RegExp(`^(?:\\^|~)?${target.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}$`, "u");
  if (
    typeof specification !== "string" ||
    expectedSpecification === undefined ||
    !expectedSpecification.test(specification)
  ) {
    throw new ApplyError("VALIDATION_FAILED");
  }
}

function validatePackageLock(
  value: Record<string, unknown>,
  plan: RemediationPlan,
): void {
  const target = plan.expectedOutcome.toVersion;
  if (target === undefined) {
    throw new ApplyError("VALIDATION_FAILED");
  }
  const manifestName =
    plan.recommendation.dependency.manifestName ??
    plan.expectedOutcome.packageName;
  const packages = objectRecord(value.packages);
  const dependencies = objectRecord(value.dependencies);
  const resolvedPackage = objectRecord(
    packages?.[`node_modules/${manifestName}`],
  );
  const legacy = objectRecord(dependencies?.[manifestName]);
  if (resolvedPackage?.version !== target && legacy?.version !== target) {
    throw new ApplyError("VALIDATION_FAILED");
  }
}

function validateXml(text: string): void {
  if (/<!DOCTYPE|<!ENTITY/iu.test(text)) {
    throw new ApplyError("INVALID_METADATA");
  }
  const parser = new SaxesParser({ xmlns: false });
  try {
    parser.write(text).close();
  } catch (error: unknown) {
    throw new ApplyError("INVALID_METADATA", undefined, { cause: error });
  }
}

/** Pure, local structural validation. It never executes project code. */
export class RemediationValidator {
  public validate(uri: vscode.Uri, bytes: Uint8Array, plan: RemediationPlan): void {
    const name = fileName(uri);
    const text = decodeText(bytes);
    if (name.endsWith(".json") || name === "package-lock.json") {
      const value = parseJsonObject(text);
      if (name === "package.json") {
        validatePackageManifest(value, plan);
      } else if (name === "package-lock.json") {
        validatePackageLock(value, plan);
      }
      return;
    }
    if (name.endsWith(".yaml") || name.endsWith(".yml")) {
      const document = parseDocument(text, { prettyErrors: false });
      if (document.errors.length > 0) {
        throw new ApplyError("INVALID_METADATA");
      }
      return;
    }
    if (name.endsWith(".toml")) {
      try {
        smolToml.parse(text);
      } catch (error: unknown) {
        throw new ApplyError("INVALID_METADATA", undefined, { cause: error });
      }
      return;
    }
    if (name.endsWith(".xml") || name.endsWith(".csproj")) {
      validateXml(text);
      return;
    }
    throw new ApplyError("INVALID_METADATA");
  }
}
