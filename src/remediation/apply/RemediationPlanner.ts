import { createHash } from "node:crypto";
import { basename, dirname, isAbsolute } from "node:path";

import {
  applyEdits,
  findNodeAtLocation,
  getNodeValue,
  modify,
  parseTree,
  type FormattingOptions,
  type Node as JsonNode,
  type ParseError,
} from "jsonc-parser";
import { gt, satisfies, valid, validRange } from "semver";
import type * as vscode from "vscode";

import { dependencyManifestPath } from "../../models/Dependency";
import { parseNpmDependencies } from "../../package-managers/npm/NpmDependencyParser";
import type { RemediationRecommendation } from "../RemediationModels";
import { ApplyError } from "./ApplyError";
import type { FileChange } from "./FileChange";
import { sha256 } from "./FileSnapshot";
import type {
  RemediationCapability,
  RemediationPlan,
  RemediationPlanReason,
  ValidationStep,
} from "./RemediationPlan";
import { createUnifiedDiff } from "./UnifiedDiff";

const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;
const MAX_LOCKFILE_BYTES = 32 * 1024 * 1024;
const MAX_JSON_NODES = 250_000;
const MAX_JSON_DEPTH = 128;
const UTF8_DECODER = new TextDecoder("utf-8", {
  fatal: true,
  ignoreBOM: true,
});
const UTF8_ENCODER = new TextEncoder();
const DECLARATION_SECTIONS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
] as const;
const GRAPH_FIELDS = new Set([
  "dependencies",
  "optionalDependencies",
  "peerDependencies",
  "peerDependenciesMeta",
  "bundledDependencies",
  "bundleDependencies",
]);
const CONTEXT_FIELDS = ["dev", "optional", "devOptional", "peer"] as const;
const SAFE_PACKAGE_NAME =
  /^(?:@[a-z0-9][a-z0-9._~-]*\/[a-z0-9][a-z0-9._~-]*|[a-z0-9][a-z0-9._~-]*)$/iu;

type JsonRecord = Record<string, unknown>;

export interface RemediationPlannerFileAccess {
  readonly fileUri: (absolutePath: string) => vscode.Uri;
  readonly readFile: (uri: vscode.Uri) => Promise<Uint8Array>;
  /**
   * Host proof for the final write primitive. Absence is fail-closed: a valid
   * diff may still be previewed, but it is not authorized for automatic apply.
   */
  readonly canGuaranteeAtomicReplace?: (
    uri: vscode.Uri,
  ) => boolean | Promise<boolean>;
}

export interface RemediationPlannerOptions {
  readonly scanGeneration?: string;
  readonly signal?: AbortSignal;
}

interface ParsedJson {
  readonly content: string;
  readonly value: JsonRecord;
  readonly root: JsonNode;
}

interface Declaration {
  readonly section: (typeof DECLARATION_SECTIONS)[number];
  readonly specification: string;
}

interface SafeNpmEdit {
  readonly manifestAfter: string;
  readonly lockfileAfter: string;
  readonly registryProvenanceFingerprint: string;
}

function throwIfCancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw new ApplyError("CANCELLED");
  }
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function safeString(value: unknown, maximumLength = 8_192): string | undefined {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximumLength &&
    !/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u.test(
      value,
    )
    ? value
    : undefined;
}

function uniqueBoundedJsonTree(root: JsonNode): boolean {
  const queue: Array<{ readonly node: JsonNode; readonly depth: number }> = [
    { node: root, depth: 0 },
  ];
  for (let index = 0; index < queue.length; index += 1) {
    const entry = queue[index];
    if (
      entry === undefined ||
      index >= MAX_JSON_NODES ||
      entry.depth > MAX_JSON_DEPTH
    ) {
      return false;
    }
    if (entry.node.type === "object") {
      const keys = new Set<string>();
      for (const property of entry.node.children ?? []) {
        const key = property.children?.[0]?.value;
        if (typeof key !== "string" || keys.has(key)) {
          return false;
        }
        keys.add(key);
      }
    }
    for (const child of entry.node.children ?? []) {
      queue.push({ node: child, depth: entry.depth + 1 });
    }
  }
  return true;
}

function decodeJson(bytes: Uint8Array, maximumBytes: number): ParsedJson {
  if (bytes.byteLength === 0 || bytes.byteLength > maximumBytes) {
    throw new ApplyError("RESOURCE_LIMIT");
  }
  let content: string;
  try {
    content = UTF8_DECODER.decode(bytes);
  } catch (error: unknown) {
    throw new ApplyError("INVALID_METADATA", undefined, { cause: error });
  }
  const parseContent = content.startsWith("\uFEFF")
    ? content.slice(1)
    : content;
  const errors: ParseError[] = [];
  const root = parseTree(parseContent, errors, {
    allowEmptyContent: false,
    allowTrailingComma: false,
    disallowComments: true,
  });
  if (
    root === undefined ||
    root.type !== "object" ||
    errors.length > 0 ||
    !uniqueBoundedJsonTree(root)
  ) {
    throw new ApplyError("INVALID_METADATA");
  }
  const value: unknown = getNodeValue(root);
  if (!isRecord(value)) {
    throw new ApplyError("INVALID_METADATA");
  }
  return { content, value, root };
}

function declarationsFor(
  document: JsonRecord,
  packageName: string,
): readonly Declaration[] {
  const declarations: Declaration[] = [];
  for (const section of DECLARATION_SECTIONS) {
    const sectionValue = document[section];
    if (sectionValue === undefined) {
      continue;
    }
    if (!isRecord(sectionValue)) {
      throw new ApplyError("INVALID_METADATA");
    }
    const value = sectionValue[packageName];
    if (value !== undefined) {
      const specification = safeString(value, 512);
      if (specification === undefined) {
        throw new ApplyError("INVALID_METADATA");
      }
      declarations.push({ section, specification });
    }
  }
  return declarations;
}

function simpleRangeReplacement(
  specification: string,
  currentVersion: string,
  targetVersion: string,
): string | undefined {
  if (
    valid(currentVersion) !== currentVersion ||
    valid(targetVersion) !== targetVersion ||
    !/^\d+\.\d+\.\d+$/u.test(currentVersion) ||
    !/^\d+\.\d+\.\d+$/u.test(targetVersion) ||
    !gt(targetVersion, currentVersion)
  ) {
    return undefined;
  }
  const match = /^(\^|~)?(\d+\.\d+\.\d+)$/u.exec(specification);
  if (match?.[2] !== currentVersion) {
    return undefined;
  }
  return `${match[1] ?? ""}${targetVersion}`;
}

function safeIntegrity(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    !/^sha512-[A-Za-z0-9+/]{86}==$/u.test(value)
  ) {
    return false;
  }
  try {
    const encoded = value.slice("sha512-".length);
    const decoded = Buffer.from(encoded, "base64");
    return decoded.byteLength === 64 && decoded.toString("base64") === encoded;
  } catch {
    return false;
  }
}

function safeRegistryUrl(
  value: unknown,
  packageName: string,
  targetVersion: string,
): value is string {
  if (typeof value !== "string" || value.length > 4_096) {
    return false;
  }
  try {
    const parsed = new URL(value);
    const tarballName = packageName.includes("/")
      ? packageName.slice(packageName.lastIndexOf("/") + 1)
      : packageName;
    return (
      parsed.protocol === "https:" &&
      parsed.hostname.toLowerCase() === "registry.npmjs.org" &&
      parsed.port.length === 0 &&
      parsed.username.length === 0 &&
      parsed.password.length === 0 &&
      parsed.search.length === 0 &&
      parsed.hash.length === 0 &&
      parsed.pathname ===
        `/${packageName}/-/${tarballName}-${targetVersion}.tgz`
    );
  } catch {
    return false;
  }
}

function isLeafRegistryDescriptor(
  value: unknown,
  packageName: string,
  targetVersion: string,
): value is JsonRecord {
  if (!isRecord(value) || value.version !== targetVersion) {
    return false;
  }
  if (
    (value.name !== undefined && value.name !== packageName) ||
    value.link !== undefined ||
    !safeRegistryUrl(value.resolved, packageName, targetVersion) ||
    !safeIntegrity(value.integrity)
  ) {
    return false;
  }
  return [...GRAPH_FIELDS].every((field) => value[field] === undefined);
}

function samePlacementContext(left: JsonRecord, right: JsonRecord): boolean {
  return CONTEXT_FIELDS.every(
    (field) => JSON.stringify(left[field]) === JSON.stringify(right[field]),
  );
}

function declarationSectionsMatch(
  manifest: JsonRecord,
  lockRoot: JsonRecord,
): boolean {
  return DECLARATION_SECTIONS.every((section) => {
    const manifestSection = manifest[section];
    const lockSection = lockRoot[section];
    if (manifestSection === undefined || lockSection === undefined) {
      return manifestSection === undefined && lockSection === undefined;
    }
    if (!isRecord(manifestSection) || !isRecord(lockSection)) {
      return false;
    }
    const manifestEntries = Object.entries(manifestSection).sort(([left], [right]) =>
      left.localeCompare(right),
    );
    const lockEntries = Object.entries(lockSection).sort(([left], [right]) =>
      left.localeCompare(right),
    );
    return (
      manifestEntries.length === lockEntries.length &&
      manifestEntries.every(([name, specification], index) => {
        const lockEntry = lockEntries[index];
        return (
          lockEntry !== undefined &&
          lockEntry[0] === name &&
          safeString(specification, 512) !== undefined &&
          specification === lockEntry[1]
        );
      })
    );
  });
}

function rootIdentityMatches(
  manifest: JsonRecord,
  lockfile: JsonRecord,
  lockRoot: JsonRecord,
): boolean {
  for (const field of ["name", "version"] as const) {
    const manifestValue = manifest[field];
    const lockfileValue = lockfile[field];
    const lockRootValue = lockRoot[field];
    if (
      manifestValue !== lockfileValue ||
      manifestValue !== lockRootValue ||
      (manifestValue !== undefined && safeString(manifestValue, 512) === undefined)
    ) {
      return false;
    }
  }
  return true;
}

function directOwnerCandidateIsReachable(
  candidateLocation: string,
  packageName: string,
  targetVersion: string,
  packages: JsonRecord,
  manifest: JsonRecord,
  lockRoot: JsonRecord,
  graph: ReturnType<typeof parseNpmDependencies>,
): boolean {
  const suffix = `/node_modules/${packageName}`;
  if (!candidateLocation.endsWith(suffix)) return false;
  const ownerLocation = candidateLocation.slice(0, -suffix.length);
  if (!ownerLocation.startsWith("node_modules/")) return false;
  const ownerName = ownerLocation.slice("node_modules/".length);
  const ownerSegments = ownerName.split("/");
  if (
    !SAFE_PACKAGE_NAME.test(ownerName) ||
    (ownerName.startsWith("@")
      ? ownerSegments.length !== 2
      : ownerSegments.length !== 1)
  ) {
    return false;
  }
  const ownerDescriptor = packages[ownerLocation];
  if (
    !isRecord(ownerDescriptor) ||
    ownerDescriptor.link !== undefined ||
    (ownerDescriptor.name !== undefined && ownerDescriptor.name !== ownerName)
  ) {
    return false;
  }
  const ownerVersion = safeString(ownerDescriptor.version, 256);
  if (ownerVersion === undefined || valid(ownerVersion) !== ownerVersion) {
    return false;
  }
  const manifestOwner = declarationsFor(manifest, ownerName);
  const lockOwner = declarationsFor(lockRoot, ownerName);
  if (
    manifestOwner.length !== 1 ||
    lockOwner.length !== 1 ||
    manifestOwner[0]?.section !== lockOwner[0]?.section ||
    manifestOwner[0]?.specification !== lockOwner[0]?.specification ||
    validRange(manifestOwner[0]?.specification) === null ||
    !satisfies(ownerVersion, manifestOwner[0]?.specification ?? "")
  ) {
    return false;
  }
  const ownerEdges = declarationsFor(ownerDescriptor, packageName).filter(
    (declaration) => declaration.section !== "devDependencies",
  );
  if (
    ownerEdges.length !== 1 ||
    validRange(ownerEdges[0]?.specification) === null ||
    !satisfies(targetVersion, ownerEdges[0]?.specification ?? "")
  ) {
    return false;
  }
  const manifestName = safeString(manifest.name, 214) ?? "application";
  const ownerLabel = `${ownerName}@${ownerVersion}`;
  const targetLabel = `${packageName}@${targetVersion}`;
  const ownerIsDirect = graph.dependencies.some(
    (entry) =>
      entry.dependencyType === "direct" &&
      entry.name === ownerName &&
      entry.manifestName === ownerName &&
      entry.installedVersion === ownerVersion &&
      entry.dependencyPath?.length === 2 &&
      entry.dependencyPath[0] === manifestName &&
      entry.dependencyPath[1] === ownerLabel,
  );
  const exactChildIsReachable = graph.dependencies.some(
    (entry) =>
      entry.dependencyType === "transitive" &&
      entry.name === packageName &&
      entry.manifestName === packageName &&
      entry.installedVersion === targetVersion &&
      entry.parent === ownerLabel &&
      entry.dependencyPath?.length === 3 &&
      entry.dependencyPath[0] === manifestName &&
      entry.dependencyPath[1] === ownerLabel &&
      entry.dependencyPath[2] === targetLabel,
  );
  return ownerIsDirect && exactChildIsReachable;
}

function safeCandidateLocation(
  location: string,
  packageName: string,
): boolean {
  if (
    location.length === 0 ||
    location.length > 8_192 ||
    location.includes("\\") ||
    /[\u0000-\u001f\u007f]/u.test(location)
  ) {
    return false;
  }
  const segments = location.split("/");
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    return false;
  }
  return (
    location.startsWith("node_modules/") &&
    (location === `node_modules/${packageName}` ||
      location.endsWith(`/node_modules/${packageName}`))
  );
}

function formattingFor(content: string): FormattingOptions {
  const eol = content.includes("\r\n") ? "\r\n" : "\n";
  const indent = /(?:^|\r?\n)([ \t]+)"/u.exec(content)?.[1] ?? "  ";
  return indent.includes("\t")
    ? { insertSpaces: false, tabSize: 1, eol }
    : { insertSpaces: true, tabSize: Math.max(1, Math.min(8, indent.length)), eol };
}

function updateJsonValue(
  originalContent: string,
  path: (string | number)[],
  value: unknown,
): string {
  const hadBom = originalContent.startsWith("\uFEFF");
  const content = hadBom ? originalContent.slice(1) : originalContent;
  const updated = applyEdits(
    content,
    modify(content, path, value, {
      formattingOptions: formattingFor(content),
      isArrayInsertion: false,
    }),
  );
  return hadBom ? `\uFEFF${updated}` : updated;
}

function safePlanEdit(
  recommendation: RemediationRecommendation,
  manifest: ParsedJson,
  lockfile: ParsedJson,
  signal: AbortSignal | undefined,
): SafeNpmEdit | undefined {
  const dependency = recommendation.dependency;
  const packageName = dependency.manifestName ?? dependency.name;
  const targetVersion = recommendation.recommendedVersion;
  if (
    targetVersion === undefined ||
    packageName !== dependency.name ||
    !SAFE_PACKAGE_NAME.test(packageName) ||
    manifest.value.workspaces !== undefined ||
    lockfile.value.lockfileVersion !== 3 ||
    lockfile.value.dependencies !== undefined
  ) {
    return undefined;
  }
  const packages = lockfile.value.packages;
  if (!isRecord(packages)) {
    return undefined;
  }
  // Root-only support: any non-node_modules package entry is a workspace.
  if (
    Object.keys(packages).some(
      (location) =>
        location !== "" && !location.startsWith("node_modules/") &&
        !location.includes("/node_modules/"),
    )
  ) {
    return undefined;
  }
  const rootPackage = packages[""];
  if (
    !isRecord(rootPackage) ||
    !declarationSectionsMatch(manifest.value, rootPackage) ||
    !rootIdentityMatches(manifest.value, lockfile.value, rootPackage)
  ) {
    return undefined;
  }
  const manifestDeclarations = declarationsFor(manifest.value, packageName);
  const lockDeclarations = declarationsFor(rootPackage, packageName);
  if (manifestDeclarations.length !== 1 || lockDeclarations.length !== 1) {
    return undefined;
  }
  const manifestDeclaration = manifestDeclarations[0];
  const lockDeclaration = lockDeclarations[0];
  if (
    manifestDeclaration === undefined ||
    lockDeclaration === undefined ||
    manifestDeclaration.section !== lockDeclaration.section ||
    manifestDeclaration.specification !== lockDeclaration.specification ||
    manifestDeclaration.specification !== dependency.requestedVersion
  ) {
    return undefined;
  }
  const nextSpecification = simpleRangeReplacement(
    manifestDeclaration.specification,
    recommendation.currentVersion,
    targetVersion,
  );
  if (nextSpecification === undefined) {
    return undefined;
  }
  const currentLocation = `node_modules/${packageName}`;
  const currentDescriptor = packages[currentLocation];
  if (
    !isRecord(currentDescriptor) ||
    currentDescriptor.version !== recommendation.currentVersion ||
    (currentDescriptor.name !== undefined && currentDescriptor.name !== dependency.name)
  ) {
    return undefined;
  }
  const candidates = Object.entries(packages).filter(
    ([location, descriptor]) =>
      location !== currentLocation &&
      safeCandidateLocation(location, packageName) &&
      isLeafRegistryDescriptor(descriptor, dependency.name, targetVersion) &&
      samePlacementContext(currentDescriptor, descriptor),
  );
  if (candidates.length !== 1) {
    return undefined;
  }
  const candidateLocation = candidates[0]?.[0];
  const candidateDescriptor = candidates[0]?.[1];
  if (candidateLocation === undefined || !isRecord(candidateDescriptor)) {
    return undefined;
  }

  const parserInput = {
    packageJsonPath: dependencyManifestPath(dependency) ?? "package.json",
    lockfilePath: dependency.lockfilePath ?? "package-lock.json",
    ...(signal === undefined ? {} : { signal }),
  };
  const originalGraph = parseNpmDependencies({
    ...parserInput,
    packageJson: manifest.content.startsWith("\uFEFF")
      ? manifest.content.slice(1)
      : manifest.content,
    lockfile: lockfile.content.startsWith("\uFEFF")
      ? lockfile.content.slice(1)
      : lockfile.content,
  });
  if (originalGraph.cancelled) {
    throw new ApplyError("CANCELLED");
  }
  if (
    originalGraph.truncated ||
    originalGraph.unresolvedDependencies !== 0 ||
    originalGraph.issues.some((issue) => issue.level === "error") ||
    !directOwnerCandidateIsReachable(
      candidateLocation,
      dependency.name,
      targetVersion,
      packages,
      manifest.value,
      rootPackage,
      originalGraph,
    )
  ) {
    return undefined;
  }

  const manifestAfter = updateJsonValue(
    manifest.content,
    [manifestDeclaration.section, packageName],
    nextSpecification,
  );
  let lockfileAfter = updateJsonValue(
    lockfile.content,
    ["packages", "", lockDeclaration.section, packageName],
    nextSpecification,
  );
  lockfileAfter = updateJsonValue(
    lockfileAfter,
    ["packages", currentLocation],
    candidateDescriptor,
  );
  if (manifestAfter === manifest.content || lockfileAfter === lockfile.content) {
    return undefined;
  }
  // Reparse generated bytes with the production npm graph parser. SAFE means
  // the entire bounded lock graph remains resolved, not merely valid JSON.
  const reparsedManifest = decodeJson(
    UTF8_ENCODER.encode(manifestAfter),
    MAX_MANIFEST_BYTES,
  );
  const reparsedLock = decodeJson(
    UTF8_ENCODER.encode(lockfileAfter),
    MAX_LOCKFILE_BYTES,
  );
  if (
    findNodeAtLocation(reparsedManifest.root, [manifestDeclaration.section, packageName])
      ?.value !== nextSpecification ||
    findNodeAtLocation(reparsedLock.root, ["packages", currentLocation, "version"])
      ?.value !== targetVersion
  ) {
    return undefined;
  }
  const parsedGraph = parseNpmDependencies({
    ...parserInput,
    packageJson: manifestAfter.startsWith("\uFEFF")
      ? manifestAfter.slice(1)
      : manifestAfter,
    lockfile: lockfileAfter.startsWith("\uFEFF")
      ? lockfileAfter.slice(1)
      : lockfileAfter,
  });
  if (parsedGraph.cancelled) {
    throw new ApplyError("CANCELLED");
  }
  if (
    parsedGraph.truncated ||
    parsedGraph.unresolvedDependencies !== 0 ||
    parsedGraph.issues.some((issue) => issue.level === "error") ||
    !parsedGraph.dependencies.some(
      (entry) =>
        entry.dependencyType === "direct" &&
        entry.name === dependency.name &&
        entry.manifestName === packageName &&
        entry.installedVersion === targetVersion &&
        entry.requestedVersion === nextSpecification,
    )
  ) {
    return undefined;
  }
  const candidateResolved = safeString(candidateDescriptor.resolved, 4_096);
  const candidateIntegrity = safeString(candidateDescriptor.integrity, 1_024);
  if (candidateResolved === undefined || candidateIntegrity === undefined) {
    return undefined;
  }
  const registryProvenanceFingerprint = createHash("sha256")
    .update(candidateResolved)
    .update("\u0000")
    .update(candidateIntegrity)
    .digest("hex");
  return { manifestAfter, lockfileAfter, registryProvenanceFingerprint };
}

function validationSteps(capability: RemediationCapability): readonly ValidationStep[] {
  if (capability !== "safe") {
    return Object.freeze([]);
  }
  return Object.freeze([
    Object.freeze({
      kind: "file-format" as const,
      description: "Validate the modified npm manifest and lockfile as bounded JSON.",
      required: true,
    }),
    Object.freeze({
      kind: "dependency-resolution" as const,
      description: "Verify the existing package-lock v3 resolution selects the exact candidate.",
      required: true,
    }),
    Object.freeze({
      kind: "rescan" as const,
      description: "Run the existing dependency scanner and require complete vulnerability coverage.",
      required: true,
    }),
  ]);
}

function planId(
  recommendation: RemediationRecommendation,
  capability: RemediationCapability,
  reasonCode: RemediationPlanReason,
  files: readonly FileChange[],
): string {
  return createHash("sha256")
    .update(recommendation.recommendationKey)
    .update("\u0000")
    .update(capability)
    .update("\u0000")
    .update(reasonCode)
    .update("\u0000")
    .update(files.map((file) => `${file.beforeHash}:${file.afterHash ?? ""}`).join("\u0000"))
    .digest("base64url");
}

function immutablePlan(
  recommendation: RemediationRecommendation,
  capability: RemediationCapability,
  reasonCode: RemediationPlanReason,
  warnings: readonly string[],
  files: readonly FileChange[],
  options: RemediationPlannerOptions,
  registryProvenanceFingerprint?: string,
): RemediationPlan {
  const frozenFiles = Object.freeze(files.map((file) => Object.freeze(file)));
  const frozenWarnings = Object.freeze([...warnings]);
  return Object.freeze({
    id: planId(recommendation, capability, reasonCode, frozenFiles),
    recommendationKey: recommendation.recommendationKey,
    recommendation,
    capability,
    files: frozenFiles,
    warnings: frozenWarnings,
    validationSteps: validationSteps(capability),
    expectedOutcome: Object.freeze({
      packageName: recommendation.dependency.name,
      fromVersion: recommendation.currentVersion,
      ...(recommendation.recommendedVersion === undefined
        ? {}
        : { toVersion: recommendation.recommendedVersion }),
      targetedVulnerabilityIds: Object.freeze([...recommendation.vulnerabilityIds]),
      expectedAddressed: recommendation.vulnerabilityIds.length,
      requiresCompleteCoverage: true,
    }),
    reasonCode,
    ...(registryProvenanceFingerprint === undefined
      ? {}
      : { registryProvenanceFingerprint }),
    ...(options.scanGeneration === undefined
      ? {}
      : { scanGeneration: options.scanGeneration }),
  });
}

function fallbackPlan(
  recommendation: RemediationRecommendation,
  options: RemediationPlannerOptions,
): RemediationPlan {
  if (recommendation.recommendedVersion === undefined) {
    return immutablePlan(
      recommendation,
      "unsupported",
      "no-exact-target",
      ["No exact provider-proven remediation target is available."],
      [],
      options,
    );
  }
  if (
    recommendation.dependency.ecosystem !== "npm" ||
    recommendation.dependency.packageManager !== "npm"
  ) {
    return immutablePlan(
      recommendation,
      "preview-only",
      "unsupported-ecosystem",
      [
        "Automatic modification is unavailable because safe lockfile resolution is not established for this ecosystem.",
      ],
      [],
      options,
    );
  }
  if (
    recommendation.strategy !== "upgrade-direct" ||
    !recommendation.directDependency ||
    recommendation.dependency.dependencyType !== "direct"
  ) {
    return immutablePlan(
      recommendation,
      "preview-only",
      "transitive-manual-review",
      [
        "Transitive remediation requires an authoritative parent-package target; the vulnerable child version will not be written to the parent declaration.",
      ],
      [],
      options,
    );
  }
  if (
    recommendation.dependency.requestedVersion === undefined ||
    simpleRangeReplacement(
      recommendation.dependency.requestedVersion,
      recommendation.currentVersion,
      recommendation.recommendedVersion,
    ) === undefined
  ) {
    return immutablePlan(
      recommendation,
      "preview-only",
      "range-semantics-change",
      [
        "The dependency specification is not an exact, caret, or tilde range anchored at the resolved version. Changing its semantics requires manual review.",
      ],
      [],
      options,
    );
  }
  return immutablePlan(
    recommendation,
    "preview-only",
    "requires-package-manager-resolution",
    [
      "A trustworthy existing npm lockfile artifact could not be proven. Package-manager resolution is required and was not executed.",
    ],
    [],
    options,
  );
}

/**
 * Pure planning boundary. It reads bounded metadata through an injected
 * adapter, never writes files, starts processes, or contacts a registry.
 */
export class RemediationPlanner {
  public constructor(private readonly fileAccess: RemediationPlannerFileAccess) {}

  public async plan(
    recommendation: RemediationRecommendation,
    options: RemediationPlannerOptions = {},
  ): Promise<RemediationPlan> {
    throwIfCancelled(options.signal);
    const fallback = fallbackPlan(recommendation, options);
    if (
      fallback.reasonCode !== "requires-package-manager-resolution" ||
      recommendation.confidence !== "high" ||
      recommendation.breakingChangeRisk !== "low" ||
      !recommendation.fixedVersions.includes(
        recommendation.recommendedVersion ?? "",
      ) ||
      !recommendation.vulnerabilityIds.every((id) => id.length > 0)
    ) {
      return fallback;
    }
    const manifestPath = dependencyManifestPath(recommendation.dependency);
    const lockfilePath = recommendation.dependency.lockfilePath;
    if (
      manifestPath === undefined ||
      lockfilePath === undefined ||
      !isAbsolute(manifestPath) ||
      !isAbsolute(lockfilePath) ||
      basename(manifestPath).toLowerCase() !== "package.json" ||
      basename(lockfilePath).toLowerCase() !== "package-lock.json" ||
      dirname(manifestPath) !== dirname(lockfilePath)
    ) {
      return fallback;
    }
    let manifestUri: vscode.Uri;
    let lockfileUri: vscode.Uri;
    let manifestBytes: Uint8Array;
    let lockfileBytes: Uint8Array;
    try {
      manifestUri = this.fileAccess.fileUri(manifestPath);
      lockfileUri = this.fileAccess.fileUri(lockfilePath);
      [manifestBytes, lockfileBytes] = await Promise.all([
        this.fileAccess.readFile(manifestUri),
        this.fileAccess.readFile(lockfileUri),
      ]);
      throwIfCancelled(options.signal);
    } catch (error: unknown) {
      if (error instanceof ApplyError && error.code === "CANCELLED") {
        throw error;
      }
      return fallback;
    }
    let manifest: ParsedJson;
    let lockfile: ParsedJson;
    let edit: SafeNpmEdit | undefined;
    try {
      manifest = decodeJson(manifestBytes, MAX_MANIFEST_BYTES);
      lockfile = decodeJson(lockfileBytes, MAX_LOCKFILE_BYTES);
      edit = safePlanEdit(recommendation, manifest, lockfile, options.signal);
    } catch (error: unknown) {
      if (error instanceof ApplyError && error.code === "CANCELLED") {
        throw error;
      }
      return fallback;
    }
    if (edit === undefined) {
      return fallback;
    }
    const manifestDiff = createUnifiedDiff(
      "package.json",
      manifest.content,
      edit.manifestAfter,
    );
    const lockfileDiff = createUnifiedDiff(
      "package-lock.json",
      lockfile.content,
      edit.lockfileAfter,
    );
    if (
      manifestDiff === undefined ||
      lockfileDiff === undefined ||
      manifestDiff.length === 0 ||
      lockfileDiff.length === 0
    ) {
      return fallback;
    }
    const manifestAfterBytes = UTF8_ENCODER.encode(edit.manifestAfter);
    const lockfileAfterBytes = UTF8_ENCODER.encode(edit.lockfileAfter);
    const files: readonly FileChange[] = [
      {
        uri: manifestUri,
        operation: "modify",
        beforeHash: sha256(manifestBytes),
        afterHash: sha256(manifestAfterBytes),
        beforeContent: manifest.content,
        afterContent: edit.manifestAfter,
        description: "Minimal range-preserving npm manifest update.",
        unifiedDiff: manifestDiff,
      },
      {
        uri: lockfileUri,
        operation: "modify",
        beforeHash: sha256(lockfileBytes),
        afterHash: sha256(lockfileAfterBytes),
        beforeContent: lockfile.content,
        afterContent: edit.lockfileAfter,
        description:
          "Reuse the unique complete registry artifact already present in package-lock v3.",
        unifiedDiff: lockfileDiff,
      },
    ];
    let atomicReplaceAvailable = false;
    try {
      const prove = this.fileAccess.canGuaranteeAtomicReplace;
      atomicReplaceAvailable =
        prove !== undefined &&
        (await Promise.all(files.map((file) => prove(file.uri)))).every(
          (available) => available === true,
        );
      throwIfCancelled(options.signal);
    } catch (error: unknown) {
      if (error instanceof ApplyError && error.code === "CANCELLED") {
        throw error;
      }
      throwIfCancelled(options.signal);
      atomicReplaceAvailable = false;
    }
    if (!atomicReplaceAvailable) {
      return immutablePlan(
        recommendation,
        "preview-only",
        "atomic-replace-unavailable",
        [
          "The proposed npm metadata change is deterministic, but this host cannot guarantee a race-safe atomic replacement, so automatic apply is disabled.",
        ],
        files,
        options,
        edit.registryProvenanceFingerprint,
      );
    }
    return immutablePlan(
      recommendation,
      "safe",
      "safe-npm-existing-resolution",
      [
        "Only an existing complete leaf artifact is reused; no integrity, URL, checksum, or dependency graph value is invented.",
      ],
      files,
      options,
      edit.registryProvenanceFingerprint,
    );
  }
}
