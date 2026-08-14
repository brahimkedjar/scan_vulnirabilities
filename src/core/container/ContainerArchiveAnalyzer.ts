import { createHash } from "node:crypto";

import {
  BoundedJsonError,
  parseBoundedJson,
  type JsonValue,
} from "../security/BoundedJson";

export type ContainerArchiveFormat =
  | "docker-archive"
  | "oci-archive"
  | "unknown";

export type ContainerAnalysisStatus =
  | "analyzed"
  | "incomplete"
  | "unsupported";

export type ContainerIssueCode =
  | "INVALID_ARCHIVE"
  | "UNSUPPORTED_ARCHIVE"
  | "UNSUPPORTED_LAYER"
  | "UNSAFE_ARCHIVE_ENTRY"
  | "DIGEST_MISMATCH"
  | "LIMIT_EXCEEDED"
  | "INVALID_METADATA"
  | "PACKAGE_DATABASE_INVALID"
  | "VULNERABILITY_PROVIDER_NOT_CONFIGURED"
  | "CANCELLED";

export interface ContainerAnalysisIssue {
  readonly code: ContainerIssueCode;
  readonly message: string;
}

export interface ContainerOsPackage {
  readonly packageManager: "dpkg" | "apk";
  readonly name: string;
  readonly version: string;
  readonly architecture?: string;
}

export interface ContainerImageAnalysis {
  /** Sanitized tag from a Docker archive, when present. */
  readonly reference?: string;
  /** Verified OCI manifest digest or a content-derived Docker config digest. */
  readonly digest: string;
  readonly operatingSystem?: string;
  readonly architecture?: string;
  readonly layersDeclared: number;
  readonly layersAnalyzed: number;
  readonly osPackages: readonly ContainerOsPackage[];
  readonly osPackageInventoryComplete: boolean;
}

export interface ContainerArchiveCoverage {
  readonly archiveMetadata: "complete" | "partial" | "unsupported";
  readonly osPackages: "complete" | "partial" | "unknown";
  /** Phase 8 has no configured OS-package advisory provider. */
  readonly vulnerabilities: "not-configured";
  /** Package metadata in an image archive does not prove license coverage. */
  readonly licenses: "unknown";
}

export interface ContainerArchiveAnalysis {
  readonly format: ContainerArchiveFormat;
  readonly status: ContainerAnalysisStatus;
  readonly images: readonly ContainerImageAnalysis[];
  readonly issues: readonly ContainerAnalysisIssue[];
  readonly coverage: ContainerArchiveCoverage;
}

export interface ContainerArchiveLimits {
  readonly maximumArchiveBytes: number;
  readonly maximumEntries: number;
  readonly maximumEntryBytes: number;
  readonly maximumLayerBytes: number;
  readonly maximumLayers: number;
  readonly maximumImages: number;
  readonly maximumPackages: number;
  readonly maximumPackageDatabaseBytes: number;
}

export interface AnalyzeContainerArchiveOptions {
  readonly signal?: AbortSignal;
  readonly limits?: Partial<ContainerArchiveLimits>;
}

const HARD_LIMITS: Readonly<ContainerArchiveLimits> = Object.freeze({
  maximumArchiveBytes: 128 * 1024 * 1024,
  maximumEntries: 25_000,
  maximumEntryBytes: 64 * 1024 * 1024,
  maximumLayerBytes: 64 * 1024 * 1024,
  maximumLayers: 512,
  maximumImages: 64,
  maximumPackages: 100_000,
  maximumPackageDatabaseBytes: 32 * 1024 * 1024,
});

const DEFAULT_LIMITS: Readonly<ContainerArchiveLimits> = Object.freeze({
  maximumArchiveBytes: 64 * 1024 * 1024,
  maximumEntries: 10_000,
  maximumEntryBytes: 32 * 1024 * 1024,
  maximumLayerBytes: 32 * 1024 * 1024,
  maximumLayers: 256,
  maximumImages: 16,
  maximumPackages: 50_000,
  maximumPackageDatabaseBytes: 16 * 1024 * 1024,
});

const TAR_BLOCK_SIZE = 512;
const MAXIMUM_SAFE_TEXT = 4_096;
const MAXIMUM_PACKAGE_LINE = 16 * 1024;
const MAXIMUM_PACKAGE_LINES = 250_000;
const UNSAFE_TEXT =
  /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u;
const SAFE_DIGEST = /^sha256:[a-f0-9]{64}$/u;
const SAFE_PACKAGE_FIELD =
  /^[\p{L}\p{N}][\p{L}\p{N}._+~:@/=-]{0,1023}$/u;

class ContainerArchiveError extends Error {
  public constructor(
    public readonly code: ContainerIssueCode,
    message: string,
    options: { readonly cause?: unknown } = {},
  ) {
    super(message, options);
    this.name = "ContainerArchiveError";
  }
}

interface TarEntry {
  readonly path: string;
  readonly type: "file" | "directory";
  readonly data: Uint8Array;
}

interface TarReadResult {
  readonly entries: ReadonlyMap<string, TarEntry>;
  readonly consumedBytes: number;
}

interface MutableRootFile {
  readonly data: Uint8Array;
}

function throwIfCancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw new ContainerArchiveError(
      "CANCELLED",
      "Container archive analysis was cancelled",
    );
  }
}

function resolveLimits(
  requested: Partial<ContainerArchiveLimits> | undefined,
): ContainerArchiveLimits {
  const result = { ...DEFAULT_LIMITS };
  for (const key of Object.keys(DEFAULT_LIMITS) as (keyof ContainerArchiveLimits)[]) {
    const value = requested?.[key];
    if (value === undefined) {
      continue;
    }
    if (
      !Number.isSafeInteger(value) ||
      value < 1 ||
      value > HARD_LIMITS[key]
    ) {
      throw new ContainerArchiveError(
        "LIMIT_EXCEEDED",
        `${key} is outside the supported safety range`,
      );
    }
    result[key] = value;
  }
  return Object.freeze(result);
}

function isZeroBlock(bytes: Uint8Array, offset: number): boolean {
  for (let index = offset; index < offset + TAR_BLOCK_SIZE; index += 1) {
    if (bytes[index] !== 0) {
      return false;
    }
  }
  return true;
}

function decodeTarField(
  bytes: Uint8Array,
  offset: number,
  length: number,
): string {
  const field = bytes.subarray(offset, offset + length);
  let end = field.indexOf(0);
  if (end < 0) {
    end = field.length;
  }
  let value: string;
  try {
    value = new TextDecoder("utf-8", { fatal: true }).decode(
      field.subarray(0, end),
    );
  } catch (error: unknown) {
    throw new ContainerArchiveError(
      "INVALID_ARCHIVE",
      "A tar header contains invalid UTF-8",
      { cause: error },
    );
  }
  if (value.length > MAXIMUM_SAFE_TEXT || UNSAFE_TEXT.test(value)) {
    throw new ContainerArchiveError(
      "UNSAFE_ARCHIVE_ENTRY",
      "A tar header contains unsafe text",
    );
  }
  return value;
}

function parseTarOctal(
  bytes: Uint8Array,
  offset: number,
  length: number,
  label: string,
): number {
  const raw = decodeTarField(bytes, offset, length).trim();
  if (raw.length === 0) {
    return 0;
  }
  if (!/^[0-7]+$/u.test(raw)) {
    throw new ContainerArchiveError(
      "INVALID_ARCHIVE",
      `A tar ${label} field is invalid`,
    );
  }
  const value = Number.parseInt(raw, 8);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new ContainerArchiveError(
      "LIMIT_EXCEEDED",
      `A tar ${label} field exceeds the numeric limit`,
    );
  }
  return value;
}

function validateTarChecksum(bytes: Uint8Array, offset: number): void {
  const expected = parseTarOctal(bytes, offset + 148, 8, "checksum");
  let actual = 0;
  for (let index = 0; index < TAR_BLOCK_SIZE; index += 1) {
    actual += index >= 148 && index < 156
      ? 32
      : (bytes[offset + index] ?? 0);
  }
  if (actual !== expected) {
    throw new ContainerArchiveError(
      "INVALID_ARCHIVE",
      "A tar header checksum does not match",
    );
  }
}

function safeArchivePath(value: string): string {
  if (
    value.length === 0 ||
    value.length > MAXIMUM_SAFE_TEXT ||
    value.startsWith("/") ||
    value.startsWith("\\") ||
    value.includes("\\") ||
    /^[A-Za-z]:/u.test(value) ||
    UNSAFE_TEXT.test(value)
  ) {
    throw new ContainerArchiveError(
      "UNSAFE_ARCHIVE_ENTRY",
      "An archive entry path is unsafe",
    );
  }
  const segments = value.split("/");
  const normalized: string[] = [];
  for (const segment of segments) {
    if (segment.length === 0 || segment === ".") {
      continue;
    }
    if (segment === ".." || UNSAFE_TEXT.test(segment)) {
      throw new ContainerArchiveError(
        "UNSAFE_ARCHIVE_ENTRY",
        "An archive entry attempts path traversal",
      );
    }
    normalized.push(segment);
  }
  if (normalized.length === 0) {
    throw new ContainerArchiveError(
      "UNSAFE_ARCHIVE_ENTRY",
      "An archive entry has no safe path",
    );
  }
  return normalized.join("/");
}

function readTar(
  bytes: Uint8Array,
  limits: ContainerArchiveLimits,
  signal: AbortSignal | undefined,
  maximumBytes: number,
  totalBudget?: { remaining: number },
): TarReadResult {
  if (bytes.byteLength > maximumBytes) {
    throw new ContainerArchiveError(
      "LIMIT_EXCEEDED",
      "The tar input exceeds the configured byte limit",
    );
  }
  const entries = new Map<string, TarEntry>();
  let offset = 0;
  let count = 0;
  let terminated = false;
  let consumedBytes = 0;
  while (offset + TAR_BLOCK_SIZE <= bytes.byteLength) {
    if ((count & 63) === 0) {
      throwIfCancelled(signal);
    }
    if (isZeroBlock(bytes, offset)) {
      terminated = true;
      break;
    }
    count += 1;
    if (count > limits.maximumEntries) {
      throw new ContainerArchiveError(
        "LIMIT_EXCEEDED",
        "The tar entry count exceeds the configured limit",
      );
    }
    validateTarChecksum(bytes, offset);
    const name = decodeTarField(bytes, offset, 100);
    const prefix = decodeTarField(bytes, offset + 345, 155);
    const path = safeArchivePath(prefix.length === 0 ? name : `${prefix}/${name}`);
    const size = parseTarOctal(bytes, offset + 124, 12, "size");
    if (size > limits.maximumEntryBytes) {
      throw new ContainerArchiveError(
        "LIMIT_EXCEEDED",
        "A tar entry exceeds the configured byte limit",
      );
    }
    const typeByte = bytes[offset + 156] ?? 0;
    const type = typeByte === 0 || typeByte === 48
      ? "file"
      : typeByte === 53
        ? "directory"
        : undefined;
    if (type === undefined) {
      throw new ContainerArchiveError(
        "UNSAFE_ARCHIVE_ENTRY",
        "Links, devices, extended headers, and special tar entries are unsupported",
      );
    }
    const dataStart = offset + TAR_BLOCK_SIZE;
    const dataEnd = dataStart + size;
    if (dataEnd > bytes.byteLength) {
      throw new ContainerArchiveError(
        "INVALID_ARCHIVE",
        "A tar entry extends beyond the archive",
      );
    }
    if (entries.has(path)) {
      throw new ContainerArchiveError(
        "INVALID_ARCHIVE",
        "The tar archive contains duplicate entry paths",
      );
    }
    entries.set(path, {
      path,
      type,
      data: type === "file" ? bytes.subarray(dataStart, dataEnd) : new Uint8Array(),
    });
    consumedBytes += size;
    if (consumedBytes > maximumBytes) {
      throw new ContainerArchiveError(
        "LIMIT_EXCEEDED",
        "The cumulative tar entry bytes exceed the configured limit",
      );
    }
    if (totalBudget !== undefined) {
      totalBudget.remaining -= size;
      if (totalBudget.remaining < 0) {
        throw new ContainerArchiveError(
          "LIMIT_EXCEEDED",
          "Nested container layer bytes exceed the cumulative archive budget",
        );
      }
    }
    const paddedSize = Math.ceil(size / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE;
    offset = dataStart + paddedSize;
  }
  if (!terminated) {
    throw new ContainerArchiveError(
      "INVALID_ARCHIVE",
      "The tar archive is not terminated by a zero block",
    );
  }
  return { entries, consumedBytes };
}

function decodeJson(entry: TarEntry, maximumBytes: number): JsonValue {
  if (entry.type !== "file" || entry.data.byteLength > maximumBytes) {
    throw new ContainerArchiveError(
      "LIMIT_EXCEEDED",
      "Container metadata exceeds its byte limit",
    );
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(entry.data);
  } catch (error: unknown) {
    throw new ContainerArchiveError(
      "INVALID_METADATA",
      "Container metadata is not UTF-8 JSON",
      { cause: error },
    );
  }
  if (text.includes("\u0000")) {
    throw new ContainerArchiveError(
      "INVALID_METADATA",
      "Container metadata contains a NUL byte",
    );
  }
  try {
    return parseBoundedJson(text, {
      limits: {
        maximumBytes,
        maximumDepth: 32,
        maximumNodes: 100_000,
        maximumObjectProperties: 25_000,
        maximumArrayItems: 25_000,
        maximumStringLength: 64 * 1024,
      },
    });
  } catch (error: unknown) {
    throw new ContainerArchiveError(
      error instanceof BoundedJsonError && error.code === "LIMIT_EXCEEDED"
        ? "LIMIT_EXCEEDED"
        : "INVALID_METADATA",
      "Container metadata is not bounded strict JSON",
      { cause: error },
    );
  }
}

function record(value: JsonValue | undefined): Record<string, JsonValue> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, JsonValue>
    : undefined;
}

function array(value: JsonValue | undefined): readonly JsonValue[] | undefined {
  return Array.isArray(value) ? value : undefined;
}

function boundedString(value: JsonValue | undefined, maximum = 1024): string | undefined {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    value.trim() === value &&
    !UNSAFE_TEXT.test(value)
    ? value
    : undefined;
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function verifiedBlob(
  entries: ReadonlyMap<string, TarEntry>,
  digest: string,
  expectedSize: number,
): TarEntry {
  if (!SAFE_DIGEST.test(digest)) {
    throw new ContainerArchiveError(
      "INVALID_METADATA",
      "An OCI descriptor digest is invalid",
    );
  }
  const entry = entries.get(`blobs/sha256/${digest.slice(7)}`);
  if (entry === undefined || entry.type !== "file") {
    throw new ContainerArchiveError(
      "INVALID_ARCHIVE",
      "An OCI descriptor blob is missing",
    );
  }
  if (entry.data.byteLength !== expectedSize) {
    throw new ContainerArchiveError(
      "DIGEST_MISMATCH",
      "An OCI descriptor size does not match its blob",
    );
  }
  if (sha256(entry.data) !== digest.slice(7)) {
    throw new ContainerArchiveError(
      "DIGEST_MISMATCH",
      "An OCI descriptor digest does not match its blob",
    );
  }
  return entry;
}

function descriptorSize(value: JsonValue | undefined): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    throw new ContainerArchiveError(
      "INVALID_METADATA",
      "An OCI descriptor size is invalid",
    );
  }
  return value;
}

function safePackageField(value: string | undefined): string | undefined {
  return value !== undefined &&
    value.length <= 1024 &&
    SAFE_PACKAGE_FIELD.test(value) &&
    !UNSAFE_TEXT.test(value)
    ? value
    : undefined;
}

function decodePackageDatabase(data: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(data);
  } catch (error: unknown) {
    throw new ContainerArchiveError(
      "PACKAGE_DATABASE_INVALID",
      "An OS package database is not valid UTF-8",
      { cause: error },
    );
  }
}

function boundedLines(text: string): readonly string[] {
  const lines = text.split(/\r?\n/u);
  if (
    lines.length > MAXIMUM_PACKAGE_LINES ||
    lines.some((line) => line.length > MAXIMUM_PACKAGE_LINE || UNSAFE_TEXT.test(line))
  ) {
    throw new ContainerArchiveError(
      "LIMIT_EXCEEDED",
      "An OS package database exceeds the line safety limit",
    );
  }
  return lines;
}

function parseDpkgPackages(
  data: Uint8Array,
  maximumPackages: number,
): readonly ContainerOsPackage[] {
  const paragraphs = boundedLines(decodePackageDatabase(data)).join("\n").split(/\n\s*\n/u);
  const result: ContainerOsPackage[] = [];
  for (const paragraph of paragraphs) {
    if (paragraph.trim().length === 0) {
      continue;
    }
    const fields = new Map<string, string>();
    for (const line of paragraph.split("\n")) {
      const separator = line.indexOf(":");
      if (separator <= 0 || line.startsWith(" ") || line.startsWith("\t")) {
        continue;
      }
      fields.set(line.slice(0, separator), line.slice(separator + 1).trim());
    }
    if (fields.get("Status") !== "install ok installed") {
      continue;
    }
    const name = safePackageField(fields.get("Package"));
    const version = safePackageField(fields.get("Version"));
    const architecture = safePackageField(fields.get("Architecture"));
    if (name === undefined || version === undefined) {
      throw new ContainerArchiveError(
        "PACKAGE_DATABASE_INVALID",
        "An installed dpkg record lacks a safe package identity",
      );
    }
    result.push({
      packageManager: "dpkg",
      name,
      version,
      ...(architecture === undefined ? {} : { architecture }),
    });
    if (result.length > maximumPackages) {
      throw new ContainerArchiveError(
        "LIMIT_EXCEEDED",
        "The OS package count exceeds the configured limit",
      );
    }
  }
  return result;
}

function parseApkPackages(
  data: Uint8Array,
  maximumPackages: number,
): readonly ContainerOsPackage[] {
  const paragraphs = boundedLines(decodePackageDatabase(data)).join("\n").split(/\n\s*\n/u);
  const result: ContainerOsPackage[] = [];
  for (const paragraph of paragraphs) {
    if (paragraph.trim().length === 0) {
      continue;
    }
    const fields = new Map<string, string>();
    for (const line of paragraph.split("\n")) {
      if (line.length >= 3 && line[1] === ":") {
        fields.set(line[0] ?? "", line.slice(2));
      }
    }
    const name = safePackageField(fields.get("P"));
    const version = safePackageField(fields.get("V"));
    const architecture = safePackageField(fields.get("A"));
    if (name === undefined || version === undefined) {
      throw new ContainerArchiveError(
        "PACKAGE_DATABASE_INVALID",
        "An apk record lacks a safe package identity",
      );
    }
    result.push({
      packageManager: "apk",
      name,
      version,
      ...(architecture === undefined ? {} : { architecture }),
    });
    if (result.length > maximumPackages) {
      throw new ContainerArchiveError(
        "LIMIT_EXCEEDED",
        "The OS package count exceeds the configured limit",
      );
    }
  }
  return result;
}

function applyLayer(
  rootFiles: Map<string, MutableRootFile>,
  layer: TarReadResult,
  limits: ContainerArchiveLimits,
): void {
  for (const entry of layer.entries.values()) {
    if (entry.type !== "file") {
      continue;
    }
    const segments = entry.path.split("/");
    const base = segments.at(-1) ?? "";
    const parent = segments.slice(0, -1).join("/");
    if (base === ".wh..wh..opq") {
      for (const candidate of [...rootFiles.keys()]) {
        if (candidate.startsWith(parent.length === 0 ? "" : `${parent}/`)) {
          rootFiles.delete(candidate);
        }
      }
      continue;
    }
    if (base.startsWith(".wh.")) {
      const target = `${parent.length === 0 ? "" : `${parent}/`}${base.slice(4)}`;
      rootFiles.delete(target);
      continue;
    }
    if (
      entry.path === "var/lib/dpkg/status" ||
      entry.path === "lib/apk/db/installed"
    ) {
      if (entry.data.byteLength > limits.maximumPackageDatabaseBytes) {
        throw new ContainerArchiveError(
          "LIMIT_EXCEEDED",
          "An OS package database exceeds the configured byte limit",
        );
      }
      rootFiles.set(entry.path, { data: entry.data });
    }
  }
}

function packagesFromRootFiles(
  rootFiles: ReadonlyMap<string, MutableRootFile>,
  maximumPackages: number,
): readonly ContainerOsPackage[] {
  const result: ContainerOsPackage[] = [];
  const dpkg = rootFiles.get("var/lib/dpkg/status");
  if (dpkg !== undefined) {
    result.push(...parseDpkgPackages(dpkg.data, maximumPackages));
  }
  const apk = rootFiles.get("lib/apk/db/installed");
  if (apk !== undefined) {
    result.push(...parseApkPackages(apk.data, maximumPackages - result.length));
  }
  const deduplicated = new Map<string, ContainerOsPackage>();
  for (const entry of result) {
    const key = JSON.stringify([
      entry.packageManager,
      entry.name,
      entry.version,
      entry.architecture ?? "",
    ]);
    if (!deduplicated.has(key)) {
      deduplicated.set(key, Object.freeze(entry));
    }
  }
  return Object.freeze(
    [...deduplicated.values()].sort(
      (left, right) =>
        left.packageManager.localeCompare(right.packageManager, "en") ||
        left.name.localeCompare(right.name, "en") ||
        left.version.localeCompare(right.version, "en") ||
        (left.architecture ?? "").localeCompare(right.architecture ?? "", "en"),
    ),
  );
}

function safeReference(value: string): string | undefined {
  return value.length > 0 &&
    value.length <= 512 &&
    !UNSAFE_TEXT.test(value) &&
    !/[@:]https?:/iu.test(value) &&
    !value.includes("@")
    ? value
    : undefined;
}

function analyzeDockerArchive(
  tar: TarReadResult,
  limits: ContainerArchiveLimits,
  signal: AbortSignal | undefined,
): readonly ContainerImageAnalysis[] {
  const manifestEntry = tar.entries.get("manifest.json");
  if (manifestEntry === undefined) {
    return [];
  }
  const manifest = array(decodeJson(manifestEntry, 4 * 1024 * 1024));
  if (manifest === undefined || manifest.length === 0 || manifest.length > limits.maximumImages) {
    throw new ContainerArchiveError(
      "INVALID_METADATA",
      "Docker archive manifest.json is invalid or exceeds the image limit",
    );
  }
  const images: ContainerImageAnalysis[] = [];
  const layerBudget = { remaining: limits.maximumArchiveBytes };
  for (const item of manifest) {
    throwIfCancelled(signal);
    const descriptor = record(item);
    const configPath = safeArchivePath(boundedString(descriptor?.Config) ?? "");
    const layerValues = array(descriptor?.Layers);
    if (layerValues === undefined || layerValues.length > limits.maximumLayers) {
      throw new ContainerArchiveError(
        "INVALID_METADATA",
        "A Docker image has an invalid layer list",
      );
    }
    const configEntry = tar.entries.get(configPath);
    if (configEntry === undefined) {
      throw new ContainerArchiveError(
        "INVALID_ARCHIVE",
        "A Docker image config entry is missing",
      );
    }
    const config = record(decodeJson(configEntry, 4 * 1024 * 1024));
    if (config === undefined) {
      throw new ContainerArchiveError(
        "INVALID_METADATA",
        "A Docker image config is invalid",
      );
    }
    const rootFiles = new Map<string, MutableRootFile>();
    let analyzed = 0;
    for (const layerValue of layerValues) {
      const layerPath = safeArchivePath(boundedString(layerValue) ?? "");
      const layerEntry = tar.entries.get(layerPath);
      if (layerEntry === undefined || layerEntry.type !== "file") {
        throw new ContainerArchiveError(
          "INVALID_ARCHIVE",
          "A Docker image layer is missing",
        );
      }
      const layer = readTar(
        layerEntry.data,
        limits,
        signal,
        limits.maximumLayerBytes,
        layerBudget,
      );
      applyLayer(rootFiles, layer, limits);
      analyzed += 1;
    }
    const repoTags = array(descriptor?.RepoTags) ?? [];
    const reference = repoTags
      .map((value) => typeof value === "string" ? safeReference(value) : undefined)
      .find((value): value is string => value !== undefined);
    const operatingSystem = boundedString(config.os, 128);
    const architecture = boundedString(config.architecture, 128);
    images.push(Object.freeze({
      ...(reference === undefined ? {} : { reference }),
      digest: `sha256:${sha256(configEntry.data)}`,
      ...(operatingSystem === undefined ? {} : { operatingSystem }),
      ...(architecture === undefined ? {} : { architecture }),
      layersDeclared: layerValues.length,
      layersAnalyzed: analyzed,
      osPackages: packagesFromRootFiles(rootFiles, limits.maximumPackages),
      osPackageInventoryComplete: true,
    }));
  }
  return Object.freeze(images);
}

function analyzeOciArchive(
  tar: TarReadResult,
  limits: ContainerArchiveLimits,
  signal: AbortSignal | undefined,
): readonly ContainerImageAnalysis[] {
  const layoutEntry = tar.entries.get("oci-layout");
  const indexEntry = tar.entries.get("index.json");
  if (layoutEntry === undefined || indexEntry === undefined) {
    return [];
  }
  const layout = record(decodeJson(layoutEntry, 64 * 1024));
  if (boundedString(layout?.imageLayoutVersion, 32) !== "1.0.0") {
    throw new ContainerArchiveError(
      "INVALID_METADATA",
      "The OCI image layout version is unsupported",
    );
  }
  const index = record(decodeJson(indexEntry, 4 * 1024 * 1024));
  const descriptors = array(index?.manifests);
  if (descriptors === undefined || descriptors.length === 0 || descriptors.length > limits.maximumImages) {
    throw new ContainerArchiveError(
      "INVALID_METADATA",
      "The OCI index has an invalid manifest list",
    );
  }
  const images: ContainerImageAnalysis[] = [];
  const layerBudget = { remaining: limits.maximumArchiveBytes };
  for (const descriptorValue of descriptors) {
    throwIfCancelled(signal);
    const descriptor = record(descriptorValue);
    const digest = boundedString(descriptor?.digest, 128);
    const mediaType = boundedString(descriptor?.mediaType, 256);
    if (
      digest === undefined ||
      (mediaType !== "application/vnd.oci.image.manifest.v1+json" &&
        mediaType !== "application/vnd.docker.distribution.manifest.v2+json")
    ) {
      throw new ContainerArchiveError(
        "UNSUPPORTED_ARCHIVE",
        "The OCI index contains an unsupported manifest descriptor",
      );
    }
    const manifestEntry = verifiedBlob(
      tar.entries,
      digest,
      descriptorSize(descriptor?.size),
    );
    const manifest = record(decodeJson(manifestEntry, 4 * 1024 * 1024));
    const configDescriptor = record(manifest?.config);
    const configDigest = boundedString(configDescriptor?.digest, 128);
    const layers = array(manifest?.layers);
    if (configDigest === undefined || layers === undefined || layers.length > limits.maximumLayers) {
      throw new ContainerArchiveError(
        "INVALID_METADATA",
        "An OCI image manifest is invalid",
      );
    }
    const configEntry = verifiedBlob(
      tar.entries,
      configDigest,
      descriptorSize(configDescriptor?.size),
    );
    const config = record(decodeJson(configEntry, 4 * 1024 * 1024));
    const rootFiles = new Map<string, MutableRootFile>();
    let analyzed = 0;
    for (const layerValue of layers) {
      const layerDescriptor = record(layerValue);
      const layerDigest = boundedString(layerDescriptor?.digest, 128);
      const layerMediaType = boundedString(layerDescriptor?.mediaType, 256);
      if (layerDigest === undefined) {
        throw new ContainerArchiveError(
          "INVALID_METADATA",
          "An OCI layer descriptor is invalid",
        );
      }
      if (
        layerMediaType !== "application/vnd.oci.image.layer.v1.tar" &&
        layerMediaType !== "application/vnd.docker.image.rootfs.diff.tar"
      ) {
        throw new ContainerArchiveError(
          "UNSUPPORTED_LAYER",
          "Compressed, encrypted, foreign, and non-tar OCI layers are unsupported",
        );
      }
      const layerEntry = verifiedBlob(
        tar.entries,
        layerDigest,
        descriptorSize(layerDescriptor?.size),
      );
      const layer = readTar(
        layerEntry.data,
        limits,
        signal,
        limits.maximumLayerBytes,
        layerBudget,
      );
      applyLayer(rootFiles, layer, limits);
      analyzed += 1;
    }
    const annotations = record(descriptor?.annotations);
    const reference = boundedString(
      annotations?.["org.opencontainers.image.ref.name"],
      512,
    );
    const operatingSystem = boundedString(config?.os, 128);
    const architecture = boundedString(config?.architecture, 128);
    images.push(Object.freeze({
      ...(reference === undefined ? {} : { reference }),
      digest,
      ...(operatingSystem === undefined ? {} : { operatingSystem }),
      ...(architecture === undefined ? {} : { architecture }),
      layersDeclared: layers.length,
      layersAnalyzed: analyzed,
      osPackages: packagesFromRootFiles(rootFiles, limits.maximumPackages),
      osPackageInventoryComplete: true,
    }));
  }
  return Object.freeze(images);
}

function issueFromError(error: unknown): ContainerAnalysisIssue {
  if (error instanceof ContainerArchiveError) {
    return Object.freeze({ code: error.code, message: error.message });
  }
  return Object.freeze({
    code: "INVALID_ARCHIVE",
    message: "Container archive analysis failed safely",
  });
}

/**
 * Statically inspects an uncompressed Docker or OCI tar archive. Nothing is
 * extracted, executed, mounted, or fetched. Compressed layers and registry
 * image references are deliberately unsupported in this first safe slice.
 */
export function analyzeContainerArchive(
  archive: Uint8Array,
  options: AnalyzeContainerArchiveOptions = {},
): ContainerArchiveAnalysis {
  let format: ContainerArchiveFormat = "unknown";
  try {
    const limits = resolveLimits(options.limits);
    throwIfCancelled(options.signal);
    if (!(archive instanceof Uint8Array) || archive.byteLength > limits.maximumArchiveBytes) {
      throw new ContainerArchiveError(
        "LIMIT_EXCEEDED",
        "The container archive exceeds the configured byte limit",
      );
    }
    const tar = readTar(
      archive,
      limits,
      options.signal,
      limits.maximumArchiveBytes,
    );
    let images: readonly ContainerImageAnalysis[];
    if (tar.entries.has("oci-layout") || tar.entries.has("index.json")) {
      format = "oci-archive";
      images = analyzeOciArchive(tar, limits, options.signal);
    } else if (tar.entries.has("manifest.json")) {
      format = "docker-archive";
      images = analyzeDockerArchive(tar, limits, options.signal);
    } else {
      throw new ContainerArchiveError(
        "UNSUPPORTED_ARCHIVE",
        "The tar is neither a supported Docker archive nor an OCI image layout",
      );
    }
    if (images.length === 0) {
      throw new ContainerArchiveError(
        "UNSUPPORTED_ARCHIVE",
        "The archive contains no supported image manifest",
      );
    }
    return Object.freeze({
      format,
      status: "incomplete",
      images,
      issues: Object.freeze([
        Object.freeze({
          code: "VULNERABILITY_PROVIDER_NOT_CONFIGURED" as const,
          message:
            "OS package inventory was parsed statically, but no OS-package advisory provider is configured; the image is not classified as clean.",
        }),
      ]),
      coverage: Object.freeze({
        archiveMetadata: "complete" as const,
        osPackages: "complete" as const,
        vulnerabilities: "not-configured" as const,
        licenses: "unknown" as const,
      }),
    });
  } catch (error: unknown) {
    const issue = issueFromError(error);
    const unsupported =
      issue.code === "UNSUPPORTED_ARCHIVE" ||
      issue.code === "UNSUPPORTED_LAYER";
    return Object.freeze({
      format,
      status: unsupported ? "unsupported" : "incomplete",
      images: Object.freeze([]),
      issues: Object.freeze([issue]),
      coverage: Object.freeze({
        archiveMetadata: unsupported ? "unsupported" as const : "partial" as const,
        osPackages: "unknown" as const,
        vulnerabilities: "not-configured" as const,
        licenses: "unknown" as const,
      }),
    });
  }
}
