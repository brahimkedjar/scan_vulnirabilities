import { constants as fileConstants, type Stats } from "node:fs";
import { lstat, open, realpath, unlink } from "node:fs/promises";
import { dirname, join, parse, relative, resolve, sep } from "node:path";

import type { HeadlessScanOutput } from "../core/scanner/HeadlessScanner";
import {
  buildSecurityReport,
  exportSecurityReport,
  type SecurityReportDiffEvidence,
  type SecurityReportKnownExploitationEvidence,
  type SecurityReportLicenseEvidence,
  type SecurityReportProvenanceEvidence,
  type SecurityReportReachabilityEvidence,
} from "../core/reporting/SecurityReport";
import type { SecurityGateResult } from "../policy/PolicyModels";
import { exportSarifJson } from "../reporting/SarifExporter";
import { stableSha256 } from "../sbom/ComponentIdentity";
import { exportCycloneDxJson } from "../sbom/CycloneDxJson";

export class CliOutputError extends Error {
  public constructor(
    public readonly code: "INVALID_OUTPUT" | "OUTPUT_EXISTS" | "OUTPUT_FAILED",
    message: string,
    options: { readonly cause?: unknown } = {},
  ) {
    super(message, options);
    this.name = "CliOutputError";
  }
}

const MAXIMUM_OUTPUT_BYTES = 128 * 1024 * 1024;
const UNSAFE_TERMINAL_TEXT =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/gu;

function terminalText(value: string): string {
  return value.replace(UNSAFE_TERMINAL_TEXT, "\uFFFD").slice(0, 4_096);
}

function deterministicUuid(results: HeadlessScanOutput): string {
  const evidence = results.results.flatMap((result) => [
    result.workspacePath,
    ...result.dependencies.map((dependency) =>
      JSON.stringify([
        dependency.ecosystem,
        dependency.name,
        dependency.installedVersion,
      ]),
    ),
  ]);
  const hash = stableSha256(JSON.stringify(evidence));
  return `urn:uuid:${hash.slice(0, 8)}-${hash.slice(8, 12)}-4${hash.slice(13, 16)}-8${hash.slice(17, 20)}-${hash.slice(20, 32)}`;
}

export function renderTextScan(output: HeadlessScanOutput): string {
  const dependencyCount = output.results.reduce(
    (sum, result) => sum + result.dependenciesScanned,
    0,
  );
  const findingCount = output.results.reduce(
    (sum, result) => sum + (result.unfilteredVulnerabilities ?? result.vulnerabilities).length,
    0,
  );
  const lines = [
    `Security state: ${output.status.toUpperCase()}`,
    `Coverage: ${output.coverage}`,
    `Mode: ${output.offline ? "offline (no network)" : "online"}`,
    `Dependencies: ${dependencyCount.toString()}`,
    `Vulnerabilities: ${findingCount.toString()}`,
  ];
  const offlineDatabase = (
    output as HeadlessScanOutput & {
      readonly offlineAdvisoryDatabase?: {
        readonly source: string;
        readonly ageMs: number;
        readonly validUntil: string;
        readonly status: string;
      };
    }
  ).offlineAdvisoryDatabase;
  if (offlineDatabase !== undefined) {
    lines.push(
      `Offline advisory evidence: ${terminalText(offlineDatabase.status)} (${terminalText(offlineDatabase.source)})`,
      `Offline advisory age: ${offlineDatabase.ageMs.toString()} ms`,
      `Offline advisory valid until: ${terminalText(offlineDatabase.validUntil)}`,
    );
  }
  if (output.reasons.length > 0) {
    lines.push("Evidence gaps:");
    for (const reason of output.reasons.slice(0, 100)) {
      lines.push(
        `- [${terminalText(reason.code)}] ${terminalText(reason.message)}`,
      );
    }
    if (output.reasons.length > 100) {
      lines.push(
        `- ${(output.reasons.length - 100).toString()} additional gap(s) omitted`,
      );
    }
  }
  for (const result of output.results) {
    for (const vulnerability of result.vulnerabilities.slice(0, 1_000)) {
      lines.push(
        `${terminalText(vulnerability.severity)} ${terminalText(vulnerability.id)} ${terminalText(vulnerability.packageName)}@${terminalText(vulnerability.installedVersion)}`,
      );
    }
  }
  return `${lines.join("\n")}\n`;
}

export function renderScanOutput(
  output: HeadlessScanOutput,
  format:
    | "text"
    | "json"
    | "sarif"
    | "cyclonedx"
    | "html"
    | "markdown"
    | "csv",
  toolVersion: string,
  evidence: {
    readonly policy?: SecurityGateResult;
    readonly licenses?: readonly SecurityReportLicenseEvidence[];
    readonly provenance?: readonly SecurityReportProvenanceEvidence[];
    readonly reachability?: readonly SecurityReportReachabilityEvidence[];
    readonly knownExploitation?: readonly SecurityReportKnownExploitationEvidence[];
    readonly diff?: SecurityReportDiffEvidence;
  } = {},
): string {
  switch (format) {
    case "text":
      return renderTextScan(output);
    case "json":
      return `${JSON.stringify(output, null, 2)}\n`;
    case "sarif":
      return exportSarifJson(output.results, {
        workspaceRoots: output.results.map((result) => result.workspacePath),
        toolVersion,
      });
    case "cyclonedx":
      return exportCycloneDxJson(output.results, {
        timestamp: output.results[0]?.scannedAt ?? new Date(0).toISOString(),
        serialNumber: deterministicUuid(output),
        workspaceRoots: output.results.map((result) => result.workspacePath),
        toolVersion,
      });
    case "html":
    case "markdown":
    case "csv": {
      const report = buildSecurityReport(output.results, {
        generatedAt:
          output.results[0]?.scannedAt ?? new Date(0).toISOString(),
        toolVersion,
        workspaceRoots: output.results.map((result) => result.workspacePath),
        ...(evidence.policy === undefined ? {} : { policy: evidence.policy }),
        ...(evidence.licenses === undefined
          ? {}
          : { licenses: evidence.licenses }),
        ...(evidence.provenance === undefined
          ? {}
          : { provenance: evidence.provenance }),
        ...(evidence.reachability === undefined
          ? {}
          : { reachability: evidence.reachability }),
        ...(evidence.knownExploitation === undefined
          ? {}
          : { knownExploitation: evidence.knownExploitation }),
        ...(evidence.diff === undefined ? {} : { diff: evidence.diff }),
      });
      return exportSecurityReport(report, format);
    }
  }
}

function outputBytes(content: string): Uint8Array {
  const bytes = new TextEncoder().encode(content);
  if (bytes.byteLength > MAXIMUM_OUTPUT_BYTES) {
    throw new CliOutputError(
      "INVALID_OUTPUT",
      "The generated report exceeds the output safety limit.",
    );
  }
  return bytes;
}

function sameFileIdentity(left: Stats, right: Stats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mtimeMs === right.mtimeMs
  );
}

async function assertSafeParentComponents(parent: string): Promise<void> {
  const root = parse(parent).root;
  let current = root;
  for (const component of relative(root, parent).split(sep)) {
    if (component.length === 0) continue;
    current = join(current, component);
    const stat = await lstat(current);
    const attributes = (stat as Stats & { readonly fileAttributes?: number })
      .fileAttributes;
    const constants = fileConstants as typeof fileConstants & {
      readonly FILE_ATTRIBUTE_REPARSE_POINT?: number;
    };
    if (
      stat.isSymbolicLink() ||
      (process.platform === "win32" &&
        attributes !== undefined &&
        constants.FILE_ATTRIBUTE_REPARSE_POINT !== undefined &&
        (attributes & constants.FILE_ATTRIBUTE_REPARSE_POINT) !== 0)
    ) {
      throw new CliOutputError(
        "INVALID_OUTPUT",
        "The output parent cannot contain a symbolic link, junction, or reparse point.",
      );
    }
    if (!stat.isDirectory()) {
      throw new CliOutputError(
        "INVALID_OUTPUT",
        "Every output parent component must be an existing directory.",
      );
    }
  }
}

export async function writeNewOutputFile(
  outputPath: string,
  content: string,
): Promise<void> {
  const absolute = resolve(outputPath);
  if (absolute.length > 32_768) {
    throw new CliOutputError("INVALID_OUTPUT", "The output path is too long.");
  }
  const bytes = outputBytes(content);
  let parent: string;
  try {
    const requestedParent = resolve(dirname(absolute));
    await assertSafeParentComponents(requestedParent);
    parent = await realpath(requestedParent);
    const parentStat = await lstat(parent);
    if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) {
      throw new CliOutputError(
        "INVALID_OUTPUT",
        "The output parent must be an existing regular directory.",
      );
    }
    const comparable = (value: string): string =>
      process.platform === "win32" ? value.toLowerCase() : value;
    if (comparable(resolve(parent)) !== comparable(requestedParent)) {
      throw new CliOutputError(
        "INVALID_OUTPUT",
        "The output parent cannot be reached through a symbolic link or junction.",
      );
    }
  } catch (error: unknown) {
    if (error instanceof CliOutputError) throw error;
    throw new CliOutputError(
      "INVALID_OUTPUT",
      "The output parent directory could not be resolved safely.",
      { cause: error },
    );
  }
  let handle;
  let createdIdentity: Stats | undefined;
  let completed = false;
  try {
    handle = await open(
      absolute,
      fileConstants.O_CREAT |
        fileConstants.O_EXCL |
        fileConstants.O_WRONLY |
        (fileConstants.O_NOFOLLOW ?? 0),
      0o600,
    );
    const stat = await handle.stat();
    if (stat.isFile()) createdIdentity = stat;
    if (!stat.isFile() || stat.size !== 0) {
      throw new CliOutputError(
        "OUTPUT_FAILED",
        "The exclusively created output is not an empty regular file.",
      );
    }
    await handle.writeFile(bytes);
    await handle.sync();
    const after = await handle.stat();
    if (!after.isFile() || after.size !== bytes.byteLength) {
      throw new CliOutputError(
        "OUTPUT_FAILED",
        "The report output could not be verified after writing.",
      );
    }
    completed = true;
  } catch (error: unknown) {
    if (error instanceof CliOutputError) throw error;
    const code =
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      typeof error.code === "string"
        ? error.code
        : undefined;
    throw new CliOutputError(
      code === "EEXIST" ? "OUTPUT_EXISTS" : "OUTPUT_FAILED",
      code === "EEXIST"
        ? "The output path already exists; reports are never overwritten."
        : "The report output could not be created safely.",
      { cause: error },
    );
  } finally {
    try {
      await handle?.close();
    } catch {
      // Preserve the primary output result.
    }
    if (!completed && createdIdentity !== undefined) {
      try {
        const current = await lstat(absolute);
        if (
          current.isFile() &&
          !current.isSymbolicLink() &&
          sameFileIdentity(createdIdentity, current)
        ) {
          await unlink(absolute);
        }
      } catch {
        // Cleanup is identity-gated and best-effort; never delete an unknown replacement.
      }
    }
  }
}
