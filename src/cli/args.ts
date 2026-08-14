import type { Severity } from "../models/Vulnerability";

export const CLI_EXIT_CODES = Object.freeze({
  SUCCESS: 0,
  POLICY_VIOLATION: 1,
  INCOMPLETE: 2,
  INVALID_CONFIGURATION: 3,
  INTERNAL_ERROR: 4,
} as const);

export type CliExitCode =
  (typeof CLI_EXIT_CODES)[keyof typeof CLI_EXIT_CODES];

export type CliCommand =
  | "scan"
  | "gate"
  | "licenses"
  | "provenance"
  | "reachability"
  | "snapshot"
  | "diff"
  | "sbom"
  | "baseline"
  | "container"
  | "help"
  | "version";

export type CliFormat =
  | "text"
  | "json"
  | "sarif"
  | "cyclonedx"
  | "html"
  | "markdown"
  | "csv";

export interface CliArguments {
  readonly command: CliCommand;
  readonly subcommand?: string;
  readonly workspacePaths: readonly string[];
  readonly severity: Severity;
  readonly includeProduction: boolean;
  readonly includeDevelopment: boolean;
  readonly includeTransitive: boolean;
  readonly offline: boolean;
  readonly offlineDatabasePath?: string;
  readonly failOn?: Severity;
  readonly policyPath?: string;
  readonly baselinePath?: string;
  readonly format: CliFormat;
  readonly outputPath?: string;
  readonly timeoutMs: number;
  readonly maximumDependencies: number;
  readonly maximumFiles: number;
  readonly maximumBytes: number;
  readonly noCache: boolean;
  readonly refresh: boolean;
  readonly verbose: boolean;
  readonly quiet: boolean;
}

export class CliUsageError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "CliUsageError";
  }
}

const COMMANDS: ReadonlySet<string> = new Set<CliCommand>([
  "scan",
  "gate",
  "licenses",
  "provenance",
  "reachability",
  "snapshot",
  "diff",
  "sbom",
  "baseline",
  "container",
  "help",
  "version",
]);
const SEVERITIES: ReadonlySet<string> = new Set<Severity>([
  "UNKNOWN",
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
]);
const FORMATS: ReadonlyMap<string, CliFormat> = new Map([
  ["text", "text"],
  ["json", "json"],
  ["sarif", "sarif"],
  ["cyclonedx", "cyclonedx"],
  ["sbom", "cyclonedx"],
  ["html", "html"],
  ["markdown", "markdown"],
  ["md", "markdown"],
  ["csv", "csv"],
]);
const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MAXIMUM_DEPENDENCIES = 10_000;
const DEFAULT_MAXIMUM_FILES = 100_000;
const DEFAULT_MAXIMUM_BYTES = 256 * 1024 * 1024;
const MAXIMUM_ARGUMENTS = 512;
const MAXIMUM_ARGUMENT_LENGTH = 32_768;
const UNSAFE_ARGUMENT = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/u;

function requireSafeArgument(value: string): string {
  if (
    value.length === 0 ||
    value.length > MAXIMUM_ARGUMENT_LENGTH ||
    UNSAFE_ARGUMENT.test(value)
  ) {
    throw new CliUsageError("An argument contains unsafe or excessively long text.");
  }
  return value;
}

function severity(value: string, option: string): Severity {
  const normalized = value.toUpperCase();
  if (!SEVERITIES.has(normalized)) {
    throw new CliUsageError(`${option} must be UNKNOWN, LOW, MEDIUM, HIGH, or CRITICAL.`);
  }
  return normalized as Severity;
}

function format(value: string): CliFormat {
  const selected = FORMATS.get(value.toLowerCase());
  if (selected === undefined) {
    throw new CliUsageError(
      "--format must be text, json, sarif, cyclonedx, html, markdown, or csv.",
    );
  }
  return selected;
}

function positiveInteger(
  value: string,
  option: string,
  maximum: number,
): number {
  if (!/^\d+$/u.test(value)) {
    throw new CliUsageError(`${option} must be a positive integer.`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw new CliUsageError(
      `${option} must be between 1 and ${maximum.toString()}.`,
    );
  }
  return parsed;
}

function timeout(value: string): number {
  const match = /^(\d+)(ms|s|m)?$/iu.exec(value);
  if (match?.[1] === undefined) {
    throw new CliUsageError("--timeout must be milliseconds or use an ms, s, or m suffix.");
  }
  const amount = Number(match[1]);
  const unit = match[2]?.toLowerCase() ?? "ms";
  const multiplier = unit === "m" ? 60_000 : unit === "s" ? 1_000 : 1;
  return positiveInteger(
    String(amount * multiplier),
    "--timeout",
    60 * 60 * 1_000,
  );
}

function splitLongOption(argument: string): {
  readonly name: string;
  readonly inlineValue?: string;
} {
  const separator = argument.indexOf("=");
  if (separator === -1) return { name: argument };
  const value = argument.slice(separator + 1);
  if (value.length === 0) {
    throw new CliUsageError(`${argument.slice(0, separator)} requires a value.`);
  }
  return { name: argument.slice(0, separator), inlineValue: value };
}

export function parseCliArguments(argv: readonly string[]): CliArguments {
  if (!Array.isArray(argv) || argv.length > MAXIMUM_ARGUMENTS) {
    throw new CliUsageError("The CLI argument count exceeds the safety limit.");
  }
  const input = argv.map(requireSafeArgument);
  let command: CliCommand = "help";
  let subcommand: string | undefined;
  let index = 0;
  const first = input[0];
  if (first !== undefined) {
    if (first === "--help" || first === "-h") {
      command = "help";
      index = 1;
    } else if (first === "--version" || first === "-V") {
      command = "version";
      index = 1;
    } else if (!COMMANDS.has(first.toLowerCase())) {
      throw new CliUsageError(`Unknown command: ${first}`);
    } else {
      command = first.toLowerCase() as CliCommand;
      index = 1;
    }
  }

  const operationCandidate = input[index]?.toLowerCase();
  if (
    command === "sbom" &&
    operationCandidate !== undefined &&
    ["import", "diff", "merge"].includes(operationCandidate)
  ) {
    subcommand = operationCandidate;
    index += 1;
  } else if (
    command === "baseline" &&
    operationCandidate !== undefined &&
    ["create", "compare"].includes(operationCandidate)
  ) {
    subcommand = operationCandidate;
    index += 1;
  }

  const workspaces: string[] = [];
  let severityValue: Severity = "UNKNOWN";
  let failOn: Severity | undefined;
  let policyPath: string | undefined;
  let baselinePath: string | undefined;
  let formatValue: CliFormat = "text";
  let formatSelected = false;
  let outputPath: string | undefined;
  let timeoutMs = DEFAULT_TIMEOUT_MS;
  let maximumDependencies = DEFAULT_MAXIMUM_DEPENDENCIES;
  let maximumFiles = DEFAULT_MAXIMUM_FILES;
  let maximumBytes = DEFAULT_MAXIMUM_BYTES;
  let productionSelected = false;
  let developmentSelected = false;
  let includeTransitive = true;
  let transitiveSelection: boolean | undefined;
  let offline = false;
  let offlineDatabasePath: string | undefined;
  let noCache = false;
  let refresh = false;
  let verbose = false;
  let quiet = false;
  let positionalOnly = false;
  const singletons = new Set<string>();

  const useSingleton = (name: string): void => {
    if (singletons.has(name)) {
      throw new CliUsageError(`${name} may be specified only once.`);
    }
    singletons.add(name);
  };
  const nextValue = (
    name: string,
    inlineValue: string | undefined,
  ): string => {
    if (inlineValue !== undefined) return requireSafeArgument(inlineValue);
    const value = input[index + 1];
    if (value === undefined || value === "--") {
      throw new CliUsageError(`${name} requires a value.`);
    }
    index += 1;
    return requireSafeArgument(value);
  };
  const selectFormat = (selected: CliFormat, source: string): void => {
    if (formatSelected && formatValue !== selected) {
      throw new CliUsageError(`${source} conflicts with the selected output format.`);
    }
    formatSelected = true;
    formatValue = selected;
  };

  for (; index < input.length; index += 1) {
    const argument = input[index];
    if (argument === undefined) continue;
    if (argument === "--" && !positionalOnly) {
      positionalOnly = true;
      continue;
    }
    if (positionalOnly || !argument.startsWith("-")) {
      workspaces.push(argument);
      continue;
    }
    if (argument === "-h" || argument === "--help") {
      command = "help";
      continue;
    }
    const { name, inlineValue } = splitLongOption(argument);
    switch (name) {
      case "--severity":
        useSingleton(name);
        severityValue = severity(nextValue(name, inlineValue), name);
        break;
      case "--production":
        if (inlineValue !== undefined) throw new CliUsageError(`${name} does not take a value.`);
        productionSelected = true;
        break;
      case "--development":
        if (inlineValue !== undefined) throw new CliUsageError(`${name} does not take a value.`);
        developmentSelected = true;
        break;
      case "--transitive":
      case "--no-transitive": {
        if (inlineValue !== undefined) throw new CliUsageError(`${name} does not take a value.`);
        const selected = name === "--transitive";
        if (transitiveSelection !== undefined && transitiveSelection !== selected) {
          throw new CliUsageError("--transitive conflicts with --no-transitive.");
        }
        transitiveSelection = selected;
        includeTransitive = selected;
        break;
      }
      case "--offline":
        if (inlineValue !== undefined) throw new CliUsageError(`${name} does not take a value.`);
        offline = true;
        break;
      case "--offline-db":
        useSingleton(name);
        offlineDatabasePath = nextValue(name, inlineValue);
        offline = true;
        break;
      case "--fail-on":
        useSingleton(name);
        failOn = severity(nextValue(name, inlineValue), name);
        break;
      case "--policy":
        useSingleton(name);
        policyPath = nextValue(name, inlineValue);
        break;
      case "--baseline":
        useSingleton(name);
        baselinePath = nextValue(name, inlineValue);
        break;
      case "--format":
        useSingleton(name);
        selectFormat(format(nextValue(name, inlineValue)), name);
        break;
      case "--json":
        if (inlineValue !== undefined) throw new CliUsageError(`${name} does not take a value.`);
        selectFormat("json", name);
        break;
      case "--sarif":
        if (inlineValue !== undefined) throw new CliUsageError(`${name} does not take a value.`);
        selectFormat("sarif", name);
        break;
      case "--sbom":
        if (inlineValue !== undefined) throw new CliUsageError(`${name} does not take a value.`);
        selectFormat("cyclonedx", name);
        break;
      case "--output":
        useSingleton(name);
        outputPath = nextValue(name, inlineValue);
        break;
      case "--timeout":
        useSingleton(name);
        timeoutMs = timeout(nextValue(name, inlineValue));
        break;
      case "--max-dependencies":
        useSingleton(name);
        maximumDependencies = positiveInteger(
          nextValue(name, inlineValue),
          name,
          100_000,
        );
        break;
      case "--max-files":
        useSingleton(name);
        maximumFiles = positiveInteger(
          nextValue(name, inlineValue),
          name,
          2_000_000,
        );
        break;
      case "--max-bytes":
        useSingleton(name);
        maximumBytes = positiveInteger(
          nextValue(name, inlineValue),
          name,
          2 * 1024 * 1024 * 1024,
        );
        break;
      case "--no-cache":
        if (inlineValue !== undefined) throw new CliUsageError(`${name} does not take a value.`);
        noCache = true;
        break;
      case "--refresh":
        if (inlineValue !== undefined) throw new CliUsageError(`${name} does not take a value.`);
        refresh = true;
        break;
      case "--workspace":
        workspaces.push(nextValue(name, inlineValue));
        break;
      case "--verbose":
        if (inlineValue !== undefined) throw new CliUsageError(`${name} does not take a value.`);
        verbose = true;
        break;
      case "--quiet":
        if (inlineValue !== undefined) throw new CliUsageError(`${name} does not take a value.`);
        quiet = true;
        break;
      case "--version":
        if (inlineValue !== undefined) throw new CliUsageError(`${name} does not take a value.`);
        command = "version";
        break;
      default:
        throw new CliUsageError(`Unknown option: ${name}`);
    }
  }

  if (verbose && quiet) {
    throw new CliUsageError("--verbose and --quiet cannot be used together.");
  }
  if (policyPath !== undefined && failOn !== undefined) {
    throw new CliUsageError("--policy and --fail-on cannot be combined ambiguously.");
  }
  const environmentSelected = productionSelected || developmentSelected;
  const workspacePaths =
    workspaces.length === 0 &&
    (command === "scan" ||
      command === "gate" ||
      command === "licenses" ||
      command === "provenance" ||
      command === "reachability" ||
      command === "snapshot" ||
      (command === "baseline" && subcommand === "create"))
      ? ["."]
      : workspaces;
  return {
    command,
    ...(subcommand === undefined ? {} : { subcommand }),
    workspacePaths,
    severity: severityValue,
    includeProduction: environmentSelected ? productionSelected : true,
    includeDevelopment: environmentSelected ? developmentSelected : true,
    includeTransitive,
    offline,
    ...(offlineDatabasePath === undefined
      ? {}
      : { offlineDatabasePath }),
    ...(failOn === undefined ? {} : { failOn }),
    ...(policyPath === undefined ? {} : { policyPath }),
    ...(baselinePath === undefined ? {} : { baselinePath }),
    format: formatValue,
    ...(outputPath === undefined ? {} : { outputPath }),
    timeoutMs,
    maximumDependencies,
    maximumFiles,
    maximumBytes,
    noCache,
    refresh,
    verbose,
    quiet,
  };
}

export const CLI_USAGE = `Dependency Vulnerability Auditor (headless)

Usage:
  dependency-auditor scan [options] [workspace ...]
  dependency-auditor gate [options] [workspace ...]
  dependency-auditor licenses [options] [workspace ...]
  dependency-auditor provenance [options] [workspace ...]
  dependency-auditor reachability [options] [workspace ...]
  dependency-auditor snapshot [options] [workspace ...]
  dependency-auditor diff SNAPSHOT_A SNAPSHOT_B
  dependency-auditor baseline create [options] [workspace ...]
  dependency-auditor baseline compare BASELINE [workspace ...]
  dependency-auditor sbom import FILE
  dependency-auditor sbom diff BOM_A BOM_B
  dependency-auditor sbom merge BOM [BOM ...]
  dependency-auditor container ARCHIVE

Implemented output formats:
  --format text|json|sarif|cyclonedx|html|markdown|csv
  --json | --sarif | --sbom

Scan options:
  --severity LEVEL          Display UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL and above
  --production              Select non-development dependencies
  --development             Select development dependencies
  --transitive              Include transitive dependencies (default)
  --no-transitive           Restrict to direct dependencies
  --offline                 Make no network requests; fails incomplete without local evidence
  --offline-db FILE         Use a bounded local advisory database; implies --offline
  --fail-on LEVEL           Fail a complete scan on findings at or above LEVEL
  --policy FILE             Evaluate a bounded JSON security policy
  --baseline FILE           Integrity-verified baseline evidence for gate
  --output FILE             Create a new report without overwriting any path
  --timeout VALUE           Overall timeout in ms, s, or m (default 120s)
  --max-dependencies N      Maximum dependency records (default 10000)
  --max-files N             Maximum visited workspace entries (default 100000)
  --max-bytes N             Maximum dependency metadata bytes (default 268435456)
  --workspace PATH          Add a workspace root
  --no-cache | --refresh    Accepted; the current CLI uses no persistent cache
  --verbose | --quiet

Exit codes: 0 pass, 1 policy violation, 2 incomplete/unknown, 3 invalid configuration, 4 internal error.
Static scanning never executes package managers, project code, build tools, or containers.
Container input is a local static Docker/OCI tar archive; it is parsed, never executed.
`;
