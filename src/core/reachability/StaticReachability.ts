import {
  boundedEvidenceText,
  boundedOpaqueId,
  boundedPositiveLimit,
  boundedRelativeId,
  compareText,
  freezeStrings,
  isAnalysisCancelled,
} from "../evidence/EvidenceControls";

export type StaticSourceLanguage =
  | "javascript"
  | "typescript"
  | "jsx"
  | "tsx"
  | "python";
export type ReachabilityStatus = "REACHABLE" | "NOT_OBSERVED" | "UNKNOWN";
export type ReachabilityConfidence = "HIGH" | "MEDIUM" | "LOW";

export interface StaticSourceInput {
  /** Relative, traversal-free identifier. Absolute host paths are rejected. */
  readonly fileId: string;
  readonly language: StaticSourceLanguage;
  readonly content: string;
  readonly entrypoint?: boolean;
}

export interface ReachabilityTargetInput {
  readonly targetId: string;
  readonly ecosystem: "npm" | "PyPI";
  readonly packageName: string;
  /** Advisory-supplied symbols only; this analyzer never invents affected APIs. */
  readonly affectedSymbols?: readonly string[];
}

export interface StaticReachabilityInput {
  readonly sources: readonly StaticSourceInput[];
  readonly targets: readonly ReachabilityTargetInput[];
  /** Optional relative identifiers; source-level entrypoint flags are additive. */
  readonly entrypoints?: readonly string[];
}

export interface StaticReachabilityFinding {
  readonly targetId: string;
  readonly ecosystem: "npm" | "PyPI";
  readonly packageName: string;
  readonly affectedSymbols: readonly string[];
  readonly status: ReachabilityStatus;
  readonly confidence: ReachabilityConfidence;
  readonly path: readonly string[];
  readonly observedSymbol?: string;
  readonly evidence: string;
  readonly limitations: readonly string[];
  readonly exploitability: "NOT_ESTABLISHED";
}

export interface StaticReachabilityCoverage {
  readonly sourceFilesTotal: number;
  readonly sourceFilesAnalyzed: number;
  readonly sourceFilesInvalid: number;
  readonly sourceFilesOmitted: number;
  readonly bytesAnalyzed: number;
  readonly targetsTotal: number;
  readonly targetsAnalyzed: number;
  readonly entrypointsResolved: number;
  readonly importEdgesObserved: number;
  readonly uncertainReachableFiles: number;
  readonly truncated: boolean;
  readonly cancelled: boolean;
  readonly analysisComplete: boolean;
}

export interface StaticReachabilityResult {
  readonly findings: readonly StaticReachabilityFinding[];
  readonly coverage: StaticReachabilityCoverage;
}

export interface StaticReachabilityLimits {
  readonly maximumFiles?: number;
  readonly maximumBytes?: number;
  readonly maximumBytesPerFile?: number;
  readonly maximumTargets?: number;
  readonly maximumImportsPerFile?: number;
  readonly maximumEdges?: number;
  readonly maximumPathDepth?: number;
}

export interface StaticReachabilityOptions {
  readonly limits?: StaticReachabilityLimits;
  readonly signal?: AbortSignal;
}

const HARD_LIMITS = Object.freeze({
  maximumFiles: 20_000,
  maximumBytes: 32 * 1024 * 1024,
  maximumBytesPerFile: 2 * 1024 * 1024,
  maximumTargets: 10_000,
  maximumImportsPerFile: 2_048,
  maximumEdges: 200_000,
  maximumPathDepth: 512,
});
const MAXIMUM_IDENTITY = 256;
const PACKAGE_RE = /^(?:@[a-z0-9._~-]+\/[a-z0-9._~-]+|[a-z0-9._~-]+)$/iu;
const PYTHON_PACKAGE_RE = /^[A-Za-z_][A-Za-z0-9_.-]*$/u;

interface ResolvedLimits {
  readonly maximumFiles: number;
  readonly maximumBytes: number;
  readonly maximumBytesPerFile: number;
  readonly maximumTargets: number;
  readonly maximumImportsPerFile: number;
  readonly maximumEdges: number;
  readonly maximumPathDepth: number;
}

interface ImportObservation {
  readonly specifier: string;
  readonly symbols: ReadonlySet<string>;
  readonly wildcard: boolean;
}

interface ParsedSource {
  readonly fileId: string;
  readonly language: StaticSourceLanguage;
  readonly imports: readonly ImportObservation[];
  readonly uncertain: boolean;
  readonly entrypoint: boolean;
}

function limits(options: StaticReachabilityOptions): ResolvedLimits {
  const configured = options.limits;
  return {
    maximumFiles: boundedPositiveLimit(configured?.maximumFiles, 5_000, HARD_LIMITS.maximumFiles),
    maximumBytes: boundedPositiveLimit(configured?.maximumBytes, 8 * 1024 * 1024, HARD_LIMITS.maximumBytes),
    maximumBytesPerFile: boundedPositiveLimit(configured?.maximumBytesPerFile, 512 * 1024, HARD_LIMITS.maximumBytesPerFile),
    maximumTargets: boundedPositiveLimit(configured?.maximumTargets, 2_000, HARD_LIMITS.maximumTargets),
    maximumImportsPerFile: boundedPositiveLimit(configured?.maximumImportsPerFile, 512, HARD_LIMITS.maximumImportsPerFile),
    maximumEdges: boundedPositiveLimit(configured?.maximumEdges, 50_000, HARD_LIMITS.maximumEdges),
    maximumPathDepth: boundedPositiveLimit(configured?.maximumPathDepth, 128, HARD_LIMITS.maximumPathDepth),
  };
}

function safePackageName(value: unknown, ecosystem: "npm" | "PyPI"): string | undefined {
  const text = boundedEvidenceText(value, MAXIMUM_IDENTITY);
  if (text === undefined) {
    return undefined;
  }
  if (ecosystem === "npm") {
    return PACKAGE_RE.test(text) ? text.toLowerCase() : undefined;
  }
  return PYTHON_PACKAGE_RE.test(text)
    ? text.toLowerCase().replaceAll("_", "-")
    : undefined;
}

function npmPackage(specifier: string): string | undefined {
  if (specifier.startsWith(".") || specifier.startsWith("/") || specifier.includes("\\")) {
    return undefined;
  }
  const pieces = specifier.split("/");
  const candidate = specifier.startsWith("@")
    ? pieces.length >= 2
      ? `${pieces[0]}/${pieces[1]}`
      : undefined
    : pieces[0];
  return candidate === undefined ? undefined : safePackageName(candidate, "npm");
}

function pythonPackage(specifier: string): string | undefined {
  if (specifier.startsWith(".")) {
    return undefined;
  }
  return safePackageName(specifier.split(".")[0], "PyPI");
}

/** Removes comments while retaining quoted import specifiers and line offsets. */
function stripJavaScriptComments(content: string): {
  readonly text: string;
  readonly uncertain: boolean;
  readonly stringRanges: readonly (readonly [number, number])[];
} {
  let state:
    | "code"
    | "single"
    | "double"
    | "template"
    | "regex"
    | "line"
    | "block" = "code";
  let escaped = false;
  let regexCharacterClass = false;
  let uncertain = false;
  let quoteStart = -1;
  const stringRanges: Array<readonly [number, number]> = [];
  const output = [...content];
  for (let index = 0; index < content.length; index += 1) {
    const char = content[index] ?? "";
    const next = content[index + 1] ?? "";
    if (state === "line") {
      if (char === "\n" || char === "\r") {
        state = "code";
      } else {
        output[index] = " ";
      }
      continue;
    }
    if (state === "block") {
      output[index] = char === "\n" || char === "\r" ? char : " ";
      if (char === "*" && next === "/") {
        output[index + 1] = " ";
        index += 1;
        state = "code";
      }
      continue;
    }
    if (state === "regex") {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === "[") {
        regexCharacterClass = true;
      } else if (char === "]") {
        regexCharacterClass = false;
      } else if (char === "/" && !regexCharacterClass) {
        stringRanges.push([quoteStart, index + 1]);
        quoteStart = -1;
        state = "code";
      } else if (char === "\n" || char === "\r") {
        stringRanges.push([quoteStart, index]);
        quoteStart = -1;
        state = "code";
        uncertain = true;
      }
      continue;
    }
    if (state !== "code") {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (
        (state === "single" && char === "'") ||
        (state === "double" && char === '"') ||
        (state === "template" && char === "`")
      ) {
        stringRanges.push([quoteStart, index + 1]);
        quoteStart = -1;
        state = "code";
      } else if (state === "template" && char === "$" && next === "{") {
        uncertain = true;
      }
      continue;
    }
    if (char === "/" && next === "/") {
      output[index] = " ";
      output[index + 1] = " ";
      index += 1;
      state = "line";
    } else if (char === "/" && next === "*") {
      output[index] = " ";
      output[index + 1] = " ";
      index += 1;
      state = "block";
    } else if (
      char === "/" &&
      /(?:^|[({[=,:;!?&|+*%~<>-]|=>|\b(?:return|throw|case|delete|void|typeof|instanceof|in|of|yield|await))\s*$/u.test(
        content.slice(Math.max(0, index - 24), index),
      )
    ) {
      quoteStart = index;
      regexCharacterClass = false;
      state = "regex";
    } else if (char === "'") {
      quoteStart = index;
      state = "single";
    } else if (char === '"') {
      quoteStart = index;
      state = "double";
    } else if (char === "`") {
      quoteStart = index;
      state = "template";
    }
  }
  if (
    state === "single" ||
    state === "double" ||
    state === "template" ||
    state === "regex" ||
    state === "block"
  ) {
    uncertain = true;
  }
  if (quoteStart >= 0) {
    stringRanges.push([quoteStart, content.length]);
  }
  return { text: output.join(""), uncertain, stringRanges: Object.freeze(stringRanges) };
}

function observation(
  specifier: string,
  symbols: readonly string[] = [],
  wildcard = false,
): ImportObservation {
  return Object.freeze({
    specifier,
    symbols: new Set(symbols),
    wildcard,
  });
}

function indexInRanges(
  index: number,
  ranges: readonly (readonly [number, number])[],
): boolean {
  let low = 0;
  let high = ranges.length - 1;
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const range = ranges[middle];
    if (range === undefined) {
      return false;
    }
    if (index < range[0]) {
      high = middle - 1;
    } else if (index >= range[1]) {
      low = middle + 1;
    } else {
      return true;
    }
  }
  return false;
}

function memberSymbols(
  body: string,
  ignoredRanges: readonly (readonly [number, number])[] = [],
): ReadonlyMap<string, ReadonlySet<string>> {
  const observed = new Map<string, Set<string>>();
  for (const match of body.matchAll(/\b([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)/gu)) {
    if (match.index === undefined || indexInRanges(match.index, ignoredRanges)) {
      continue;
    }
    const binding = match[1];
    const symbol = match[2];
    if (binding === undefined || symbol === undefined) {
      continue;
    }
    const values = observed.get(binding) ?? new Set<string>();
    values.add(symbol);
    observed.set(binding, values);
  }
  return observed;
}

function balancedDelimiters(
  body: string,
  ignoredRanges: readonly (readonly [number, number])[] = [],
): boolean {
  const stack: string[] = [];
  const closing: Readonly<Record<string, string>> = Object.freeze({
    ")": "(",
    "]": "[",
    "}": "{",
  });
  for (let index = 0; index < body.length; index += 1) {
    if (indexInRanges(index, ignoredRanges)) {
      continue;
    }
    const character = body[index];
    if (character === "(" || character === "[" || character === "{") {
      stack.push(character);
    } else if (
      (character === ")" || character === "]" || character === "}") &&
      stack.pop() !== closing[character]
    ) {
      return false;
    }
  }
  return stack.length === 0;
}

function importedBindingSymbols(
  clause: string,
  observedMembers: ReadonlyMap<string, ReadonlySet<string>>,
): { readonly symbols: readonly string[]; readonly wildcard: boolean } {
  const symbols = new Set<string>();
  let wildcard = false;
  const named = /\{([^}]*)\}/u.exec(clause)?.[1];
  if (named !== undefined) {
    for (const item of named.split(",")) {
      const original = boundedEvidenceText(item.trim().split(/\s+as\s+/iu)[0], MAXIMUM_IDENTITY);
      if (original !== undefined) {
        symbols.add(original);
      }
    }
  }
  const namespace = /\*\s+as\s+([A-Za-z_$][\w$]*)/u.exec(clause)?.[1];
  if (namespace !== undefined) {
    for (const symbol of observedMembers.get(namespace) ?? []) {
      symbols.add(symbol);
    }
    wildcard = symbols.size === 0;
  }
  const withoutNamed = clause.replace(/\{[^}]*\}/gu, "").replace(/\*\s+as\s+[A-Za-z_$][\w$]*/gu, "").trim();
  const defaultBinding = /^([A-Za-z_$][\w$]*)/u.exec(withoutNamed)?.[1];
  if (defaultBinding !== undefined) {
    for (const symbol of observedMembers.get(defaultBinding) ?? []) {
      symbols.add(symbol);
    }
    wildcard = symbols.size === 0;
  }
  return { symbols: Object.freeze([...symbols]), wildcard };
}

function parseJavaScript(content: string, maximumImports: number): { readonly imports: readonly ImportObservation[]; readonly uncertain: boolean } {
  const stripped = stripJavaScriptComments(content);
  const imports: ImportObservation[] = [];
  let uncertain =
    stripped.uncertain ||
    !balancedDelimiters(stripped.text, stripped.stringRanges);
  const add = (item: ImportObservation): void => {
    if (imports.length < maximumImports) {
      imports.push(item);
    } else {
      uncertain = true;
    }
  };
  const coveredRanges: Array<readonly [number, number]> = [];
  const insideString = (index: number): boolean =>
    indexInRanges(index, stripped.stringRanges);
  const observedMembers = memberSymbols(stripped.text, stripped.stringRanges);
  const staticPattern = /\bimport\s+([^;]*?)\s+from\s*(["'])([^"'\r\n]+)\2|\b(?:import|export)\s*(["'])([^"'\r\n]+)\4/gu;
  for (const match of stripped.text.matchAll(staticPattern)) {
    if (match.index === undefined || insideString(match.index)) {
      continue;
    }
    const specifier = match[3] ?? match[5];
    if (specifier !== undefined) {
      const details = importedBindingSymbols(match[1] ?? "", observedMembers);
      add(observation(specifier, details.symbols, match[1] === undefined || details.wildcard));
      if (match.index !== undefined) {
        coveredRanges.push([match.index, match.index + match[0].length]);
      }
    }
  }
  const requirePattern = /\b(?:const|let|var)\s+([^=;\r\n]+?)\s*=\s*require\s*\(\s*(["'])([^"'\r\n]+)\2\s*\)|\brequire\s*\(\s*(["'])([^"'\r\n]+)\4\s*\)(?:\.([A-Za-z_$][\w$]*))?/gu;
  for (const match of stripped.text.matchAll(requirePattern)) {
    if (match.index === undefined || insideString(match.index)) {
      continue;
    }
    const specifier = match[3] ?? match[5];
    if (specifier === undefined) {
      continue;
    }
    const symbols: string[] = [];
    let wildcard = true;
    const binding = match[1]?.trim();
    if (binding?.startsWith("{") === true && binding.endsWith("}")) {
      for (const item of binding.slice(1, -1).split(",")) {
        const name = boundedEvidenceText(item.trim().split(/\s*:\s*/u)[0], MAXIMUM_IDENTITY);
        if (name !== undefined) {
          symbols.push(name);
        }
      }
      wildcard = false;
    } else if (binding !== undefined && /^[A-Za-z_$][\w$]*$/u.test(binding)) {
      for (const symbol of observedMembers.get(binding) ?? []) {
        symbols.push(symbol);
      }
      wildcard = symbols.length === 0;
    } else if (match[6] !== undefined) {
      symbols.push(match[6]);
      wildcard = false;
    }
    add(observation(specifier, symbols, wildcard));
    if (match.index !== undefined) {
      coveredRanges.push([match.index, match.index + match[0].length]);
    }
  }
  const dynamicLiteral = /\bimport\s*\(\s*(["'])([^"'\r\n]+)\1\s*\)/gu;
  for (const match of stripped.text.matchAll(dynamicLiteral)) {
    if (match.index === undefined || insideString(match.index)) {
      continue;
    }
    if (match[2] !== undefined) {
      add(observation(match[2], [], true));
      if (match.index !== undefined) {
        coveredRanges.push([match.index, match.index + match[0].length]);
      }
    }
  }
  const covered = (index: number): boolean => coveredRanges.some(([start, end]) => index >= start && index < end);
  for (const match of stripped.text.matchAll(/\b(?:import|require)\s*\(/gu)) {
    if (match.index !== undefined && !insideString(match.index) && !covered(match.index)) {
      uncertain = true;
    }
  }
  if (/\b(?:eval|Function)\s*\(|\bnew\s+Function\b/u.test(stripped.text)) {
    uncertain = true;
  }
  return { imports: Object.freeze(imports), uncertain };
}

function stripPythonComments(content: string): { readonly text: string; readonly uncertain: boolean } {
  const output = [...content];
  let quote: "'" | '"' | "'''" | '\"\"\"' | undefined;
  let escaped = false;
  for (let index = 0; index < content.length; index += 1) {
    const char = content[index] ?? "";
    if (quote === undefined) {
      if (char === "#") {
        while (index < content.length && content[index] !== "\n" && content[index] !== "\r") {
          output[index] = " ";
          index += 1;
        }
        index -= 1;
      } else if (content.startsWith("'''", index)) {
        output[index] = " ";
        output[index + 1] = " ";
        output[index + 2] = " ";
        quote = "'''";
        index += 2;
      } else if (content.startsWith('\"\"\"', index)) {
        output[index] = " ";
        output[index + 1] = " ";
        output[index + 2] = " ";
        quote = '\"\"\"';
        index += 2;
      } else if (char === "'" || char === '"') {
        output[index] = " ";
        quote = char;
      }
    } else if (quote === "'''" || quote === '\"\"\"') {
      if (content.startsWith(quote, index)) {
        output[index] = " ";
        output[index + 1] = " ";
        output[index + 2] = " ";
        index += 2;
        quote = undefined;
      } else if (char !== "\n" && char !== "\r") {
        output[index] = " ";
      }
    } else if (escaped) {
      if (char !== "\n" && char !== "\r") {
        output[index] = " ";
      }
      escaped = false;
    } else if (char === "\\") {
      output[index] = " ";
      escaped = true;
    } else if (char === quote) {
      output[index] = " ";
      quote = undefined;
    } else if (char !== "\n" && char !== "\r") {
      output[index] = " ";
    }
  }
  return { text: output.join(""), uncertain: quote !== undefined };
}

function parsePython(content: string, maximumImports: number): { readonly imports: readonly ImportObservation[]; readonly uncertain: boolean } {
  const stripped = stripPythonComments(content);
  const observedMembers = memberSymbols(stripped.text);
  const imports: ImportObservation[] = [];
  let uncertain = stripped.uncertain || !balancedDelimiters(stripped.text);
  const add = (item: ImportObservation): void => {
    if (imports.length < maximumImports) {
      imports.push(item);
    } else {
      uncertain = true;
    }
  };
  for (const match of stripped.text.matchAll(/^\s*from\s+([.A-Za-z_][\w.]*)\s+import\s+([^#\r\n;]+)/gmu)) {
    if (match[1] === undefined || match[2] === undefined) {
      continue;
    }
    const symbols = match[2].split(",").map((item) => item.trim().split(/\s+as\s+/u)[0])
      .filter((item): item is string => boundedEvidenceText(item, MAXIMUM_IDENTITY) !== undefined && item !== "*");
    add(observation(match[1], symbols, match[2].includes("*")));
  }
  for (const match of stripped.text.matchAll(/^\s*import\s+([^#\r\n;]+)/gmu)) {
    for (const item of match[1]?.split(",") ?? []) {
      const pieces = item.trim().split(/\s+as\s+/u);
      const specifier = boundedEvidenceText(pieces[0], MAXIMUM_IDENTITY);
      if (specifier === undefined) {
        uncertain = true;
        continue;
      }
      const binding = pieces[1] ?? specifier.split(".")[0];
      const symbols = [...(binding === undefined ? [] : (observedMembers.get(binding) ?? []))];
      add(observation(specifier, symbols, symbols.length === 0));
    }
  }
  if (/\b(?:eval|exec|__import__|importlib\s*\.\s*import_module)\s*\(/u.test(stripped.text)) {
    uncertain = true;
  }
  if (/^\s*(?:from|import)\b[^\r\n]*(?:\\$|\([^\r\n]*$)/gmu.test(stripped.text)) {
    uncertain = true;
  }
  return { imports: Object.freeze(imports), uncertain };
}

function sourceModuleIds(fileId: string, language: StaticSourceLanguage): readonly string[] {
  if (language === "python") {
    const withoutExtension = fileId.endsWith(".py") ? fileId.slice(0, -3) : fileId;
    const module = withoutExtension.endsWith("/__init__") ? withoutExtension.slice(0, -9) : withoutExtension;
    return freezeStrings([module.replaceAll("/", ".")]);
  }
  const extensionless = fileId.replace(/\.(?:[cm]?[jt]sx?)$/u, "");
  const ids = [extensionless];
  if (extensionless.endsWith("/index")) {
    ids.push(extensionless.slice(0, -6));
  }
  return freezeStrings(ids);
}

function resolveRelativeJavaScript(from: string, specifier: string, sources: ReadonlyMap<string, ParsedSource>): string | undefined {
  if (!specifier.startsWith(".")) {
    return undefined;
  }
  const stack = from.split("/").slice(0, -1);
  for (const segment of specifier.replaceAll("\\", "/").split("/")) {
    if (segment === "." || segment.length === 0) {
      continue;
    }
    if (segment === "..") {
      if (stack.length === 0) {
        return undefined;
      }
      stack.pop();
    } else {
      stack.push(segment);
    }
  }
  const base = stack.join("/");
  const candidates = [base, ...[".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"].map((extension) => `${base}${extension}`), ...["js", "mjs", "cjs", "ts", "tsx", "jsx"].map((extension) => `${base}/index.${extension}`)];
  return candidates.find((candidate) => sources.has(candidate));
}

function resolvePython(from: string, specifier: string, moduleToFile: ReadonlyMap<string, string>): string | undefined {
  if (!specifier.startsWith(".")) {
    return moduleToFile.get(specifier);
  }
  const leading = /^\.+/u.exec(specifier)?.[0].length ?? 0;
  const current = from.endsWith("/__init__.py") ? from.slice(0, -12).split("/") : from.split("/").slice(0, -1);
  for (let count = 1; count < leading; count += 1) {
    if (current.length === 0) {
      return undefined;
    }
    current.pop();
  }
  const tail = specifier.slice(leading).replaceAll(".", "/");
  const target = [...current, ...(tail.length === 0 ? [] : tail.split("/"))].join(".");
  return moduleToFile.get(target);
}

function symbolMatch(observation: ImportObservation, affected: readonly string[]): string | undefined {
  if (affected.length === 0) {
    return "*";
  }
  for (const symbol of affected) {
    const leaf = symbol.split(/[.#/]/u).at(-1) ?? symbol;
    if (observation.symbols.has(symbol) || observation.symbols.has(leaf)) {
      return symbol;
    }
  }
  return undefined;
}

function unknownFinding(target: ReachabilityTargetInput, reason: string): StaticReachabilityFinding {
  const safeName = safePackageName(target.packageName, target.ecosystem) ?? "UNKNOWN";
  const targetId = boundedOpaqueId(target.targetId, MAXIMUM_IDENTITY) ?? "UNKNOWN";
  return Object.freeze({
    targetId, ecosystem: target.ecosystem, packageName: safeName,
    affectedSymbols: Object.freeze([]), status: "UNKNOWN", confidence: "LOW", path: Object.freeze([]),
    evidence: reason,
    limitations: freezeStrings(["Static source observation cannot establish exploitability or runtime behavior."]),
    exploitability: "NOT_ESTABLISHED",
  });
}

export function analyzeStaticReachability(
  input: StaticReachabilityInput,
  options: StaticReachabilityOptions = {},
): StaticReachabilityResult {
  const resolvedLimits = limits(options);
  const sources = new Map<string, ParsedSource>();
  let bytesAnalyzed = 0;
  let invalid = 0;
  let omitted = 0;
  let cancelled = isAnalysisCancelled(options.signal);
  let truncated = false;
  const explicitEntrypoints = new Set((input.entrypoints ?? []).map((value) => boundedRelativeId(value)).filter((value): value is string => value !== undefined));
  for (let index = 0; !cancelled && index < input.sources.length; index += 1) {
    const raw = input.sources[index];
    if (raw === undefined) {
      continue;
    }
    if (sources.size >= resolvedLimits.maximumFiles) {
      omitted = input.sources.length - index;
      truncated = true;
      break;
    }
    const fileId = boundedRelativeId(raw.fileId);
    const byteLength = new TextEncoder().encode(raw.content).length;
    if (fileId === undefined || sources.has(fileId) || byteLength > resolvedLimits.maximumBytesPerFile) {
      invalid += 1;
      continue;
    }
    if (bytesAnalyzed + byteLength > resolvedLimits.maximumBytes) {
      omitted = input.sources.length - index;
      truncated = true;
      break;
    }
    const parsed = raw.language === "python"
      ? parsePython(raw.content, resolvedLimits.maximumImportsPerFile)
      : parseJavaScript(raw.content, resolvedLimits.maximumImportsPerFile);
    sources.set(fileId, Object.freeze({ fileId, language: raw.language, imports: parsed.imports, uncertain: parsed.uncertain, entrypoint: raw.entrypoint === true || explicitEntrypoints.has(fileId) }));
    bytesAnalyzed += byteLength;
    cancelled = isAnalysisCancelled(options.signal);
  }
  omitted = Math.max(omitted, input.sources.length - sources.size - invalid);
  const moduleToFile = new Map<string, string>();
  for (const source of sources.values()) {
    for (const moduleId of sourceModuleIds(source.fileId, source.language)) {
      moduleToFile.set(moduleId, source.fileId);
    }
  }
  const edges = new Map<string, string[]>();
  let edgeCount = 0;
  for (const source of sources.values()) {
    const targets: string[] = [];
    for (const observed of source.imports) {
      const resolved = source.language === "python"
        ? resolvePython(source.fileId, observed.specifier, moduleToFile)
        : resolveRelativeJavaScript(source.fileId, observed.specifier, sources);
      if (resolved !== undefined) {
        if (edgeCount >= resolvedLimits.maximumEdges) {
          truncated = true;
          break;
        }
        targets.push(resolved);
        edgeCount += 1;
      }
    }
    edges.set(source.fileId, [...new Set(targets)].sort(compareText));
  }
  const predecessor = new Map<string, string | undefined>();
  const queue = [...sources.values()].filter((source) => source.entrypoint).map((source) => source.fileId).sort(compareText);
  queue.forEach((fileId) => predecessor.set(fileId, undefined));
  for (let index = 0; index < queue.length && !cancelled; index += 1) {
    const fileId = queue[index];
    if (fileId === undefined) {
      continue;
    }
    for (const target of edges.get(fileId) ?? []) {
      if (!predecessor.has(target)) {
        predecessor.set(target, fileId);
        queue.push(target);
      }
    }
    cancelled = isAnalysisCancelled(options.signal);
  }
  const uncertainReachableFiles = [...predecessor.keys()].filter((fileId) => sources.get(fileId)?.uncertain === true).length;
  const baseIncomplete = cancelled || truncated || invalid > 0 || omitted > 0 || queue.length === 0 || uncertainReachableFiles > 0;
  const findings: StaticReachabilityFinding[] = [];
  const targetLimit = Math.min(input.targets.length, resolvedLimits.maximumTargets);
  if (input.targets.length > targetLimit) {
    truncated = true;
  }
  for (let index = 0; index < targetLimit; index += 1) {
    const target = input.targets[index];
    if (target === undefined) {
      continue;
    }
    const packageName = safePackageName(target.packageName, target.ecosystem);
    const targetId = boundedOpaqueId(target.targetId, MAXIMUM_IDENTITY);
    const affectedSymbols = (target.affectedSymbols ?? []).slice(0, 128)
      .map((value) => boundedEvidenceText(value, MAXIMUM_IDENTITY))
      .filter((value): value is string => value !== undefined).sort(compareText);
    if (packageName === undefined || targetId === undefined || affectedSymbols.length !== (target.affectedSymbols?.length ?? 0)) {
      findings.push(unknownFinding(target, "Target identity or advisory symbol evidence is invalid or exceeds bounds."));
      continue;
    }
    let reached: { readonly fileId: string; readonly symbol: string; readonly wildcard: boolean } | undefined;
    let ambiguousPackageUse = false;
    for (const fileId of [...predecessor.keys()].sort(compareText)) {
      const source = sources.get(fileId);
      if (source === undefined || (target.ecosystem === "npm" && source.language === "python") || (target.ecosystem === "PyPI" && source.language !== "python")) {
        continue;
      }
      for (const observed of source.imports) {
        const observedPackage = target.ecosystem === "npm" ? npmPackage(observed.specifier) : pythonPackage(observed.specifier);
        if (observedPackage === packageName) {
          const symbol = symbolMatch(observed, affectedSymbols);
          if (symbol !== undefined) {
            reached = { fileId, symbol, wildcard: observed.wildcard };
            break;
          }
          if (observed.wildcard && affectedSymbols.length > 0) {
            ambiguousPackageUse = true;
          }
        }
      }
      if (reached !== undefined) {
        break;
      }
    }
    if (reached !== undefined) {
      const sourcePath: string[] = [];
      let cursor: string | undefined = reached.fileId;
      while (cursor !== undefined && sourcePath.length < resolvedLimits.maximumPathDepth) {
        sourcePath.push(cursor);
        cursor = predecessor.get(cursor);
      }
      if (cursor !== undefined) {
        findings.push(unknownFinding(target, "A candidate static path exceeded the configured path-depth limit."));
        truncated = true;
        continue;
      }
      sourcePath.reverse();
      if (
        sourcePath.some((fileId) => sources.get(fileId)?.uncertain === true)
      ) {
        findings.push(
          unknownFinding(
            target,
            "A candidate static path crosses source with parser or dynamic-loading uncertainty.",
          ),
        );
        continue;
      }
      const path = [...sourcePath, packageName, ...(reached.symbol === "*" ? [] : [reached.symbol])];
      findings.push(Object.freeze({
        targetId, ecosystem: target.ecosystem, packageName,
        affectedSymbols: freezeStrings(affectedSymbols), status: "REACHABLE",
        confidence: reached.wildcard && affectedSymbols.length > 0 ? "MEDIUM" : affectedSymbols.length > 0 ? "HIGH" : "MEDIUM",
        path: freezeStrings(path), ...(reached.symbol === "*" ? {} : { observedSymbol: reached.symbol }),
        evidence: affectedSymbols.length > 0
          ? "A bounded static import/reference path observes an advisory-supplied symbol."
          : "A bounded static import path observes the vulnerable dependency.",
        limitations: freezeStrings(["Static reachability is not runtime reachability and does not establish exploitability."]),
        exploitability: "NOT_ESTABLISHED",
      }));
    } else if (baseIncomplete || ambiguousPackageUse) {
      findings.push(
        unknownFinding(
          target,
          ambiguousPackageUse
            ? "The package is statically observed, but affected-symbol use cannot be resolved safely."
            : "Reachability is unknown because entrypoints, parsing, dynamic imports, cancellation, or resource coverage are incomplete.",
        ),
      );
    } else {
      findings.push(Object.freeze({
        targetId, ecosystem: target.ecosystem, packageName,
        affectedSymbols: freezeStrings(affectedSymbols), status: "NOT_OBSERVED", confidence: "MEDIUM",
        path: Object.freeze([]), evidence: "No matching static import/reference was observed from the supplied entrypoints within complete bounded coverage.",
        limitations: freezeStrings(["NOT_OBSERVED does not mean unreachable, safe, or non-exploitable; runtime loading, reflection, aliases, generated code, and parser limits may differ."]),
        exploitability: "NOT_ESTABLISHED",
      }));
    }
  }
  findings.sort((left, right) => compareText(JSON.stringify([left.ecosystem, left.packageName, left.targetId]), JSON.stringify([right.ecosystem, right.packageName, right.targetId])));
  const analysisComplete = !cancelled && !truncated && invalid === 0 && omitted === 0 && queue.length > 0 && uncertainReachableFiles === 0 && findings.every((finding) => finding.status !== "UNKNOWN");
  const coverage = Object.freeze({
    sourceFilesTotal: input.sources.length, sourceFilesAnalyzed: sources.size, sourceFilesInvalid: invalid,
    sourceFilesOmitted: omitted, bytesAnalyzed, targetsTotal: input.targets.length, targetsAnalyzed: findings.length,
    entrypointsResolved: [...sources.values()].filter((source) => source.entrypoint).length,
    importEdgesObserved: edgeCount, uncertainReachableFiles, truncated, cancelled, analysisComplete,
  });
  return Object.freeze({ findings: Object.freeze(findings), coverage });
}
