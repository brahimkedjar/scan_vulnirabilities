import type { Dependency } from "../models/Dependency";
import { isVulnerabilityArray } from "../models/validators";
import type {
  ProviderResult,
  ProviderStatus,
  ScanError,
} from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";
import type { VulnerabilityProvider } from "../vulnerability/VulnerabilityProvider";
import {
  mapDependencyToOsv,
  type SupportedOsvEcosystem,
} from "../vulnerability/EcosystemMapper";
import type {
  SuccessfulCacheWrite,
  VulnerabilityCache,
  VulnerabilityCacheKey,
} from "./VulnerabilityCache";

export type DependencyAuditProgressSource =
  | "fresh-cache"
  | "provider"
  | "stale-cache"
  | "provider-error";

export interface DependencyAuditProgress {
  readonly completed: number;
  readonly total: number;
  readonly packageName: string;
  readonly version: string;
  readonly source: DependencyAuditProgressSource;
}

export interface DependencyAuditOptions {
  readonly signal?: AbortSignal;
  readonly onProgress?: (progress: DependencyAuditProgress) => void;
}

export interface DependencyAuditServiceOptions {
  readonly maximumConcurrency?: number;
  readonly maximumVulnerabilities?: number;
  readonly maximumResultBytes?: number;
  readonly maximumDurationMs?: number;
}

export interface DependencyAuditResult {
  readonly vulnerabilities: readonly Vulnerability[];
  readonly errors: readonly ScanError[];
  readonly providerResult: ProviderResult;
  readonly subjectResults: readonly DependencyAuditSubjectResult[];
  readonly cancelled: boolean;
}

export interface DependencyAuditSubjectResult {
  readonly packageName: string;
  readonly ecosystem: SupportedOsvEcosystem;
  readonly version: string;
  readonly checked: boolean;
  readonly vulnerabilityCount: number;
  readonly source?: DependencyAuditProgressSource;
}

export type DependencyAuditCache = Pick<
  VulnerabilityCache<Vulnerability[]>,
  "get" | "setMany"
>;

interface AuditSubject {
  readonly packageName: string;
  readonly ecosystem: SupportedOsvEcosystem;
  readonly version: string;
  readonly cacheKey: VulnerabilityCacheKey;
}

type AuditOutcome =
  | {
      readonly kind: "fresh-cache";
      readonly vulnerabilities: Vulnerability[];
    }
  | {
      readonly kind: "provider-success";
      readonly vulnerabilities: Vulnerability[];
    }
  | {
      readonly kind: "provider-error";
      readonly vulnerabilities: Vulnerability[];
      readonly usedStaleCache: boolean;
    };

interface SubjectState {
  readonly subject: AuditSubject;
  staleValue: Vulnerability[] | undefined;
  cacheReadFailed: boolean;
  submitted: boolean;
  outcome: AuditOutcome | undefined;
}

const DEFAULT_MAXIMUM_CONCURRENCY = 5;
const HARD_MAXIMUM_CONCURRENCY = 5;
const MAXIMUM_UNIQUE_SUBJECTS = 5_000;
const DEFAULT_MAXIMUM_VULNERABILITIES = 50_000;
const DEFAULT_MAXIMUM_RESULT_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAXIMUM_DURATION_MS = 10 * 60 * 1_000;

function boundedOption(
  value: number | undefined,
  fallback: number,
  hardMaximum: number,
  name: string,
): number {
  const selected = value ?? fallback;
  if (
    !Number.isSafeInteger(selected) ||
    selected < 1 ||
    selected > hardMaximum
  ) {
    throw new RangeError(`${name} is outside the supported safety range`);
  }
  return selected;
}

function queryKey(
  ecosystem: string,
  packageName: string,
  version: string,
): string {
  return JSON.stringify([ecosystem, packageName, version]);
}

function deduplicateVulnerabilities(
  vulnerabilities: readonly Vulnerability[],
): Vulnerability[] {
  const unique = new Map<string, Vulnerability>();
  for (const vulnerability of vulnerabilities) {
    const key = JSON.stringify([
      vulnerability.source,
      vulnerability.id,
      vulnerability.ecosystem,
      vulnerability.packageName,
      vulnerability.installedVersion,
    ]);
    if (!unique.has(key)) {
      unique.set(key, vulnerability);
    }
  }
  return [...unique.values()];
}

function vulnerabilitiesMatchSubject(
  value: readonly Vulnerability[],
  subject: AuditSubject,
  providerName: string,
): boolean {
  return (
    isVulnerabilityArray(value) &&
    value.every(
      (vulnerability) =>
        typeof vulnerability === "object" &&
        vulnerability !== null &&
        vulnerability.packageName === subject.packageName &&
        vulnerability.ecosystem === subject.ecosystem &&
        vulnerability.installedVersion === subject.version &&
        vulnerability.source === providerName,
    )
  );
}

function statusForResult(
  cancelled: boolean,
  successful: number,
  failed: number,
): ProviderStatus {
  if (cancelled) {
    return "partial";
  }
  if (failed === 0) {
    return "available";
  }
  return successful === 0 ? "unavailable" : "partial";
}

export class DependencyAuditService {
  private readonly maximumConcurrency: number;
  private readonly maximumVulnerabilities: number;
  private readonly maximumResultBytes: number;
  private readonly maximumDurationMs: number;

  public constructor(
    private readonly provider: VulnerabilityProvider,
    private readonly cache: DependencyAuditCache,
    options: DependencyAuditServiceOptions = {},
  ) {
    const maximumConcurrency =
      options.maximumConcurrency ?? DEFAULT_MAXIMUM_CONCURRENCY;
    if (
      !Number.isSafeInteger(maximumConcurrency) ||
      maximumConcurrency < 1 ||
      maximumConcurrency > HARD_MAXIMUM_CONCURRENCY
    ) {
      throw new RangeError("maximumConcurrency must be between 1 and 5");
    }
    this.maximumConcurrency = maximumConcurrency;
    this.maximumVulnerabilities = boundedOption(
      options.maximumVulnerabilities,
      DEFAULT_MAXIMUM_VULNERABILITIES,
      100_000,
      "maximumVulnerabilities",
    );
    this.maximumResultBytes = boundedOption(
      options.maximumResultBytes,
      DEFAULT_MAXIMUM_RESULT_BYTES,
      256 * 1024 * 1024,
      "maximumResultBytes",
    );
    this.maximumDurationMs = boundedOption(
      options.maximumDurationMs,
      DEFAULT_MAXIMUM_DURATION_MS,
      60 * 60 * 1_000,
      "maximumDurationMs",
    );
  }

  public async audit(
    dependencies: readonly Dependency[],
    options: DependencyAuditOptions = {},
  ): Promise<DependencyAuditResult> {
    const validationErrors: ScanError[] = [];
    const subjects = this.collectEligibleSubjects(dependencies, validationErrors);
    const states = subjects.map<SubjectState>((subject) => ({
      subject,
      staleValue: undefined,
      cacheReadFailed: false,
      submitted: false,
      outcome: undefined,
    }));
    const queryIndexes: number[] = [];
    const controller = new AbortController();
    let externallyCancelled = false;
    let limitExceeded = false;
    let limitMessage = "The scan-wide vulnerability result safety limit was reached.";
    const onExternalCancellation = (): void => {
      externallyCancelled = true;
      controller.abort();
    };
    options.signal?.addEventListener("abort", onExternalCancellation, {
      once: true,
    });
    if (options.signal?.aborted === true) {
      onExternalCancellation();
    }
    const stopForLimit = (message: string): void => {
      if (!limitExceeded) {
        limitExceeded = true;
        limitMessage = message;
      }
      controller.abort();
    };
    const deadline = setTimeout(() => {
      stopForLimit("The dependency audit exceeded its scan-wide time limit.");
    }, this.maximumDurationMs);

    try {
      let completed = 0;
      let accumulatedVulnerabilities = 0;
      let accumulatedBytes = 0;
      const consumeResultBudget = (
        value: readonly Vulnerability[],
      ): boolean => {
        let serialized: string;
        try {
          serialized = JSON.stringify(value);
        } catch {
          stopForLimit("A provider result could not be measured safely.");
          return false;
        }
        const bytes = new TextEncoder().encode(serialized).byteLength;
        if (
          value.length >
            this.maximumVulnerabilities - accumulatedVulnerabilities ||
          bytes > this.maximumResultBytes - accumulatedBytes
        ) {
          stopForLimit(
            "The dependency audit exceeded its scan-wide vulnerability result limit.",
          );
          return false;
        }
        accumulatedVulnerabilities += value.length;
        accumulatedBytes += bytes;
        return true;
      };
    const report = (
      state: SubjectState,
      source: DependencyAuditProgressSource,
    ): void => {
      completed += 1;
      try {
        options.onProgress?.({
          completed,
          total: states.length,
          packageName: state.subject.packageName,
          version: state.subject.version,
          source,
        });
      } catch {
        // Progress reporting must not change audit correctness.
      }
    };

    for (let index = 0; index < states.length; index += 1) {
        if (controller.signal.aborted) {
          break;
        }
        const state = states[index];
        if (state === undefined) {
          continue;
        }

        try {
          const cached = this.cache.get(state.subject.cacheKey);
          if (cached.status === "fresh") {
            if (
              vulnerabilitiesMatchSubject(
                cached.value,
                state.subject,
                this.provider.name,
              )
            ) {
              if (!consumeResultBudget(cached.value)) {
                break;
              }
              state.outcome = {
                kind: "fresh-cache",
                vulnerabilities: cached.value,
              };
              report(state, "fresh-cache");
              continue;
            }
            state.cacheReadFailed = true;
          }
          if (cached.status === "stale") {
            if (
              vulnerabilitiesMatchSubject(
                cached.value,
                state.subject,
                this.provider.name,
              )
            ) {
              state.staleValue = cached.value;
            } else {
              state.cacheReadFailed = true;
            }
          }
        } catch {
          state.cacheReadFailed = true;
        }
        queryIndexes.push(index);
    }

    let nextQueryIndex = 0;
    const worker = async (): Promise<void> => {
        while (!controller.signal.aborted) {
          const queueIndex = nextQueryIndex;
          nextQueryIndex += 1;
          const stateIndex = queryIndexes[queueIndex];
          if (stateIndex === undefined) {
            return;
          }
          const state = states[stateIndex];
          if (state === undefined) {
            continue;
          }

          state.submitted = true;
          try {
            const providerValue = await this.provider.checkPackage(
              state.subject.packageName,
              state.subject.ecosystem,
              state.subject.version,
              controller.signal,
            );
            if (controller.signal.aborted) {
              return;
            }
            if (!Array.isArray(providerValue)) {
              throw new TypeError("Provider result must be an array");
            }
            if (
              !vulnerabilitiesMatchSubject(
                providerValue,
                state.subject,
                this.provider.name,
              )
            ) {
              throw new TypeError(
                "Provider result does not match the requested package identity",
              );
            }
            if (!consumeResultBudget(providerValue)) {
              return;
            }
            state.outcome = {
              kind: "provider-success",
              vulnerabilities: [...providerValue],
            };
            report(state, "provider");
          } catch (_error: unknown) {
            if (controller.signal.aborted) {
              return;
            }
            const staleValue = state.staleValue;
            if (
              staleValue !== undefined &&
              !consumeResultBudget(staleValue)
            ) {
              return;
            }
            state.outcome = {
              kind: "provider-error",
              vulnerabilities: staleValue === undefined ? [] : staleValue,
              usedStaleCache: staleValue !== undefined,
            };
            report(
              state,
              staleValue === undefined ? "provider-error" : "stale-cache",
            );
          }
        }
    };

    if (!controller.signal.aborted && queryIndexes.length > 0) {
      await Promise.all(
        Array.from(
          {
            length: Math.min(
              this.maximumConcurrency,
              queryIndexes.length,
            ),
          },
          worker,
        ),
      );
    }

    const errors: ScanError[] = [...validationErrors];
    if (limitExceeded) {
      errors.push({
        code: "DEPENDENCY_LIMIT",
        message: limitMessage,
        provider: this.provider.name,
      });
    }
    const vulnerabilities: Vulnerability[] = [];
    const stagedWrites: SuccessfulCacheWrite<Vulnerability[]>[] = [];
    let submitted = 0;
    let successful = 0;
    let failed = 0;
    let cacheHits = 0;
    let staleCacheFallbacks = 0;

    for (const state of states) {
      if (state.cacheReadFailed) {
        errors.push({
          code: "CACHE_ERROR",
          message: "The vulnerability cache could not be read for this dependency.",
          packageName: state.subject.packageName,
          provider: this.provider.name,
        });
      }
      if (state.submitted) {
        submitted += 1;
      }

      const outcome = state.outcome;
      if (outcome === undefined) {
        continue;
      }
      vulnerabilities.push(...outcome.vulnerabilities);

      if (outcome.kind === "fresh-cache") {
        cacheHits += 1;
        successful += 1;
      } else if (outcome.kind === "provider-success") {
        successful += 1;
        stagedWrites.push({
          key: state.subject.cacheKey,
          value: outcome.vulnerabilities,
        });
      } else {
        failed += 1;
        if (outcome.usedStaleCache) {
          staleCacheFallbacks += 1;
        }
        errors.push({
          code: "PROVIDER_ERROR",
          message: "The vulnerability provider could not audit this dependency.",
          packageName: state.subject.packageName,
          provider: this.provider.name,
        });
      }
    }

    if (limitExceeded) {
      failed += states.filter((state) => state.outcome === undefined).length;
    }

    // Yield once so cancellation queued by the final progress event is observed
    // before the cache's single atomic commit begins.
    await Promise.resolve();
    if (!controller.signal.aborted && stagedWrites.length > 0) {
      try {
        await this.cache.setMany(stagedWrites);
      } catch {
        errors.push({
          code: "CACHE_ERROR",
          message: "Successful vulnerability results could not be cached.",
          provider: this.provider.name,
        });
      }
    }

    const cancelled = externallyCancelled;
    const uniqueVulnerabilities = deduplicateVulnerabilities(vulnerabilities);
    const providerResult: ProviderResult = {
      provider: this.provider.name,
      status: statusForResult(cancelled || limitExceeded, successful, failed),
      dependenciesEligible: states.length,
      dependenciesSubmitted: submitted,
      successful,
      failed,
      cacheHits,
      staleCacheFallbacks,
      vulnerabilitiesFound: uniqueVulnerabilities.length,
    };

      const subjectResults: DependencyAuditSubjectResult[] = states.map(
        (state) => {
          const outcome = state.outcome;
          const source: DependencyAuditProgressSource | undefined =
            outcome?.kind === "fresh-cache"
              ? "fresh-cache"
              : outcome?.kind === "provider-success"
                ? "provider"
                : outcome?.kind === "provider-error"
                  ? outcome.usedStaleCache
                    ? "stale-cache"
                    : "provider-error"
                  : undefined;
          const base = {
            packageName: state.subject.packageName,
            ecosystem: state.subject.ecosystem,
            version: state.subject.version,
            checked:
              outcome?.kind === "fresh-cache" ||
              outcome?.kind === "provider-success" ||
              (outcome?.kind === "provider-error" &&
                outcome.usedStaleCache),
            vulnerabilityCount: outcome?.vulnerabilities.length ?? 0,
          };
          return source === undefined ? base : { ...base, source };
        },
      );
      const result: DependencyAuditResult = {
        vulnerabilities: uniqueVulnerabilities,
        errors,
        providerResult,
        subjectResults,
        cancelled,
      };
      return result;
    } finally {
      clearTimeout(deadline);
      options.signal?.removeEventListener("abort", onExternalCancellation);
    }
  }

  private collectEligibleSubjects(
    dependencies: readonly Dependency[],
    errors: ScanError[],
  ): AuditSubject[] {
    const subjects = new Map<string, AuditSubject>();
    const invalidDependencies = new Set<string>();
    let dependencyLimitReached = false;

    for (const dependency of dependencies) {
      const mapping = mapDependencyToOsv(dependency);
      if (!mapping.supported) {
        const invalidKey = queryKey(
          dependency.ecosystem,
          dependency.name,
          dependency.installedVersion,
        );
        if (!invalidDependencies.has(invalidKey)) {
          invalidDependencies.add(invalidKey);
          errors.push({
            code:
              mapping.kind === "unresolved"
                ? "DEPENDENCY_UNRESOLVED"
                : mapping.kind === "version"
                  ? "UNSUPPORTED_VERSION"
                  : "UNSUPPORTED_PACKAGE_IDENTITY",
            message: mapping.reason,
            packageName: dependency.name,
            provider: this.provider.name,
          });
        }
        continue;
      }
      const { packageName, ecosystem, version } = mapping.identity;

      const key = queryKey(ecosystem, packageName, version);
      if (!subjects.has(key)) {
        if (subjects.size >= MAXIMUM_UNIQUE_SUBJECTS) {
          dependencyLimitReached = true;
          continue;
        }
        subjects.set(key, {
          packageName,
          ecosystem,
          version,
          cacheKey: {
            provider: this.provider.name,
            ecosystem,
            packageName,
            version,
          },
        });
      }
    }
    if (dependencyLimitReached) {
      errors.push({
        code: "DEPENDENCY_LIMIT",
        message: `Only the first ${MAXIMUM_UNIQUE_SUBJECTS.toString()} unique ecosystem/package/version identities were audited.`,
        provider: this.provider.name,
      });
    }
    return [...subjects.values()];
  }
}
